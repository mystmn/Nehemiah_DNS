"""Blocklist acquisition (GitHub raw .txt -> local cache) and the in-memory index.

Index design (see docs/DESIGN.md):
  * `categories`: dict domain -> category        => O(1) average membership per label
  * `keys`: tuple of reversed-label keys sorted by Timsort (O(N log N) build)
            => O(log N) binary search + O(log N + k) subtree range queries
The Snapshot is immutable and swapped by reference, so readers never take a lock.
"""

from __future__ import annotations

import bisect
import hashlib
import logging
import os
import tempfile
import time
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from urllib.parse import urlsplit

from . import __version__
from .domains import candidate_suffixes, normalize_category, parse_list_line, reverse_labels

LOG = logging.getLogger(__name__)


class FetchError(Exception):
    """Raised when a remote list cannot be retrieved safely."""


@dataclass(frozen=True)
class Snapshot:
    """Immutable, lock-free-readable blocklist index."""

    keys: tuple[str, ...] = ()
    categories: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    built_at: float = 0.0

    @property
    def size(self) -> int:
        """
        Number of unique domains in the index.
        Complexity: Time O(1) | Space O(1)
        """
        # --- DATA ---
        count = len(self.keys)

        # --- CONDITIONS ---
        # (none)

        # --- RETURNS ---
        return count


EMPTY_SNAPSHOT = Snapshot()


@dataclass
class SourceResult:
    """Outcome of syncing one remote source."""

    url: str
    category: str
    ok: bool = False
    from_cache: bool = False
    entries: int = 0
    error: str = ""


# =====================================================================
# INDEX BUILD & LOOKUP
# =====================================================================
def build_snapshot(entries: Iterable[tuple[str, str]]) -> Snapshot:
    """
    Deduplicates (domain, category) pairs (first source wins) and Timsorts reversed keys.
    Complexity: Time O(N log N) worst, O(N) on pre-sorted input | Space O(N)
    """
    # --- DATA ---
    categories: dict[str, str] = {}
    keys: list[str] = []

    # --- CONDITIONS ---
    for domain, category in entries:
        categories.setdefault(domain, category)

    keys = [reverse_labels(domain) for domain in categories]
    keys.sort()

    # --- RETURNS ---
    return Snapshot(tuple(keys), MappingProxyType(categories), time.time())


def lookup_hash(snapshot: Snapshot, domain: str) -> tuple[str, str] | None:
    """
    Hot-path lookup: hash probe for the domain and each parent (most specific first).
    Returns (matched_domain, category) or None.
    Complexity: Time O(M) average where M is label depth | Space O(M)
    """
    # --- DATA ---
    categories = snapshot.categories
    match: tuple[str, str] | None = None

    # --- CONDITIONS ---
    if not domain or not categories:
        return None

    for candidate in candidate_suffixes(domain):
        category = categories.get(candidate)
        if category is not None:
            match = (candidate, category)
            break

    # --- RETURNS ---
    return match


def lookup_bisect(snapshot: Snapshot, domain: str) -> tuple[str, str] | None:
    """
    Equivalent lookup using binary search over the sorted reversed-key tuple.
    Kept as the verifiable O(log N) reference implementation and for admin tooling.
    Complexity: Time O(M * log N) | Space O(M)
    """
    # --- DATA ---
    keys = snapshot.keys
    size = len(keys)
    match: tuple[str, str] | None = None

    # --- CONDITIONS ---
    if not domain or not size:
        return None

    for candidate in candidate_suffixes(domain):
        key = reverse_labels(candidate)
        index = bisect.bisect_left(keys, key)
        if index < size and keys[index] == key:
            match = (candidate, snapshot.categories.get(candidate, "uncategorized"))
            break

    # --- RETURNS ---
    return match


def subtree(snapshot: Snapshot, domain: str, limit: int = 100) -> list[str]:
    """
    Lists the domain and every listed descendant (e.g. all '*.example.com' entries).
    Uses two bisect range scans: exact key, then [key + '.', key + '/').
    Complexity: Time O(log N + k) | Space O(k) where k = min(matches, limit)
    """
    # --- DATA ---
    keys = snapshot.keys
    key = reverse_labels(domain)
    found: list[str] = []

    # --- CONDITIONS ---
    if not key or not keys or limit <= 0:
        return found

    exact = bisect.bisect_left(keys, key)
    if exact < len(keys) and keys[exact] == key:
        found.append(domain)

    low = bisect.bisect_left(keys, key + ".")
    high = bisect.bisect_left(keys, key + "/")
    for child_key in keys[low : min(high, low + max(limit - len(found), 0))]:
        found.append(reverse_labels(child_key))

    # --- RETURNS ---
    return found


def parse_list_text(text: str, default_category: str) -> list[tuple[str, str]]:
    """
    Parses an entire list file into validated (domain, category) pairs.
    Complexity: Time O(L) over total characters | Space O(N)
    """
    # --- DATA ---
    category = normalize_category(default_category)
    entries: list[tuple[str, str]] = []

    # --- CONDITIONS ---
    for line in (text or "").splitlines():
        parsed = parse_list_line(line, category)
        if parsed is not None:
            entries.append(parsed)

    # --- RETURNS ---
    return entries


# =====================================================================
# SAFE REMOTE FETCH (SSRF-hardened)
# =====================================================================
def validate_source_url(url: str, allowed_hosts: Iterable[str]) -> str:
    """
    Validates a remote list URL. Returns '' when acceptable, else an error message.
    Rules: https only, host allow-listed, no credentials, default port.
    Complexity: Time O(H) where H is the allow-list size | Space O(1)
    """
    # --- DATA ---
    error = ""
    allowed = {host.lower() for host in allowed_hosts}

    # --- CONDITIONS ---
    try:
        parts = urlsplit(url or "")
        port = parts.port
    except ValueError:
        return "Malformed URL"

    if parts.scheme != "https":
        error = "Only https:// URLs are permitted"
    elif not parts.hostname or parts.hostname.lower() not in allowed:
        error = f"Host not in NEHEMIAH_ALLOWED_SOURCE_HOSTS: {parts.hostname}"
    elif parts.username or parts.password:
        error = "Credentials in URLs are not permitted"
    elif port not in (None, 443):
        error = "Non-default ports are not permitted"

    # --- RETURNS ---
    return error


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validates every redirect hop so a redirect cannot bypass the host allow-list."""

    def __init__(self, allowed_hosts: Iterable[str]) -> None:
        # --- DATA ---
        super().__init__()
        self._allowed = tuple(allowed_hosts)

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        """
        Rejects redirects to non-allow-listed or non-https targets.
        Complexity: Time O(H) | Space O(1)
        """
        # --- DATA ---
        error = validate_source_url(newurl, self._allowed)

        # --- CONDITIONS ---
        if error:
            raise FetchError(f"Blocked redirect to {newurl}: {error}")

        # --- RETURNS ---
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch_source_text(
    url: str, allowed_hosts: Iterable[str], max_bytes: int, timeout: float
) -> str:
    """
    Downloads a list over HTTPS with host allow-listing, redirect checks and a size cap.
    Complexity: Time O(B) network/IO bound | Space O(B) where B <= max_bytes
    """
    # --- DATA ---
    hosts = tuple(allowed_hosts)
    error = validate_source_url(url, hosts)
    request = urllib.request.Request(  # noqa: S310 - scheme/host validated above
        url, headers={"User-Agent": f"Nehemiah_DNS/{__version__}", "Accept": "text/plain"}
    )
    opener = urllib.request.build_opener(_SafeRedirectHandler(hosts))
    payload = b""

    # --- CONDITIONS ---
    if error:
        raise FetchError(error)

    try:
        with opener.open(request, timeout=timeout) as response:  # nosec B310
            payload = response.read(max_bytes + 1)
    except FetchError:
        raise
    except Exception as exc:  # network, TLS, HTTP errors
        raise FetchError(f"{type(exc).__name__}: {exc}") from exc

    if len(payload) > max_bytes:
        raise FetchError(f"List exceeds NEHEMIAH_MAX_LIST_BYTES ({max_bytes})")

    # --- RETURNS ---
    return payload.decode("utf-8", errors="replace")


# =====================================================================
# LOCAL CACHE ("pulled down for local consumption")
# =====================================================================
def cache_path_for(cache_dir: str, url: str) -> str:
    """
    Deterministic cache file path for a source URL.
    Complexity: Time O(L) | Space O(1)
    """
    # --- DATA ---
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:24]

    # --- CONDITIONS ---
    # (none)

    # --- RETURNS ---
    return os.path.join(cache_dir, f"{digest}.txt")


def write_cache_atomic(path: str, text: str) -> bool:
    """
    Writes text to a temp file then os.replace()s it, so readers never see partial files.
    Complexity: Time O(B) | Space O(1) beyond the input
    """
    # --- DATA ---
    directory = os.path.dirname(path) or "."
    written = False
    temp_path = ""

    # --- CONDITIONS ---
    os.makedirs(directory, exist_ok=True)
    try:
        handle, temp_path = tempfile.mkstemp(dir=directory, suffix=".tmp")
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        written = True
    except OSError as exc:
        LOG.error("Cache write failed for %s: %s", path, exc)
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

    # --- RETURNS ---
    return written


def read_text_file(path: str) -> str | None:
    """
    Reads a UTF-8 text file, returning None if it does not exist or is unreadable.
    Complexity: Time O(B) | Space O(B)
    """
    # --- DATA ---
    content: str | None = None

    # --- CONDITIONS ---
    if not os.path.isfile(path):
        return None

    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            content = handle.read()
    except OSError:
        content = None

    # --- RETURNS ---
    return content


def sync_sources(
    sources: Iterable[tuple[str, str]],
    cache_dir: str,
    allowed_hosts: Iterable[str],
    max_bytes: int,
    timeout: float,
    fetcher=fetch_source_text,  # noqa: ANN001 - injectable for tests
) -> list[SourceResult]:
    """
    Fetches each (url, category) source into the local cache, falling back to the
    last good cached copy on failure (fail-static, never fail-open to an empty list).
    Complexity: Time O(S * B) network bound | Space O(B) per source
    """
    # --- DATA ---
    hosts = tuple(allowed_hosts)
    results: list[SourceResult] = []

    # --- CONDITIONS ---
    for url, category in sources:
        result = SourceResult(url=url, category=category)
        path = cache_path_for(cache_dir, url)
        text: str | None = None
        try:
            text = fetcher(url, hosts, max_bytes, timeout)
            result.ok = write_cache_atomic(path, text)
        except FetchError as exc:
            result.error = str(exc)
            text = read_text_file(path)
            result.from_cache = text is not None
        if text is not None:
            result.entries = len(parse_list_text(text, category))
        results.append(result)

    # --- RETURNS ---
    return results


def load_entries(
    sources: Iterable[tuple[str, str]], cache_dir: str, local_lists_dir: str
) -> list[tuple[str, str]]:
    """
    Loads entries from cached remote sources plus every *.txt in the local lists directory
    (category defaults to the file stem, e.g. lists/malware.txt -> 'malware').
    Complexity: Time O(L) over all list bytes | Space O(N)
    """
    # --- DATA ---
    entries: list[tuple[str, str]] = []
    local_files: list[str] = []

    # --- CONDITIONS ---
    for url, category in sources:
        text = read_text_file(cache_path_for(cache_dir, url))
        if text is not None:
            entries.extend(parse_list_text(text, category))

    if local_lists_dir and os.path.isdir(local_lists_dir):
        local_files = sorted(
            name for name in os.listdir(local_lists_dir) if name.lower().endswith(".txt")
        )
    for name in local_files:
        text = read_text_file(os.path.join(local_lists_dir, name))
        if text is not None:
            entries.extend(parse_list_text(text, os.path.splitext(name)[0]))

    # --- RETURNS ---
    return entries
