"""Domain normalization, validation, and list-line parsing.

All untrusted input (DNS queries, list files, admin forms) passes through
`normalize_domain` before it touches memory structures, SQL, or email headers.
"""

from __future__ import annotations

import re

MAX_DOMAIN_LENGTH = 253
_LABEL_RE = re.compile(r"(?!-)[a-z0-9_-]{1,63}(?<!-)")
_CATEGORY_RE = re.compile(r"[a-z0-9][a-z0-9_-]{0,31}")
_HOSTS_PREFIXES = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})  # nosec B104 # noqa: S104
_RESERVED = frozenset({"localhost", "localhost.localdomain", "local", "broadcasthost"})


def normalize_domain(raw: str) -> str:
    """
    Returns the canonical lowercase ASCII (IDNA) form of a domain, or '' if invalid.
    Complexity: Time O(L) | Space O(L) where L is the domain length
    """
    # --- DATA ---
    candidate = (raw or "").strip().lower().rstrip(".")
    normalized = ""
    labels: list[str] = []

    # --- CONDITIONS ---
    if not candidate or len(candidate) > MAX_DOMAIN_LENGTH * 4:
        return ""

    if candidate.startswith("*."):
        candidate = candidate[2:]
    if not candidate.isascii():
        try:
            candidate = candidate.encode("idna").decode("ascii")
        except UnicodeError:
            candidate = ""

    labels = candidate.split(".") if candidate else []
    if (
        labels
        and len(candidate) <= MAX_DOMAIN_LENGTH
        and all(_LABEL_RE.fullmatch(label) for label in labels)
    ):
        normalized = candidate

    # --- RETURNS ---
    return normalized


def normalize_category(raw: str, default: str = "uncategorized") -> str:
    """
    Returns a safe category slug (a-z, 0-9, '_', '-', max 32 chars) or the default.
    Complexity: Time O(L) | Space O(L)
    """
    # --- DATA ---
    candidate = (raw or "").strip().lower()
    category = default

    # --- CONDITIONS ---
    if _CATEGORY_RE.fullmatch(candidate):
        category = candidate

    # --- RETURNS ---
    return category


def is_listable(domain: str) -> bool:
    """
    True if a normalized domain may be placed on a list (>= 2 labels, not reserved).
    Prevents accidentally blocking an entire TLD such as 'com'.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    listable = False

    # --- CONDITIONS ---
    if domain and "." in domain and domain not in _RESERVED:
        listable = True

    # --- RETURNS ---
    return listable


def parse_list_line(line: str, default_category: str) -> tuple[str, str] | None:
    """
    Parses one list line. Supported formats:
      'domain.com'            'domain.com,category'
      '0.0.0.0 domain.com'    'domain.com  # trailing comment'
    Complexity: Time O(L) | Space O(L)
    """
    # --- DATA ---
    text = (line or "").split("#", 1)[0].strip()
    domain_part = ""
    category = default_category
    result: tuple[str, str] | None = None

    # --- CONDITIONS ---
    if not text:
        return None

    if "," in text:
        domain_part, _, category_part = text.partition(",")
        category = normalize_category(category_part, default_category)
        tokens = domain_part.split()
        if len(tokens) >= 2 and tokens[0] in _HOSTS_PREFIXES:
            domain_part = tokens[1]
    else:
        tokens = text.split()
        has_hosts_prefix = len(tokens) >= 2 and tokens[0] in _HOSTS_PREFIXES
        domain_part = tokens[1] if has_hosts_prefix else tokens[0]

    domain = normalize_domain(domain_part)
    if is_listable(domain):
        result = (domain, category)

    # --- RETURNS ---
    return result


def candidate_suffixes(domain: str) -> list[str]:
    """
    Expands a domain into itself plus every parent, most specific first, excluding the TLD.
    'a.b.example.com' -> ['a.b.example.com', 'b.example.com', 'example.com']
    Complexity: Time O(M * L) | Space O(M * L) where M is label depth
    """
    # --- DATA ---
    labels = domain.split(".") if domain else []
    candidates: list[str] = []

    # --- CONDITIONS ---
    if len(labels) >= 2:
        candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)]

    # --- RETURNS ---
    return candidates


def reverse_labels(domain: str) -> str:
    """
    Reverses label order so a sorted list groups whole subtrees together.
    'ads.example.com' -> 'com.example.ads'
    Complexity: Time O(L) | Space O(L)
    """
    # --- DATA ---
    reversed_key = ""

    # --- CONDITIONS ---
    if domain:
        reversed_key = ".".join(reversed(domain.split(".")))

    # --- RETURNS ---
    return reversed_key
