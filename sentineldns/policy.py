"""Policy engine: merges admin rules, category actions and the blocklist index.

Readers call `decide()` without locks: the whole PolicyState is immutable and
replaced by a single reference assignment (atomic under CPython).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from . import db
from .blocklist import EMPTY_SNAPSHOT, Snapshot, build_snapshot, load_entries, lookup_hash
from .config import Settings
from .domains import candidate_suffixes, normalize_domain

LOG = logging.getLogger(__name__)


@dataclass(frozen=True)
class Decision:
    """Result of evaluating one query."""

    query: str
    action: str  # BLOCK | MONITOR | ALLOW | PASS
    category: str = "clean"
    matched: str = ""
    origin: str = "none"  # rule | list | none

    @property
    def is_blocked(self) -> bool:
        """
        True when traffic must be blocked.
        Complexity: Time O(1) | Space O(1)
        """
        # --- DATA ---
        blocked = self.action == "BLOCK"

        # --- CONDITIONS ---
        # (none)

        # --- RETURNS ---
        return blocked

    @property
    def should_record(self) -> bool:
        """
        True when the hit is logged and queued for human review.
        Complexity: Time O(1) | Space O(1)
        """
        # --- DATA ---
        record = self.action in ("BLOCK", "MONITOR")

        # --- CONDITIONS ---
        # (none)

        # --- RETURNS ---
        return record


@dataclass(frozen=True)
class PolicyState:
    """Immutable snapshot of everything `decide()` needs."""

    snapshot: Snapshot = EMPTY_SNAPSHOT
    rules: Mapping[str, tuple[str, str]] = field(default_factory=lambda: MappingProxyType({}))
    category_actions: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    versions: tuple[int, int] = (-1, -1)


def evaluate(state: PolicyState, query: str, default_action: str = "BLOCK") -> Decision:
    """
    Pure decision function. Precedence: admin rule (most specific) > list category > PASS.
    Complexity: Time O(M) average where M is label depth | Space O(M)
    """
    # --- DATA ---
    domain = normalize_domain(query)
    decision = Decision(query=query, action="PASS")
    suffixes: list[str] = []

    # --- CONDITIONS ---
    if not domain:
        return decision

    suffixes = candidate_suffixes(domain)
    for candidate in suffixes:
        rule = state.rules.get(candidate)
        if rule is not None:
            decision = Decision(domain, rule[0], rule[1], candidate, "rule")
            break

    if decision.origin == "none":
        match = lookup_hash(state.snapshot, domain)
        if match is not None:
            matched, category = match
            action = state.category_actions.get(category, default_action)
            decision = Decision(domain, action, category, matched, "list")
        else:
            decision = Decision(domain, "PASS")

    # --- RETURNS ---
    return decision


class PolicyEngine:
    """Holds the current PolicyState and refreshes it when DB versions change."""

    def __init__(self, settings: Settings) -> None:
        # --- DATA ---
        self._settings = settings
        self._state = PolicyState()
        self._write_lock = threading.Lock()
        self._stop = threading.Event()
        self._watcher: threading.Thread | None = None

    @property
    def state(self) -> PolicyState:
        """
        Current immutable state (lock-free read).
        Complexity: Time O(1) | Space O(1)
        """
        # --- DATA ---
        current = self._state

        # --- CONDITIONS ---
        # (none)

        # --- RETURNS ---
        return current

    def decide(self, query: str) -> Decision:
        """
        Evaluates a query against the current state.
        Complexity: Time O(M) | Space O(M)
        """
        # --- DATA ---
        state = self._state

        # --- CONDITIONS ---
        # (none)

        # --- RETURNS ---
        return evaluate(state, query, self._settings.default_category_action)

    def reload(self, force: bool = False) -> bool:
        """
        Rebuilds rules/categories (cheap) and/or the blocklist snapshot (O(N log N))
        only when the corresponding DB version changed. Writers are serialized.
        Complexity: Time O(R + C) or O(N log N) on list change | Space O(N)
        """
        # --- DATA ---
        settings = self._settings
        changed = False

        # --- CONDITIONS ---
        with self._write_lock:
            current = self._state
            conn = db.connect(settings.db_path)
            try:
                versions = db.get_versions(conn)
                list_changed = force or versions[1] != current.versions[1]
                policy_changed = force or versions[0] != current.versions[0] or list_changed
                snapshot = current.snapshot
                if list_changed:
                    sources = [(r["url"], r["category"]) for r in db.list_sources(conn, True)]
                    entries = load_entries(sources, settings.cache_dir, settings.local_lists_dir)
                    snapshot = build_snapshot(entries)
                    db.ensure_categories(
                        conn,
                        sorted(set(snapshot.categories.values())),
                        settings.default_category_action,
                    )
                if policy_changed:
                    rules = {
                        r["domain"]: (r["action"], r["category"]) for r in db.list_rules(conn)
                    }
                    self._state = PolicyState(
                        snapshot=snapshot,
                        rules=MappingProxyType(rules),
                        category_actions=MappingProxyType(db.category_actions(conn)),
                        versions=versions,
                    )
                    changed = True
                    LOG.info(
                        "Policy reloaded: %d domains, %d rules", snapshot.size, len(rules)
                    )
            finally:
                conn.close()

        # --- RETURNS ---
        return changed

    def start_watcher(self) -> None:
        """
        Starts a daemon thread that polls DB versions every reload_interval seconds.
        Complexity: Time O(1) per poll when unchanged | Space O(1)
        """
        # --- DATA ---
        interval = self._settings.reload_interval

        # --- CONDITIONS ---
        if self._watcher is not None and self._watcher.is_alive():
            return

        def _loop() -> None:
            while not self._stop.wait(interval):
                try:
                    self.reload()
                except Exception:  # keep serving the last good state
                    LOG.exception("Policy reload failed; keeping previous state")

        self._watcher = threading.Thread(target=_loop, name="policy-watcher", daemon=True)
        self._watcher.start()

        # --- RETURNS ---
        return None

    def stop(self) -> None:
        """
        Signals the watcher thread to exit.
        Complexity: Time O(1) | Space O(1)
        """
        # --- DATA ---
        stop_event = self._stop

        # --- CONDITIONS ---
        stop_event.set()

        # --- RETURNS ---
        return None
