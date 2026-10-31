"""Orchestration shared by the CLI and the admin UI."""

from __future__ import annotations

import logging
import threading

from . import db
from .blocklist import SourceResult, sync_sources
from .config import Settings

LOG = logging.getLogger(__name__)
_SYNC_LOCK = threading.Lock()


def bootstrap(settings: Settings) -> bool:
    """
    Initializes the database and seeds configured sources (idempotent).
    Complexity: Time O(S) | Space O(1)
    """
    # --- DATA ---
    ready = db.init_database(settings.db_path)

    # --- CONDITIONS ---
    if ready and settings.seed_sources:
        conn = db.connect(settings.db_path)
        try:
            if db.seed_sources(conn, settings.seed_sources):
                db.bump_version(conn, db.LIST_VERSION)
        finally:
            conn.close()

    # --- RETURNS ---
    return ready


def run_sync(settings: Settings) -> list[SourceResult]:
    """
    Pulls every enabled source into the local cache, records status, prunes old
    events and bumps list_version so all processes rebuild their index.
    Non-reentrant: concurrent calls return [] immediately.
    Complexity: Time O(S * B) network + O(E) prune | Space O(B)
    """
    # --- DATA ---
    results: list[SourceResult] = []

    # --- CONDITIONS ---
    if not _SYNC_LOCK.acquire(blocking=False):
        return results

    try:
        conn = db.connect(settings.db_path)
        try:
            sources = [(r["url"], r["category"]) for r in db.list_sources(conn, True)]
            results = sync_sources(
                sources,
                settings.cache_dir,
                settings.allowed_source_hosts,
                settings.max_list_bytes,
                settings.fetch_timeout,
            )
            for result in results:
                status = "ok" if result.ok else f"cached: {result.error}" if result.from_cache \
                    else f"failed: {result.error}"
                db.update_source_status(conn, result.url, status, result.entries)
                LOG.info("Sync %s -> %s (%d entries)", result.url, status, result.entries)
            db.prune_events(conn, settings.retention_days)
            db.bump_version(conn, db.LIST_VERSION)
        finally:
            conn.close()
    finally:
        _SYNC_LOCK.release()

    # --- RETURNS ---
    return results


def run_sync_async(settings: Settings) -> bool:
    """
    Starts run_sync in a daemon thread (used by the admin UI to avoid request timeouts).
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    started = False

    # --- CONDITIONS ---
    if not _SYNC_LOCK.locked():
        threading.Thread(target=run_sync, args=(settings,), name="sync", daemon=True).start()
        started = True

    # --- RETURNS ---
    return started
