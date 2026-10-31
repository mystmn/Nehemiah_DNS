"""Hit recorder: O(1) non-blocking submit on the hot path, batched SQLite writes
off the hot path, then cooldown-gated review e-mails."""

from __future__ import annotations

import logging
import queue
import threading

from . import db
from .alerts import AlertDispatcher
from .config import Settings
from .policy import Decision

LOG = logging.getLogger(__name__)
BATCH_SIZE = 500


class HitRecorder:
    """Buffers BLOCK/MONITOR decisions and flushes them in batches."""

    def __init__(self, settings: Settings, dispatcher: AlertDispatcher) -> None:
        # --- DATA ---
        self._settings = settings
        self._dispatcher = dispatcher
        self._queue: queue.Queue = queue.Queue(maxsize=settings.hit_queue_size)
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.dropped = 0
        self.recorded = 0

    def submit(self, decision: Decision, client_ip: str, channel: str) -> bool:
        """
        Enqueues a hit without blocking; drops and counts when the buffer is full so
        the DNS data plane can never be stalled by disk I/O.
        Complexity: Time O(1) | Space O(1)
        """
        # --- DATA ---
        accepted = False
        hit = (
            db.utc_now(),
            decision.query,
            decision.matched,
            decision.category,
            decision.action,
            client_ip or "unknown",
            channel,
        )

        # --- CONDITIONS ---
        if not decision.should_record:
            return False

        try:
            self._queue.put_nowait(hit)
            accepted = True
        except queue.Full:
            self.dropped += 1

        # --- RETURNS ---
        return accepted

    def drain(self, wait: float = 0.0) -> int:
        """
        Drains up to BATCH_SIZE hits, persists them and claims e-mail notifications.
        Complexity: Time O(B log R) | Space O(B)
        """
        # --- DATA ---
        batch: list[tuple] = []
        flushed = 0

        # --- CONDITIONS ---
        try:
            batch.append(self._queue.get(timeout=wait) if wait > 0 else self._queue.get_nowait())
        except queue.Empty:
            return 0

        while len(batch) < BATCH_SIZE:
            try:
                batch.append(self._queue.get_nowait())
            except queue.Empty:
                break

        conn = db.connect(self._settings.db_path)
        try:
            flushed = db.record_hits(conn, batch)
            for matched in {hit[2] for hit in batch}:
                row = db.claim_notification(conn, matched, self._settings.alert_cooldown)
                if row is not None:
                    self._dispatcher.enqueue(row)
        finally:
            conn.close()
        self.recorded += flushed

        # --- RETURNS ---
        return flushed

    def start(self) -> None:
        """
        Starts the background flush thread.
        Complexity: Time O(1) | Space O(1)
        """
        # --- DATA ---
        running = self._thread is not None and self._thread.is_alive()

        # --- CONDITIONS ---
        if running:
            return

        def _loop() -> None:
            while not self._stop.is_set():
                try:
                    self.drain(wait=1.0)
                except Exception:
                    LOG.exception("Hit recorder flush failed")

        self._thread = threading.Thread(target=_loop, name="hit-recorder", daemon=True)
        self._thread.start()

        # --- RETURNS ---
        return None

    def stop(self) -> int:
        """
        Stops the worker and flushes anything still buffered.
        Complexity: Time O(Q log R) | Space O(B)
        """
        # --- DATA ---
        flushed = 0

        # --- CONDITIONS ---
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        while True:
            count = self.drain()
            if count == 0:
                break
            flushed += count

        # --- RETURNS ---
        return flushed
