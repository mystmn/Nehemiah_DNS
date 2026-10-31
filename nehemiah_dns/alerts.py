"""Review e-mail alerts: bounded queue + single worker so SMTP latency never
touches the DNS/HTTP hot path, and a per-domain cooldown prevents mail floods."""

from __future__ import annotations

import logging
import queue
import smtplib
import ssl
import threading
from collections.abc import Mapping
from email.message import EmailMessage

from .config import Settings

LOG = logging.getLogger(__name__)


def build_review_email(settings: Settings, review: Mapping) -> EmailMessage:
    """
    Builds the review e-mail. Values are pre-validated domains; EmailMessage also
    rejects CR/LF in headers, preventing header injection.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    message = EmailMessage()
    matched = review["matched"]
    review_url = f"{settings.public_url}/admin#review-{matched}"

    # --- CONDITIONS ---
    message["Subject"] = f"[Nehemiah_DNS Review] {review['action']} hit on {matched}"
    message["From"] = settings.alert_from
    message["To"] = settings.alert_to
    message.set_content(
        "Nehemiah_DNS domain hit - review requested\n"
        "-----------------------------------------\n"
        f"Matched rule : {matched}\n"
        f"Last query   : {review['last_query']}\n"
        f"Category     : {review['category']}\n"
        f"Action       : {review['action']}\n"
        f"Client IP    : {review['last_client']}\n"
        f"Hit count    : {review['hit_count']}\n"
        f"First seen   : {review['first_seen']} (UTC)\n"
        f"Last seen    : {review['last_seen']} (UTC)\n\n"
        f"Review: {review_url}\n"
        "Choose Confirm (keep blocking), Allow (whitelist) or Dismiss.\n"
    )

    # --- RETURNS ---
    return message


def send_email(settings: Settings, message: EmailMessage) -> bool:
    """
    Sends via SMTP with verified TLS (implicit TLS on 465, STARTTLS otherwise).
    Complexity: Time O(1) network bound | Space O(1)
    """
    # --- DATA ---
    context = ssl.create_default_context()
    sent = False

    # --- CONDITIONS ---
    if not settings.smtp_host or not settings.alert_to:
        return False

    try:
        if settings.smtp_port == 465:
            client: smtplib.SMTP = smtplib.SMTP_SSL(
                settings.smtp_host, settings.smtp_port, timeout=10.0, context=context
            )
        else:
            client = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10.0)
        with client:
            if settings.smtp_port != 465 and settings.smtp_starttls:
                client.starttls(context=context)
            if settings.smtp_user and settings.smtp_secret:
                client.login(settings.smtp_user, settings.smtp_secret)
            client.send_message(message)
        sent = True
    except (smtplib.SMTPException, OSError) as exc:
        LOG.error("Alert e-mail failed: %s", exc)
        sent = False

    # --- RETURNS ---
    return sent


class AlertDispatcher:
    """Bounded queue of review rows, drained by one daemon worker."""

    def __init__(self, settings: Settings, sender=send_email, maxsize: int = 1000) -> None:  # noqa: ANN001
        # --- DATA ---
        self._settings = settings
        self._sender = sender
        self._queue: queue.Queue = queue.Queue(maxsize=maxsize)
        self._thread: threading.Thread | None = None
        self.sent = 0
        self.dropped = 0

    @property
    def enabled(self) -> bool:
        """
        True when SMTP and a recipient are configured.
        Complexity: Time O(1) | Space O(1)
        """
        # --- DATA ---
        configured = bool(self._settings.smtp_host and self._settings.alert_to)

        # --- CONDITIONS ---
        # (none)

        # --- RETURNS ---
        return configured

    def enqueue(self, review: Mapping) -> bool:
        """
        Non-blocking enqueue; drops (and counts) when full.
        Complexity: Time O(1) | Space O(1)
        """
        # --- DATA ---
        accepted = False

        # --- CONDITIONS ---
        if not self.enabled:
            LOG.info("Review pending for %s (SMTP not configured)", review["matched"])
            return False

        try:
            self._queue.put_nowait(dict(review))
            accepted = True
        except queue.Full:
            self.dropped += 1

        # --- RETURNS ---
        return accepted

    def process_one(self, timeout: float = 1.0) -> bool:
        """
        Sends at most one queued alert. Returns True if one was processed.
        Complexity: Time O(1) network bound | Space O(1)
        """
        # --- DATA ---
        processed = False

        # --- CONDITIONS ---
        try:
            review = self._queue.get(timeout=timeout)
        except queue.Empty:
            return False

        try:
            if self._sender(self._settings, build_review_email(self._settings, review)):
                self.sent += 1
            processed = True
        finally:
            self._queue.task_done()

        # --- RETURNS ---
        return processed

    def start(self) -> None:
        """
        Starts the daemon worker thread.
        Complexity: Time O(1) | Space O(1)
        """
        # --- DATA ---
        running = self._thread is not None and self._thread.is_alive()

        # --- CONDITIONS ---
        if running:
            return

        def _loop() -> None:
            while True:
                try:
                    self.process_one()
                except Exception:
                    LOG.exception("Alert worker error")

        self._thread = threading.Thread(target=_loop, name="alert-dispatcher", daemon=True)
        self._thread.start()

        # --- RETURNS ---
        return None
