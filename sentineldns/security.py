"""Web security primitives: CSRF tokens, login throttling, security headers."""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import deque

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
}


def new_token() -> str:
    """
    Generates a cryptographically secure URL-safe token.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    token = secrets.token_urlsafe(32)

    # --- CONDITIONS ---
    # (none)

    # --- RETURNS ---
    return token


def tokens_match(expected: str | None, provided: str | None) -> bool:
    """
    Constant-time token comparison (prevents timing side channels).
    Complexity: Time O(L) constant w.r.t. content | Space O(1)
    """
    # --- DATA ---
    matched = False

    # --- CONDITIONS ---
    if expected and provided:
        matched = hmac.compare_digest(expected.encode("utf-8"), provided.encode("utf-8"))

    # --- RETURNS ---
    return matched


class LoginThrottle:
    """Sliding-window failed-login limiter keyed by client IP (memory-bounded)."""

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 900,
        max_keys: int = 10000,
    ) -> None:
        # --- DATA ---
        self._max_attempts = max_attempts
        self._window = window_seconds
        self._max_keys = max_keys
        self._failures: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def is_blocked(self, key: str) -> bool:
        """
        True if the key exceeded max_attempts within the window.
        Complexity: Time O(A) where A <= max_attempts | Space O(1)
        """
        # --- DATA ---
        cutoff = time.monotonic() - self._window
        blocked = False

        # --- CONDITIONS ---
        with self._lock:
            attempts = self._failures.get(key)
            if attempts is not None:
                while attempts and attempts[0] < cutoff:
                    attempts.popleft()
                blocked = len(attempts) >= self._max_attempts

        # --- RETURNS ---
        return blocked

    def record_failure(self, key: str) -> None:
        """
        Records a failed attempt; evicts all state if the key table grows too large.
        Complexity: Time O(1) amortized | Space O(K * A)
        """
        # --- DATA ---
        now = time.monotonic()

        # --- CONDITIONS ---
        with self._lock:
            if len(self._failures) >= self._max_keys and key not in self._failures:
                self._failures.clear()
            attempts = self._failures.setdefault(key, deque(maxlen=self._max_attempts))
            attempts.append(now)

        # --- RETURNS ---
        return None

    def reset(self, key: str) -> None:
        """
        Clears failures after a successful login.
        Complexity: Time O(1) | Space O(1)
        """
        # --- DATA ---
        failures = self._failures

        # --- CONDITIONS ---
        with self._lock:
            failures.pop(key, None)

        # --- RETURNS ---
        return None
