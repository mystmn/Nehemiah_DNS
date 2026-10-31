"""Runtime configuration loaded from environment variables (12-factor style).

Every function follows the DATA -> CONDITIONS -> RETURNS layout.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

TRUTHY = frozenset({"1", "true", "yes", "on"})
VALID_ACTIONS = ("BLOCK", "MONITOR", "ALLOW")
VALID_BLOCK_MODES = ("nxdomain", "zero")


@dataclass(frozen=True)
class Settings:
    """Immutable settings object shared by the data plane and control plane."""

    db_path: str = "nehemiah.db"
    cache_dir: str = "cache"
    local_lists_dir: str = "lists"
    secret_key: str = ""
    admin_user: str = "admin"
    admin_password_hash: str = ""
    api_token: str = ""
    cookie_secure: bool = True
    trust_proxy: bool = False
    public_url: str = "http://127.0.0.1:8080"
    seed_sources: tuple[tuple[str, str], ...] = ()
    allowed_source_hosts: tuple[str, ...] = ("raw.githubusercontent.com",)
    max_list_bytes: int = 50 * 1024 * 1024
    fetch_timeout: float = 15.0
    reload_interval: float = 5.0
    default_category_action: str = "BLOCK"
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_user: str = ""
    smtp_secret: str = ""
    smtp_starttls: bool = True
    alert_from: str = "nehemiah_dns@localhost"
    alert_to: str = ""
    alert_cooldown: int = 3600
    dns_host: str = "127.0.0.1"
    dns_port: int = 5353
    dns_upstream: str = "1.1.1.1"
    dns_upstream_port: int = 53
    dns_timeout: float = 3.0
    dns_block_mode: str = "nxdomain"
    hit_queue_size: int = 10000
    retention_days: int = 30


def _env_bool(env: Mapping[str, str], key: str, default: bool) -> bool:
    """
    Parses a boolean environment variable.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    raw = env.get(key)
    value = default

    # --- CONDITIONS ---
    if raw is not None and raw.strip():
        value = raw.strip().lower() in TRUTHY

    # --- RETURNS ---
    return value


def _env_int(env: Mapping[str, str], key: str, default: int, minimum: int = 0) -> int:
    """
    Parses an integer environment variable, clamped to a minimum.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    raw = env.get(key, "")
    value = default

    # --- CONDITIONS ---
    if raw.strip():
        try:
            value = int(raw.strip())
        except ValueError:
            value = default
    value = max(value, minimum)

    # --- RETURNS ---
    return value


def _env_float(env: Mapping[str, str], key: str, default: float, minimum: float = 0.1) -> float:
    """
    Parses a float environment variable, clamped to a minimum.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    raw = env.get(key, "")
    value = default

    # --- CONDITIONS ---
    if raw.strip():
        try:
            value = float(raw.strip())
        except ValueError:
            value = default
    value = max(value, minimum)

    # --- RETURNS ---
    return value


def _env_list(env: Mapping[str, str], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    """
    Parses a comma-separated list environment variable.
    Complexity: Time O(L) | Space O(L) where L is the string length
    """
    # --- DATA ---
    raw = env.get(key, "")
    items: tuple[str, ...] = default

    # --- CONDITIONS ---
    if raw.strip():
        items = tuple(part.strip().lower() for part in raw.split(",") if part.strip())

    # --- RETURNS ---
    return items


def parse_seed_sources(raw: str) -> tuple[tuple[str, str], ...]:
    """
    Parses 'url|category;url|category' into (url, category) pairs.
    Complexity: Time O(L) | Space O(L)
    """
    # --- DATA ---
    pairs: list[tuple[str, str]] = []

    # --- CONDITIONS ---
    for entry in (raw or "").split(";"):
        entry = entry.strip()
        if not entry:
            continue
        url, _, category = entry.partition("|")
        pairs.append((url.strip(), (category.strip() or "uncategorized").lower()))

    # --- RETURNS ---
    return tuple(pairs)


def load_env_file(path: str, env: dict[str, str] | None = None) -> int:
    """
    Loads KEY=VALUE pairs from a dotenv-style file without overriding existing keys.
    Complexity: Time O(L) | Space O(L)
    """
    # --- DATA ---
    target = os.environ if env is None else env
    loaded = 0
    lines: list[str] = []

    # --- CONDITIONS ---
    if not path or not os.path.isfile(path):
        return 0

    with open(path, encoding="utf-8") as handle:
        lines = handle.read().splitlines()

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in target:
            target[key] = value
            loaded += 1

    # --- RETURNS ---
    return loaded


def load_settings(env: Mapping[str, str] | None = None) -> Settings:
    """
    Builds a Settings object from environment variables (prefix NEHEMIAH_).
    Complexity: Time O(K) | Space O(K) where K is the number of variables
    """
    # --- DATA ---
    source = os.environ if env is None else env

    def _val(suffix: str, default: str = "") -> str:
        return source.get(f"NEHEMIAH_{suffix}", default)

    def _bool(suffix: str, default: bool) -> bool:
        return _env_bool(source, f"NEHEMIAH_{suffix}", default)

    def _int(suffix: str, default: int, minimum: int = 0) -> int:
        return _env_int(source, f"NEHEMIAH_{suffix}", default, minimum)

    def _float(suffix: str, default: float, minimum: float = 0.1) -> float:
        return _env_float(source, f"NEHEMIAH_{suffix}", default, minimum)

    def _list(suffix: str, default: tuple[str, ...]) -> tuple[str, ...]:
        return _env_list(source, f"NEHEMIAH_{suffix}", default)

    block_mode = _val("DNS_BLOCK_MODE", "nxdomain").strip().lower()
    default_action = _val("DEFAULT_CATEGORY_ACTION", "BLOCK").strip().upper()

    # --- CONDITIONS ---
    if block_mode not in VALID_BLOCK_MODES:
        block_mode = "nxdomain"
    if default_action not in VALID_ACTIONS:
        default_action = "BLOCK"

    settings = Settings(
        db_path=_val("DB", "nehemiah.db"),
        cache_dir=_val("CACHE_DIR", "cache"),
        local_lists_dir=_val("LOCAL_LISTS", "lists"),
        secret_key=_val("SECRET_KEY", ""),
        admin_user=_val("ADMIN_USER", "admin"),
        admin_password_hash=_val("ADMIN_PASSWORD_HASH", ""),
        api_token=_val("API_TOKEN", ""),
        cookie_secure=_bool("COOKIE_SECURE", True),
        trust_proxy=_bool("TRUST_PROXY", False),
        public_url=_val("PUBLIC_URL", "http://127.0.0.1:8080").rstrip("/"),
        seed_sources=parse_seed_sources(_val("SOURCES", "")),
        allowed_source_hosts=_list("ALLOWED_SOURCE_HOSTS", ("raw.githubusercontent.com",)),
        max_list_bytes=_int("MAX_LIST_BYTES", 50 * 1024 * 1024, 1024),
        fetch_timeout=_float("FETCH_TIMEOUT", 15.0),
        reload_interval=_float("RELOAD_INTERVAL", 5.0, 0.5),
        default_category_action=default_action,
        smtp_host=source.get("SMTP_HOST", ""),
        smtp_port=_env_int(source, "SMTP_PORT", 587, 1),
        smtp_user=source.get("SMTP_USER", ""),
        smtp_secret=source.get("SMTP_PASS", ""),
        smtp_starttls=_env_bool(source, "SMTP_STARTTLS", True),
        alert_from=source.get("ALERT_FROM", "nehemiah_dns@localhost"),
        alert_to=source.get("ALERT_EMAIL", ""),
        alert_cooldown=_env_int(source, "ALERT_COOLDOWN_SECONDS", 3600, 0),
        dns_host=_val("DNS_HOST", "127.0.0.1"),
        dns_port=_int("DNS_PORT", 5353, 1),
        dns_upstream=_val("DNS_UPSTREAM", "1.1.1.1"),
        dns_upstream_port=_int("DNS_UPSTREAM_PORT", 53, 1),
        dns_timeout=_float("DNS_TIMEOUT", 3.0),
        dns_block_mode=block_mode,
        hit_queue_size=_int("HIT_QUEUE_SIZE", 10000, 100),
        retention_days=_int("RETENTION_DAYS", 30, 1),
    )

    # --- RETURNS ---
    return settings
