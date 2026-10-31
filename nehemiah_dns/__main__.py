"""Nehemiah_DNS command line: python -m nehemiah_dns <command>."""

from __future__ import annotations

import argparse
import getpass
import json
import logging
import secrets
import sys

from werkzeug.security import generate_password_hash

from .config import load_env_file, load_settings


def cmd_init(_: argparse.Namespace) -> int:
    """
    Creates the database and seeds sources from NEHEMIAH_SOURCES.
    Complexity: Time O(S) | Space O(1)
    """
    # --- DATA ---
    from .service import bootstrap

    settings = load_settings()

    # --- CONDITIONS ---
    ok = bootstrap(settings)
    print(f"Database {'ready' if ok else 'FAILED'}: {settings.db_path}")

    # --- RETURNS ---
    return 0 if ok else 1


def cmd_sync(_: argparse.Namespace) -> int:
    """
    Fetches all enabled sources into the local cache (run hourly by systemd timer).
    Complexity: Time O(S * B) | Space O(B)
    """
    # --- DATA ---
    from .service import bootstrap, run_sync

    settings = load_settings()
    failures = 0

    # --- CONDITIONS ---
    if not bootstrap(settings):
        return 1
    for result in run_sync(settings):
        state = "ok" if result.ok else "cached" if result.from_cache else "FAILED"
        failures += 0 if (result.ok or result.from_cache) else 1
        print(f"[{state:6}] {result.entries:>9,} {result.url} {result.error}")

    # --- RETURNS ---
    return 1 if failures else 0


def cmd_dns(_: argparse.Namespace) -> int:
    """
    Runs the DNS data plane in the foreground.
    Complexity: Time O(N log N) startup | Space O(N)
    """
    # --- DATA ---
    from .dns_server import run_dns_server

    settings = load_settings()

    # --- CONDITIONS ---
    # (none)

    # --- RETURNS ---
    return run_dns_server(settings)


def cmd_check(args: argparse.Namespace) -> int:
    """
    Prints the policy decision for a domain (offline debugging).
    Complexity: Time O(N log N) index build + O(M) lookup | Space O(N)
    """
    # --- DATA ---
    from .policy import PolicyEngine
    from .service import bootstrap

    settings = load_settings()
    engine = PolicyEngine(settings)

    # --- CONDITIONS ---
    if not bootstrap(settings):
        return 1
    engine.reload(force=True)
    decision = engine.decide(args.domain)
    print(json.dumps(decision.__dict__, indent=2))

    # --- RETURNS ---
    return 2 if decision.is_blocked else 0


def cmd_hash_password(_: argparse.Namespace) -> int:
    """
    Prompts for a password and prints a hash for NEHEMIAH_ADMIN_PASSWORD_HASH.
    Complexity: Time O(1) + KDF cost | Space O(1)
    """
    # --- DATA ---
    first = getpass.getpass("New admin password (min 12 chars): ")
    second = getpass.getpass("Repeat: ")

    # --- CONDITIONS ---
    if first != second:
        print("Passwords do not match.", file=sys.stderr)
        return 1
    if len(first) < 12:
        print("Password must be at least 12 characters.", file=sys.stderr)
        return 1
    print(generate_password_hash(first))

    # --- RETURNS ---
    return 0


def cmd_gen_secret(_: argparse.Namespace) -> int:
    """
    Prints a random value suitable for NEHEMIAH_SECRET_KEY / NEHEMIAH_API_TOKEN.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    value = secrets.token_urlsafe(48)

    # --- CONDITIONS ---
    print(value)

    # --- RETURNS ---
    return 0


def build_parser() -> argparse.ArgumentParser:
    """
    Builds the argparse command tree.
    Complexity: Time O(1) | Space O(1)
    """
    # --- DATA ---
    parser = argparse.ArgumentParser(prog="nehemiah_dns", description="Nehemiah_DNS CLI")
    parser.add_argument("--env-file", default=".env", help="dotenv file to load (default .env)")
    sub = parser.add_subparsers(dest="command", required=True)
    commands = {
        "init": (cmd_init, "Create database and seed sources"),
        "sync": (cmd_sync, "Fetch remote lists into the local cache"),
        "dns": (cmd_dns, "Run the DNS filtering server"),
        "hash-password": (cmd_hash_password, "Generate an admin password hash"),
        "gen-secret": (cmd_gen_secret, "Generate a random secret"),
    }

    # --- CONDITIONS ---
    for name, (handler, help_text) in commands.items():
        sub.add_parser(name, help=help_text).set_defaults(func=handler)
    check = sub.add_parser("check", help="Evaluate a domain against current policy")
    check.add_argument("domain")
    check.set_defaults(func=cmd_check)

    # --- RETURNS ---
    return parser


def main(argv: list[str] | None = None) -> int:
    """
    CLI entry point.
    Complexity: Time O(C) where C is command cost | Space O(C)
    """
    # --- DATA ---
    args = build_parser().parse_args(argv)

    # --- CONDITIONS ---
    load_env_file(args.env_file)
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    # --- RETURNS ---
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
