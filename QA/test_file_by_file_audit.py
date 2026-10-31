"""QA File-by-File Invariant & Unit Audit.

Validates that every Python source file in nehemiah_dns/ satisfies:
1. Valid Python AST parsing.
2. Coding invariants: '# --- DATA ---', '# --- CONDITIONS ---', '# --- RETURNS ---'.
3. Big-O Complexity contract in every function docstring: 'Complexity: Time O(...) | Space O(...)'.
4. Specific functional contract checks for each module.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from nehemiah_dns import (
    alerts,
    blocklist,
    config,
    db,
    dns_server,
    domains,
    policy,
    recorder,
    security,
    service,
    web,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
NEHEMIAH_DIR = ROOT_DIR / "nehemiah_dns"

MODULES = [
    config,
    domains,
    blocklist,
    db,
    policy,
    alerts,
    recorder,
    security,
    dns_server,
    service,
    web,
]


def _get_py_files() -> list[Path]:
    return sorted(
        [p for p in NEHEMIAH_DIR.glob("*.py") if p.name not in ("__init__.py",)]
    )


# -----------------------------------------------------------------------------
# 1. Structural Invariant Audits (AST Analysis)
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("py_file", _get_py_files(), ids=lambda p: p.name)
def test_file_coding_invariants(py_file: Path):
    """Verifies DATA -> CONDITIONS -> RETURNS and Complexity docstrings."""
    content = py_file.read_text(encoding="utf-8")
    tree = ast.parse(content, filename=str(py_file))

    for node in tree.body:
        # Check top-level functions
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            func_name = node.name
            if func_name in ("login_required", "wrapper"):
                continue

            docstring = ast.get_docstring(node)
            assert docstring is not None, f"{py_file.name}:{func_name} is missing a docstring"
            assert "Complexity:" in docstring, (
                f"{py_file.name}:{func_name} docstring missing 'Complexity:'"
            )
            assert "Time O(" in docstring, (
                f"{py_file.name}:{func_name} docstring missing 'Time O('"
            )
            assert "Space O(" in docstring, (
                f"{py_file.name}:{func_name} docstring missing 'Space O('"
            )

            func_source = ast.get_source_segment(content, node)
            if func_source and len(node.body) > 2:
                assert "# --- DATA ---" in func_source, (
                    f"{py_file.name}:{func_name} missing '# --- DATA ---'"
                )
                assert "# --- CONDITIONS ---" in func_source, (
                    f"{py_file.name}:{func_name} missing '# --- CONDITIONS ---'"
                )
                assert "# --- RETURNS ---" in func_source, (
                    f"{py_file.name}:{func_name} missing '# --- RETURNS ---'"
                )

        # Check classes and their methods
        elif isinstance(node, ast.ClassDef):
            for item in node.body:
                if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                m_name = item.name
                if m_name.startswith("__"):
                    continue

                # Skip properties
                is_prop = any(
                    isinstance(dec, ast.Name) and dec.id == "property"
                    for dec in item.decorator_list
                )
                if is_prop:
                    continue

                docstring = ast.get_docstring(item)
                assert docstring is not None, (
                    f"{py_file.name}:{node.name}.{m_name} missing docstring"
                )
                assert "Complexity:" in docstring, (
                    f"{py_file.name}:{node.name}.{m_name} docstring missing 'Complexity:'"
                )
                assert "Time O(" in docstring, (
                    f"{py_file.name}:{node.name}.{m_name} docstring missing 'Time O('"
                )
                assert "Space O(" in docstring, (
                    f"{py_file.name}:{node.name}.{m_name} docstring missing 'Space O('"
                )

                func_source = ast.get_source_segment(content, item)
                if func_source and len(item.body) > 2:
                    assert "# --- DATA ---" in func_source, (
                        f"{py_file.name}:{node.name}.{m_name} missing '# --- DATA ---'"
                    )
                    assert "# --- CONDITIONS ---" in func_source, (
                        f"{py_file.name}:{node.name}.{m_name} missing '# --- CONDITIONS ---'"
                    )
                    assert "# --- RETURNS ---" in func_source, (
                        f"{py_file.name}:{node.name}.{m_name} missing '# --- RETURNS ---'"
                    )


# -----------------------------------------------------------------------------
# 2. File-by-File Functional Verification
# -----------------------------------------------------------------------------


def test_qa_domains_module():
    """Verify domains.py normalization, candidate suffixes, and edge cases."""
    # Test valid domains
    assert domains.normalize_domain("EXAMPLE.COM.") == "example.com"
    assert domains.normalize_domain("sub.test.org") == "sub.test.org"
    assert domains.normalize_domain("xn--e1afmkfd.xn--p1ai") == "xn--e1afmkfd.xn--p1ai"

    # Test invalid / rejection cases
    assert domains.normalize_domain("") == ""
    assert domains.normalize_domain("a" * 255) == ""
    assert domains.normalize_domain("-bad.domain") == ""
    assert domains.normalize_domain("bad..domain") == ""

    # Test candidate suffixes
    candidates = list(domains.candidate_suffixes("sub.deep.example.com"))
    assert candidates == [
        "sub.deep.example.com",
        "deep.example.com",
        "example.com",
    ]

    # Test reversed labels: returns dot-separated reversed string
    assert domains.reverse_labels("a.b.com") == "com.b.a"


def test_qa_blocklist_module(tmp_path: Path):
    """Verify blocklist.py parser, bisect lookup, and snapshot building."""
    lines = (
        "# Comment header\n"
        "doubleclick.net\n"
        "0.0.0.0 badtracker.com,ads\n"
        "phishing.bank.com,phishing\n"
    )
    entries = blocklist.parse_list_text(lines, default_category="malware")
    assert ("doubleclick.net", "malware") in entries
    assert ("badtracker.com", "ads") in entries
    assert ("phishing.bank.com", "phishing") in entries

    snapshot = blocklist.build_snapshot(entries)
    assert snapshot.size == 3

    # Exact hash lookup
    matched = blocklist.lookup_hash(snapshot, "doubleclick.net")
    assert matched == ("doubleclick.net", "malware")
    assert blocklist.lookup_hash(snapshot, "unknown.com") is None

    # Binary search reversed labels
    result = blocklist.lookup_bisect(snapshot, "sub.ad.badtracker.com")
    assert result == ("badtracker.com", "ads")


def test_qa_db_module(tmp_path: Path):
    """Verify db.py schema initialization, atomic rule updates, and review aggregation."""
    db_file = tmp_path / "qa_test.db"
    assert db.init_database(str(db_file))

    conn = db.connect(str(db_file))
    try:
        # Check WAL mode
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"

        # Check rule management
        db.upsert_rule(conn, "allowed.internal", "internal", "ALLOW", "testing rule")
        rules = {r["domain"]: r["action"] for r in db.list_rules(conn)}
        assert rules.get("allowed.internal") == "ALLOW"

        # Check review recording & aggregation
        now = db.utc_now()
        hits = [
            (now, "bad.site.com", "site.com", "malware", "BLOCK", "192.168.1.100", "dns"),
            (now, "other.site.com", "site.com", "malware", "BLOCK", "192.168.1.101", "dns"),
        ]
        assert db.record_hits(conn, hits) == 2

        reviews = db.list_reviews(conn)
        assert len(reviews) == 1
        assert reviews[0]["matched"] == "site.com"
        assert reviews[0]["hit_count"] == 2
    finally:
        conn.close()


def test_qa_policy_engine(tmp_path: Path):
    """Verify policy.py precedence: Rules > Category Policy > Blocklist > PASS."""
    entries = [("doubleclick.net", "ads")]
    snapshot = blocklist.build_snapshot(entries)

    state = policy.PolicyState(
        rules={"trusted.doubleclick.net": ("ALLOW", "ads")},
        category_actions={"ads": "BLOCK"},
        snapshot=snapshot,
    )

    # 1. Direct rule override ALLOW
    dec1 = policy.evaluate(state, "trusted.doubleclick.net")
    assert dec1.action == "ALLOW"
    assert dec1.origin == "rule"

    # 2. Blocklist hit (inherits category BLOCK)
    dec2 = policy.evaluate(state, "ads.doubleclick.net")
    assert dec2.action == "BLOCK"
    assert dec2.category == "ads"
    assert dec2.matched == "doubleclick.net"

    # 3. Unlisted clean domain
    dec3 = policy.evaluate(state, "wikipedia.org")
    assert dec3.action == "PASS"


def test_qa_security_module():
    """Verify security.py token generation and login rate limiter."""
    tok1 = security.new_token()
    tok2 = security.new_token()
    assert len(tok1) >= 32
    assert tok1 != tok2
    assert security.tokens_match(tok1, tok1)
    assert not security.tokens_match(tok1, tok2)

    # Rate limiter
    throttle = security.LoginThrottle(max_attempts=3, window_seconds=60)
    assert not throttle.is_blocked("1.2.3.4")
    throttle.record_failure("1.2.3.4")
    throttle.record_failure("1.2.3.4")
    assert not throttle.is_blocked("1.2.3.4")
    throttle.record_failure("1.2.3.4")
    assert throttle.is_blocked("1.2.3.4")
    throttle.reset("1.2.3.4")
    assert not throttle.is_blocked("1.2.3.4")
