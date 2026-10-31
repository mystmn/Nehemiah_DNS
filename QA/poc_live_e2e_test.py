"""Nehemiah_DNS: Standalone Live Proof-of-Concept (POC) End-to-End Test.

This script executes a full end-to-end verification of Nehemiah_DNS:
1. Bootstraps an isolated SQLite database and local blocklists.
2. Starts an in-process live UDP DNS server on 127.0.0.1:15353.
3. Sends live DNS wire-protocol queries for blocked, subdomain, and allowed traffic.
4. Verifies database hit recording and aggregated review queues in SQLite.
5. Tests live zero-downtime policy overrides (changing a blocked domain to ALLOW).
6. Tests the Flask Web Admin UI and HTTP check API (/api/v1/check).
7. Shuts down background threads cleanly.

Throw-away code: Entire QA folder can be deleted when testing is complete.
"""

from __future__ import annotations

import contextlib
import shutil
import socket
import sys
import tempfile
import time
from pathlib import Path

from dnslib import QTYPE, RCODE, DNSQuestion, DNSRecord
from werkzeug.security import generate_password_hash

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from nehemiah_dns import db
from nehemiah_dns.alerts import AlertDispatcher
from nehemiah_dns.config import Settings
from nehemiah_dns.dns_server import FilteringResolver
from nehemiah_dns.policy import PolicyEngine
from nehemiah_dns.recorder import HitRecorder
from nehemiah_dns.service import bootstrap
from nehemiah_dns.web import create_app


def send_dns_query(qname: str, host: str, port: int, timeout: float = 2.0) -> DNSRecord:
    """Sends a raw UDP DNS query and parses the wire-format response."""
    # --- DATA ---
    query = DNSRecord(q=DNSQuestion(qname, QTYPE.A))
    packet = query.pack()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    response = None

    # --- CONDITIONS ---
    try:
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(4096)
        response = DNSRecord.parse(data)
    finally:
        sock.close()

    # --- RETURNS ---
    return response


def main() -> int:
    print("=" * 70)
    print("[*] Nehemiah_DNS: Live End-to-End Proof of Concept (POC) [*]")
    print("=" * 70)

    sandbox_dir = Path(tempfile.mkdtemp(prefix="nehemiah_poc_"))
    dns_port = 15353
    dns_host = "127.0.0.1"
    admin_pass = "PocAdminSecurePass123!"

    try:
        # Step 1: Prepare environment & sample blocklists
        print("\n[1/6] Bootstrapping isolated sandbox environment...")
        lists_dir = sandbox_dir / "lists"
        lists_dir.mkdir(parents=True)
        cache_dir = sandbox_dir / "cache"
        cache_dir.mkdir(parents=True)
        db_path = str(sandbox_dir / "nehemiah_poc.db")

        # Create sample local blocklists
        (lists_dir / "ads.txt").write_text(
            "# Local ads blocklist\n"
            "doubleclick.net\n"
            "adnxs.com\n"
            "0.0.0.0 telemetry.tracker.io\n",
            encoding="utf-8"
        )
        (lists_dir / "malware.txt").write_text(
            "# Local malware blocklist\n"
            "badware.evil.com,malware\n"
            "c2-beacon.botnet.net,c2\n",
            encoding="utf-8"
        )

        settings = Settings(
            db_path=db_path,
            cache_dir=str(cache_dir),
            local_lists_dir=str(lists_dir),
            dns_host=dns_host,
            dns_port=dns_port,
            secret_key="poc-test-secret-key-at-least-32-bytes-long",
            admin_user="secops",
            admin_password_hash=generate_password_hash(admin_pass),
            cookie_secure=False,
            dns_block_mode="nxdomain",
            alert_cooldown=3600,
            dns_upstream="1.1.1.1",
            dns_upstream_port=53,
        )

        assert bootstrap(settings), "Bootstrap failed"
        print("  [OK] SQLite database initialized with WAL mode")
        print("  [OK] Local lists indexed (ads.txt, malware.txt)")

        # Step 2: Initialize engine, recorder, and resolver
        print("\n[2/6] Starting in-process DNS Data Plane...")
        engine = PolicyEngine(settings)
        engine.reload(force=True)
        print(f"  [OK] In-memory index loaded: {engine.state.snapshot.size} domains")

        dispatcher = AlertDispatcher(settings, sender=lambda s, m: True)
        dispatcher.start()

        recorder = HitRecorder(settings, dispatcher)
        recorder.start()

        # Dummy upstream forwarder for clean pass-throughs
        def mock_upstream(request, upstream, port, timeout, tcp):
            reply = request.reply()
            reply.header.rcode = RCODE.NOERROR
            return reply

        resolver = FilteringResolver(settings, engine, recorder, forwarder=mock_upstream)

        # Start live UDP server socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((dns_host, dns_port))
        sock.settimeout(0.5)

        running = True
        def udp_worker():
            while running:
                try:
                    data, addr = sock.recvfrom(4096)
                    request = DNSRecord.parse(data)
                    reply = resolver.resolve(request, None)
                    sock.sendto(reply.pack(), addr)
                except (TimeoutError, OSError):
                    continue

        import threading
        server_thread = threading.Thread(target=udp_worker, daemon=True)
        server_thread.start()
        time.sleep(0.2)
        print(f"  [OK] Live UDP DNS server listening on {dns_host}:{dns_port}")

        # Step 3: Run Live DNS Queries
        print("\n[3/6] Sending live DNS wire-format queries...")

        # Query A: Direct blocked domain
        res_a = send_dns_query("doubleclick.net", dns_host, dns_port)
        rcode_a = RCODE.get(res_a.header.rcode)
        print(f"  * Query: doubleclick.net -> RCODE: {rcode_a}")
        assert rcode_a == "NXDOMAIN", f"Expected NXDOMAIN, got {rcode_a}"
        print("    [PASS] Direct domain blocking verified (NXDOMAIN)")

        # Query B: Subdomain wildcard matching
        res_b = send_dns_query("deep.analytics.doubleclick.net", dns_host, dns_port)
        rcode_b = RCODE.get(res_b.header.rcode)
        print(f"  * Query: deep.analytics.doubleclick.net -> RCODE: {rcode_b}")
        assert rcode_b == "NXDOMAIN", f"Expected NXDOMAIN, got {rcode_b}"
        print("    [PASS] Subdomain suffix matching verified (NXDOMAIN)")

        # Query C: Clean / Allowed domain
        res_c = send_dns_query("kernel.org", dns_host, dns_port)
        rcode_c = RCODE.get(res_c.header.rcode)
        print(f"  * Query: kernel.org -> RCODE: {rcode_c}")
        assert rcode_c == "NOERROR", f"Expected NOERROR, got {rcode_c}"
        print("    [PASS] Clean domain resolution verified (NOERROR)")

        # Step 4: Verify Persistence & Review Queue
        print("\n[4/6] Verifying SQLite WAL persistence & review queue...")
        # Drain recorder queue into SQLite
        recorder.drain()
        time.sleep(0.3)

        conn = db.connect(db_path)
        reviews = db.list_reviews(conn)
        stats = db.dashboard_stats(conn)
        conn.close()

        print(f"  * Aggregated reviews queued: {len(reviews)}")
        for r in reviews:
            print(
                f"    - Matched: {r['matched']} | Category: {r['category']} "
                f"| Hit Count: {r['hit_count']}"
            )
        assert any(r["matched"] == "doubleclick.net" for r in reviews), (
            "doubleclick.net missing from reviews"
        )
        assert stats["hits_24h"] >= 2, f"Expected at least 2 hits, got {stats['hits_24h']}"
        assert stats["blocked_24h"] >= 2, f"Expected at least 2 blocked, got {stats['blocked_24h']}"
        print("    [PASS] Hit aggregation and SQLite audit recording verified")

        # Step 5: Test Live Policy Override (Zero-Downtime Admin Action)
        print("\n[5/6] Testing live zero-downtime policy override...")
        conn = db.connect(db_path)
        db.upsert_rule(conn, "doubleclick.net", "ads", "ALLOW", "Whitelisted by SecOps")
        db.bump_version(conn, db.POLICY_VERSION)
        conn.close()

        # Engine detects rule bump and hot-swaps immutable PolicyState
        engine.reload()
        print("  [OK] Admin rule added: doubleclick.net -> ALLOW (Policy hot-swapped)")

        res_override = send_dns_query("doubleclick.net", dns_host, dns_port)
        rcode_override = RCODE.get(res_override.header.rcode)
        print(f"  * Re-query: doubleclick.net -> RCODE: {rcode_override}")
        assert rcode_override == "NOERROR", f"Expected NOERROR after override, got {rcode_override}"
        print("    [PASS] Instant override without DNS service restart verified")

        # Step 6: Test Flask Web Control Plane
        print("\n[6/6] Testing Flask Web Administration plane...")
        flask_app = create_app(settings, start_workers=False)
        client = flask_app.test_client()

        # Test API endpoint
        api_res = client.get("/api/v1/check?domain=badware.evil.com")
        print(f"  * API Check (badware.evil.com) -> Status: {api_res.status_code}")
        assert api_res.status_code == 403, f"Expected 403, got {api_res.status_code}"
        assert api_res.json["blocked"] is True
        print(f"    [PASS] API returned: {api_res.json}")

        # Test Admin Dashboard Authentication
        unauth_res = client.get("/admin")
        assert unauth_res.status_code == 302 and "/login" in unauth_res.headers["Location"]
        print("  [PASS] Protected /admin endpoint redirects unauthenticated requests")

        # Login with CSRF token
        import re
        login_page = client.get("/login").get_data(as_text=True)
        csrf_token = re.search(r'name="csrf_token" value="([^"]+)"', login_page).group(1)
        login_res = client.post(
            "/login",
            data={"username": "secops", "password": admin_pass, "csrf_token": csrf_token},
            follow_redirects=True,
        )
        assert login_res.status_code == 200
        assert b"Review queue" in login_res.data
        print("  [PASS] Admin login successful; dashboard renders review queue")

        # Clean shutdown
        print("\n" + "=" * 70)
        print("[*] POC COMPLETE: ALL END-TO-END TESTS PASSED SUCCESSFULLY! [*]")
        print("=" * 70)
        return 0

    finally:
        # Shutdown background listeners and cleanup
        running = False
        with contextlib.suppress(Exception):
            sock.close()
        with contextlib.suppress(Exception):
            recorder.stop()
            dispatcher.stop()
        shutil.rmtree(sandbox_dir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
