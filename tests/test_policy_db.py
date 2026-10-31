import sqlite3

from sentineldns import db
from sentineldns.alerts import AlertDispatcher, build_review_email
from sentineldns.policy import Decision, PolicyEngine
from sentineldns.recorder import HitRecorder


def test_init_database_enables_wal(settings):
    conn = sqlite3.connect(settings.db_path)
    try:
        assert conn.execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    finally:
        conn.close()
    assert {"sources", "categories", "domain_rules", "hit_events", "reviews", "meta"} <= tables


def test_init_database_rejects_empty_path():
    assert db.init_database("") is False


def test_engine_loads_local_lists_and_rules_override(settings):
    engine = PolicyEngine(settings)
    engine.reload(force=True)
    assert engine.decide("x.doubleclick.net").action == "BLOCK"
    assert engine.decide("phish.example.org").category == "phishing"
    assert engine.decide("example.com").action == "PASS"

    conn = db.connect(settings.db_path)
    db.upsert_rule(conn, "doubleclick.net", "ads", "ALLOW")
    db.set_category_action(conn, "malware", "MONITOR")
    db.bump_version(conn, db.POLICY_VERSION)
    conn.close()

    assert engine.reload() is True
    assert engine.decide("x.doubleclick.net").action == "ALLOW"
    assert engine.decide("evil.example").action == "MONITOR"
    assert engine.reload() is False  # unchanged versions -> no work


def test_recorder_aggregates_and_cooldown_limits_email(settings):
    queued = []

    class FakeDispatcher(AlertDispatcher):
        def enqueue(self, review):
            queued.append(dict(review))
            return True

    recorder = HitRecorder(settings, FakeDispatcher(settings))
    decision = Decision("a.doubleclick.net", "BLOCK", "ads", "doubleclick.net", "list")
    for _ in range(3):
        assert recorder.submit(decision, "10.0.0.5", "dns")
    assert recorder.submit(Decision("ok.com", "PASS"), "10.0.0.5", "dns") is False
    assert recorder.drain() == 3
    recorder.submit(decision, "10.0.0.6", "dns")
    recorder.drain()

    conn = db.connect(settings.db_path)
    row = conn.execute("SELECT * FROM reviews WHERE matched='doubleclick.net'").fetchone()
    conn.close()
    assert row["hit_count"] == 4 and row["last_client"] == "10.0.0.6"
    assert len(queued) == 1  # second batch within cooldown -> no second e-mail


def test_review_email_contents(settings):
    review = {"matched": "doubleclick.net", "last_query": "a.doubleclick.net", "category": "ads",
              "action": "BLOCK", "last_client": "10.0.0.5", "hit_count": 3,
              "first_seen": "t0", "last_seen": "t1"}
    msg = build_review_email(settings, review)
    assert "doubleclick.net" in msg["Subject"]
    assert "10.0.0.5" in msg.get_content()


def test_dispatcher_disabled_without_smtp(settings):
    assert AlertDispatcher(settings).enqueue({"matched": "x.com"}) is False
