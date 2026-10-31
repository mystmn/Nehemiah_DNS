import re

import pytest

from sentineldns import db
from sentineldns.web import create_app
from tests.conftest import ADMIN_PASSWORD


@pytest.fixture
def app(settings):
    application = create_app(settings, start_workers=False)
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


def _csrf(client, path="/login"):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def _login(client):
    token = _csrf(client)
    return client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD,
                                       "csrf_token": token})


def test_refuses_to_start_without_secrets(settings):
    from dataclasses import replace
    with pytest.raises(RuntimeError):
        create_app(replace(settings, secret_key=""), start_workers=False)
    with pytest.raises(RuntimeError):
        create_app(replace(settings, admin_password_hash=""), start_workers=False)


def test_admin_requires_login(client):
    assert client.get("/admin").status_code == 302


def test_post_without_csrf_rejected(client):
    assert client.post("/login", data={"username": "admin", "password": "x"}).status_code == 400


def test_login_flow_and_dashboard(client):
    assert _login(client).status_code == 302
    page = client.get("/admin")
    assert page.status_code == 200
    assert b"Review queue" in page.data


def test_bad_password_and_throttle(client):
    for _ in range(5):
        token = _csrf(client)
        resp = client.post("/login", data={"username": "admin", "password": "wrong",
                                           "csrf_token": token})
        assert resp.status_code == 401
    token = _csrf(client)
    assert client.post("/login", data={"username": "admin", "password": ADMIN_PASSWORD,
                                       "csrf_token": token}).status_code == 429


def test_security_headers(client):
    resp = client.get("/login")
    assert "frame-ancestors 'none'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["X-Content-Type-Options"] == "nosniff"


def test_check_endpoint(client):
    blocked = client.get("/api/v1/check?domain=ads.doubleclick.net")
    assert blocked.status_code == 403 and blocked.json["category"] == "ads"
    assert client.get("/api/v1/check?domain=example.com").status_code == 200
    assert client.get("/api/v1/check?domain=").status_code == 400
    proxied = client.get("/api/v1/check?domain=example.com", headers={"X-Forwarded-For": "1.2.3.4"})
    assert proxied.status_code == 401


def test_check_endpoint_bearer_token(settings):
    from dataclasses import replace
    app = create_app(replace(settings, api_token="t" * 40), start_workers=False)
    c = app.test_client()
    assert c.get("/api/v1/check?domain=example.com").status_code == 401
    ok = c.get("/api/v1/check?domain=example.com", headers={"Authorization": "Bearer " + "t" * 40})
    assert ok.status_code == 200


def test_add_rule_and_review_confirm(app, client):
    _login(client)
    token = _csrf(client, "/admin/rules")
    client.post("/admin/rules", data={"domain": "tracker.example.com", "action": "BLOCK",
                                      "category": "custom", "csrf_token": token})
    assert client.get("/api/v1/check?domain=a.tracker.example.com").status_code == 403

    services = app.extensions["sentineldns"]
    services.recorder.drain()
    resp = client.post("/admin/reviews", data={"matched": "tracker.example.com",
                                               "action": "allow", "csrf_token": token})
    assert resp.status_code == 302
    assert client.get("/api/v1/check?domain=a.tracker.example.com").status_code == 200

    conn = db.connect(services.settings.db_path)
    status = conn.execute("SELECT status FROM reviews WHERE matched='tracker.example.com'").fetchone()
    conn.close()
    assert status["status"] == "ALLOWED"


def test_rejects_disallowed_source(client, settings):
    _login(client)
    token = _csrf(client, "/admin/sources")
    resp = client.post("/admin/sources", data={"url": "https://evil.example.com/list.txt",
                                        "category": "ads", "csrf_token": token}, follow_redirects=True)
    assert b"Host not in SENTINEL_ALLOWED_SOURCE_HOSTS" in resp.data
    conn = db.connect(settings.db_path)
    try:
        assert db.list_sources(conn) == []
    finally:
        conn.close()
