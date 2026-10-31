import pytest
from werkzeug.security import generate_password_hash

from nehemiah_dns.config import Settings
from nehemiah_dns.service import bootstrap

ADMIN_PASSWORD = "correct-horse-battery-staple"


@pytest.fixture
def settings(tmp_path):
    lists = tmp_path / "lists"
    lists.mkdir()
    (lists / "ads.txt").write_text("doubleclick.net\n0.0.0.0 adnxs.com\n", encoding="utf-8")
    (lists / "malware.txt").write_text(
        "evil.example\nphish.example.org,phishing\n", encoding="utf-8"
    )
    cfg = Settings(
        db_path=str(tmp_path / "test.db"),
        cache_dir=str(tmp_path / "cache"),
        local_lists_dir=str(lists),
        secret_key="x" * 48,
        admin_user="admin",
        admin_password_hash=generate_password_hash(ADMIN_PASSWORD),
        cookie_secure=False,
        alert_cooldown=3600,
    )
    assert bootstrap(cfg)
    return cfg
