import random
import string
import time

import pytest

from sentineldns import blocklist
from sentineldns.blocklist import (
    FetchError,
    build_snapshot,
    cache_path_for,
    load_entries,
    lookup_bisect,
    lookup_hash,
    subtree,
    sync_sources,
    validate_source_url,
)

HOSTS = ("raw.githubusercontent.com",)


def test_build_snapshot_sorts_and_dedupes_first_wins():
    snap = build_snapshot([("b.com", "x"), ("a.com", "y"), ("b.com", "z")])
    assert snap.size == 2
    assert list(snap.keys) == sorted(snap.keys)
    assert snap.categories["b.com"] == "x"


def test_lookup_matches_parent_domains():
    snap = build_snapshot([("example.com", "ads")])
    assert lookup_hash(snap, "deep.sub.example.com") == ("example.com", "ads")
    assert lookup_bisect(snap, "deep.sub.example.com") == ("example.com", "ads")
    assert lookup_hash(snap, "notexample.com") is None
    assert lookup_bisect(snap, "notexample.com") is None


def test_lookup_prefers_most_specific():
    snap = build_snapshot([("example.com", "ads"), ("bad.example.com", "malware")])
    assert lookup_hash(snap, "x.bad.example.com") == ("bad.example.com", "malware")


def test_subtree_range_scan_excludes_lookalikes():
    snap = build_snapshot(
        [("example.com", "a"), ("ads.example.com", "a"), ("x.y.example.com", "a"),
         ("example-foo.com", "a"), ("example.com.evil.net", "a")]
    )
    assert sorted(subtree(snap, "example.com")) == ["ads.example.com", "example.com", "x.y.example.com"]
    assert subtree(snap, "example.com", limit=1) == ["example.com"]


@pytest.mark.parametrize(
    ("url", "ok"),
    [
        ("https://raw.githubusercontent.com/o/r/main/a.txt", True),
        ("http://raw.githubusercontent.com/o/r/main/a.txt", False),
        ("https://evil.example.com/a.txt", False),
        ("https://user:pw@raw.githubusercontent.com/a.txt", False),
        ("https://raw.githubusercontent.com:8443/a.txt", False),
        ("file:///etc/passwd", False),
    ],
)
def test_validate_source_url(url, ok):
    assert (validate_source_url(url, HOSTS) == "") is ok


def test_fetch_rejects_non_https_without_network():
    with pytest.raises(FetchError):
        blocklist.fetch_source_text("http://raw.githubusercontent.com/x", HOSTS, 1024, 1.0)


def test_sync_caches_and_falls_back(tmp_path):
    url = "https://raw.githubusercontent.com/o/r/main/ads.txt"
    cache = str(tmp_path / "cache")

    results = sync_sources([(url, "ads")], cache, HOSTS, 1024, 1.0,
                           fetcher=lambda *a: "one.com\ntwo.com\n")
    assert results[0].ok and results[0].entries == 2

    def failing(*_):
        raise FetchError("down")

    results = sync_sources([(url, "ads")], cache, HOSTS, 1024, 1.0, fetcher=failing)
    assert not results[0].ok and results[0].from_cache and results[0].entries == 2
    assert load_entries([(url, "ads")], cache, "") == [("one.com", "ads"), ("two.com", "ads")]
    assert cache_path_for(cache, url).endswith(".txt")


def _random_domains(count: int) -> list[tuple[str, str]]:
    rng = random.Random(42)
    letters = string.ascii_lowercase
    return [("".join(rng.choices(letters, k=12)) + ".com", "ads") for _ in range(count)]


@pytest.mark.perf
def test_big_o_budget_500k_domains_10k_queries():
    entries = _random_domains(500_000)

    start = time.perf_counter()
    snap = build_snapshot(entries)
    build_seconds = time.perf_counter() - start

    queries = [f"sub.{d}" for d, _ in entries[:5_000]] + [f"miss{i}.example.net" for i in range(5_000)]

    start = time.perf_counter()
    hash_hits = sum(1 for q in queries if lookup_hash(snap, q))
    hash_ms = (time.perf_counter() - start) * 1000

    start = time.perf_counter()
    bisect_hits = sum(1 for q in queries if lookup_bisect(snap, q))
    bisect_ms = (time.perf_counter() - start) * 1000

    assert hash_hits == bisect_hits == 5_000
    assert build_seconds < 10.0, f"build took {build_seconds:.2f}s"
    assert hash_ms < 150, f"hash lookups took {hash_ms:.1f}ms"
    assert bisect_ms < 300, f"bisect lookups took {bisect_ms:.1f}ms"
