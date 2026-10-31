import pytest

from sentineldns.domains import (
    candidate_suffixes,
    is_listable,
    normalize_category,
    normalize_domain,
    parse_list_line,
    reverse_labels,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM.", "example.com"),
        ("  sub.example.com  ", "sub.example.com"),
        ("*.ads.example.com", "ads.example.com"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("_dmarc.example.com", "_dmarc.example.com"),
        ("-bad.example.com", ""),
        ("bad-.example.com", ""),
        ("exa mple.com", ""),
        ("example.com\nBcc: x@y", ""),
        ("a" * 64 + ".com", ""),
        ("", ""),
    ],
)
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


def test_normalize_category():
    assert normalize_category("Malware") == "malware"
    assert normalize_category("bad cat!", "fallback") == "fallback"


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ("ads.example.com", ("ads.example.com", "ads")),
        ("phish.example.com,phishing", ("phish.example.com", "phishing")),
        ("0.0.0.0 tracker.example.com", ("tracker.example.com", "ads")),
        ("tracker.example.com # note", ("tracker.example.com", "ads")),
        ("# comment", None),
        ("", None),
        ("com", None),
        ("127.0.0.1 localhost", None),
        ("0.0.0.0 localhost.localdomain", None),
    ],
)
def test_parse_list_line(line, expected):
    assert parse_list_line(line, "ads") == expected


def test_candidate_suffixes_excludes_tld():
    assert candidate_suffixes("a.b.example.com") == ["a.b.example.com", "b.example.com", "example.com"]
    assert candidate_suffixes("com") == []


def test_reverse_labels_and_listable():
    assert reverse_labels("ads.example.com") == "com.example.ads"
    assert not is_listable("com")
    assert is_listable("example.com")
