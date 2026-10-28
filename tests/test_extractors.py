import pytest

from lucent_ioc.extractors import derive_host, detect, mask, trim_url
from lucent_ioc.models import IOCType, SourceRef

SRC = SourceRef(file="t.txt", line=1)
H32 = "d41d8cd98f00b204e9800998ecf8427e"
H40 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
H64 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
LONG_URL = "https://example.com/" + "a" * 2100

# Detection side of the §B15.2 golden rows: (input, [(type, raw candidate), ...])
DETECTION_CASES = [
    # IPv4
    ("203.0.113.10", [("ipv4", "203.0.113.10")]),
    ("203.0.113[.]10", [("ipv4", "203.0.113[.]10")]),
    ("203.0.113.10:8080", [("ipv4", "203.0.113.10")]),
    ("Seen from 192.0.2.1.", [("ipv4", "192.0.2.1")]),
    ("999.1.1.1", [("ipv4", "999.1.1.1")]),
    ("010.0.0.1", [("ipv4", "010.0.0.1")]),
    ("1.2.3.4.5", []),
    ("v1.2.3.4", []),
    # Domains
    ("example.com", [("domain", "example.com")]),
    ("Example[.]COM", [("domain", "Example[.]COM")]),
    ("sub.example(.)org", [("domain", "sub.example(.)org")]),
    ("example{.}net", [("domain", "example{.}net")]),
    ("example[dot]net", [("domain", "example[dot]net")]),
    ("example(DOT)net", [("domain", "example(DOT)net")]),
    ("See example.com.", [("domain", "example.com")]),
    ("xn--80ak6aa92e.com", [("domain", "xn--80ak6aa92e.com")]),
    ("report.pdf", [("domain", "report.pdf")]),
    ("version 2.4.1", []),
    ("invoice.zip", [("domain", "invoice.zip")]),
    ("invoice[.]zip", [("domain", "invoice[.]zip")]),
    ("analyst@example.org", []),
    # URLs (derived hosts are added after validation, not here)
    ("https://example.com/a?b=1", [("url", "https://example.com/a?b=1")]),
    ("hxxps://example[.]com/test", [("url", "hxxps://example[.]com/test")]),
    ("hXXp[:]//example[.]com/x", [("url", "hXXp[:]//example[.]com/x")]),
    ("hxxp[://]example[.]com", [("url", "hxxp[://]example[.]com")]),
    ("(see https://example.com/page).", [("url", "https://example.com/page")]),
    (
        "https://en.wikipedia.org/wiki/Foo_(bar)",
        [("url", "https://en.wikipedia.org/wiki/Foo_(bar)")],
    ),
    ("HTTPS://EXAMPLE.COM/Path?Q=A", [("url", "HTTPS://EXAMPLE.COM/Path?Q=A")]),
    ("https://example.com/a[.]b", [("url", "https://example.com/a[.]b")]),
    ("https://203.0.113.10:8443/login", [("url", "https://203.0.113.10:8443/login")]),
    (
        "https://bank.example.com@evil.example.org/",
        [("url", "https://bank.example.com@evil.example.org/")],
    ),
    ("https://example.com/files/other.com", [("url", "https://example.com/files/other.com")]),
    ("ftp://example.com/file", [("domain", "example.com")]),
    ("http://intranet/", [("url", "http://intranet/")]),
    ("https://[2001:db8::1]/", [("url", "https://[2001:db8::1]/")]),
    ("https://example.com:99999/", [("url", "https://example.com:99999/")]),
    (LONG_URL, [("url", LONG_URL)]),
    # Hashes
    (H32, [("md5", H32)]),
    (H40, [("sha1", H40)]),
    (H64, [("sha256", H64)]),
    (H64.upper(), [("sha256", H64.upper())]),
    (f"sha256={H64}", [("sha256", H64)]),
    (f"https://example.com/d?h={H64}", [("url", f"https://example.com/d?h={H64}"), ("sha256", H64)]),
    (H64 + "a", []),
    (H32[:31], []),
    (f"abc{H32}xyz", []),
    (H64[:63] + "g", []),
]


@pytest.mark.parametrize(("text", "expected"), DETECTION_CASES)
def test_detection_golden(text, expected):
    got = sorted((c.type.value, c.original_value) for c in detect(text, SRC))
    assert got == sorted(expected)


def test_offsets_point_at_raw_text():
    text = "ip 203.0.113[.]10 then hxxps://example[.]com/x and " + H32
    for c in detect(text, SRC):
        assert text[c.start : c.end] == c.original_value
        assert c.source == SRC
        assert not c.derived


def test_defanged_flag():
    by_raw = {c.original_value: c for c in detect("invoice.zip invoice[.]zip", SRC)}
    assert by_raw["invoice.zip"].defanged is False
    assert by_raw["invoice[.]zip"].defanged is True


def test_email_and_url_masking_offsets():
    text = "mail bob@example.org see https://example.com/x/other.com end example.net"
    got = [(c.type, c.original_value) for c in detect(text, SRC)]
    assert (IOCType.domain, "example.net") in got
    assert (IOCType.domain, "example.org") not in got
    assert (IOCType.domain, "other.com") not in got


def test_mask_keeps_length():
    assert mask("abcdef", [(1, 3), (4, 5)]) == "a  d f"


@pytest.mark.parametrize(
    ("raw", "trimmed"),
    [
        ("https://example.com/page).", "https://example.com/page"),
        ("https://example.com/x,;:!?", "https://example.com/x"),
        ("https://example.com/Foo_(bar)", "https://example.com/Foo_(bar)"),
        ("https://example.com/a]", "https://example.com/a"),
        ("https://example.com/{a}}", "https://example.com/{a}"),
        ("hxxp[://]example[.]com", "hxxp[://]example[.]com"),
        ("hxxp[:]//example[.]com/x).", "hxxp[:]//example[.]com/x"),
    ],
)
def test_trim_url(raw, trimmed):
    assert trim_url(raw) == trimmed


def test_derive_host_offsets_and_raw_value():
    text = "URL: hxxps://user@Example[.]com:8443/p"
    (url,) = [c for c in detect(text, SRC) if c.type is IOCType.url]
    host = derive_host(url, IOCType.domain)
    assert host.original_value == "Example[.]com"
    assert text[host.start : host.end] == "Example[.]com"
    assert host.source.via == "url_host"
    assert host.derived and host.defanged


def test_long_line_is_fast():
    # Bounded patterns: a long hostile-looking line must not blow up.
    text = ("a[.]" * 5000) + ("1." * 5000) + ("x" * 20000)
    detect(text, SRC)
