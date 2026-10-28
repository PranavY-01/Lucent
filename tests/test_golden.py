"""Every §B15.2 single-segment golden row, end to end through detect/validate/derive."""

import pytest

from lucent_ioc.models import SourceRef
from lucent_ioc.pipeline import process_segment

SRC = SourceRef(file="golden.txt", line=1)
H32 = "d41d8cd98f00b204e9800998ecf8427e"
H40 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
H64 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
H64_MIXED = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"

U = "url_host"  # marks a derived IOC

# (input, allow_ambiguous_tlds, expected IOCs [(type, value[, via])], expected rejections)
GOLDEN = [
    # IPv4
    ("203.0.113.10", False, [("ipv4", "203.0.113.10")], []),
    ("203.0.113[.]10", False, [("ipv4", "203.0.113.10")], []),
    ("203.0.113.10:8080", False, [("ipv4", "203.0.113.10")], []),
    ("Seen from 192.0.2.1.", False, [("ipv4", "192.0.2.1")], []),
    ("999.1.1.1", False, [], ["invalid_ipv4"]),
    ("010.0.0.1", False, [], ["invalid_ipv4"]),
    ("1.2.3.4.5", False, [], []),
    ("v1.2.3.4", False, [], []),
    # Domains
    ("example.com", False, [("domain", "example.com")], []),
    ("Example[.]COM", False, [("domain", "example.com")], []),
    ("sub.example(.)org", False, [("domain", "sub.example.org")], []),
    ("example{.}net", False, [("domain", "example.net")], []),
    ("example[dot]net", False, [("domain", "example.net")], []),
    ("example(DOT)net", False, [("domain", "example.net")], []),
    ("See example.com.", False, [("domain", "example.com")], []),
    ("xn--80ak6aa92e.com", False, [("domain", "xn--80ak6aa92e.com")], []),
    ("report.pdf", False, [], ["unknown_tld"]),
    ("version 2.4.1", False, [], []),
    ("invoice.zip", False, [], ["ambiguous_file_extension_tld"]),
    ("invoice[.]zip", False, [("domain", "invoice.zip")], []),
    ("invoice.zip", True, [("domain", "invoice.zip")], []),
    ("analyst@example.org", False, [], []),
    # URLs
    (
        "https://example.com/a?b=1",
        False,
        [("url", "https://example.com/a?b=1"), ("domain", "example.com", U)],
        [],
    ),
    (
        "hxxps://example[.]com/test",
        False,
        [("url", "https://example.com/test"), ("domain", "example.com", U)],
        [],
    ),
    (
        "hXXp[:]//example[.]com/x",
        False,
        [("url", "http://example.com/x"), ("domain", "example.com", U)],
        [],
    ),
    (
        "hxxp[://]example[.]com",
        False,
        [("url", "http://example.com"), ("domain", "example.com", U)],
        [],
    ),
    (
        "(see https://example.com/page).",
        False,
        [("url", "https://example.com/page"), ("domain", "example.com", U)],
        [],
    ),
    (
        "https://en.wikipedia.org/wiki/Foo_(bar)",
        False,
        [("url", "https://en.wikipedia.org/wiki/Foo_(bar)"), ("domain", "en.wikipedia.org", U)],
        [],
    ),
    (
        "HTTPS://EXAMPLE.COM/Path?Q=A",
        False,
        [("url", "https://example.com/Path?Q=A"), ("domain", "example.com", U)],
        [],
    ),
    (
        "https://example.com/a[.]b",
        False,
        [("url", "https://example.com/a[.]b"), ("domain", "example.com", U)],
        [],
    ),
    (
        "https://203.0.113.10:8443/login",
        False,
        [("url", "https://203.0.113.10:8443/login"), ("ipv4", "203.0.113.10", U)],
        [],
    ),
    (
        "https://bank.example.com@evil.example.org/",
        False,
        [("url", "https://bank.example.com@evil.example.org/"), ("domain", "evil.example.org", U)],
        [],
    ),
    (
        "https://example.com/files/other.com",
        False,
        [("url", "https://example.com/files/other.com"), ("domain", "example.com", U)],
        [],
    ),
    ("ftp://example.com/file", False, [("domain", "example.com")], []),
    ("http://intranet/", False, [], ["invalid_url"]),
    ("https://[2001:db8::1]/", False, [], ["unsupported_host"]),
    ("https://example.com:99999/", False, [], ["invalid_url"]),
    ("https://example.com/" + "a" * 2100, False, [], ["url_too_long"]),
    # Hashes
    (H32, False, [("md5", H32)], []),
    (H40, False, [("sha1", H40)], []),
    (H64, False, [("sha256", H64)], []),
    (H64_MIXED, False, [("sha256", H64)], []),
    (f"sha256={H64}", False, [("sha256", H64)], []),
    (
        f"https://example.com/d?h={H64}",
        False,
        [("url", f"https://example.com/d?h={H64}"), ("domain", "example.com", U), ("sha256", H64)],
        [],
    ),
    (H64 + "b", False, [], []),
    (H32[:31], False, [], []),
    (f"abc{H32}xyz", False, [], []),
    (H64[:20] + "g" + H64[21:], False, [], []),
]


def _ids():
    return [f"{i:02d}-{row[0][:40]}{'-allow' if row[1] else ''}" for i, row in enumerate(GOLDEN)]


@pytest.mark.parametrize(("text", "allow", "iocs", "rejected"), GOLDEN, ids=_ids())
def test_golden_row(text, allow, iocs, rejected):
    sightings, reasons = process_segment(text, SRC, allow_ambiguous_tlds=allow)
    got = sorted(
        (s.type.value, s.value, s.source.via) if s.source.via else (s.type.value, s.value)
        for s in sightings
    )
    assert got == sorted(tuple(x) for x in iocs)
    assert sorted(reasons) == sorted(rejected)


def test_original_value_kept():
    sightings, _ = process_segment("Example[.]COM", SRC)
    assert [s.original_value for s in sightings] == ["Example[.]COM"]


def test_derived_original_is_raw_host():
    sightings, _ = process_segment("hxxps://example[.]com/test?id=42", SRC)
    derived = [s for s in sightings if s.source.via == "url_host"]
    assert [(s.original_value, s.source.line) for s in derived] == [("example[.]com", 1)]
