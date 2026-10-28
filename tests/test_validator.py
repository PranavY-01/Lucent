import pytest

from lucent_ioc.models import IOCType
from lucent_ioc.validator import (
    ambiguous_tld_set,
    parse_entries,
    parse_snapshot,
    tld_set,
    tld_snapshot,
    validate,
    validate_domain,
    validate_hash,
    validate_ipv4,
    validate_url,
)


def test_tld_loader():
    tlds = tld_set()
    assert len(tlds) > 1000
    assert {"com", "org", "net", "zip", "xn--p1ai"} <= tlds
    assert not {"pdf", "exe", "bin"} & tlds
    assert all(t == t.lower() and not t.startswith("#") for t in tlds)
    assert tld_set() is tlds  # cached


def test_ambiguous_loader():
    amb = ambiguous_tld_set()
    assert amb == {"zip", "mov", "sh", "py", "pl", "rs", "md", "ps", "so", "cab", "one"}


def test_parse_entries_skips_comments_and_blanks():
    assert parse_entries("# c\n\n COM \nNet\n#x\n") == {"com", "net"}


@pytest.mark.parametrize(
    ("first_line", "expected"),
    [
        ("# Version 2026102800, Last Updated Wed Oct 28 07:07:01 2026 UTC", "2026102800"),
        ("#Version 2024010100", "2024010100"),
        ("# Something else", "unknown"),
        ("COM", "unknown"),
        ("# Version , x", "unknown"),
        ("", "unknown"),
    ],
)
def test_parse_snapshot(first_line, expected):
    assert parse_snapshot(first_line + "\nCOM\n") == expected


def test_bundled_snapshot_is_parsed():
    snap = tld_snapshot()
    assert snap != "unknown"
    assert snap.isdigit()


def test_ipv4():
    assert validate_ipv4("203.0.113[.]10").canonical == "203.0.113.10"
    assert validate_ipv4("10.0.0.1").ok  # private is still valid syntax
    assert validate_ipv4("999.1.1.1").reason == "invalid_ipv4"
    assert validate_ipv4("010.0.0.1").reason == "invalid_ipv4"


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("localhost", "invalid_domain"),
        ("-bad.com", "invalid_domain"),
        ("bad-.com", "invalid_domain"),
        ("a" * 64 + ".com", "invalid_domain"),
        (".".join(["a" * 63] * 4) + ".com", "invalid_domain"),  # > 253 chars
        ("bad_label.com", "invalid_domain"),
        ("report.pdf", "unknown_tld"),
        ("invoice.zip", "ambiguous_file_extension_tld"),
        ("example.pl", "ambiguous_file_extension_tld"),
    ],
)
def test_domain_rejections(raw, reason):
    out = validate_domain(raw)
    assert (out.ok, out.reason, out.canonical) == (False, reason, None)


def test_domain_ambiguous_exemptions():
    assert validate_domain("invoice.zip", defanged=True).canonical == "invoice.zip"
    assert validate_domain("invoice.zip", url_host=True).canonical == "invoice.zip"
    assert validate_domain("invoice.zip", allow_ambiguous_tlds=True).canonical == "invoice.zip"


def test_domain_canonical():
    assert validate_domain("Sub.Example[.]ORG.").canonical == "sub.example.org"
    assert validate_domain("xn--80ak6aa92e.com").canonical == "xn--80ak6aa92e.com"


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("https://example.com/" + "a" * 2100, "url_too_long"),
        ("http://intranet/", "invalid_url"),
        ("http://server.local/", "invalid_url"),
        ("https://", "invalid_url"),
        ("https://[2001:db8::1]/", "unsupported_host"),
        ("https://[not-ipv6/", "invalid_url"),
        ("https://example.com:99999/", "invalid_url"),
        ("https://example.com:0/", "invalid_url"),
        ("https://example.com:abc/", "invalid_url"),
        ("https://999.1.1.1/", "invalid_url"),
        ("https://1.2.3/", "invalid_url"),
        ("https://report.pdf/", "invalid_url"),
        ("ftp://example.com/", "invalid_url"),
    ],
)
def test_url_rejections(raw, reason):
    out = validate_url(raw)
    assert (out.ok, out.reason) == (False, reason)


def test_url_ok_and_host_type():
    out = validate_url("hxxps://Example[.]com:8443/a")
    assert out.canonical == "https://example.com:8443/a"
    assert out.host_type is IOCType.domain
    assert validate_url("http://203.0.113.10/").host_type is IOCType.ipv4
    # The ambiguous-TLD rule does not apply to URL hosts.
    assert validate_url("https://invoice.zip/").ok


def test_url_length_boundary():
    base = "https://example.com/"
    assert validate_url(base + "a" * (2048 - len(base))).ok
    assert validate_url(base + "a" * (2049 - len(base))).reason == "url_too_long"


def test_hash_always_valid():
    assert validate_hash("ABCDEF" * 5 + "AB").canonical == ("abcdef" * 5 + "ab")


def test_dispatch_never_raises_on_garbage():
    for t in IOCType:
        out = validate(t, "%%%[.]::@@//")
        assert isinstance(out.ok, bool)
