import pytest

from lucent_ioc.normalizer import (
    is_defanged,
    normalize_domain,
    normalize_hash,
    normalize_ipv4,
    normalize_url,
    replace_dots,
    split_url,
)


@pytest.mark.parametrize("token", ["[.]", "(.)", "{.}", "[dot]", "(dot)", "[DOT]", "(Dot)"])
def test_each_dot_token(token):
    assert replace_dots(f"example{token}com") == "example.com"
    assert normalize_ipv4(f"192{token}0{token}2{token}1") == "192.0.2.1"
    assert is_defanged(f"example{token}com")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("hxxp://example.com/", "http://example.com/"),
        ("hxxps://example.com/", "https://example.com/"),
        ("HXXPS://example.com/", "https://example.com/"),
        ("http[://]example.com/", "http://example.com/"),
        ("https[:]//example.com/", "https://example.com/"),
    ],
)
def test_scheme_and_separator(raw, expected):
    assert normalize_url(raw) == expected
    assert is_defanged(raw) == (raw != expected and raw.lower() != expected)


def test_url_authority_only_scope():
    raw = "hxxps://Sub.Example[.]COM/Path[.]X?Q=A[dot]B#Frag(.)"
    assert normalize_url(raw) == "https://sub.example.com/Path[.]X?Q=A[dot]B#Frag(.)"


def test_url_userinfo_and_port_preserved():
    raw = "https://User.Name@Example[.]COM:08443/x"
    assert normalize_url(raw) == "https://User.Name@example.com:08443/x"


def test_url_last_at_splits_userinfo():
    assert normalize_url("https://a@b@EXAMPLE.com/") == "https://a@b@example.com/"


def test_url_ipv6_literal_left_as_is():
    assert normalize_url("https://[2001:DB8::1]:443/") == "https://[2001:DB8::1]:443/"


def test_url_no_trailing_slash_added():
    assert normalize_url("hxxp[://]example[.]com") == "http://example.com"


def test_not_a_url():
    assert normalize_url("ftp://example.com/") is None
    assert split_url("example.com") is None


def test_split_url_raw_host():
    parts = split_url("hxxps://u@Example[.]com:8443/p?q")
    assert parts.raw_host == "Example[.]com"
    assert "hxxps://u@Example[.]com:8443/p?q"[parts.raw_host_offset :].startswith("Example[.]com")
    assert parts.remainder == "/p?q"


def test_domain_trailing_dot_and_case():
    assert normalize_domain("Example[.]COM.") == "example.com"
    assert normalize_domain("example.com..") == "example.com."  # only one dot stripped


def test_hash_lowercase():
    assert normalize_hash("ABCdef") == "abcdef"


@pytest.mark.parametrize(
    ("func", "canonical"),
    [
        (normalize_url, "https://user@example.com:8443/Path[.]x?q=1"),
        (normalize_url, "http://203.0.113.10/"),
        (normalize_domain, "sub.example.org"),
        (normalize_ipv4, "203.0.113.10"),
        (normalize_hash, "d41d8cd98f00b204e9800998ecf8427e"),
    ],
)
def test_idempotent(func, canonical):
    assert func(canonical) == canonical
    assert func(func(canonical)) == canonical


def test_plain_values_not_defanged():
    for raw in ("example.com", "203.0.113.10", "https://example.com/x", "http://example.com"):
        assert not is_defanged(raw)
