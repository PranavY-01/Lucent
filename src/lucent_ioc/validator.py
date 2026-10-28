"""Per-type syntax validation with structured outcomes (§B6). Never prints or raises."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from functools import cache
from importlib.resources import files
from urllib.parse import urlsplit

from lucent_ioc.config import (
    MAX_URL_LENGTH,
    REASON_AMBIGUOUS_TLD,
    REASON_INVALID_DOMAIN,
    REASON_INVALID_IPV4,
    REASON_INVALID_URL,
    REASON_UNKNOWN_TLD,
    REASON_UNSUPPORTED_HOST,
    REASON_URL_TOO_LONG,
)
from lucent_ioc.models import IOCType
from lucent_ioc.normalizer import normalize_domain, normalize_hash, normalize_ipv4, normalize_url

_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_DIGITS_AND_DOTS = re.compile(r"^[0-9.]+$")
_VERSION_LINE = re.compile(r"^#\s*Version\s+([^,]*)")


@dataclass(frozen=True)
class Outcome:
    ok: bool
    canonical: str | None = None
    reason: str | None = None
    host_type: IOCType | None = None  # URLs only: type of the host to derive


def _reject(reason: str) -> Outcome:
    return Outcome(ok=False, reason=reason)


# --------------------------------------------------------------------------- data files


def _read_data(name: str) -> str:
    return (files("lucent_ioc") / "data" / name).read_text(encoding="utf-8")


def parse_entries(text: str) -> frozenset[str]:
    entries = (line.strip().lower() for line in text.splitlines())
    return frozenset(e for e in entries if e and not e.startswith("#"))


def parse_snapshot(text: str) -> str:
    """Version text from the first line of an IANA TLD file, or "unknown"."""
    first = text.split("\n", 1)[0].strip()
    m = _VERSION_LINE.match(first)
    if m is None or not m.group(1).strip():
        return "unknown"
    return m.group(1).strip()


@cache
def tld_set() -> frozenset[str]:
    return parse_entries(_read_data("tlds.txt"))


@cache
def ambiguous_tld_set() -> frozenset[str]:
    return parse_entries(_read_data("ambiguous_tlds.txt"))


@cache
def tld_snapshot() -> str:
    return parse_snapshot(_read_data("tlds.txt"))


# --------------------------------------------------------------------------- validators


def validate_ipv4(raw: str) -> Outcome:
    try:
        return Outcome(ok=True, canonical=str(ipaddress.IPv4Address(normalize_ipv4(raw))))
    except ValueError:
        return _reject(REASON_INVALID_IPV4)


def _check_domain(name: str) -> str | None:
    """§B6.2 steps 2-4 on a normalized name. Returns a rejection reason or None."""
    labels = name.split(".")
    if len(labels) < 2 or len(name) > 253:
        return REASON_INVALID_DOMAIN
    if not all(_LABEL_RE.match(label) for label in labels):
        return REASON_INVALID_DOMAIN
    if labels[-1] not in tld_set():
        return REASON_UNKNOWN_TLD
    return None


def validate_domain(
    raw: str, *, url_host: bool = False, defanged: bool = False, allow_ambiguous_tlds: bool = False
) -> Outcome:
    name = normalize_domain(raw)
    reason = _check_domain(name)
    if reason:
        return _reject(reason)
    tld = name.rsplit(".", 1)[1]
    if (
        tld in ambiguous_tld_set()
        and not url_host
        and not defanged
        and not allow_ambiguous_tlds
    ):
        return _reject(REASON_AMBIGUOUS_TLD)
    return Outcome(ok=True, canonical=name)


def validate_url(raw: str) -> Outcome:
    normalized = normalize_url(raw)
    if normalized is None:
        return _reject(REASON_INVALID_URL)
    if len(normalized) > MAX_URL_LENGTH:
        return _reject(REASON_URL_TOO_LONG)
    try:
        parts = urlsplit(normalized)
        if parts.scheme not in ("http", "https"):
            return _reject(REASON_INVALID_URL)
        host = parts.hostname
        if not host:
            return _reject(REASON_INVALID_URL)
        if ":" in host:
            return _reject(REASON_UNSUPPORTED_HOST)
        port = parts.port
    except ValueError:
        return _reject(REASON_INVALID_URL)
    if port is not None and not 1 <= port <= 65535:
        return _reject(REASON_INVALID_URL)
    if _DIGITS_AND_DOTS.match(host):
        if not validate_ipv4(host).ok:
            return _reject(REASON_INVALID_URL)
        host_type = IOCType.ipv4
    else:
        if _check_domain(normalize_domain(host)):
            return _reject(REASON_INVALID_URL)
        host_type = IOCType.domain
    return Outcome(ok=True, canonical=normalized, host_type=host_type)


def validate_hash(raw: str) -> Outcome:
    return Outcome(ok=True, canonical=normalize_hash(raw))


def validate(
    ioc_type: IOCType,
    raw: str,
    *,
    url_host: bool = False,
    defanged: bool = False,
    allow_ambiguous_tlds: bool = False,
) -> Outcome:
    """Dispatch to the validator for `ioc_type`."""
    if ioc_type is IOCType.ipv4:
        return validate_ipv4(raw)
    if ioc_type is IOCType.domain:
        return validate_domain(
            raw, url_host=url_host, defanged=defanged, allow_ambiguous_tlds=allow_ambiguous_tlds
        )
    if ioc_type is IOCType.url:
        return validate_url(raw)
    return validate_hash(raw)
