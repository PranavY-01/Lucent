"""Candidate detection on raw segment text (§B5). Detects; never validates."""

from __future__ import annotations

import re
from dataclasses import dataclass

from lucent_ioc.models import IOCType, SourceRef
from lucent_ioc.normalizer import DOT, is_defanged, split_url

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_TLD = r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"

IPV4_RE = re.compile(rf"(?<![\w.])(?:\d{{1,3}}{DOT}){{3}}\d{{1,3}}(?!\w)(?!{DOT}\w)", re.IGNORECASE)
DOMAIN_RE = re.compile(
    rf"(?<![\w.@-])(?:{_LABEL}{DOT}){{1,126}}{_TLD}(?![\w-])(?!{DOT}\w)", re.IGNORECASE
)
URL_RE = re.compile(
    r"(?<!\w)(?:https?|hxxps?)(?::\/\/|\[:\/\/\]|\[:\]\/\/)[^\s<>\"'`]{1,4096}", re.IGNORECASE
)
EMAIL_RE = re.compile(
    rf"[A-Za-z0-9._%+-]{{1,64}}@(?:{_LABEL}{DOT}){{1,126}}{_TLD}", re.IGNORECASE
)


def _hex_token(n: int) -> re.Pattern[str]:
    return re.compile(rf"(?<![0-9A-Za-z])[0-9A-Fa-f]{{{n}}}(?![0-9A-Za-z])")


HASH_RES = (
    (IOCType.md5, _hex_token(32)),
    (IOCType.sha1, _hex_token(40)),
    (IOCType.sha256, _hex_token(64)),
)

_TRAILING_PUNCT = ".,;:!?"
_BRACKET_PAIRS = ((")", "("), ("]", "["), ("}", "{"))


@dataclass(frozen=True)
class Candidate:
    type: IOCType
    original_value: str
    source: SourceRef
    start: int
    end: int
    defanged: bool
    derived: bool = False


def trim_url(raw: str) -> str:
    """Trim trailing punctuation and unbalanced closing brackets until stable (§B6.3)."""
    while True:
        before = raw
        if raw and raw[-1] in _TRAILING_PUNCT:
            raw = raw[:-1]
        for close, open_ in _BRACKET_PAIRS:
            if raw.endswith(close) and raw.count(close) > raw.count(open_):
                raw = raw[:-1]
        if raw == before:
            return raw


def mask(text: str, spans: list[tuple[int, int]]) -> str:
    """Replace each span with spaces of equal length, keeping offsets valid."""
    chars = list(text)
    for start, end in spans:
        chars[start:end] = " " * (end - start)
    return "".join(chars)


def _url_candidates(text: str, source: SourceRef) -> list[Candidate]:
    found = []
    for m in URL_RE.finditer(text):
        raw = trim_url(m.group())
        if split_url(raw) is None:  # trimmed back to a bare scheme
            continue
        found.append(
            Candidate(
                type=IOCType.url,
                original_value=raw,
                source=source,
                start=m.start(),
                end=m.start() + len(raw),
                defanged=is_defanged(raw),
            )
        )
    return found


def detect(text: str, source: SourceRef) -> list[Candidate]:
    """Detect URL, IPv4, domain and hash candidates in one segment (§B5.2 steps 1-5)."""
    urls = _url_candidates(text, source)
    spans = [(c.start, c.end) for c in urls]
    spans += [m.span() for m in EMAIL_RE.finditer(text)]
    masked = mask(text, spans) if spans else text

    found = list(urls)
    for ioc_type, pattern in ((IOCType.ipv4, IPV4_RE), (IOCType.domain, DOMAIN_RE)):
        for m in pattern.finditer(masked):
            raw = text[m.start() : m.end()]
            found.append(
                Candidate(ioc_type, raw, source, m.start(), m.end(), defanged=is_defanged(raw))
            )
    for ioc_type, pattern in HASH_RES:
        for m in pattern.finditer(text):
            found.append(Candidate(ioc_type, m.group(), source, m.start(), m.end(), False))
    return found


def derive_host(url: Candidate, host_type: IOCType) -> Candidate:
    """Build the derived host candidate of a validated URL (§B5.2 step 6)."""
    parts = split_url(url.original_value)
    assert parts is not None  # url candidates always split
    raw_host = parts.raw_host
    start = url.start + parts.raw_host_offset
    return Candidate(
        type=host_type,
        original_value=raw_host,
        source=url.source.model_copy(update={"via": "url_host"}),
        start=start,
        end=start + len(raw_host),
        defanged=is_defanged(raw_host),
        derived=True,
    )
