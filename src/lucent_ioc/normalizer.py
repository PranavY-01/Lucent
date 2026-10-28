"""Defang reversal and canonical forms (§B7). Pure string functions; no validation."""

from __future__ import annotations

import re
from dataclasses import dataclass

DOT = r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))"

_DOT_TOKEN = re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.IGNORECASE)
_DEFANG_TOKEN = re.compile(
    r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|hxxps?|\[://\]|\[:\]//", re.IGNORECASE
)
_URL_SPLIT = re.compile(
    r"^(?P<scheme>https?|hxxps?)(?P<sep>://|\[://\]|\[:\]//)(?P<rest>.*)$",
    re.IGNORECASE | re.DOTALL,
)
_AUTHORITY_END = re.compile(r"[/?#]")


def replace_dots(text: str) -> str:
    """Replace every defanged dot token with '.'."""
    return _DOT_TOKEN.sub(".", text)


def is_defanged(raw: str) -> bool:
    """True if the raw text contains any supported defang token (§B7.1)."""
    return _DEFANG_TOKEN.search(raw) is not None


def normalize_ipv4(raw: str) -> str:
    return replace_dots(raw)


def normalize_domain(raw: str) -> str:
    """Replace dot tokens, strip one trailing '.', lowercase (§B6.2 step 1)."""
    return replace_dots(raw).removesuffix(".").lower()


@dataclass(frozen=True)
class UrlParts:
    """Pieces of a raw URL, all as written in the raw text."""

    scheme: str
    sep: str
    authority: str
    remainder: str
    authority_offset: int  # offset of the authority within the raw URL

    @property
    def raw_hostport(self) -> str:
        return self.authority.rpartition("@")[2]

    @property
    def raw_host(self) -> str:
        """Host as written in the raw authority (no userinfo, no port)."""
        hostport = self.raw_hostport
        if hostport.startswith("["):
            return hostport
        return hostport.partition(":")[0]

    @property
    def raw_host_offset(self) -> int:
        """Offset of `raw_host` within the raw URL."""
        return self.authority_offset + len(self.authority) - len(self.raw_hostport)


def split_url(raw: str) -> UrlParts | None:
    m = _URL_SPLIT.match(raw)
    if m is None:
        return None
    rest = m.group("rest")
    end = _AUTHORITY_END.search(rest)
    cut = end.start() if end else len(rest)
    return UrlParts(
        scheme=m.group("scheme"),
        sep=m.group("sep"),
        authority=rest[:cut],
        remainder=rest[cut:],
        authority_offset=m.start("rest"),
    )


def normalize_url(raw: str) -> str | None:
    """Normalize scheme, separator and authority only (§B6.3). None if not a URL."""
    parts = split_url(raw)
    if parts is None:
        return None
    scheme = parts.scheme.lower().replace("hxxp", "http")
    authority = replace_dots(parts.authority)
    userinfo, at, hostport = authority.rpartition("@")
    if not hostport.startswith("["):
        host, colon, port = hostport.partition(":")
        hostport = host.lower() + colon + port
    return f"{scheme}://{userinfo}{at}{hostport}{parts.remainder}"


def normalize_hash(raw: str) -> str:
    return raw.lower()
