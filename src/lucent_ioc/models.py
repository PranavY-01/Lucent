"""Pydantic v2 data models for Lucent reports (§B9)."""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from lucent_ioc.config import IOC_TYPE_ORDER, SCHEMA_VERSION, TOOL_NAME


class IOCType(str, Enum):
    ipv4 = "ipv4"
    domain = "domain"
    url = "url"
    md5 = "md5"
    sha1 = "sha1"
    sha256 = "sha256"


class ScanStatus(str, Enum):
    completed = "completed"
    completed_with_warnings = "completed_with_warnings"
    partial = "partial"


class LucentFatalError(Exception):
    """A condition that aborts the whole run (exit code 1, no report written)."""


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SourceRef(_Model):
    model_config = ConfigDict(extra="forbid", frozen=True)

    file: str
    line: int | None = None
    record: int | None = None
    column: str | None = None
    path: str | None = None
    via: Literal["url_host"] | None = None

    def identity(self) -> tuple:
        """Full source identity used for dedup (§B8.3)."""
        return (self.file, self.line, self.record, self.column, self.path, self.via)

    def sort_key(self) -> tuple:
        """Sort order for sources (§B8.3)."""
        return (
            self.file,
            self.line or 0,
            self.record or 0,
            self.column or "",
            self.path or "",
            self.via or "",
        )


class IOCRecord(_Model):
    type: IOCType
    value: str
    validation_status: Literal["valid_syntax"] = "valid_syntax"
    occurrences: int = Field(ge=1)
    source_count: int = Field(ge=1)
    sources_truncated: bool
    original_values: list[str]
    original_values_truncated: bool
    sources: list[SourceRef]


class ScanWarning(_Model):
    code: str
    path: str
    message: str


class ErrorEntry(_Model):
    path: str
    stage: Literal["read", "parse", "export"]
    error_type: str
    message: str
    recoverable: bool


class FileCounts(_Model):
    discovered: int = Field(ge=0)
    processed: int = Field(ge=0)
    skipped: int = Field(ge=0)
    failed: int = Field(ge=0)


class Limits(_Model):
    max_file_size_bytes: int
    max_files: int
    max_sources_per_ioc: int


class ScanInfo(_Model):
    timestamp_utc: str
    input: str
    recursive: bool
    strict: bool
    allow_ambiguous_tlds: bool
    status: ScanStatus
    files: FileCounts
    limits: Limits
    tld_snapshot: str


class Rejected(_Model):
    total: int = Field(ge=0)
    by_reason: dict[str, int]


class Summary(_Model):
    total_unique_iocs: int = Field(ge=0)
    by_type: dict[str, int]
    rejected_candidates: Rejected


class ToolInfo(_Model):
    name: str = TOOL_NAME
    version: str


def expected_status(files: FileCounts, n_warnings: int, n_errors: int) -> ScanStatus:
    """Status rule of §B9.2."""
    if files.failed > 0:
        return ScanStatus.partial
    if n_warnings == 0 and n_errors == 0:
        return ScanStatus.completed
    return ScanStatus.completed_with_warnings


class Report(_Model):
    schema_version: str = SCHEMA_VERSION
    tool: ToolInfo
    scan: ScanInfo
    summary: Summary
    iocs: list[IOCRecord]
    warnings: list[ScanWarning]
    errors: list[ErrorEntry]

    @model_validator(mode="after")
    def _check_invariants(self) -> Report:
        """Enforce the report invariants of §B9.4."""
        s = self.summary
        if s.total_unique_iocs != len(self.iocs):
            raise ValueError("total_unique_iocs does not match len(iocs)")
        if tuple(s.by_type.keys()) != IOC_TYPE_ORDER:
            raise ValueError("by_type must list exactly the six IOC types in order")
        if sum(s.by_type.values()) != s.total_unique_iocs:
            raise ValueError("by_type does not sum to total_unique_iocs")
        for t in IOC_TYPE_ORDER:
            if s.by_type[t] != sum(1 for i in self.iocs if i.type.value == t):
                raise ValueError(f"by_type[{t}] does not match iocs")
        if sum(s.rejected_candidates.by_reason.values()) != s.rejected_candidates.total:
            raise ValueError("rejected by_reason does not sum to total")

        keys = [(i.type.value, i.value) for i in self.iocs]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate (type, value) in iocs")
        for i in self.iocs:
            if i.validation_status != "valid_syntax":
                raise ValueError("validation_status must be valid_syntax")
            if not (i.occurrences >= i.source_count >= len(i.sources) >= 1):
                raise ValueError(f"occurrence/source counts inconsistent for {i.type.value}")

        f = self.scan.files
        if f.discovered != f.processed + f.skipped + f.failed:
            raise ValueError("files.discovered != processed + skipped + failed")
        if self.scan.status != expected_status(f, len(self.warnings), len(self.errors)):
            raise ValueError("scan.status does not follow the status rule")

        order = {t: n for n, t in enumerate(IOC_TYPE_ORDER)}
        sort_keys = [(order[i.type.value], i.value) for i in self.iocs]
        if sort_keys != sorted(sort_keys):
            raise ValueError("iocs are not sorted by type order then value")
        return self

    def to_dict(self) -> dict:
        """JSON-ready dict; None fields (only SourceRef has any) are omitted."""
        return self.model_dump(mode="json", exclude_none=True)
