"""Scan orchestration (§B8). Returns a Report; never prints."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from lucent_ioc import __version__
from lucent_ioc.config import (
    DEFAULT_MAX_FILE_SIZE_BYTES,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_SOURCES_PER_IOC,
    IOC_TYPE_ORDER,
)
from lucent_ioc.deduplicator import Deduplicator
from lucent_ioc.extractors import derive_host, detect
from lucent_ioc.models import (
    ErrorEntry,
    FileCounts,
    IOCType,
    Limits,
    LucentFatalError,
    Rejected,
    Report,
    ScanInfo,
    ScanWarning,
    SourceRef,
    Summary,
    ToolInfo,
    expected_status,
)
from lucent_ioc.reader import FileFailure, discover, read_segments
from lucent_ioc.validator import tld_snapshot, validate

__all__ = ["LucentFatalError", "Sighting", "process_segment", "run_scan"]


@dataclass(frozen=True)
class Sighting:
    """One valid occurrence of an IOC, ready for deduplication."""

    type: IOCType
    value: str
    original_value: str
    source: SourceRef


def process_segment(
    text: str, source: SourceRef, *, allow_ambiguous_tlds: bool = False
) -> tuple[list[Sighting], list[str]]:
    """Detect, validate and derive within one segment (§B5.2, §B8.1 steps 4-6).

    Returns the valid sightings and the rejection reason of every rejected candidate.
    """
    sightings: list[Sighting] = []
    rejected: list[str] = []
    for cand in detect(text, source):
        outcome = validate(
            cand.type,
            cand.original_value,
            defanged=cand.defanged,
            allow_ambiguous_tlds=allow_ambiguous_tlds,
        )
        if not outcome.ok:
            rejected.append(outcome.reason)
            continue
        sightings.append(Sighting(cand.type, outcome.canonical, cand.original_value, cand.source))
        if cand.type is IOCType.url:
            host = derive_host(cand, outcome.host_type)
            host_outcome = validate(host.type, host.original_value, url_host=True)
            if host_outcome.ok:
                sightings.append(
                    Sighting(host.type, host_outcome.canonical, host.original_value, host.source)
                )
    return sightings, rejected


def _input_name(input_path: Path) -> str:
    if input_path.name not in ("", ".", ".."):
        return input_path.name
    return input_path.resolve().name


def _format_timestamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_scan(
    input_path: Path,
    *,
    recursive: bool = False,
    strict: bool = False,
    allow_ambiguous_tlds: bool = False,
    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES,
    max_files: int = DEFAULT_MAX_FILES,
    max_sources_per_ioc: int = DEFAULT_MAX_SOURCES_PER_IOC,
    excluded_paths: Sequence[Path] = (),
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    on_file: Callable[[str, BaseException | None], None] | None = None,
) -> Report:
    """Scan `input_path` and return a validated Report. Raises LucentFatalError.

    `on_file(rel_path, exc)` is called after each file is read: `exc` is None on success,
    or the exception that made the file fail.
    """
    timestamp = _format_timestamp(clock())
    discovery = discover(
        input_path,
        recursive=recursive,
        max_files=max_files,
        max_file_size_bytes=max_file_size_bytes,
        excluded_paths=excluded_paths,
    )
    warnings: list[ScanWarning] = list(discovery.warnings)
    errors: list[ErrorEntry] = []
    dedup = Deduplicator()
    rejected: Counter[str] = Counter()
    processed = failed = 0

    for entry in discovery.to_read:
        file_sightings: list[Sighting] = []
        file_rejected: Counter[str] = Counter()
        try:
            segments = read_segments(
                entry, max_file_size_bytes=max_file_size_bytes, warnings=warnings
            )
            for segment in segments:
                sightings, reasons = process_segment(
                    segment.text, segment.source, allow_ambiguous_tlds=allow_ambiguous_tlds
                )
                file_sightings.extend(sightings)
                file_rejected.update(reasons)
        except FileFailure as exc:
            failed += 1
            errors.append(
                ErrorEntry(
                    path=entry.rel,
                    stage=exc.stage,
                    error_type=exc.error_type,
                    message=exc.message,
                    recoverable=True,
                )
            )
            if on_file:
                on_file(entry.rel, exc)
            continue
        except Exception as exc:  # noqa: BLE001 - per-file isolation (§B11)
            failed += 1
            errors.append(
                ErrorEntry(
                    path=entry.rel,
                    stage="read",
                    error_type=type(exc).__name__,
                    message=f"{entry.rel}: unexpected error while reading",
                    recoverable=True,
                )
            )
            if on_file:
                on_file(entry.rel, exc)
            continue
        processed += 1
        if on_file:
            on_file(entry.rel, None)
        for s in file_sightings:
            dedup.add(s.type, s.value, s.original_value, s.source)
        rejected.update(file_rejected)

    if processed == 0 and failed == 0:
        raise LucentFatalError("no files were processed")

    iocs = dedup.records(max_sources_per_ioc)
    files = FileCounts(
        discovered=discovery.discovered,
        processed=processed,
        skipped=discovery.skipped,
        failed=failed,
    )
    by_type = {t: 0 for t in IOC_TYPE_ORDER}
    for record in iocs:
        by_type[record.type.value] += 1

    return Report(
        tool=ToolInfo(version=__version__),
        scan=ScanInfo(
            timestamp_utc=timestamp,
            input=_input_name(input_path),
            recursive=recursive,
            strict=strict,
            allow_ambiguous_tlds=allow_ambiguous_tlds,
            status=expected_status(files, len(warnings), len(errors)),
            files=files,
            limits=Limits(
                max_file_size_bytes=max_file_size_bytes,
                max_files=max_files,
                max_sources_per_ioc=max_sources_per_ioc,
            ),
            tld_snapshot=tld_snapshot(),
        ),
        summary=Summary(
            total_unique_iocs=len(iocs),
            by_type=by_type,
            rejected_candidates=Rejected(
                total=sum(rejected.values()),
                by_reason={k: rejected[k] for k in sorted(rejected) if rejected[k] > 0},
            ),
        ),
        iocs=iocs,
        warnings=warnings,
        errors=errors,
    )
