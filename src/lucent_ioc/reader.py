"""File discovery and format-aware readers (§B4).

Readers yield `Segment` objects: a unit of text plus its `SourceRef`. They never detect IOCs.
"""

from __future__ import annotations

import codecs
import csv
import json
import os
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from lucent_ioc.config import (
    CSV_EXTENSIONS,
    JSON_EXTENSIONS,
    JSONL_EXTENSIONS,
    SUPPORTED_EXTENSIONS,
    TEXT_EXTENSIONS,
    WARN_DECODE_REPLACEMENT,
    WARN_FILE_LIMIT_REACHED,
    WARN_JSONL_LINE_INVALID,
    WARN_OVER_SIZE_LIMIT,
    WARN_SYMLINK_SKIPPED,
    WARN_UNSUPPORTED_EXTENSION,
)
from lucent_ioc.models import LucentFatalError, ScanWarning, SourceRef

_CSV_FIELD_LIMIT_MAX = 2**31 - 1  # C long on Windows
_IDENT_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DECODE_CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Segment:
    text: str
    source: SourceRef


@dataclass(frozen=True)
class FileEntry:
    path: Path
    rel: str

    @property
    def suffix(self) -> str:
        return self.path.suffix.lower()


@dataclass
class Discovery:
    """Outcome of discovery: files to read, plus counts and warnings for skipped files."""

    to_read: list[FileEntry] = field(default_factory=list)
    discovered: int = 0
    skipped: int = 0
    warnings: list[ScanWarning] = field(default_factory=list)


class FileFailure(Exception):
    """A per-file failure; the file is counted as failed and the scan continues."""

    def __init__(self, stage: str, error_type: str, message: str) -> None:
        super().__init__(message)
        self.stage = stage
        self.error_type = error_type
        self.message = message


# --------------------------------------------------------------------------- discovery


def _is_link(entry: os.DirEntry) -> bool:
    if entry.is_symlink():
        return True
    is_junction = getattr(entry, "is_junction", None)  # Python 3.12+
    return bool(is_junction and is_junction())


def _is_excluded(path: Path, excluded: Sequence[Path]) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    return any(resolved == ex or ex in resolved.parents for ex in excluded)


def _walk(
    root: Path, current: Path, recursive: bool, excluded: Sequence[Path], out: list, dir_links: list
) -> None:
    """Collect (rel, path, is_symlink) for files under `current`, recording skipped dir links."""
    try:
        entries = list(os.scandir(current))
    except OSError:
        return
    for entry in entries:
        path = Path(entry.path)
        rel = path.relative_to(root).as_posix()
        is_link = _is_link(entry)
        if not is_link and entry.is_dir(follow_symlinks=False):
            if recursive and not entry.name.startswith("."):
                _walk(root, path, recursive, excluded, out, dir_links)
            continue
        if is_link:
            try:
                points_to_dir = entry.is_dir(follow_symlinks=True)
            except OSError:
                points_to_dir = False
            if points_to_dir:
                if recursive and not entry.name.startswith("."):
                    dir_links.append(rel)
                continue
            if not _is_excluded(path, excluded):
                out.append((rel, path, True))
            continue
        if entry.is_file(follow_symlinks=False) and not _is_excluded(path, excluded):
            out.append((rel, path, False))


def _file_size(path: Path) -> int | None:
    try:
        return path.stat().st_size
    except OSError:
        return None


def discover(
    input_path: Path,
    *,
    recursive: bool = False,
    max_files: int,
    max_file_size_bytes: int,
    excluded_paths: Sequence[Path] = (),
) -> Discovery:
    """Discover files to scan, applying §B4.6 and §B4.7. Raises LucentFatalError."""
    if not input_path.exists():
        raise LucentFatalError(f"input not found: {input_path.name}")
    excluded = [Path(p).resolve() for p in excluded_paths]
    result = Discovery()

    if input_path.is_file():
        if input_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            raise LucentFatalError(
                f"unsupported file extension '{input_path.suffix}': {input_path.name}"
            )
        candidates = [(input_path.name, input_path, False)]
        dir_links: list[str] = []
    elif input_path.is_dir():
        candidates = []
        dir_links = []
        _walk(input_path, input_path, recursive, excluded, candidates, dir_links)
    else:
        raise LucentFatalError(f"input is not a file or directory: {input_path.name}")

    for rel in sorted(dir_links):
        result.warnings.append(
            ScanWarning(
                code=WARN_SYMLINK_SKIPPED,
                path=rel,
                message=f"{rel}: symlinked directory not entered",
            )
        )

    readable = 0
    limit_warned = False
    for rel, path, is_link in sorted(candidates, key=lambda c: c[0]):
        result.discovered += 1
        if is_link:
            result.skipped += 1
            result.warnings.append(
                ScanWarning(
                    code=WARN_SYMLINK_SKIPPED, path=rel, message=f"{rel}: symlink skipped"
                )
            )
            continue
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            result.skipped += 1
            result.warnings.append(
                ScanWarning(
                    code=WARN_UNSUPPORTED_EXTENSION,
                    path=rel,
                    message=f"{rel}: unsupported file extension, skipped",
                )
            )
            continue
        if readable >= max_files:
            result.skipped += 1
            if not limit_warned:
                limit_warned = True
                result.warnings.append(
                    ScanWarning(
                        code=WARN_FILE_LIMIT_REACHED,
                        path=rel,
                        message=f"file limit of {max_files} reached; "
                        f"{rel} and later files skipped",
                    )
                )
            continue
        readable += 1
        size = _file_size(path)
        if size is not None and size > max_file_size_bytes:
            result.skipped += 1
            result.warnings.append(
                ScanWarning(
                    code=WARN_OVER_SIZE_LIMIT,
                    path=rel,
                    message=f"{rel}: {size} bytes exceeds limit of "
                    f"{max_file_size_bytes} bytes, skipped",
                )
            )
            continue
        result.to_read.append(FileEntry(path=path, rel=rel))
    return result


# --------------------------------------------------------------------------- reading


def _needs_replacement(path: Path) -> bool:
    """True if the file is not valid UTF-8 (BOM allowed). Streams in chunks."""
    decoder = codecs.getincrementaldecoder("utf-8-sig")(errors="strict")
    with open(path, "rb") as fh:
        try:
            while chunk := fh.read(_DECODE_CHUNK):
                decoder.decode(chunk)
            decoder.decode(b"", final=True)
        except UnicodeDecodeError:
            return True
    return False


def _iter_text(entry: FileEntry, errors: str) -> Iterator[Segment]:
    with open(entry.path, encoding="utf-8-sig", errors=errors, newline=None) as fh:
        for line_no, line in enumerate(fh, start=1):
            yield Segment(line.rstrip("\n"), SourceRef(file=entry.rel, line=line_no))


def _column_name(header: list[str], index: int) -> str:
    if index < len(header) and header[index] != "":
        return header[index]
    return f"col_{index + 1}"


def _iter_csv(entry: FileEntry, errors: str, max_file_size_bytes: int) -> Iterator[Segment]:
    csv.field_size_limit(min(max(max_file_size_bytes, 1), _CSV_FIELD_LIMIT_MAX))
    with open(entry.path, encoding="utf-8-sig", errors=errors, newline="") as fh:
        header: list[str] | None = None
        try:
            for record, row in enumerate(csv.reader(fh), start=1):
                if header is None:
                    header = row
                for index, cell in enumerate(row):
                    if cell:
                        source = SourceRef(
                            file=entry.rel, record=record, column=_column_name(header, index)
                        )
                        yield Segment(cell, source)
        except csv.Error as exc:
            raise FileFailure("parse", "csv.Error", f"{entry.rel}: CSV parse error: {exc}") from exc


def _child_path(parent: str, key: str | int) -> str:
    if isinstance(key, int):
        return f"{parent}[{key}]"
    if _IDENT_KEY.match(key):
        return f"{parent}.{key}"
    return f"{parent}[{json.dumps(key, ensure_ascii=False)}]"


def iter_json_strings(document: object, root: str = "$") -> Iterator[tuple[str, str]]:
    """Yield (path, string) for every string value in document order. Keys are not scanned."""
    stack: list[tuple[str, object]] = [(root, document)]
    while stack:
        path, node = stack.pop()
        if isinstance(node, str):
            yield path, node
        elif isinstance(node, dict):
            children = [(_child_path(path, k), v) for k, v in node.items()]
            stack.extend(reversed(children))
        elif isinstance(node, list):
            children = [(_child_path(path, i), v) for i, v in enumerate(node)]
            stack.extend(reversed(children))


def _iter_json(entry: FileEntry, errors: str) -> Iterator[Segment]:
    with open(entry.path, encoding="utf-8-sig", errors=errors) as fh:
        text = fh.read()
    try:
        document = json.loads(text)
    except json.JSONDecodeError as exc:
        raise FileFailure(
            "parse", "JSONDecodeError", f"{entry.rel}: invalid JSON at line {exc.lineno}"
        ) from exc
    except RecursionError as exc:
        raise FileFailure("parse", "RecursionError", f"{entry.rel}: JSON nested too deeply") from exc
    for path, value in iter_json_strings(document):
        yield Segment(value, SourceRef(file=entry.rel, path=path))


def _iter_jsonl(entry: FileEntry, errors: str, warnings: list[ScanWarning]) -> Iterator[Segment]:
    with open(entry.path, encoding="utf-8-sig", errors=errors, newline=None) as fh:
        for line_no, line in enumerate(fh, start=1):
            if not line.strip():
                continue
            try:
                document = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                warnings.append(
                    ScanWarning(
                        code=WARN_JSONL_LINE_INVALID,
                        path=entry.rel,
                        message=f"{entry.rel}: line {line_no} is not valid JSON, skipped",
                    )
                )
                continue
            for path, value in iter_json_strings(document):
                yield Segment(value, SourceRef(file=entry.rel, line=line_no, path=path))


def read_segments(
    entry: FileEntry, *, max_file_size_bytes: int, warnings: list[ScanWarning]
) -> Iterator[Segment]:
    """Yield the segments of one file.

    A decode problem appends a `decode_replacement` warning to `warnings` and reads with
    replacement characters. Raises FileFailure for unreadable or unparsable files.
    """
    try:
        replace = _needs_replacement(entry.path)
    except OSError as exc:
        raise FileFailure("read", type(exc).__name__, f"{entry.rel}: cannot open file") from exc
    errors = "replace" if replace else "strict"
    if replace:
        warnings.append(
            ScanWarning(
                code=WARN_DECODE_REPLACEMENT,
                path=entry.rel,
                message=f"{entry.rel}: not valid UTF-8; undecodable bytes replaced",
            )
        )

    suffix = entry.suffix
    if suffix in TEXT_EXTENSIONS:
        segments = _iter_text(entry, errors)
    elif suffix in CSV_EXTENSIONS:
        segments = _iter_csv(entry, errors, max_file_size_bytes)
    elif suffix in JSON_EXTENSIONS:
        segments = _iter_json(entry, errors)
    elif suffix in JSONL_EXTENSIONS:
        segments = _iter_jsonl(entry, errors, warnings)
    else:  # pragma: no cover - discovery never yields unsupported files
        raise FileFailure("read", "UnsupportedExtension", f"{entry.rel}: unsupported extension")
    try:
        yield from segments
    except OSError as exc:
        raise FileFailure("read", type(exc).__name__, f"{entry.rel}: read error") from exc
