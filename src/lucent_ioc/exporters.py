"""JSON and CSV serialization of one Report, plus atomic writes (§B9.5, §B9.6, §B10.2)."""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import sys
import tempfile
from pathlib import Path

from lucent_ioc.config import CSV_FORMULA_PREFIXES, CSV_HEADER
from lucent_ioc.models import Report


def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"


def guard_cell(text: str) -> str:
    """Prefix a cell that a spreadsheet could interpret as a formula."""
    return "'" + text if text.startswith(CSV_FORMULA_PREFIXES) else text


def _compact(value: list) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def render_csv(report: Report) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(CSV_HEADER)
    for ioc in report.to_dict()["iocs"]:
        row = [
            ioc["type"],
            ioc["value"],
            ioc["validation_status"],
            str(ioc["occurrences"]),
            str(ioc["source_count"]),
            _compact(ioc["original_values"]),
            _compact(ioc["sources"]),
        ]
        writer.writerow([guard_cell(cell) for cell in row])
    return buffer.getvalue()


def render(report: Report, fmt: str) -> str:
    return render_json(report) if fmt == "json" else render_csv(report)


def write_atomic(target: Path, content: str) -> None:
    """Write UTF-8 text via a temp file in the target directory, then os.replace."""
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = tempfile.NamedTemporaryFile(  # noqa: SIM115 - closed explicitly before replace
        mode="w",
        encoding="utf-8",
        newline="",
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        with tmp:
            tmp.write(content)
            tmp.flush()
        os.replace(tmp.name, target)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp.name)
        raise


def write_stdout(content: str) -> None:
    """Write UTF-8 bytes to stdout regardless of the console encoding."""
    sys.stdout.flush()
    buffer = getattr(sys.stdout, "buffer", None)
    if buffer is None:
        sys.stdout.write(content)
    else:
        buffer.write(content.encode("utf-8"))
        buffer.flush()
