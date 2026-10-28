import csv
import io
import json
from pathlib import Path

import pytest

from lucent_ioc import exporters
from lucent_ioc.config import CSV_HEADER
from lucent_ioc.exporters import guard_cell, render_csv, render_json, write_atomic
from lucent_ioc.models import Report
from lucent_ioc.pipeline import run_scan

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def report(frozen_clock) -> Report:
    return run_scan(SAMPLES, clock=frozen_clock)


def test_json_round_trip(report):
    text = render_json(report)
    assert text.endswith("}\n")
    again = Report.model_validate(json.loads(text))
    assert again == report
    assert list(json.loads(text)) == [
        "schema_version",
        "tool",
        "scan",
        "summary",
        "iocs",
        "warnings",
        "errors",
    ]


def test_json_omits_none_source_fields(report):
    data = json.loads(render_json(report))
    for ioc in data["iocs"]:
        for src in ioc["sources"]:
            assert None not in src.values()
            assert "file" in src


def test_csv_header_and_rows(report):
    rows = list(csv.reader(io.StringIO(render_csv(report), newline="")))
    assert tuple(rows[0]) == CSV_HEADER
    body = rows[1:]
    assert len(body) == len(report.iocs)
    for row, ioc in zip(body, report.iocs, strict=True):
        assert row[0] == ioc.type.value
        assert row[1] == ioc.value
        assert row[2] == "valid_syntax"
        assert int(row[3]) == ioc.occurrences
        assert int(row[4]) == ioc.source_count
        assert json.loads(row[5]) == ioc.original_values
        assert json.loads(row[6]) == [s.model_dump(exclude_none=True) for s in ioc.sources]


def test_csv_cells_are_compact_json(report):
    rows = list(csv.reader(io.StringIO(render_csv(report), newline="")))
    assert all(", " not in r[6] and ": " not in r[6] for r in rows[1:])


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_formula_guard(prefix):
    assert guard_cell(prefix + "SUM(A1)") == "'" + prefix + "SUM(A1)"


def test_formula_guard_leaves_normal_cells():
    assert guard_cell("https://example.com/") == "https://example.com/"
    assert guard_cell('["x"]') == '["x"]'


def test_formula_guard_applied_in_csv_only(report):
    hostile = report.model_copy(deep=True)
    hostile.iocs[0].original_values = ["=cmd"]
    rows = list(csv.reader(io.StringIO(render_csv(hostile), newline="")))
    # The JSON-encoded cell starts with '[' so it is unchanged; the JSON export is untouched.
    assert rows[1][5] == '["=cmd"]'
    assert json.loads(render_json(hostile))["iocs"][0]["original_values"] == ["=cmd"]


def test_csv_formula_guard_on_cells(monkeypatch, report):
    monkeypatch.setattr(exporters, "_compact", lambda value: "=HYPERLINK()")
    rows = list(csv.reader(io.StringIO(render_csv(report), newline="")))
    assert rows[1][5] == "'=HYPERLINK()"


def test_atomic_write_creates_dirs_and_leaves_no_temp(tmp_path):
    target = tmp_path / "a" / "b" / "out.json"
    write_atomic(target, "hello\n")
    assert target.read_bytes() == b"hello\n"
    assert [p.name for p in target.parent.iterdir()] == ["out.json"]


def test_atomic_write_replaces_existing(tmp_path):
    target = tmp_path / "out.csv"
    target.write_text("old", encoding="utf-8")
    write_atomic(target, "a,b\r\n")
    assert target.read_bytes() == b"a,b\r\n"


def test_atomic_write_failure_removes_temp(tmp_path, monkeypatch):
    target = tmp_path / "out.json"
    target.write_text("old", encoding="utf-8")

    def boom(src, dst):
        raise PermissionError("denied")

    monkeypatch.setattr(exporters.os, "replace", boom)
    with pytest.raises(PermissionError):
        write_atomic(target, "new")
    assert [p.name for p in tmp_path.iterdir()] == ["out.json"]
    assert target.read_text(encoding="utf-8") == "old"


def test_json_and_csv_agree(report):
    data = json.loads(render_json(report))
    rows = list(csv.reader(io.StringIO(render_csv(report), newline="")))[1:]
    assert [(i["type"], i["value"]) for i in data["iocs"]] == [(r[0], r[1]) for r in rows]
