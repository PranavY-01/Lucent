from pathlib import Path

import pytest
from pydantic import ValidationError

from lucent_ioc.config import IOC_TYPE_ORDER
from lucent_ioc.exporters import render_csv, render_json
from lucent_ioc.models import LucentFatalError, Report, ScanStatus
from lucent_ioc.pipeline import run_scan

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
SAMPLE_FILES = sorted(p for p in SAMPLES.iterdir() if p.is_file())


def assert_invariants(report: Report) -> None:
    """§B9.4, checked independently of the model validator."""
    s = report.summary
    assert s.total_unique_iocs == len(report.iocs)
    assert list(s.by_type) == list(IOC_TYPE_ORDER)
    assert sum(s.by_type.values()) == s.total_unique_iocs
    assert sum(s.rejected_candidates.by_reason.values()) == s.rejected_candidates.total
    assert list(s.rejected_candidates.by_reason) == sorted(s.rejected_candidates.by_reason)
    assert all(v > 0 for v in s.rejected_candidates.by_reason.values())
    keys = [(i.type, i.value) for i in report.iocs]
    assert len(keys) == len(set(keys))
    for i in report.iocs:
        assert i.validation_status == "valid_syntax"
        assert i.occurrences >= i.source_count >= len(i.sources) >= 1
    f = report.scan.files
    assert f.discovered == f.processed + f.skipped + f.failed
    if f.failed:
        assert report.scan.status is ScanStatus.partial
    elif report.warnings or report.errors:
        assert report.scan.status is ScanStatus.completed_with_warnings
    else:
        assert report.scan.status is ScanStatus.completed
    order = [(IOC_TYPE_ORDER.index(i.type.value), i.value) for i in report.iocs]
    assert order == sorted(order)


@pytest.mark.parametrize("path", SAMPLE_FILES, ids=lambda p: p.name)
def test_invariants_on_each_sample(path, frozen_clock):
    report = run_scan(path, clock=frozen_clock)
    assert_invariants(report)
    assert report.scan.status is ScanStatus.completed
    assert report.scan.input == path.name
    assert all(src.file == path.name for i in report.iocs for src in i.sources)


def test_invariants_on_samples_dir(frozen_clock):
    report = run_scan(SAMPLES, recursive=True, clock=frozen_clock)
    assert_invariants(report)
    assert report.scan.input == "samples"
    assert report.scan.timestamp_utc == "2026-10-28T12:00:00Z"


def test_sample_csv_and_json_provenance(frozen_clock):
    report = run_scan(SAMPLES, clock=frozen_clock)
    by_key = {(i.type.value, i.value): i for i in report.iocs}
    evil = by_key[("domain", "evil-portal.example.com")]
    assert [s.model_dump(exclude_none=True) for s in evil.sources] == [
        {"file": "sample_iocs.csv", "record": 3, "column": "indicator"}
    ]
    src_ip = by_key[("ipv4", "192.0.2.44")]
    assert [s.model_dump(exclude_none=True) for s in src_ip.sources] == [
        {"file": "sample_events.json", "path": '$.events[0]["src ip"]'}
    ]
    assert ("domain", "example.org") in by_key  # from the CSV URL host
    assert ("domain", "soc.example.com") not in by_key  # email masked


def _mixed_dir(tmp_path: Path) -> Path:
    d = tmp_path / "mixed"
    d.mkdir()
    (d / "good.txt").write_text("203.0.113.5 and example.net\n", encoding="utf-8")
    (d / "bad.json").write_text('{"a": "203.0.113.99"', encoding="utf-8")
    (d / "empty.log").write_bytes(b"")
    (d / "huge.txt").write_text("203.0.113.200\n" * 10, encoding="utf-8")
    (d / "blob.bin").write_bytes(b"\x00\x01")
    return d


def test_mixed_fixture_dir_partial(tmp_path, frozen_clock):
    report = run_scan(_mixed_dir(tmp_path), max_file_size_bytes=100, clock=frozen_clock)
    assert_invariants(report)
    f = report.scan.files
    assert (f.discovered, f.processed, f.skipped, f.failed) == (5, 2, 2, 1)
    assert report.scan.status is ScanStatus.partial
    assert {(i.type.value, i.value) for i in report.iocs} == {
        ("ipv4", "203.0.113.5"),
        ("domain", "example.net"),
    }
    assert [(e.path, e.stage, e.recoverable) for e in report.errors] == [
        ("bad.json", "parse", True)
    ]
    assert sorted(w.code for w in report.warnings) == ["over_size_limit", "unsupported_extension"]


def test_failed_file_contributes_nothing(tmp_path, frozen_clock, monkeypatch):
    import csv

    from lucent_ioc import reader

    d = tmp_path / "in"
    d.mkdir()
    (d / "x.csv").write_text("h\n203.0.113.1\n203.0.113.2\n", encoding="utf-8")
    (d / "ok.txt").write_text("198.51.100.1\n", encoding="utf-8")
    real = reader.csv.reader

    def broken(fh):
        rows = real(fh)
        yield next(rows)
        yield next(rows)
        raise csv.Error("boom")

    monkeypatch.setattr(reader.csv, "reader", broken)
    report = run_scan(d, clock=frozen_clock)
    assert [i.value for i in report.iocs] == ["198.51.100.1"]
    assert report.scan.status is ScanStatus.partial
    assert report.summary.rejected_candidates.total == 0


def test_warnings_only_status(tmp_path, frozen_clock):
    d = tmp_path / "w"
    d.mkdir()
    (d / "a.txt").write_text("example.com\n", encoding="utf-8")
    (d / "b.exe").write_bytes(b"MZ")
    report = run_scan(d, clock=frozen_clock)
    assert report.scan.status is ScanStatus.completed_with_warnings


def test_zero_iocs_is_valid(tmp_path, frozen_clock):
    f = tmp_path / "plain.txt"
    f.write_text("nothing to see\n", encoding="utf-8")
    report = run_scan(f, clock=frozen_clock)
    assert report.iocs == []
    assert report.scan.status is ScanStatus.completed


@pytest.mark.parametrize("kind", ["empty_dir", "only_unsupported", "single_oversize"])
def test_nothing_processed_is_fatal(tmp_path, kind, frozen_clock):
    d = tmp_path / "d"
    d.mkdir()
    target = d
    if kind == "only_unsupported":
        (d / "x.bin").write_bytes(b"\x00")
    elif kind == "single_oversize":
        target = d / "big.txt"
        target.write_text("x" * 50, encoding="utf-8")
    with pytest.raises(LucentFatalError, match="no files were processed"):
        run_scan(target, max_file_size_bytes=10, clock=frozen_clock)


def test_determinism(tmp_path, frozen_clock):
    a = run_scan(SAMPLES, recursive=True, clock=frozen_clock)
    b = run_scan(SAMPLES, recursive=True, clock=frozen_clock)
    assert render_json(a) == render_json(b)
    assert render_csv(a) == render_csv(b)


def test_allow_ambiguous_flag_recorded(frozen_clock):
    report = run_scan(
        SAMPLES / "incident_report.txt", allow_ambiguous_tlds=True, clock=frozen_clock
    )
    assert report.scan.allow_ambiguous_tlds is True
    assert ("domain", "invoice.zip") in {(i.type.value, i.value) for i in report.iocs}


def test_model_validator_rejects_broken_report(frozen_clock):
    report = run_scan(SAMPLES / "incident_report.txt", clock=frozen_clock)
    data = report.to_dict()
    data["summary"]["total_unique_iocs"] = 99
    with pytest.raises(ValidationError):
        Report.model_validate(data)
    data = report.to_dict()
    data["iocs"].reverse()
    with pytest.raises(ValidationError):
        Report.model_validate(data)
    data = report.to_dict()
    data["scan"]["status"] = "partial"
    with pytest.raises(ValidationError):
        Report.model_validate(data)
