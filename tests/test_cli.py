import csv
import functools
import io
import json
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from lucent_ioc import __version__, cli
from lucent_ioc.cli import app
from lucent_ioc.models import Report
from lucent_ioc.pipeline import run_scan

runner = CliRunner()
ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "samples"
REPORT = SAMPLES / "incident_report.txt"
MIXED = ROOT / "tests" / "fixtures" / "mixed"
SAMPLE_FILES = sorted(p for p in SAMPLES.iterdir() if p.is_file())


def run(*args: str):
    return runner.invoke(app, ["scan", *map(str, args)])


# --------------------------------------------------------------------------- basics


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == f"lucent {__version__}"


def test_help_lists_scan():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout


def test_module_entry_help():
    proc = subprocess.run(
        [sys.executable, "-m", "lucent_ioc", "--help"],
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0
    assert "scan" in proc.stdout


# --------------------------------------------------------------------------- usage errors (exit 2)


@pytest.mark.parametrize(
    "args",
    [
        ["--output", "x.json", "--output-dir", "out"],
        ["--format", "both", "--output", "x.json"],
        ["--format", "both"],
        ["--format", "csv"],
        ["--format", "xml"],
        ["--max-files", "0"],
        ["--max-file-size", "0"],
        ["--max-sources-per-ioc", "0"],
        ["--verbose", "--quiet"],
    ],
    ids=[
        "output+output-dir",
        "both+output",
        "both-no-dir",
        "csv-no-dest",
        "bad-format",
        "max-files-0",
        "max-size-0",
        "max-sources-0",
        "verbose+quiet",
    ],
)
def test_usage_errors(tmp_path, args):
    result = run(REPORT, *args)
    assert result.exit_code == 2
    assert result.stdout == ""
    assert not (tmp_path / "x.json").exists()


# --------------------------------------------------------------------------- destinations


def test_terminal_only_writes_nothing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = run(REPORT)
    assert result.exit_code == 0
    assert "Input: incident_report.txt" in result.stdout
    assert "IOCs: 4 unique" in result.stdout
    assert "Rejected candidates: 1 (ambiguous_file_extension_tld 1)" in result.stdout
    assert "Status: completed" in result.stdout
    assert "https://example.com/test?id=42" in result.stdout
    assert list(tmp_path.iterdir()) == []


def test_terminal_table_capped(tmp_path):
    f = tmp_path / "many.txt"
    f.write_text("\n".join(f"192.0.2.{i}" for i in range(60)) + "\n", encoding="utf-8")
    result = run(f)
    assert result.exit_code == 0
    assert "showing 50 of 60" in result.stdout
    shown = [line for line in result.stdout.splitlines() if "192.0.2." in line]
    assert len(shown) == 50


def test_output_file_creates_parents(tmp_path):
    target = tmp_path / "a" / "b" / "r.json"
    result = run(REPORT, "--output", target)
    assert result.exit_code == 0
    report = Report.model_validate(json.loads(target.read_text(encoding="utf-8")))
    assert report.summary.total_unique_iocs == 4
    assert f"Output: {target}" in result.stdout


def test_output_csv_file(tmp_path):
    target = tmp_path / "r.csv"
    result = run(REPORT, "--format", "csv", "--output", target)
    assert result.exit_code == 0
    assert target.read_text(encoding="utf-8").startswith(
        "type,value,validation_status,occurrences,source_count,original_values,sources"
    )


def test_output_stdout_only_json():
    result = run(REPORT, "--output", "-")
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["summary"]["total_unique_iocs"] == 4
    assert "Status: completed" in result.stderr
    assert "Status" not in result.stdout


def test_output_stdout_csv():
    result = run(REPORT, "--format", "csv", "--output", "-")
    assert result.exit_code == 0
    assert result.stdout.splitlines()[0].startswith("type,value,")
    assert len(result.stdout.splitlines()) == 5


def test_output_dir_both(tmp_path):
    out = tmp_path / "new" / "reports"
    result = run(SAMPLES, "--format", "both", "--output-dir", out)
    assert result.exit_code == 0
    assert sorted(p.name for p in out.iterdir()) == ["lucent_iocs.csv", "lucent_iocs.json"]


def test_output_dir_default_json(tmp_path):
    result = run(REPORT, "--output-dir", tmp_path)
    assert result.exit_code == 0
    assert [p.name for p in tmp_path.iterdir()] == ["lucent_iocs.json"]


def test_existing_output_refused_then_forced(tmp_path):
    target = tmp_path / "r.json"
    target.write_text("keep", encoding="utf-8")
    result = run(REPORT, "--output", target)
    assert result.exit_code == 1
    assert "Error:" in result.stderr and "already exists" in result.stderr
    assert target.read_text(encoding="utf-8") == "keep"
    result = run(REPORT, "--output", target, "--force")
    assert result.exit_code == 0
    assert json.loads(target.read_text(encoding="utf-8"))["schema_version"] == "1.0"


def test_existing_one_of_two_refuses_both(tmp_path):
    (tmp_path / "lucent_iocs.csv").write_text("keep", encoding="utf-8")
    result = run(REPORT, "--format", "both", "--output-dir", tmp_path)
    assert result.exit_code == 1
    assert not (tmp_path / "lucent_iocs.json").exists()


def test_output_is_input_fatal_even_with_force(tmp_path):
    f = tmp_path / "in.txt"
    f.write_text("203.0.113.1\n", encoding="utf-8")
    result = run(f, "--output", f, "--force")
    assert result.exit_code == 1
    assert "is the input file" in result.stderr
    assert f.read_text(encoding="utf-8") == "203.0.113.1\n"


def test_output_dir_inside_input_dir_is_excluded(tmp_path):
    d = tmp_path / "in"
    d.mkdir()
    (d / "a.txt").write_text("203.0.113.1\n", encoding="utf-8")
    out = d / "reports"
    assert run(d, "--recursive", "--output-dir", out).exit_code == 0
    result = run(d, "--recursive", "--output-dir", out, "--force", "--format", "json")
    assert result.exit_code == 0
    data = json.loads((out / "lucent_iocs.json").read_text(encoding="utf-8"))
    assert data["scan"]["files"]["discovered"] == 1


# --------------------------------------------------------------------------- exit codes


def test_exit_0_with_warnings(tmp_path):
    (tmp_path / "a.txt").write_text("example.com\n", encoding="utf-8")
    (tmp_path / "b.bin").write_bytes(b"\x00")
    result = run(tmp_path)
    assert result.exit_code == 0
    assert "Warning [unsupported_extension]: b.bin" in result.stdout
    assert "Status: completed_with_warnings" in result.stdout


def test_exit_3_strict_with_warnings(tmp_path):
    (tmp_path / "a.txt").write_text("example.com\n", encoding="utf-8")
    (tmp_path / "b.bin").write_bytes(b"\x00")
    out = tmp_path / "out"
    plain = run(tmp_path, "--output-dir", out)
    strict = run(tmp_path, "--output-dir", out, "--force", "--strict")
    assert (plain.exit_code, strict.exit_code) == (0, 3)
    # --strict never changes output content (other than the recorded flag)
    data = json.loads((out / "lucent_iocs.json").read_text(encoding="utf-8"))
    assert data["scan"]["strict"] is True
    assert data["summary"]["total_unique_iocs"] == 1


def test_strict_without_warnings_is_0():
    assert run(REPORT, "--strict").exit_code == 0


def test_exit_3_partial(tmp_path):
    (tmp_path / "ok.txt").write_text("203.0.113.1\n", encoding="utf-8")
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    result = run(tmp_path)
    assert result.exit_code == 3
    assert "Error [parse] JSONDecodeError: bad.json" in result.stdout
    assert "Status: partial" in result.stdout


def test_exit_1_missing_input(tmp_path):
    result = run(tmp_path / "missing.txt")
    assert result.exit_code == 1
    assert result.stderr.startswith("Error: input not found")


def test_exit_1_unsupported_single_file(tmp_path):
    f = tmp_path / "x.exe"
    f.write_bytes(b"MZ")
    result = run(f)
    assert result.exit_code == 1
    assert "unsupported file extension" in result.stderr


def test_exit_1_nothing_processed(tmp_path):
    result = run(tmp_path)
    assert result.exit_code == 1
    assert "Error: no files were processed" in result.stderr


def test_exit_1_oversize_single_file(tmp_path):
    f = tmp_path / "big.txt"
    f.write_bytes(b"x" * (1024 * 1024 + 1))
    result = run(f, "--max-file-size", "1")
    assert result.exit_code == 1


# --------------------------------------------------------------------------- Tier 2 flags


def test_allow_ambiguous_tlds_flag():
    data = json.loads(run(REPORT, "--output", "-", "--allow-ambiguous-tlds").stdout)
    assert data["scan"]["allow_ambiguous_tlds"] is True
    assert {"type": "domain", "value": "invoice.zip"}.items() <= next(
        i for i in data["iocs"] if i["value"] == "invoice.zip"
    ).items()
    assert data["summary"]["rejected_candidates"] == {"total": 0, "by_reason": {}}


def test_max_sources_per_ioc_flag(tmp_path):
    f = tmp_path / "rep.txt"
    f.write_text("203.0.113.9\n" * 5, encoding="utf-8")
    data = json.loads(run(f, "--output", "-", "--max-sources-per-ioc", "2").stdout)
    (ioc,) = data["iocs"]
    assert (ioc["occurrences"], ioc["source_count"], len(ioc["sources"])) == (5, 5, 2)
    assert ioc["sources_truncated"] is True
    assert data["scan"]["limits"]["max_sources_per_ioc"] == 2


def test_quiet(tmp_path):
    (tmp_path / "ok.txt").write_text("203.0.113.1\n", encoding="utf-8")
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    (tmp_path / "x.bin").write_bytes(b"\x00")
    result = run(tmp_path, "--quiet")
    assert result.exit_code == 3
    assert result.stdout.splitlines() == [
        "Error [parse] JSONDecodeError: bad.json: invalid JSON at line 1",
        "Status: partial",
    ]


def test_verbose_lists_files_and_tracebacks(tmp_path):
    (tmp_path / "ok.txt").write_text("203.0.113.1\n", encoding="utf-8")
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    result = run(tmp_path, "--verbose")
    assert result.exit_code == 3
    assert "Processed: ok.txt" in result.stdout
    assert "Failed: bad.json" in result.stdout
    assert "Traceback (most recent call last)" in result.stdout


def test_no_traceback_without_verbose(tmp_path):
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    result = run(tmp_path)
    assert "Traceback" not in result.stdout + result.stderr


def test_verbose_goes_to_stderr_with_stdout_output(tmp_path):
    (tmp_path / "ok.txt").write_text("203.0.113.1\n", encoding="utf-8")
    result = run(tmp_path, "--verbose", "--output", "-")
    json.loads(result.stdout)
    assert "Processed: ok.txt" in result.stderr


def test_jsonl_input(tmp_path):
    f = tmp_path / "events.jsonl"
    f.write_text('{"m": "203.0.113.4"}\nnot json\n', encoding="utf-8")
    result = run(f, "--output", "-")
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["iocs"][0]["sources"] == [{"file": "events.jsonl", "line": 1, "path": "$.m"}]
    assert [w["code"] for w in data["warnings"]] == ["jsonl_line_invalid"]
    assert data["scan"]["status"] == "completed_with_warnings"


def _fail_for(suffix: str, monkeypatch):
    real = cli.write_atomic

    def maybe_fail(path, content):
        if path.suffix == suffix or suffix == "*":
            raise PermissionError(13, "Permission denied")
        real(path, content)

    monkeypatch.setattr(cli, "write_atomic", maybe_fail)


def test_exit_3_one_of_two_exports_failed(tmp_path, monkeypatch):
    _fail_for(".csv", monkeypatch)
    result = run(REPORT, "--format", "both", "--output-dir", tmp_path)
    assert result.exit_code == 3
    assert "could not write" in result.stderr
    assert [p.name for p in tmp_path.iterdir()] == ["lucent_iocs.json"]


def test_exit_1_all_exports_failed(tmp_path, monkeypatch):
    _fail_for("*", monkeypatch)
    assert run(REPORT, "--format", "both", "--output-dir", tmp_path).exit_code == 1
    assert run(REPORT, "--output", tmp_path / "r.json").exit_code == 1


# --------------------------------------------------------------------------- integration (§B15.4)


@pytest.fixture
def frozen_cli(monkeypatch, frozen_clock):
    monkeypatch.setattr(cli, "run_scan", functools.partial(run_scan, clock=frozen_clock))


def _both(input_path: Path, out: Path, *extra: str):
    result = run(input_path, "--format", "both", "--output-dir", out, "--force", *extra)
    data = json.loads((out / "lucent_iocs.json").read_text(encoding="utf-8"))
    rows = list(csv.reader(io.StringIO((out / "lucent_iocs.csv").read_bytes().decode("utf-8"))))
    return result, data, rows


def _assert_json_csv_agree(data: dict, rows: list[list[str]]) -> None:
    assert rows[0] == [
        "type",
        "value",
        "validation_status",
        "occurrences",
        "source_count",
        "original_values",
        "sources",
    ]
    assert [(i["type"], i["value"]) for i in data["iocs"]] == [(r[0], r[1]) for r in rows[1:]]
    for ioc, row in zip(data["iocs"], rows[1:], strict=True):
        assert int(row[3]) == ioc["occurrences"]
        assert int(row[4]) == ioc["source_count"]
        assert json.loads(row[5]) == ioc["original_values"]
        assert json.loads(row[6]) == ioc["sources"]


EXPECTED_SAMPLE_IOCS = {
    "incident_report.txt": {
        ("ipv4", "203.0.113.10"),
        ("domain", "example.com"),
        ("url", "https://example.com/test?id=42"),
        ("sha256", "a" * 64),
    },
    "sample_events.json": {
        ("ipv4", "192.0.2.44"),
        ("domain", "c2.example.net"),
        ("domain", "files.example.com"),
        ("domain", "update.example.org"),
        ("url", "http://files.example.com/drop.bin"),
        ("url", "https://c2.example.net/api/checkin"),
        ("sha1", "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
    },
    "sample_iocs.csv": {
        ("ipv4", "203.0.113.50"),
        ("domain", "evil-portal.example.com"),
        ("domain", "example.org"),
        ("url", "https://example.org/invoice?id=99"),
        ("md5", "d41d8cd98f00b204e9800998ecf8427e"),
    },
    "sample_logs.log": {
        ("ipv4", "192.0.2.15"),
        ("ipv4", "192.0.2.16"),
        ("ipv4", "198.51.100.200"),
        ("ipv4", "198.51.100.23"),
        ("ipv4", "203.0.113.77"),
        ("domain", "cdn.example.org"),
        ("domain", "downloads.example.net"),
        ("domain", "login-portal.example.com"),
        ("domain", "portal.example.com"),
        ("domain", "www.example.com"),
        ("url", "http://downloads.example.net/payload/update.exe"),
        ("url", "https://login-portal.example.com/verify?id=7781"),
        ("url", "https://www.example.com/index.html"),
        ("md5", "d41d8cd98f00b204e9800998ecf8427e"),
        ("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
    },
}

EXPECTED_SAMPLE_REJECTED = {
    "incident_report.txt": {"ambiguous_file_extension_tld": 1},
    "sample_events.json": {},
    "sample_iocs.csv": {"unknown_tld": 1},
    "sample_logs.log": {"invalid_ipv4": 1, "unknown_tld": 2},
}


@pytest.mark.parametrize("path", SAMPLE_FILES, ids=lambda p: p.name)
def test_integration_each_sample(path, tmp_path, frozen_cli):
    result, data, rows = _both(path, tmp_path / "out")
    assert result.exit_code == 0
    assert {(i["type"], i["value"]) for i in data["iocs"]} == EXPECTED_SAMPLE_IOCS[path.name]
    rejected = data["summary"]["rejected_candidates"]["by_reason"]
    assert rejected == EXPECTED_SAMPLE_REJECTED[path.name]
    assert data["scan"]["status"] == "completed"
    assert data["scan"]["files"] == {"discovered": 1, "processed": 1, "skipped": 0, "failed": 0}
    assert all(s["file"] == path.name for i in data["iocs"] for s in i["sources"])
    Report.model_validate(data)
    _assert_json_csv_agree(data, rows)


def test_integration_sample_sources(tmp_path, frozen_cli):
    _, data, _ = _both(SAMPLES, tmp_path / "out")
    by_key = {(i["type"], i["value"]): i for i in data["iocs"]}
    assert by_key[("ipv4", "192.0.2.15")]["sources"] == [
        {"file": "sample_logs.log", "line": n} for n in (4, 6, 10, 13)
    ]
    assert by_key[("md5", "d41d8cd98f00b204e9800998ecf8427e")]["sources"] == [
        {"file": "sample_iocs.csv", "record": 5, "column": "indicator"},
        {"file": "sample_logs.log", "line": 9},
    ]
    assert by_key[("domain", "example.org")]["sources"] == [
        {"file": "sample_iocs.csv", "record": 4, "column": "indicator", "via": "url_host"}
    ]


def test_integration_mixed_fixture_dir(tmp_path, frozen_cli):
    result, data, rows = _both(MIXED, tmp_path / "out")
    assert result.exit_code == 3
    assert data["scan"]["status"] == "partial"
    assert data["scan"]["files"] == {"discovered": 5, "processed": 3, "skipped": 1, "failed": 1}
    assert [(e["path"], e["stage"]) for e in data["errors"]] == [("malformed.json", "parse")]
    assert [(w["code"], w["path"]) for w in data["warnings"]] == [
        ("unsupported_extension", "unsupported.bin")
    ]
    keys = {(i["type"], i["value"]) for i in data["iocs"]}
    assert ("ipv4", "198.51.100.7") in keys
    assert ("ipv4", "192.0.2.64") in keys  # oversize.log is processed at the default limit
    assert ("ipv4", "203.0.113.8") not in keys  # a failed file contributes nothing
    Report.model_validate(data)
    _assert_json_csv_agree(data, rows)


def test_integration_mixed_fixture_tiny_limit(frozen_clock):
    report = run_scan(MIXED, max_file_size_bytes=1024, clock=frozen_clock)
    f = report.scan.files
    assert (f.discovered, f.processed, f.skipped, f.failed) == (5, 2, 2, 1)
    assert sorted(w.code for w in report.warnings) == ["over_size_limit", "unsupported_extension"]
    assert report.scan.status.value == "partial"
    assert not any(i.value.startswith("192.0.2.") for i in report.iocs)


@pytest.mark.parametrize("target", [SAMPLES, MIXED], ids=["samples", "mixed"])
def test_integration_byte_identical(target, tmp_path, frozen_cli):
    _both(target, tmp_path / "a")
    _both(target, tmp_path / "b")
    for name in ("lucent_iocs.json", "lucent_iocs.csv"):
        assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()


# --------------------------------------------------------------------------- §B23 demo

DEMO_EXPECTED = {
    "schema_version": "1.0",
    "tool": {"name": "Lucent", "version": __version__},
    "scan": {
        "input": "incident_report.txt",
        "recursive": False,
        "strict": False,
        "allow_ambiguous_tlds": False,
        "status": "completed",
        "files": {"discovered": 1, "processed": 1, "skipped": 0, "failed": 0},
        "limits": {"max_file_size_bytes": 52428800, "max_files": 10000, "max_sources_per_ioc": 100},
    },
    "summary": {
        "total_unique_iocs": 4,
        "by_type": {"ipv4": 1, "domain": 1, "url": 1, "md5": 0, "sha1": 0, "sha256": 1},
        "rejected_candidates": {"total": 1, "by_reason": {"ambiguous_file_extension_tld": 1}},
    },
    "iocs": [
        {
            "type": "ipv4",
            "value": "203.0.113.10",
            "validation_status": "valid_syntax",
            "occurrences": 2,
            "source_count": 2,
            "sources_truncated": False,
            "original_values": ["203.0.113.10"],
            "original_values_truncated": False,
            "sources": [
                {"file": "incident_report.txt", "line": 2},
                {"file": "incident_report.txt", "line": 8},
            ],
        },
        {
            "type": "domain",
            "value": "example.com",
            "validation_status": "valid_syntax",
            "occurrences": 2,
            "source_count": 2,
            "sources_truncated": False,
            "original_values": ["example[.]com"],
            "original_values_truncated": False,
            "sources": [
                {"file": "incident_report.txt", "line": 3},
                {"file": "incident_report.txt", "line": 4, "via": "url_host"},
            ],
        },
        {
            "type": "url",
            "value": "https://example.com/test?id=42",
            "validation_status": "valid_syntax",
            "occurrences": 1,
            "source_count": 1,
            "sources_truncated": False,
            "original_values": ["hxxps://example[.]com/test?id=42"],
            "original_values_truncated": False,
            "sources": [{"file": "incident_report.txt", "line": 4}],
        },
        {
            "type": "sha256",
            "value": "a" * 64,
            "validation_status": "valid_syntax",
            "occurrences": 1,
            "source_count": 1,
            "sources_truncated": False,
            "original_values": ["a" * 64],
            "original_values_truncated": False,
            "sources": [{"file": "incident_report.txt", "line": 5}],
        },
    ],
    "warnings": [],
    "errors": [],
}


def test_demo(monkeypatch):
    monkeypatch.chdir(ROOT)
    result = runner.invoke(app, ["scan", "samples/incident_report.txt", "--output", "-"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)  # stdout holds only the JSON
    assert result.stdout.endswith("}\n")
    assert len(data["scan"].pop("timestamp_utc")) == len("2026-10-28T12:00:00Z")
    assert data["scan"].pop("tld_snapshot")
    assert data == DEMO_EXPECTED
