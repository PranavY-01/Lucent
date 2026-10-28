import csv
import os
from pathlib import Path

import pytest

from lucent_ioc import reader
from lucent_ioc.models import LucentFatalError, SourceRef
from lucent_ioc.reader import FileEntry, FileFailure, discover, iter_json_strings, read_segments

SAMPLES = Path(__file__).resolve().parent.parent / "samples"
BIG = 50 * 1024 * 1024


def _read(path: Path, rel: str | None = None, max_size: int = BIG):
    warnings = []
    entry = FileEntry(path=path, rel=rel or path.name)
    segs = list(read_segments(entry, max_file_size_bytes=max_size, warnings=warnings))
    return segs, warnings


def _discover(path: Path, **kw):
    kw.setdefault("max_files", 10_000)
    kw.setdefault("max_file_size_bytes", BIG)
    return discover(path, **kw)


def _symlink(target: Path, link: Path) -> None:
    try:
        os.symlink(target, link, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform/user")


# --------------------------------------------------------------------------- text


def test_text_lines_and_provenance(tmp_path):
    f = tmp_path / "a.txt"
    f.write_bytes("first\r\nsécond\nthird".encode())
    segs, warnings = _read(f)
    assert [s.text for s in segs] == ["first", "sécond", "third"]
    assert [s.source for s in segs] == [
        SourceRef(file="a.txt", line=1),
        SourceRef(file="a.txt", line=2),
        SourceRef(file="a.txt", line=3),
    ]
    assert warnings == []


def test_bom_is_stripped(tmp_path):
    f = tmp_path / "bom.log"
    f.write_bytes(b"\xef\xbb\xbf203.0.113.10\n")
    segs, warnings = _read(f)
    assert segs[0].text == "203.0.113.10"
    assert warnings == []


def test_decode_fallback_warning(tmp_path):
    f = tmp_path / "bad.md"
    f.write_bytes(b"ok line\nbad \xff\xfe byte\n")
    segs, warnings = _read(f)
    assert [s.text for s in segs] == ["ok line", "bad �� byte"]
    assert [w.code for w in warnings] == ["decode_replacement"]
    assert warnings[0].path == "bad.md"
    assert "bad �" not in warnings[0].message


def test_empty_file(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_bytes(b"")
    assert _read(f) == ([], [])


def test_unreadable_file(tmp_path, monkeypatch):
    f = tmp_path / "locked.txt"
    f.write_text("x", encoding="utf-8")

    def deny(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(reader, "open", deny, raising=False)
    with pytest.raises(FileFailure) as exc:
        _read(f)
    assert exc.value.stage == "read"
    assert exc.value.error_type == "PermissionError"


# --------------------------------------------------------------------------- csv


def test_csv_header_records_columns(tmp_path):
    f = tmp_path / "x.csv"
    f.write_bytes(b'indicator,,notes\na,b,c,d\n"multi\nline",e\n')
    segs, _ = _read(f)
    got = [(s.text, s.source.record, s.source.column) for s in segs]
    assert got == [
        ("indicator", 1, "indicator"),
        ("notes", 1, "notes"),
        ("a", 2, "indicator"),
        ("b", 2, "col_2"),
        ("c", 2, "notes"),
        ("d", 2, "col_4"),
        ("multi\nline", 3, "indicator"),
        ("e", 3, "col_2"),
    ]
    assert all(s.source.line is None and s.source.path is None for s in segs)


def test_csv_parse_failure(tmp_path, monkeypatch):
    f = tmp_path / "x.csv"
    f.write_text("h\nrow1\nrow2\n", encoding="utf-8")

    def broken_reader(fh):
        yield ["h"]
        raise csv.Error("boom")

    monkeypatch.setattr(reader.csv, "reader", broken_reader)
    warnings = []
    gen = read_segments(FileEntry(f, "x.csv"), max_file_size_bytes=BIG, warnings=warnings)
    assert next(gen).text == "h"
    with pytest.raises(FileFailure) as exc:
        next(gen)
    assert exc.value.stage == "parse"
    assert exc.value.error_type == "csv.Error"


def test_sample_csv_multiline_record():
    segs, warnings = _read(SAMPLES / "sample_iocs.csv")
    assert warnings == []
    by_text = {s.text: s.source for s in segs}
    assert by_text["evil-portal[.]example[.]com"] == SourceRef(
        file="sample_iocs.csv", record=3, column="indicator"
    )
    assert by_text["Phishing host,\nreported by two users"].record == 3
    assert by_text["hxxps://example[.]org/invoice?id=99"].record == 4


# --------------------------------------------------------------------------- json


def test_json_paths():
    doc = {
        "events": [{"src ip": "1", "msg": "two"}, "three"],
        "n": 4,
        "b": True,
        "z": None,
        "k\"q": "five",
        "203.0.113.1": "six",
    }
    assert list(iter_json_strings(doc)) == [
        ('$.events[0]["src ip"]', "1"),
        ("$.events[0].msg", "two"),
        ("$.events[1]", "three"),
        ('$["k\\"q"]', "five"),
        ('$["203.0.113.1"]', "six"),
    ]


def test_json_top_level_string(tmp_path):
    f = tmp_path / "s.json"
    f.write_text('"example.com"', encoding="utf-8")
    segs, _ = _read(f)
    assert [(s.text, s.source) for s in segs] == [
        ("example.com", SourceRef(file="s.json", path="$"))
    ]


def test_json_malformed_fails(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text('{"a": "example.com",', encoding="utf-8")
    with pytest.raises(FileFailure) as exc:
        _read(f)
    assert exc.value.stage == "parse"
    assert exc.value.error_type == "JSONDecodeError"
    assert "example.com" not in exc.value.message


def test_sample_json_paths():
    segs, _ = _read(SAMPLES / "sample_events.json")
    paths = {s.source.path: s.text for s in segs}
    assert paths['$.events[0]["src ip"]'] == "192.0.2.44"
    assert paths["$.events[1].tags[1]"] == "hxxp://files.example[.]com/drop.bin"
    assert all(s.source.line is None for s in segs)


def test_sample_text_lines():
    segs, _ = _read(SAMPLES / "incident_report.txt")
    assert len(segs) == 8
    assert segs[3].text == "Reported URL: hxxps://example[.]com/test?id=42"
    assert segs[3].source == SourceRef(file="incident_report.txt", line=4)


# --------------------------------------------------------------------------- jsonl (Tier 2)


@pytest.mark.parametrize("ext", [".jsonl", ".ndjson", ".JSONL"])
def test_jsonl_lines_paths_and_invalid_line(tmp_path, ext):
    f = tmp_path / f"events{ext}"
    f.write_bytes(
        b'{"msg": "203.0.113.1"}\n'
        b"\n"
        b'{"broken": \n'
        b'["a", {"src ip": "example.com"}]\n'
        b'"top"\n'
    )
    segs, warnings = _read(f)
    assert [(s.text, s.source.line, s.source.path) for s in segs] == [
        ("203.0.113.1", 1, "$.msg"),
        ("a", 4, "$[0]"),
        ("example.com", 4, '$[1]["src ip"]'),
        ("top", 5, "$"),
    ]
    assert [(w.code, w.path) for w in warnings] == [("jsonl_line_invalid", f.name)]
    assert "line 3" in warnings[0].message


def test_jsonl_discovered_as_supported(tmp_path):
    (tmp_path / "a.ndjson").write_text("{}\n", encoding="utf-8")
    d = _discover(tmp_path)
    assert [e.rel for e in d.to_read] == ["a.ndjson"]


# --------------------------------------------------------------------------- discovery


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "in"
    (root / "sub").mkdir(parents=True)
    (root / ".hidden_dir").mkdir()
    (root / "b.txt").write_text("b", encoding="utf-8")
    (root / "a.json").write_text("{}", encoding="utf-8")
    (root / ".hidden.log").write_text("h", encoding="utf-8")
    (root / "image.BIN").write_bytes(b"\x00")
    (root / "UPPER.TXT").write_text("u", encoding="utf-8")
    (root / "sub" / "c.csv").write_text("c", encoding="utf-8")
    (root / ".hidden_dir" / "d.txt").write_text("d", encoding="utf-8")
    return root


def test_discovery_non_recursive_sorted(tmp_path):
    root = _tree(tmp_path)
    d = _discover(root)
    assert [e.rel for e in d.to_read] == [".hidden.log", "UPPER.TXT", "a.json", "b.txt"]
    assert d.discovered == 5
    assert d.skipped == 1
    assert [(w.code, w.path) for w in d.warnings] == [("unsupported_extension", "image.BIN")]


def test_discovery_recursive_skips_dot_dirs(tmp_path):
    root = _tree(tmp_path)
    d = _discover(root, recursive=True)
    rels = [e.rel for e in d.to_read]
    assert "sub/c.csv" in rels
    assert ".hidden_dir/d.txt" not in rels
    assert rels == sorted(rels)
    assert d.discovered == len(d.to_read) + d.skipped


def test_file_count_limit(tmp_path):
    root = _tree(tmp_path)
    d = _discover(root, max_files=2)
    assert [e.rel for e in d.to_read] == [".hidden.log", "UPPER.TXT"]
    codes = [w.code for w in d.warnings]
    assert codes.count("file_limit_reached") == 1
    assert d.discovered == 5
    assert d.skipped == 3


def test_size_limit(tmp_path):
    root = tmp_path / "in"
    root.mkdir()
    (root / "small.txt").write_text("1234", encoding="utf-8")
    (root / "big.txt").write_text("12345", encoding="utf-8")
    d = _discover(root, max_file_size_bytes=4)
    assert [e.rel for e in d.to_read] == ["small.txt"]
    assert [(w.code, w.path) for w in d.warnings] == [("over_size_limit", "big.txt")]
    assert (d.discovered, d.skipped) == (2, 1)


def test_output_exclusion(tmp_path):
    root = _tree(tmp_path)
    outdir = root / "sub"
    outfile = root / "b.txt"
    d = _discover(root, recursive=True, excluded_paths=[outdir, outfile])
    rels = [e.rel for e in d.to_read]
    assert "b.txt" not in rels and "sub/c.csv" not in rels
    assert d.discovered == 4  # excluded files are not counted


def test_single_file_input(tmp_path):
    f = tmp_path / "report.MD"
    f.write_text("x", encoding="utf-8")
    d = _discover(f)
    assert [e.rel for e in d.to_read] == ["report.MD"]
    assert (d.discovered, d.skipped) == (1, 0)


def test_single_unsupported_file_is_fatal(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"")
    with pytest.raises(LucentFatalError):
        _discover(f)


def test_missing_input_is_fatal(tmp_path):
    with pytest.raises(LucentFatalError):
        _discover(tmp_path / "nope")


def test_symlinked_file_skipped(tmp_path):
    root = tmp_path / "in"
    root.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("x", encoding="utf-8")
    _symlink(target, root / "link.txt")
    d = _discover(root)
    assert d.to_read == []
    assert (d.discovered, d.skipped) == (1, 1)
    assert [(w.code, w.path) for w in d.warnings] == [("symlink_skipped", "link.txt")]


def test_symlinked_dir_not_entered(tmp_path):
    root = tmp_path / "in"
    root.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    (other / "x.txt").write_text("x", encoding="utf-8")
    _symlink(other, root / "linkdir")
    d = _discover(root, recursive=True)
    assert d.to_read == []
    assert d.discovered == 0
    assert [(w.code, w.path) for w in d.warnings] == [("symlink_skipped", "linkdir")]


def test_explicit_symlink_input_followed(tmp_path):
    target = tmp_path / "real.txt"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "link.txt"
    _symlink(target, link)
    d = _discover(link)
    assert [e.rel for e in d.to_read] == ["link.txt"]
