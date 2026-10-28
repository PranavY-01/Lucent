import io
import json
import re
from pathlib import Path

from rich.console import Console
from typer.testing import CliRunner

from lucent_ioc import ui
from lucent_ioc.cli import app
from lucent_ioc.pipeline import run_scan

runner = CliRunner()
ROOT = Path(__file__).resolve().parent.parent
REPORT = ROOT / "samples" / "incident_report.txt"
MIXED = ROOT / "tests" / "fixtures" / "mixed"
BANNER_ROW = "|______|  \\____/   \\_____| |______| |_| \\_|    |_|"
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def _plain(text: str) -> str:
    """Strip ANSI codes; Typer forces colour for help when GITHUB_ACTIONS is set."""
    return _ANSI.sub("", text)


def _buffer_console(encoding: str = "utf-8", color: bool = False) -> tuple[Console, io.BytesIO]:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding=encoding, errors="strict")
    console = Console(
        file=stream,
        width=100,
        force_terminal=color,
        color_system="truecolor" if color else None,
        no_color=not color,  # explicit, so a NO_COLOR environment does not affect the test
        legacy_windows=False,
    )
    return console, raw


def _text(console: Console, raw: io.BytesIO, encoding: str = "utf-8") -> str:
    console.file.flush()
    return raw.getvalue().decode(encoding)


# --------------------------------------------------------------------------- gradient


def test_blend_endpoints_and_midpoint():
    assert ui.blend(0) == ui.GREEN
    assert ui.blend(1) == ui.RED
    assert ui.blend(0.5) == ui.YELLOW
    assert ui.blend(-3) == ui.GREEN and ui.blend(7) == ui.RED


def test_gradient_colours_every_character():
    text = ui.gradient("LUCENT")
    assert text.plain == "LUCENT"
    styles = [str(span.style) for span in text.spans]
    assert len(styles) == 6
    assert styles[0] == f"bold {ui.GREEN}" and styles[-1] == f"bold {ui.RED}"


def test_banner_is_ascii():
    plain = ui.banner().plain
    assert plain.isascii()
    assert BANNER_ROW in plain


def test_truecolor_output_uses_whole_palette():
    # Read colours from the style objects (HTML export), not from ANSI codes: Rich caches
    # each style's ANSI string, so codes depend on what earlier tests rendered.
    console = Console(file=io.StringIO(), record=True, width=100, legacy_windows=False)
    report = run_scan(MIXED)
    ui.print_banner(console)
    ui.print_summary(console, report, [], show_table=True, table_rows=5)
    html = console.export_html(inline_styles=True)
    for color in ui.GRADIENT:
        assert f"color: {color}" in html
    assert len(set(re.findall(r"color: (#[0-9a-f]{6})", html))) > 50
    assert "font-weight: bold" in html


def test_no_color_environment_is_respected(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    raw = io.BytesIO()
    console = Console(
        file=io.TextIOWrapper(raw, encoding="utf-8"), force_terminal=True, legacy_windows=False
    )
    ui.print_banner(console)
    console.file.flush()
    assert "38;2;" not in raw.getvalue().decode("utf-8")


def test_ascii_fallback_on_non_utf8_console():
    console, raw = _buffer_console(encoding="cp1252")
    report = run_scan(REPORT)
    ui.print_summary(console, report, [], show_table=True, table_rows=50)
    out = _text(console, raw, "cp1252")
    assert "=== SCAN REPORT ===" in out.replace("=" * 10, "===")
    assert "#" in out and "\u2588" not in out
    assert ui.spinner_name(console) == "line"


def test_big_number_digits():
    assert ui._big_number(30) == [" _   _ ", " _| | |", " _| |_|"]


# --------------------------------------------------------------------------- CLI screens


def test_bare_lucent_shows_welcome():
    result = runner.invoke(app, [])
    assert result.exit_code == 0
    out = _plain(result.stdout)
    assert BANNER_ROW in out
    assert "QUICK START" in out
    assert "lucent scan --help" in out


def test_help_screens_show_banner():
    for args in (["--help"], ["scan", "--help"]):
        result = runner.invoke(app, args)
        assert result.exit_code == 0
        out = _plain(result.stdout)
        assert BANNER_ROW in out
        assert "Usage:" in out


def test_scan_summary_sections():
    result = runner.invoke(app, ["scan", str(MIXED)])
    assert result.exit_code == 3
    out = _plain(result.stdout)
    assert BANNER_ROW in out
    for marker in ("SCAN REPORT", "FILES", "IOCS", "REJECTED", "WARNINGS", "ERRORS", "ATTENTION", "PARTIAL"):
        assert marker in out
    assert "INDICATORS" in out
    assert "Status: partial" in out.splitlines()[-1]


def test_no_attention_block_when_clean():
    result = runner.invoke(app, ["scan", str(REPORT)])
    out = _plain(result.stdout)
    assert "ATTENTION" not in out
    assert "COMPLETED" in out


def test_banner_goes_to_stderr_with_stdout_output():
    result = runner.invoke(app, ["scan", str(REPORT), "--output", "-"])
    assert result.exit_code == 0
    json.loads(result.stdout)
    assert BANNER_ROW in _plain(result.stderr)


def test_quiet_has_no_banner():
    result = runner.invoke(app, ["scan", str(REPORT), "--quiet"])
    assert result.stdout == "Status: completed\n"


def test_fatal_error_line_is_plain_text_when_not_a_terminal(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path / "missing.txt")])
    assert result.exit_code == 1
    assert result.stderr == "Error: input not found: missing.txt\n"
