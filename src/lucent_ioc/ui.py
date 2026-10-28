"""Terminal presentation: gradient theme, ASCII banner, styled help and scan summary.

Only human-readable output lives here. Report files and `--output -` are never styled.
Rich drops colour automatically when output is not a terminal and honours NO_COLOR.
"""

from __future__ import annotations

from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from typer import rich_utils

from lucent_ioc import __version__
from lucent_ioc.config import IOC_TYPE_ORDER
from lucent_ioc.models import Report

GREEN = "#00e676"
LIME = "#c6ff00"
YELLOW = "#ffd600"
ORANGE = "#ff9100"
RED = "#ff1744"
GRADIENT = (GREEN, LIME, YELLOW, ORANGE, RED)

TYPE_COLORS = dict(zip(IOC_TYPE_ORDER, (GREEN, LIME, YELLOW, "#ffb300", ORANGE, RED), strict=True))
STATUS_COLORS = {"completed": GREEN, "completed_with_warnings": YELLOW, "partial": RED}

_BANNER = r"""
 _        _    _    _____   ______   _   _   _______
| |      | |  | |  / ____| |  ____| | \ | | |__   __|
| |      | |  | | | |      | |__    |  \| |    | |
| |      | |  | | | |      |  __|   | . ` |    | |
| |____  | |__| | | |____  | |____  | |\  |    | |
|______|  \____/   \_____| |______| |_| \_|    |_|
""".strip("\n").splitlines()

_DIGITS = {
    "0": (" _ ", "| |", "|_|"),
    "1": (" ", "|", "|"),
    "2": (" _ ", " _|", "|_ "),
    "3": (" _ ", " _|", " _|"),
    "4": ("   ", "|_|", "  |"),
    "5": (" _ ", "|_ ", " _|"),
    "6": (" _ ", "|_ ", "|_|"),
    "7": (" _ ", "  |", "  |"),
    "8": (" _ ", "|_|", "|_|"),
    "9": (" _ ", "|_|", " _|"),
}


# --------------------------------------------------------------------------- colour helpers


def _rgb(color: str) -> tuple[int, int, int]:
    return int(color[1:3], 16), int(color[3:5], 16), int(color[5:7], 16)


def blend(t: float, stops: tuple[str, ...] = GRADIENT) -> str:
    """Colour at position t (0..1) along the gradient."""
    t = min(max(t, 0.0), 1.0)
    scaled = t * (len(stops) - 1)
    i = min(int(scaled), len(stops) - 2)
    frac = scaled - i
    a, b = _rgb(stops[i]), _rgb(stops[i + 1])
    return "#{:02x}{:02x}{:02x}".format(*(round(x + (y - x) * frac) for x, y in zip(a, b, strict=True)))


def gradient(text: str, *, bold: bool = True, stops: tuple[str, ...] = GRADIENT) -> Text:
    """Text coloured character by character from the first stop to the last."""
    out = Text()
    span = max(len(text) - 1, 1)
    weight = "bold " if bold else ""
    for i, char in enumerate(text):
        out.append(char, style=f"{weight}{blend(i / span, stops)}")
    return out


def _ascii_only(console: Console) -> bool:
    return not console.encoding.lower().startswith("utf")


def _line(console: Console, text: Text) -> None:
    console.print(text, soft_wrap=True)


# --------------------------------------------------------------------------- banner and rules


def banner() -> Text:
    """The LUCENT wordmark with a diagonal green-yellow-orange-red gradient."""
    width = max(len(row) for row in _BANNER)
    height = len(_BANNER)
    out = Text()
    for r, row in enumerate(_BANNER):
        for c, char in enumerate(row.ljust(width)):
            t = 0.85 * c / (width - 1) + 0.15 * r / (height - 1)
            out.append(char, style=f"bold {blend(t)}")
        out.append("\n")
    out.append_text(gradient(f" v{__version__}  |  offline IOC extraction  |  syntax only  |  no network"))
    return out


def print_banner(console: Console) -> None:
    console.print()
    console.print(banner(), soft_wrap=True)
    console.print()


def rule(console: Console, title: str, color: str | None = None) -> None:
    """A full-width heavy rule with a solid label; gradient when no colour is given."""
    char = "=" if _ascii_only(console) else "━"
    label = f" {title} "
    width = max(console.width, len(label) + 4)
    left = (width - len(label)) // 2
    right = width - left - len(label)
    if color:
        line = Text.assemble(
            (char * left, f"bold {color}"), (label, f"bold black on {color}"), (char * right, f"bold {color}")
        )
    else:
        line = gradient(char * left)
        line.append(label, style=f"bold black on {blend(0.5)}")
        line.append_text(gradient(char * right, stops=(YELLOW, ORANGE, RED)))
    _line(console, line)


def help_console() -> Console:
    """A console configured like Typer's own help console."""
    return Console(
        color_system=rich_utils.COLOR_SYSTEM,
        force_terminal=rich_utils.FORCE_TERMINAL,
        width=rich_utils.MAX_WIDTH,
    )


def apply_help_theme() -> None:
    """Restyle Typer's rich help and error panels with the Lucent palette."""
    rich_utils.STYLE_OPTION = f"bold {LIME}"
    rich_utils.STYLE_SWITCH = f"bold {GREEN}"
    rich_utils.STYLE_NEGATIVE_OPTION = f"bold {ORANGE}"
    rich_utils.STYLE_NEGATIVE_SWITCH = f"bold {RED}"
    rich_utils.STYLE_TYPES = f"bold {ORANGE}"
    rich_utils.STYLE_TYPES_SEPARATOR = YELLOW
    rich_utils.STYLE_USAGE = f"bold {YELLOW}"
    rich_utils.STYLE_USAGE_COMMAND = "bold"
    rich_utils.STYLE_HELPTEXT_FIRST_LINE = f"bold {GREEN}"
    rich_utils.STYLE_HELPTEXT = ""
    rich_utils.STYLE_OPTION_HELP = ""
    rich_utils.STYLE_OPTION_DEFAULT = f"bold {YELLOW}"
    rich_utils.STYLE_REQUIRED_SHORT = f"bold {RED}"
    rich_utils.STYLE_REQUIRED_LONG = f"bold {RED}"
    rich_utils.STYLE_OPTIONS_PANEL_BORDER = f"bold {ORANGE}"
    rich_utils.STYLE_COMMANDS_PANEL_BORDER = f"bold {GREEN}"
    rich_utils.STYLE_COMMANDS_TABLE_FIRST_COLUMN = f"bold {LIME}"
    rich_utils.STYLE_ERRORS_PANEL_BORDER = f"bold {RED}"
    rich_utils.STYLE_ERRORS_SUGGESTION = f"bold {YELLOW}"
    rich_utils.STYLE_ABORTED = f"bold {RED}"
    rich_utils.RICH_HELP = "Try [bold " + YELLOW + "]'{command_path} {help_option}'[/] for help."


# --------------------------------------------------------------------------- simple lines


def print_version(console: Console) -> None:
    line = gradient("lucent", stops=(GREEN, YELLOW))
    line.append(f" {__version__}", style=f"bold {ORANGE}")
    _line(console, line)


def print_fatal(console: Console, message: str) -> None:
    _line(console, Text.assemble(("Error:", f"bold {RED}"), (f" {message}", "bold")))


def print_file_event(console: Console, rel: str, failed: bool) -> None:
    if failed:
        _line(console, Text.assemble(("Failed: ", f"bold {RED}"), (rel, "bold")))
    else:
        _line(console, Text.assemble(("Processed: ", f"bold {GREEN}"), (rel, "bold")))


def print_welcome(console: Console) -> None:
    """Shown for a bare `lucent`."""
    print_banner(console)
    examples = Table.grid()
    rows = [
        ("lucent scan samples/incident_report.txt", "summary and IOC table in the terminal"),
        ("lucent scan FILE --output -", "JSON report on stdout"),
        ("lucent scan DIR --recursive --format both --output-dir reports/", "JSON + CSV files"),
        ("lucent scan --help", "every option"),
    ]
    for i, (command, what) in enumerate(rows):
        color = blend(i / (len(rows) - 1))
        examples.add_row(Text.assemble(("> ", f"bold {color}"), (command, f"bold {color}")))
        examples.add_row(Text(f"    {what}", style=f"italic {color}"))
    intro = Text.assemble(
        ("Extracts ", ""),
        ("potential", f"bold {YELLOW}"),
        (" IOCs from reports and logs, validates syntax, keeps provenance.\n", ""),
        ("Offline. No lookups. Never judges reputation.", f"bold {ORANGE}"),
    )
    body = Table.grid()
    body.add_row(intro)
    body.add_row("")
    body.add_row(Text("QUICK START", style=f"bold black on {LIME}"))
    body.add_row(examples)
    console.print(
        Panel(body, box=box.HEAVY, border_style=f"bold {ORANGE}", title=gradient(" WELCOME "), padding=(1, 2))
    )


# --------------------------------------------------------------------------- scan summary


def _big_number(value: int) -> list[str]:
    """Three-row seven-segment ASCII digits."""
    return [" ".join(_DIGITS[d][r] for d in str(value)) for r in range(3)]


def _card(label: str, value: int, color: str, note: str | None = None) -> Panel:
    rows = _big_number(value)
    inner = max(len(label) + 4, len(rows[0]), len(note or "") + 4)
    digits = Text("\n".join(row.center(inner) for row in rows), style=f"bold {color}")
    return Panel(
        digits,
        title=Text(label, style=f"bold black on {color}"),
        subtitle=Text(note, style=f"bold {color}") if note else None,
        box=box.HEAVY,
        border_style=f"bold {color}",
        width=inner + 4,
        padding=(0, 1),
    )


def _cards(report: Report) -> Columns:
    f = report.scan.files
    summary = report.summary
    return Columns(
        [
            _card("FILES", f.processed, GREEN, f"of {f.discovered}"),
            _card("IOCS", summary.total_unique_iocs, LIME, "unique"),
            _card("REJECTED", summary.rejected_candidates.total, YELLOW),
            _card("WARNINGS", len(report.warnings), ORANGE),
            _card("ERRORS", len(report.errors), RED),
        ],
        padding=(0, 1),
    )


def _type_bars(console: Console, report: Report) -> Table:
    full, empty = ("#", ".") if _ascii_only(console) else ("█", "░")
    by_type = report.summary.by_type
    top = max(by_type.values()) or 1
    bars = Table.grid(padding=(0, 1))
    for ioc_type, count in by_type.items():
        color = TYPE_COLORS[ioc_type]
        length = max(1, round(28 * count / top)) if count else 0
        bars.add_row(
            Text(f"{ioc_type:>7}", style=f"bold {color}"),
            Text.assemble((full * length, f"bold {color}"), (empty * (28 - length), "grey30")),
            Text(str(count), style=f"bold {color}"),
        )
    return bars


def _ioc_table(report: Report, limit: int) -> Table:
    table = Table(
        box=box.HEAVY_HEAD,
        border_style=f"bold {ORANGE}",
        header_style="bold",
        title=gradient("INDICATORS"),
        title_justify="left",
    )
    table.add_column(Text("type", style=f"bold {GREEN}"))
    table.add_column(Text("occurrences", style=f"bold {YELLOW}"), justify="right")
    table.add_column(Text("sources", style=f"bold {ORANGE}"), justify="right")
    table.add_column(Text("value", style=f"bold {RED}"), overflow="fold")
    for ioc in report.iocs[:limit]:
        color = TYPE_COLORS[ioc.type.value]
        table.add_row(
            Text(ioc.type.value, style=f"bold {color}"),
            Text(str(ioc.occurrences), style=f"bold {YELLOW}"),
            Text(str(ioc.source_count), style=f"bold {ORANGE}"),
            Text(ioc.value, style="bold"),
        )
    return table


def _kv(label: str, value: str, color: str) -> Text:
    return Text.assemble(("  ", ""), (f"{label}: ", f"bold {color}"), (value, "bold"))


def print_status(console: Console, status: str) -> None:
    _line(console, Text.assemble(("Status: ", "bold"), (status, f"bold {STATUS_COLORS[status]}")))


def print_summary(
    console: Console,
    report: Report,
    written: list,
    *,
    show_table: bool,
    table_rows: int,
) -> None:
    """The full scan summary (everything except --quiet)."""
    scan, summary = report.scan, report.summary
    f = scan.files
    rej = summary.rejected_candidates
    by_type = ", ".join(f"{t} {n}" for t, n in summary.by_type.items())
    reasons = ", ".join(f"{r} {n}" for r, n in rej.by_reason.items())

    rule(console, "SCAN REPORT")
    _line(console, _kv("Input", scan.input, GREEN))
    _line(
        console,
        _kv(
            "Files",
            f"discovered {f.discovered}, processed {f.processed}, skipped {f.skipped}, failed {f.failed}",
            LIME,
        ),
    )
    _line(console, _kv("IOCs", f"{summary.total_unique_iocs} unique ({by_type})", YELLOW))
    _line(console, _kv("Rejected candidates", f"{rej.total}" + (f" ({reasons})" if reasons else ""), ORANGE))
    console.print()
    console.print(_cards(report))
    console.print()
    console.print(_type_bars(console, report))

    if report.warnings or report.errors:
        console.print()
        rule(console, "ATTENTION", ORANGE if not report.errors else RED)
    for w in report.warnings:
        _line(console, Text.assemble(("Warning", f"bold {ORANGE}"), (f" [{w.code}]: ", ORANGE), (w.message, "bold")))
    for e in report.errors:
        _line(
            console,
            Text.assemble(("Error", f"bold {RED}"), (f" [{e.stage}] {e.error_type}: ", RED), (e.message, "bold")),
        )

    if show_table and report.iocs:
        console.print()
        console.print(_ioc_table(report, table_rows))
        if len(report.iocs) > table_rows:
            _line(console, Text(f"showing {table_rows} of {len(report.iocs)}", style=f"bold {YELLOW}"))

    if written:
        console.print()
    for path in written:
        _line(console, Text.assemble(("Output: ", f"bold {GREEN}"), (str(path), "bold")))
    console.print()
    status = scan.status.value
    rule(console, status.replace("_", " ").upper(), STATUS_COLORS[status])
    print_status(console, status)


def print_quiet(console: Console, report: Report) -> None:
    """--quiet: per-file errors and the final status line only."""
    for e in report.errors:
        _line(
            console,
            Text.assemble(("Error", f"bold {RED}"), (f" [{e.stage}] {e.error_type}: ", RED), (e.message, "bold")),
        )
    print_status(console, report.scan.status.value)


def spinner_name(console: Console) -> str:
    """Braille spinner on UTF-8 consoles, plain ASCII elsewhere."""
    return "line" if _ascii_only(console) else "dots12"


def scanning_label(count: int, rel: str | None = None) -> Text:
    text = gradient("Scanning", stops=(GREEN, YELLOW))
    text.append(f"  {count} file{'s' if count != 1 else ''} read", style=f"bold {ORANGE}")
    if rel:
        text.append(f"  {rel}", style="bold")
    return text
