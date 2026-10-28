"""Typer command-line interface for Lucent."""

from __future__ import annotations

import contextlib
import sys
import traceback
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.text import Text
from typer.core import TyperCommand, TyperGroup

from lucent_ioc import ui
from lucent_ioc.config import (
    BYTES_PER_MB,
    DEFAULT_MAX_FILE_SIZE_MB,
    DEFAULT_MAX_FILES,
    DEFAULT_MAX_SOURCES_PER_IOC,
    EXIT_FATAL,
    EXIT_OK,
    EXIT_PARTIAL,
    OUTPUT_CSV_NAME,
    OUTPUT_JSON_NAME,
    TERMINAL_TABLE_ROWS,
)
from lucent_ioc.exporters import render, write_atomic, write_stdout
from lucent_ioc.models import LucentFatalError, ScanStatus
from lucent_ioc.pipeline import run_scan

ui.apply_help_theme()


class _BannerGroup(TyperGroup):
    def format_help(self, ctx, formatter) -> None:
        ui.print_banner(ui.help_console())
        super().format_help(ctx, formatter)


class _BannerCommand(TyperCommand):
    def format_help(self, ctx, formatter) -> None:
        ui.print_banner(ui.help_console())
        super().format_help(ctx, formatter)


app = typer.Typer(
    name="lucent",
    cls=_BannerGroup,
    help="Offline extraction of potential IOCs from reports and logs.",
    add_completion=False,
)


class OutputFormat(str, Enum):
    json = "json"
    csv = "csv"
    both = "both"


def _stdout_console() -> Console:
    return Console(file=sys.stdout, highlight=False)


def _stderr_console() -> Console:
    return Console(file=sys.stderr, highlight=False)


def _version_callback(value: bool) -> None:
    if value:
        ui.print_version(_stdout_console())
        raise typer.Exit(EXIT_OK)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Lucent extracts, validates, normalizes and deduplicates potential IOCs."""
    if ctx.invoked_subcommand is None:
        ui.print_welcome(_stdout_console())


def _fatal(message: str) -> typer.Exit:
    ui.print_fatal(_stderr_console(), message)
    return typer.Exit(EXIT_FATAL)


def _check_options(
    fmt: str, output: str | None, output_dir: Path | None, verbose: bool, quiet: bool
) -> None:
    """Option rules of §B10.2 that are usage errors (exit 2)."""
    if verbose and quiet:
        raise typer.BadParameter("--verbose and --quiet cannot be used together.")
    if output is not None and output_dir is not None:
        raise typer.BadParameter("--output and --output-dir cannot be used together.")
    if fmt == "both" and output is not None:
        raise typer.BadParameter("--format both cannot be used with --output; use --output-dir.")
    if fmt == "both" and output_dir is None:
        raise typer.BadParameter("--format both requires --output-dir.")
    if fmt == "csv" and output is None and output_dir is None:
        raise typer.BadParameter("--format csv requires --output or --output-dir.")


def _targets(fmt: str, output: str | None, output_dir: Path | None) -> list[tuple[str, Path]]:
    """(format, path) pairs for file outputs. Empty for terminal-only or stdout."""
    if output_dir is not None:
        formats = ["json", "csv"] if fmt == "both" else [fmt]
        names = {"json": OUTPUT_JSON_NAME, "csv": OUTPUT_CSV_NAME}
        return [(f, output_dir / names[f]) for f in formats]
    if output is not None and output != "-":
        return [(fmt, Path(output))]
    return []


@app.command(cls=_BannerCommand)
def scan(
    input_path: Annotated[
        Path, typer.Argument(metavar="INPUT", help="File or directory to scan.")
    ],
    recursive: Annotated[
        bool, typer.Option("--recursive", help="Descend into subdirectories.")
    ] = False,
    fmt: Annotated[
        OutputFormat | None,
        typer.Option("--format", help="Output format: json (default), csv or both."),
    ] = None,
    output: Annotated[
        str | None,
        typer.Option("--output", metavar="FILE", help="Write one format to FILE, or '-' for stdout."),
    ] = None,
    output_dir: Annotated[
        Path | None,
        typer.Option(
            "--output-dir", metavar="DIR", help="Write lucent_iocs.json / lucent_iocs.csv here."
        ),
    ] = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing output files.")] = False,
    strict: Annotated[
        bool, typer.Option("--strict", help="Exit 3 if the scan produced any warning.")
    ] = False,
    max_file_size: Annotated[
        int, typer.Option("--max-file-size", metavar="MB", min=1, help="Per-file size limit in MB.")
    ] = DEFAULT_MAX_FILE_SIZE_MB,
    max_files: Annotated[
        int, typer.Option("--max-files", metavar="N", min=1, help="Maximum files per scan.")
    ] = DEFAULT_MAX_FILES,
    max_sources_per_ioc: Annotated[
        int,
        typer.Option(
            "--max-sources-per-ioc", metavar="N", min=1, help="Sources stored per IOC."
        ),
    ] = DEFAULT_MAX_SOURCES_PER_IOC,
    allow_ambiguous_tlds: Annotated[
        bool,
        typer.Option(
            "--allow-ambiguous-tlds",
            help="Accept bare domains whose TLD is also a file extension (e.g. .zip).",
        ),
    ] = False,
    verbose: Annotated[
        bool, typer.Option("--verbose", help="Show each file and full per-file tracebacks.")
    ] = False,
    quiet: Annotated[
        bool, typer.Option("--quiet", help="Show only errors and the final status.")
    ] = False,
) -> None:
    """Scan INPUT for potential IOCs."""
    fmt_value = (fmt or OutputFormat.json).value
    _check_options(fmt_value, output, output_dir, verbose, quiet)
    to_stdout = output == "-"
    console = _stderr_console() if to_stdout else _stdout_console()
    if not quiet:
        ui.print_banner(console)

    # A live spinner only on a real terminal; verbose lines print above it.
    spinner = (
        console.status(
            ui.scanning_label(0), spinner=ui.spinner_name(console), spinner_style=f"bold {ui.LIME}"
        )
        if console.is_terminal and not quiet
        else None
    )
    read = 0

    def on_file(rel: str, exc: BaseException | None) -> None:
        nonlocal read
        read += 1
        if spinner is not None:
            spinner.update(ui.scanning_label(read, rel))
        if not verbose:
            return
        ui.print_file_event(console, rel, failed=exc is not None)
        if exc is not None:
            console.print(Text("".join(traceback.format_exception(exc))), soft_wrap=True)

    targets = _targets(fmt_value, output, output_dir)
    excluded = [p.resolve() for _, p in targets]
    if output_dir is not None:
        excluded.append(output_dir.resolve())

    # Path conflicts (§B12.1). Directory scans never discover output paths, so only an
    # explicit single input file can collide with an output target.
    if input_path.is_file():
        input_resolved = input_path.resolve()
        for _, path in targets:
            if path.resolve() == input_resolved:
                raise _fatal(f"output path {path} is the input file")
    if not force:
        for _, path in targets:
            if path.exists():
                raise _fatal(f"output file {path} already exists (use --force to overwrite)")

    try:
        with spinner if spinner is not None else contextlib.nullcontext():
            report = run_scan(
                input_path,
                recursive=recursive,
                strict=strict,
                allow_ambiguous_tlds=allow_ambiguous_tlds,
                max_file_size_bytes=max_file_size * BYTES_PER_MB,
                max_files=max_files,
                max_sources_per_ioc=max_sources_per_ioc,
                excluded_paths=excluded,
                on_file=on_file,
            )
    except LucentFatalError as exc:
        raise _fatal(str(exc)) from None

    written: list[Path] = []
    export_failures = 0
    if to_stdout:
        write_stdout(render(report, fmt_value))
    for target_fmt, path in targets:
        try:
            write_atomic(path, render(report, target_fmt))
            written.append(path)
        except OSError as exc:
            export_failures += 1
            reason = exc.strerror or type(exc).__name__
            ui.print_fatal(_stderr_console(), f"could not write {path}: {reason}")

    if quiet:
        ui.print_quiet(console, report)
    else:
        ui.print_summary(
            console,
            report,
            written,
            show_table=not targets and not to_stdout,
            table_rows=TERMINAL_TABLE_ROWS,
        )

    if targets and export_failures == len(targets):
        raise typer.Exit(EXIT_FATAL)
    if export_failures or report.scan.status is ScanStatus.partial:
        raise typer.Exit(EXIT_PARTIAL)
    if strict and report.warnings:
        raise typer.Exit(EXIT_PARTIAL)
    raise typer.Exit(EXIT_OK)
