"""ghostbox command-line interface.

SAFETY: ghostbox performs static analysis only. It never executes any sample.
Use only on files you are authorized to analyze.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console

from ghostbox import __version__
from ghostbox.analyzers.yara_scan import list_rules, yara_available
from ghostbox.engine import analyze_file
from ghostbox.output import render_console
from ghostbox.utils import configure_logging

app = typer.Typer(
    add_completion=False,
    help="Static malware analysis sandbox for authorized triage (static analysis only).",
    no_args_is_help=True,
)

_console = Console()
_err_console = Console(stderr=True)

_SCANNABLE_SUFFIX_SKIP = {".pyc"}


def _emit(report, fmt: str, output: str | None) -> None:
    if fmt == "json":
        text = report.to_json()
        if output:
            Path(output).write_text(text, encoding="utf-8")
            _err_console.print(f"[green]wrote JSON report to {output}[/green]")
        else:
            print(text)
    else:
        target_console = Console(file=open(output, "w", encoding="utf-8")) if output else _console
        render_console(report, target_console)
        if output:
            target_console.file.close()
            _err_console.print(f"[green]wrote console report to {output}[/green]")


@app.command()
def analyze(
    file: Path = typer.Argument(..., exists=False, help="File to analyze (never executed)."),
    fmt: str = typer.Option("console", "--format", help="Output format: console or json."),
    yara_dir: str | None = typer.Option(None, "--yara-dir", help="Directory of YARA rules."),
    output: str | None = typer.Option(None, "--output", help="Write report to this path."),
    max_strings: int = typer.Option(2000, "--max-strings", help="Cap on extracted strings."),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose logging."),
) -> None:
    """Analyze a single file."""
    configure_logging(verbose)
    if not file.exists():
        _err_console.print(f"[red]error:[/red] no such file: {file}")
        raise typer.Exit(code=2)
    if not file.is_file():
        _err_console.print(f"[red]error:[/red] not a regular file: {file}")
        raise typer.Exit(code=2)

    report = analyze_file(file, yara_dir=yara_dir, max_strings=max_strings)
    _emit(report, fmt, output)
    raise typer.Exit(code=0)


@app.command()
def scan(
    directory: Path = typer.Argument(..., help="Directory to scan recursively."),
    fmt: str = typer.Option("console", "--format", help="Output format: console or json."),
    yara_dir: str | None = typer.Option(None, "--yara-dir", help="Directory of YARA rules."),
    min_score: int = typer.Option(0, "--min-score", help="Only report files at or above score."),
    output: str | None = typer.Option(None, "--output", help="Write JSON results to path."),
    max_strings: int = typer.Option(2000, "--max-strings", help="Cap on extracted strings."),
    verbose: bool = typer.Option(False, "--verbose", help="Verbose logging."),
) -> None:
    """Recursively scan a directory, analyzing each regular file."""
    configure_logging(verbose)
    if not directory.is_dir():
        _err_console.print(f"[red]error:[/red] not a directory: {directory}")
        raise typer.Exit(code=2)

    results = []
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        if path.suffix.lower() in _SCANNABLE_SUFFIX_SKIP:
            continue
        report = analyze_file(path, yara_dir=yara_dir, max_strings=max_strings)
        if report.error is None and report.score < min_score:
            continue
        results.append(report)

    if fmt == "json":
        payload = json.dumps([r.to_dict() for r in results], indent=2, default=str)
        if output:
            Path(output).write_text(payload, encoding="utf-8")
            _err_console.print(f"[green]wrote {len(results)} result(s) to {output}[/green]")
        else:
            print(payload)
    else:
        if not results:
            _console.print("[green]no files met the reporting threshold[/green]")
        for report in results:
            render_console(report, _console)
            _console.rule()
        _console.print(
            f"[bold]scanned directory:[/bold] {directory}  "
            f"[bold]reported:[/bold] {len(results)} file(s)"
        )
    raise typer.Exit(code=0)


@app.command()
def rules(
    yara_dir: str | None = typer.Option(None, "--yara-dir", help="Directory of YARA rules."),
) -> None:
    """List YARA rule files that would be loaded."""
    if not yara_available():
        _console.print("[yellow]yara-python is not installed; YARA scanning is disabled.[/yellow]")
        _console.print("Install with: pip install 'ghostbox[yara]'")
    if not yara_dir:
        _console.print("No --yara-dir provided. Pass a directory of .yar/.yara files.")
        raise typer.Exit(code=0)
    names = list_rules(yara_dir)
    if not names:
        _console.print(f"No rule files found under {yara_dir}")
    else:
        _console.print(f"[bold]Rule files in {yara_dir}:[/bold]")
        for n in names:
            _console.print(f"  - {n}")
    raise typer.Exit(code=0)


@app.command()
def version() -> None:
    """Print the ghostbox version."""
    _console.print(f"ghostbox {__version__}")
    raise typer.Exit(code=0)


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(app())
