"""Analysis engine.

Reads a file (never executes it), runs every registered analyzer in isolation,
applies optional configuration (max strings, YARA directory), then finalizes the
threat score. A failure in any single analyzer is captured as a warning and does
not abort the analysis.
"""

from __future__ import annotations

import logging
from pathlib import Path

from ghostbox import analyzers
from ghostbox.analyzers.strings_ioc import StringsIOCAnalyzer
from ghostbox.analyzers.yara_scan import YaraAnalyzer
from ghostbox.report import Report
from ghostbox.scoring import finalize_score

logger = logging.getLogger("ghostbox")

MAX_READ_BYTES = 256 * 1024 * 1024  # 256 MB safety cap


def analyze_bytes(
    data: bytes,
    path: str = "<bytes>",
    *,
    yara_dir: str | None = None,
    max_strings: int = 2000,
) -> Report:
    """Run the full static analysis pipeline over raw bytes."""
    analyzers.autoload()
    report = Report(path=path, size=len(data))

    for analyzer in analyzers.registered():
        try:
            _configure(analyzer, yara_dir=yara_dir, max_strings=max_strings)
            analyzer.analyze(data, report)
        except Exception as exc:  # per-analyzer isolation
            logger.exception("analyzer %s failed", analyzer.name)
            report.add_warning(f"{analyzer.name}: analyzer raised {type(exc).__name__}: {exc}")

    # Internal scratch keys are not part of the public report.
    report.sections.pop("_strings_full", None)

    finalize_score(report)
    return report


def analyze_file(
    path: str | Path,
    *,
    yara_dir: str | None = None,
    max_strings: int = 2000,
) -> Report:
    """Read a file from disk and analyze it. Never executes the file."""
    p = Path(path)
    report = Report(path=str(p))
    try:
        size = p.stat().st_size
    except OSError as exc:
        report.error = f"cannot stat file: {exc}"
        return report

    if size > MAX_READ_BYTES:
        report.error = f"file too large ({size} bytes); refusing to load into memory"
        report.size = size
        return report

    try:
        data = p.read_bytes()
    except OSError as exc:
        report.error = f"cannot read file: {exc}"
        return report

    return analyze_bytes(data, path=str(p), yara_dir=yara_dir, max_strings=max_strings)


def _configure(analyzer: analyzers.Analyzer, *, yara_dir: str | None, max_strings: int) -> None:
    if isinstance(analyzer, StringsIOCAnalyzer):
        analyzer.max_strings = max_strings
    if isinstance(analyzer, YaraAnalyzer):
        analyzer.configure(yara_dir)
