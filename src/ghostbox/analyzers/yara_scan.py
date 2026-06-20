"""Optional YARA scanning.

If ``yara-python`` is importable and a rules directory is configured, compile
every ``.yar`` / ``.yara`` file and report matches. If the library is missing,
the feature gates off cleanly and records a note rather than failing.
"""

from __future__ import annotations

from pathlib import Path

from ghostbox.analyzers import Analyzer, register
from ghostbox.report import Report


def yara_available() -> bool:
    try:
        import yara  # type: ignore  # noqa: F401

        return True
    except ImportError:
        return False


def compile_rules(yara_dir: str):
    """Compile all rule files under yara_dir. Returns a compiled rules object or None."""
    try:
        import yara  # type: ignore
    except ImportError:
        return None
    directory = Path(yara_dir)
    if not directory.is_dir():
        return None
    filepaths: dict[str, str] = {}
    for path in sorted(directory.rglob("*")):
        if path.suffix.lower() in {".yar", ".yara"} and path.is_file():
            filepaths[path.stem] = str(path)
    if not filepaths:
        return None
    try:
        return yara.compile(filepaths=filepaths)
    except Exception:
        return None


def list_rules(yara_dir: str) -> list[str]:
    """Return the names of rule files that would be loaded from yara_dir."""
    directory = Path(yara_dir)
    if not directory.is_dir():
        return []
    names = []
    for path in sorted(directory.rglob("*")):
        if path.suffix.lower() in {".yar", ".yara"} and path.is_file():
            names.append(path.name)
    return names


class YaraAnalyzer(Analyzer):
    name = "yara"

    def __init__(self, yara_dir: str | None = None) -> None:
        self.yara_dir = yara_dir
        self._compiled = None

    def configure(self, yara_dir: str | None) -> None:
        self.yara_dir = yara_dir
        self._compiled = None

    def analyze(self, data: bytes, report: Report) -> None:
        if not self.yara_dir:
            report.sections[self.name] = {"enabled": False, "reason": "no rules directory"}
            return
        if not yara_available():
            report.sections[self.name] = {
                "enabled": False,
                "reason": "yara-python not installed",
            }
            return
        if self._compiled is None:
            self._compiled = compile_rules(self.yara_dir)
        if self._compiled is None:
            report.sections[self.name] = {
                "enabled": False,
                "reason": "no compilable rules found",
            }
            return

        try:
            matches = self._compiled.match(data=data)
        except Exception as exc:  # defensive: malformed scan input
            report.add_warning(f"yara: scan failed ({exc})")
            report.sections[self.name] = {"enabled": True, "matches": []}
            return

        match_info = []
        for m in matches:
            match_info.append(
                {
                    "rule": m.rule,
                    "namespace": getattr(m, "namespace", ""),
                    "tags": list(getattr(m, "tags", []) or []),
                }
            )
        report.sections[self.name] = {"enabled": True, "matches": match_info}
        if match_info:
            report.add_signal(
                "yara-match",
                min(20 + 5 * len(match_info), 40),
                "YARA rules matched: " + ", ".join(sorted({m["rule"] for m in match_info})),
            )


register(YaraAnalyzer())
