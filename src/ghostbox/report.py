"""Report data model shared across analyzers and output formatters."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Signal:
    """A single scored contribution to the threat score."""

    name: str
    weight: int
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "weight": self.weight, "detail": self.detail}


@dataclass
class Report:
    """Aggregated static analysis result for one file."""

    path: str
    size: int = 0
    error: str | None = None
    # Per-analyzer structured output keyed by analyzer name.
    sections: dict[str, Any] = field(default_factory=dict)
    # Scoring.
    signals: list[Signal] = field(default_factory=list)
    score: int = 0
    band: str = "clean"
    # Per-analyzer warnings (non-fatal).
    warnings: list[str] = field(default_factory=list)

    def add_signal(self, name: str, weight: int, detail: str = "") -> None:
        self.signals.append(Signal(name=name, weight=weight, detail=detail))

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def get(self, analyzer: str, default: Any = None) -> Any:
        return self.sections.get(analyzer, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ghostbox_version": _version(),
            "path": self.path,
            "size": self.size,
            "error": self.error,
            "score": self.score,
            "band": self.band,
            "signals": [s.to_dict() for s in self.signals],
            "warnings": list(self.warnings),
            "sections": self.sections,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False, default=str)


def _version() -> str:
    from ghostbox import __version__

    return __version__
