"""Analyzer base class and registry.

Each analyzer subclasses Analyzer and registers itself. The engine runs every
registered analyzer in isolation: a failure in one analyzer is captured as a
warning and never aborts the overall analysis. No analyzer executes the sample;
all work is purely static (reading bytes).
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from ghostbox.report import Report

logger = logging.getLogger("ghostbox")


class Analyzer:
    """Base class for a static analyzer.

    Subclasses set ``name`` and implement ``analyze``. They may inspect prior
    results already attached to the report (analyzers run in registration
    order), and write their own structured output to ``report.sections[name]``.
    """

    name: str = "base"

    def analyze(self, data: bytes, report: Report) -> None:  # pragma: no cover
        raise NotImplementedError


_REGISTRY: list[Analyzer] = []


def register(analyzer: Analyzer) -> Analyzer:
    """Register an analyzer instance, preserving order."""
    _REGISTRY.append(analyzer)
    return analyzer


def registered() -> list[Analyzer]:
    """Return registered analyzers sorted into pipeline order."""
    rank = {name: i for i, name in enumerate(_PIPELINE_ORDER)}
    return sorted(_REGISTRY, key=lambda a: rank.get(a.name, len(rank)))


def reset_registry() -> None:
    """Clear the registry (used by tests)."""
    _REGISTRY.clear()


# Pipeline order: identity first, then file typing, then structural parsers,
# then derived analyzers that consume earlier results, then optional YARA.
_PIPELINE_ORDER = [
    "hashing",
    "filetype",
    "pe",
    "elf",
    "entropy",
    "strings_ioc",
    "capabilities",
    "yara",
]


def autoload() -> None:
    """Import analyzer modules so they self-register, idempotently.

    Module import order does not determine run order: ``registered()`` sorts by
    ``_PIPELINE_ORDER`` so analyzers that consume earlier output (capabilities,
    entropy) always run after their producers.
    """
    if len(_REGISTRY) >= len(_PIPELINE_ORDER):
        return
    from ghostbox.analyzers import (  # noqa: F401
        capabilities,
        elf,
        entropy,
        filetype,
        hashing,
        pe,
        strings_ioc,
        yara_scan,
    )


# Convenience for building analyzers from plain functions in tests.
def from_func(name: str, func: Callable[[bytes, Report], None]) -> Analyzer:
    inst = Analyzer()
    inst.name = name
    inst.analyze = func  # type: ignore[method-assign]
    return inst
