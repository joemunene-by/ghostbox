"""Threat scoring.

Aggregates the weighted signals collected by analyzers into a 0-100 score and a
band (clean / suspicious / malicious). The score is explainable: every
contributing signal is retained on the report.
"""

from __future__ import annotations

from ghostbox.report import Report

SUSPICIOUS_THRESHOLD = 25
MALICIOUS_THRESHOLD = 60


def band_for(score: int) -> str:
    if score >= MALICIOUS_THRESHOLD:
        return "malicious"
    if score >= SUSPICIOUS_THRESHOLD:
        return "suspicious"
    return "clean"


def finalize_score(report: Report) -> None:
    """Sum signal weights, clamp to 0-100, and set the band."""
    total = sum(max(s.weight, 0) for s in report.signals)
    report.score = max(0, min(total, 100))
    report.band = band_for(report.score)
