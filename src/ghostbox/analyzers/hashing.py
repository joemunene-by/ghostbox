"""Hashing analyzer: md5, sha1, sha256, and file size."""

from __future__ import annotations

import hashlib

from ghostbox.analyzers import Analyzer, register
from ghostbox.report import Report


class HashingAnalyzer(Analyzer):
    name = "hashing"

    def analyze(self, data: bytes, report: Report) -> None:
        report.sections[self.name] = {
            "md5": hashlib.md5(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }


register(HashingAnalyzer())
