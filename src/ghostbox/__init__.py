"""ghostbox: static malware analysis sandbox for authorized triage.

ghostbox performs SAFE, static-only analysis of suspicious files. It never
executes a sample. It hashes, identifies the file type, parses headers,
extracts imports, strings, and IOCs, computes entropy, applies optional YARA
rules, and produces an explainable threat score.
"""

__version__ = "0.1.0"

from ghostbox.report import Report

__all__ = ["__version__", "Report"]
