"""Filetype analyzer: magic-byte detection without libmagic.

A compact signature table maps leading (and a few trailing/offset) byte
patterns to a coarse file type. We deliberately avoid native dependencies.
"""

from __future__ import annotations

from ghostbox.analyzers import Analyzer, register
from ghostbox.report import Report

# Each entry: (label, offset, signature bytes).
_MAGIC: list[tuple[str, int, bytes]] = [
    ("pe", 0, b"MZ"),
    ("elf", 0, b"\x7fELF"),
    ("macho", 0, b"\xfe\xed\xfa\xce"),
    ("macho", 0, b"\xfe\xed\xfa\xcf"),
    ("macho", 0, b"\xce\xfa\xed\xfe"),
    ("macho", 0, b"\xcf\xfa\xed\xfe"),
    ("macho", 0, b"\xca\xfe\xba\xbe"),  # fat / universal binary
    ("pdf", 0, b"%PDF-"),
    ("zip", 0, b"PK\x03\x04"),  # also OOXML Office, jar, apk
    ("gzip", 0, b"\x1f\x8b"),
    ("rar", 0, b"Rar!\x1a\x07"),
    ("7z", 0, b"7z\xbc\xaf\x27\x1c"),
    ("ole", 0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"),  # legacy Office / MSI
    ("png", 0, b"\x89PNG\r\n\x1a\n"),
    ("class", 0, b"\xca\xfe\xba\xbe"),  # disambiguated below by mach-o ordering
]

_ARCHIVE_TYPES = {"zip", "gzip", "rar", "7z"}

# Script shebang / interpreter hints when no binary magic matched.
_SCRIPT_SHEBANGS: list[tuple[str, bytes]] = [
    ("sh", b"#!/bin/sh"),
    ("sh", b"#!/bin/bash"),
    ("sh", b"#! /bin/sh"),
    ("py", b"#!/usr/bin/env python"),
    ("py", b"#!/usr/bin/python"),
    ("perl", b"#!/usr/bin/perl"),
    ("php", b"#!/usr/bin/php"),
]


def _looks_ooxml(data: bytes) -> bool:
    # OOXML (docx/xlsx/pptx) is a zip whose archive contains these markers.
    head = data[:4096]
    return b"[Content_Types].xml" in head or b"word/" in head or b"xl/" in head


def _detect_script(data: bytes) -> str | None:
    head = data[:512]
    for label, sig in _SCRIPT_SHEBANGS:
        if head.startswith(sig):
            return label
    sample = head.lower()
    if sample.startswith(b"<?php"):
        return "php"
    if b"powershell" in sample or sample.startswith(b"# powershell"):
        return "ps1"
    if b"<script" in sample or b"function(" in sample or b"var " in sample[:64]:
        return "js"
    if sample.lstrip().startswith(b"import ") or sample.lstrip().startswith(b"def "):
        return "py"
    return None


def _is_mostly_text(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    printable = sum(1 for b in sample if b in (9, 10, 13) or 32 <= b <= 126)
    return printable / len(sample) > 0.90


def detect(data: bytes) -> dict[str, object]:
    """Detect a coarse file type. Returns a dict with type, subtype, description."""
    if not data:
        return {"type": "empty", "subtype": None, "description": "empty file"}

    matched: str | None = None
    for label, offset, sig in _MAGIC:
        if data[offset : offset + len(sig)] == sig:
            matched = label
            break

    if matched == "zip":
        if _looks_ooxml(data):
            return {
                "type": "office",
                "subtype": "ooxml",
                "description": "OOXML Office document (zip container)",
            }
        return {"type": "archive", "subtype": "zip", "description": "ZIP archive"}

    if matched == "ole":
        return {
            "type": "office",
            "subtype": "ole",
            "description": "OLE2 compound document (legacy Office or MSI)",
        }

    if matched in _ARCHIVE_TYPES:
        return {"type": "archive", "subtype": matched, "description": f"{matched} archive"}

    if matched == "pe":
        return {"type": "pe", "subtype": None, "description": "PE (Windows executable)"}
    if matched == "elf":
        return {"type": "elf", "subtype": None, "description": "ELF (Unix executable)"}
    if matched == "macho":
        return {"type": "macho", "subtype": None, "description": "Mach-O (macOS executable)"}
    if matched == "pdf":
        return {"type": "pdf", "subtype": None, "description": "PDF document"}
    if matched == "png":
        return {"type": "image", "subtype": "png", "description": "PNG image"}

    script = _detect_script(data)
    if script is not None:
        return {"type": "script", "subtype": script, "description": f"{script} script"}

    if _is_mostly_text(data):
        return {"type": "text", "subtype": None, "description": "plain text / data"}

    return {"type": "unknown", "subtype": None, "description": "unrecognized binary data"}


class FiletypeAnalyzer(Analyzer):
    name = "filetype"

    def analyze(self, data: bytes, report: Report) -> None:
        result = detect(data)
        report.sections[self.name] = result
        if result["type"] == "office" and result["subtype"] == "ole":
            report.add_signal("ole-office-document", 5, "Legacy OLE document; macro risk")
        if result["type"] == "script" and result["subtype"] in {"ps1", "js", "vbs"}:
            report.add_signal(
                "active-script", 5, f"Active script type: {result['subtype']}"
            )


register(FiletypeAnalyzer())
