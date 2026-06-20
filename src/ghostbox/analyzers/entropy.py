"""Entropy and packer heuristics.

Computes whole-file Shannon entropy, summarizes per-section entropy from any
PE/ELF parser output, and applies simple packer heuristics (UPX section names,
uniformly high entropy).
"""

from __future__ import annotations

from ghostbox.analyzers import Analyzer, register
from ghostbox.report import Report
from ghostbox.utils import shannon_entropy

# Section-name substrings that strongly indicate a known packer.
_PACKER_SECTIONS = {
    "upx": "UPX",
    "upx0": "UPX",
    "upx1": "UPX",
    ".aspack": "ASPack",
    ".adata": "ASPack",
    ".nsp": "NsPack",
    "petite": "Petite",
    ".themida": "Themida",
    ".vmp": "VMProtect",
    ".enigma": "Enigma",
    "mpress": "MPRESS",
}

HIGH_ENTROPY = 7.2


class EntropyAnalyzer(Analyzer):
    name = "entropy"

    def analyze(self, data: bytes, report: Report) -> None:
        overall = round(shannon_entropy(data), 3)
        result: dict[str, object] = {"overall": overall, "high_entropy_sections": []}

        packers: set[str] = set()
        high_sections: list[dict] = []

        for parser in ("pe", "elf"):
            parsed = report.get(parser)
            if not isinstance(parsed, dict):
                continue
            for section in parsed.get("sections", []):
                name = str(section.get("name", "")).lower().strip()
                ent = float(section.get("entropy", 0.0) or 0.0)
                if name in _PACKER_SECTIONS:
                    packers.add(_PACKER_SECTIONS[name])
                if ent >= HIGH_ENTROPY and (section.get("raw_size") or section.get("size")):
                    high_sections.append({"name": section.get("name"), "entropy": ent})

        result["high_entropy_sections"] = high_sections
        result["packers"] = sorted(packers)
        report.sections[self.name] = result

        if packers:
            report.add_signal(
                "known-packer", 15, "Packer section names: " + ", ".join(sorted(packers))
            )
        if overall >= HIGH_ENTROPY and len(data) > 1024:
            report.add_signal(
                "high-overall-entropy",
                10,
                f"Whole-file entropy {overall} suggests packing or encryption",
            )
        elif high_sections:
            report.add_signal(
                "high-section-entropy",
                8,
                f"{len(high_sections)} high-entropy section(s)",
            )


register(EntropyAnalyzer())
