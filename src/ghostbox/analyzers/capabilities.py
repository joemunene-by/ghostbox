"""Capability tagging.

Maps imports and string patterns to coarse behavior tags: networking, process
injection, persistence, anti-debug, crypto/ransomware, discovery, and more.
Each tag carries evidence and a weight used by the scorer.
"""

from __future__ import annotations

import re

from ghostbox.analyzers import Analyzer, register
from ghostbox.report import Report

# tag -> (weight, [import names], [case-insensitive string regexes])
_RULES: dict[str, tuple[int, list[str], list[str]]] = {
    "networking": (
        6,
        ["InternetOpenA", "InternetOpenUrlA", "WSASocketA", "connect", "URLDownloadToFileA"],
        [r"https?://", r"\buser-agent\b", r"\bwininet\b", r"\bwinhttp\b"],
    ),
    "process-injection": (
        18,
        [
            "WriteProcessMemory",
            "CreateRemoteThread",
            "CreateRemoteThreadEx",
            "VirtualAllocEx",
            "NtUnmapViewOfSection",
            "SetThreadContext",
        ],
        [r"\bshellcode\b", r"\bhollow", r"\binject"],
    ),
    "persistence": (
        12,
        ["RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA"],
        [
            r"\\currentversion\\run",
            r"\bschtasks\b",
            r"\bstartup\b",
            r"\bservices\\",
        ],
    ),
    "anti-debug": (
        8,
        ["IsDebuggerPresent", "CheckRemoteDebuggerPresent"],
        [r"\bvmware\b", r"\bvirtualbox\b", r"\bsandboxie\b", r"\bollydbg\b"],
    ),
    "crypto-ransomware": (
        14,
        ["CryptEncrypt", "CryptAcquireContextA"],
        [
            r"\.locked\b",
            r"\.encrypted\b",
            r"\bransom\b",
            r"\bbitcoin\b",
            r"\byour files have been encrypted\b",
            r"\bdecrypt\b",
        ],
    ),
    "discovery": (
        4,
        ["GetComputerNameA", "GetUserNameA"],
        [r"\bipconfig\b", r"\bsysteminfo\b", r"\bwhoami\b", r"\bnet view\b"],
    ),
    "process-execution": (
        6,
        ["WinExec", "ShellExecuteA", "ShellExecuteW", "CreateProcessA", "CreateProcessW"],
        [r"\bcmd\.exe\b", r"\bpowershell\b", r"\brundll32\b"],
    ),
    "keylogging": (
        10,
        ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"],
        [r"\bkeylog", r"\[backspace\]", r"\[enter\]"],
    ),
}


class CapabilitiesAnalyzer(Analyzer):
    name = "capabilities"

    def analyze(self, data: bytes, report: Report) -> None:
        all_imports = self._collect_imports(report)
        all_strings = self._collect_strings(report)
        blob = "\n".join(all_strings).lower()

        tags: list[dict] = []
        for tag, (weight, imports, patterns) in _RULES.items():
            evidence: list[str] = []
            for imp in imports:
                if imp in all_imports:
                    evidence.append(f"import:{imp}")
            for pat in patterns:
                if re.search(pat, blob, re.IGNORECASE):
                    evidence.append(f"string:{pat}")
            if evidence:
                tags.append(
                    {"tag": tag, "weight": weight, "evidence": evidence[:6]}
                )

        report.sections[self.name] = {"tags": tags}
        for t in tags:
            report.add_signal(
                f"capability:{t['tag']}",
                t["weight"],
                ", ".join(t["evidence"][:3]),
            )

    @staticmethod
    def _collect_imports(report: Report) -> set[str]:
        imports: set[str] = set()
        pe = report.get("pe")
        if isinstance(pe, dict):
            for funcs in pe.get("imports", {}).values():
                imports.update(funcs)
        elf = report.get("elf")
        if isinstance(elf, dict):
            imports.update(elf.get("dynamic_symbols", []))
        return imports

    @staticmethod
    def _collect_strings(report: Report) -> list[str]:
        full = report.get("_strings_full")
        if isinstance(full, list):
            return full
        section = report.get("strings_ioc")
        if isinstance(section, dict):
            return section.get("strings_sample", [])
        return []


register(CapabilitiesAnalyzer())
