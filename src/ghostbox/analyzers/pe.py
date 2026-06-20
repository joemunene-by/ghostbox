"""PE analyzer.

Parses DOS and NT headers, sections, and imports. Uses ``pefile`` when it is
importable, otherwise falls back to a compact built-in parser that handles the
common 32/64-bit cases. All parsing is defensive: truncated or malformed input
produces a warning rather than an exception.
"""

from __future__ import annotations

import struct

from ghostbox.analyzers import Analyzer, register
from ghostbox.report import Report
from ghostbox.utils import shannon_entropy

# Imports commonly abused by malware, mapped to a short reason.
SUSPICIOUS_IMPORTS: dict[str, str] = {
    "VirtualAlloc": "memory allocation for shellcode",
    "VirtualAllocEx": "remote memory allocation (injection)",
    "VirtualProtect": "changing memory protection (RWX)",
    "WriteProcessMemory": "writing into another process (injection)",
    "ReadProcessMemory": "reading another process memory",
    "CreateRemoteThread": "remote thread creation (injection)",
    "CreateRemoteThreadEx": "remote thread creation (injection)",
    "NtUnmapViewOfSection": "process hollowing",
    "SetWindowsHookExA": "API hooking / keylogging",
    "SetWindowsHookExW": "API hooking / keylogging",
    "GetAsyncKeyState": "keylogging",
    "GetKeyState": "keylogging",
    "LoadLibraryA": "dynamic library loading",
    "LoadLibraryW": "dynamic library loading",
    "GetProcAddress": "dynamic API resolution",
    "WinExec": "process execution",
    "ShellExecuteA": "process execution",
    "ShellExecuteW": "process execution",
    "CreateProcessA": "process execution",
    "CreateProcessW": "process execution",
    "InternetOpenA": "network access (WinINet)",
    "InternetOpenUrlA": "network download",
    "URLDownloadToFileA": "network download to disk",
    "URLDownloadToFileW": "network download to disk",
    "WSASocketA": "raw sockets",
    "connect": "network connection",
    "RegSetValueExA": "registry persistence",
    "RegSetValueExW": "registry persistence",
    "RegCreateKeyExA": "registry persistence",
    "IsDebuggerPresent": "anti-debugging",
    "CheckRemoteDebuggerPresent": "anti-debugging",
    "CryptEncrypt": "encryption (possible ransomware)",
    "CryptAcquireContextA": "crypto context",
    "CreateMutexA": "mutex (single-instance / coordination)",
    "CreateMutexW": "mutex (single-instance / coordination)",
}


def _parse_with_pefile(data: bytes) -> dict | None:
    try:
        import pefile  # type: ignore
    except ImportError:
        return None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
    except Exception:  # pefile raises its own exception types
        return None

    is_64 = pe.FILE_HEADER.Machine == 0x8664 or hasattr(pe, "OPTIONAL_HEADER") and bool(
        getattr(pe.OPTIONAL_HEADER, "Magic", 0) == 0x20B
    )
    sections = []
    for s in pe.sections:
        raw = s.get_data() or b""
        sections.append(
            {
                "name": s.Name.rstrip(b"\x00").decode("latin-1", "replace"),
                "virtual_address": int(s.VirtualAddress),
                "virtual_size": int(s.Misc_VirtualSize),
                "raw_size": int(s.SizeOfRawData),
                "entropy": round(shannon_entropy(raw), 3),
            }
        )

    imports: dict[str, list[str]] = {}
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = (entry.dll or b"").decode("latin-1", "replace")
            funcs = []
            for imp in entry.imports:
                if imp.name:
                    funcs.append(imp.name.decode("latin-1", "replace"))
                elif imp.ordinal is not None:
                    funcs.append(f"ordinal_{imp.ordinal}")
            imports[dll] = funcs

    result = {
        "backend": "pefile",
        "machine": int(pe.FILE_HEADER.Machine),
        "is_64bit": bool(is_64),
        "number_of_sections": int(pe.FILE_HEADER.NumberOfSections),
        "timestamp": int(pe.FILE_HEADER.TimeDateStamp),
        "entry_point": int(getattr(pe.OPTIONAL_HEADER, "AddressOfEntryPoint", 0)),
        "sections": sections,
        "imports": imports,
    }
    pe.close()
    return result


def _parse_builtin(data: bytes) -> dict | None:
    """Minimal PE parser for headers and the section table (no import table)."""
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        return None

    coff = e_lfanew + 4
    if coff + 20 > len(data):
        return None
    (machine, num_sections, timestamp) = struct.unpack_from("<HHI", data, coff)
    # COFF: +8 PointerToSymbolTable(I), +12 NumberOfSymbols(I),
    # +16 SizeOfOptionalHeader(H), +18 Characteristics(H).
    size_opt = struct.unpack_from("<H", data, coff + 16)[0]

    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0] if opt + 2 <= len(data) else 0
    is_64 = magic == 0x20B
    entry_point = struct.unpack_from("<I", data, opt + 16)[0] if opt + 20 <= len(data) else 0

    sec_table = opt + size_opt
    sections = []
    for i in range(num_sections):
        base = sec_table + i * 40
        if base + 40 > len(data):
            break
        name = data[base : base + 8].rstrip(b"\x00").decode("latin-1", "replace")
        virtual_size, virtual_address, raw_size, raw_ptr = struct.unpack_from(
            "<IIII", data, base + 8
        )
        raw = data[raw_ptr : raw_ptr + raw_size] if raw_size else b""
        sections.append(
            {
                "name": name,
                "virtual_address": int(virtual_address),
                "virtual_size": int(virtual_size),
                "raw_size": int(raw_size),
                "entropy": round(shannon_entropy(raw), 3),
            }
        )

    return {
        "backend": "builtin",
        "machine": int(machine),
        "is_64bit": bool(is_64),
        "number_of_sections": int(num_sections),
        "timestamp": int(timestamp),
        "entry_point": int(entry_point),
        "sections": sections,
        "imports": {},
    }


class PEAnalyzer(Analyzer):
    name = "pe"

    def analyze(self, data: bytes, report: Report) -> None:
        ftype = report.get("filetype", {})
        if not isinstance(ftype, dict) or ftype.get("type") != "pe":
            return

        parsed = _parse_with_pefile(data)
        if parsed is None:
            parsed = _parse_builtin(data)
        if parsed is None:
            report.add_warning("pe: file claims PE magic but headers are malformed")
            report.sections[self.name] = {"error": "malformed PE headers"}
            return

        # Suspicious import flagging.
        flagged: list[dict[str, str]] = []
        for dll, funcs in parsed.get("imports", {}).items():
            for fn in funcs:
                if fn in SUSPICIOUS_IMPORTS:
                    flagged.append({"dll": dll, "function": fn, "reason": SUSPICIOUS_IMPORTS[fn]})
        parsed["suspicious_imports"] = flagged

        report.sections[self.name] = parsed

        if flagged:
            report.add_signal(
                "suspicious-imports",
                min(2 + 3 * len(flagged), 25),
                f"{len(flagged)} suspicious imports: "
                + ", ".join(sorted({f['function'] for f in flagged})[:8]),
            )


register(PEAnalyzer())
