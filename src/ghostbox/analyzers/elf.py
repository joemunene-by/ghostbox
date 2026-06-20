"""ELF analyzer.

Parses the ELF header and section table. Uses ``pyelftools`` when importable,
otherwise falls back to a compact built-in parser supporting 32/64-bit and both
endiannesses. Defensive against truncation.
"""

from __future__ import annotations

import struct

from ghostbox.analyzers import Analyzer, register
from ghostbox.report import Report
from ghostbox.utils import shannon_entropy

_ELF_TYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
_MACHINES = {0x03: "x86", 0x3E: "x86-64", 0x28: "ARM", 0xB7: "AArch64", 0xF3: "RISC-V"}


def _parse_with_pyelftools(data: bytes) -> dict | None:
    try:
        import io

        from elftools.elf.elffile import ELFFile  # type: ignore
    except ImportError:
        return None
    try:
        elf = ELFFile(io.BytesIO(data))
    except Exception:
        return None

    sections = []
    for s in elf.iter_sections():
        raw = s.data() or b""
        sections.append(
            {
                "name": s.name,
                "type": s["sh_type"],
                "addr": int(s["sh_addr"]),
                "size": int(s["sh_size"]),
                "entropy": round(shannon_entropy(raw), 3) if raw else 0.0,
            }
        )

    dyn_symbols: list[str] = []
    dynsym = elf.get_section_by_name(".dynsym")
    if dynsym is not None:
        for sym in dynsym.iter_symbols():
            if sym.name:
                dyn_symbols.append(sym.name)

    return {
        "backend": "pyelftools",
        "class": "ELF64" if elf.elfclass == 64 else "ELF32",
        "endian": "little" if elf.little_endian else "big",
        "type": str(elf["e_type"]),
        "machine": str(elf["e_machine"]),
        "entry_point": int(elf["e_entry"]),
        "sections": sections,
        "dynamic_symbols": dyn_symbols[:512],
    }


def _parse_builtin(data: bytes) -> dict | None:
    if len(data) < 0x14 or data[:4] != b"\x7fELF":
        return None
    ei_class = data[4]  # 1=32, 2=64
    ei_data = data[5]  # 1=LE, 2=BE
    endian = "<" if ei_data == 1 else ">"
    is_64 = ei_class == 2

    try:
        e_type, e_machine = struct.unpack_from(endian + "HH", data, 16)
        if is_64:
            e_entry = struct.unpack_from(endian + "Q", data, 24)[0]
            e_shoff = struct.unpack_from(endian + "Q", data, 40)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 58)
        else:
            e_entry = struct.unpack_from(endian + "I", data, 24)[0]
            e_shoff = struct.unpack_from(endian + "I", data, 32)[0]
            e_shentsize, e_shnum, e_shstrndx = struct.unpack_from(endian + "HHH", data, 46)
    except struct.error:
        return None

    sections = _read_sections_builtin(
        data, endian, is_64, e_shoff, e_shentsize, e_shnum, e_shstrndx
    )

    return {
        "backend": "builtin",
        "class": "ELF64" if is_64 else "ELF32",
        "endian": "little" if ei_data == 1 else "big",
        "type": _ELF_TYPES.get(e_type, str(e_type)),
        "machine": _MACHINES.get(e_machine, hex(e_machine)),
        "entry_point": int(e_entry),
        "sections": sections,
        "dynamic_symbols": [],
    }


def _read_sections_builtin(
    data: bytes,
    endian: str,
    is_64: bool,
    e_shoff: int,
    e_shentsize: int,
    e_shnum: int,
    e_shstrndx: int,
) -> list[dict]:
    sections: list[dict] = []
    if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
        return sections

    raw_entries = []
    for i in range(e_shnum):
        base = e_shoff + i * e_shentsize
        if base + e_shentsize > len(data):
            break
        if is_64:
            sh_name, sh_type = struct.unpack_from(endian + "II", data, base)
            sh_addr = struct.unpack_from(endian + "Q", data, base + 16)[0]
            sh_offset = struct.unpack_from(endian + "Q", data, base + 24)[0]
            sh_size = struct.unpack_from(endian + "Q", data, base + 32)[0]
        else:
            sh_name, sh_type = struct.unpack_from(endian + "II", data, base)
            sh_addr = struct.unpack_from(endian + "I", data, base + 12)[0]
            sh_offset = struct.unpack_from(endian + "I", data, base + 16)[0]
            sh_size = struct.unpack_from(endian + "I", data, base + 20)[0]
        raw_entries.append((sh_name, sh_type, sh_addr, sh_offset, sh_size))

    # Resolve names from the section header string table.
    strtab = b""
    if 0 <= e_shstrndx < len(raw_entries):
        _, _, _, str_off, str_size = raw_entries[e_shstrndx]
        strtab = data[str_off : str_off + str_size]

    for sh_name, sh_type, sh_addr, sh_offset, sh_size in raw_entries:
        name = _str_from_table(strtab, sh_name)
        body = data[sh_offset : sh_offset + sh_size] if sh_type != 8 else b""  # 8 = NOBITS
        sections.append(
            {
                "name": name,
                "type": int(sh_type),
                "addr": int(sh_addr),
                "size": int(sh_size),
                "entropy": round(shannon_entropy(body), 3) if body else 0.0,
            }
        )
    return sections


def _str_from_table(strtab: bytes, offset: int) -> str:
    if offset < 0 or offset >= len(strtab):
        return ""
    end = strtab.find(b"\x00", offset)
    if end == -1:
        end = len(strtab)
    return strtab[offset:end].decode("latin-1", "replace")


class ELFAnalyzer(Analyzer):
    name = "elf"

    def analyze(self, data: bytes, report: Report) -> None:
        ftype = report.get("filetype", {})
        if not isinstance(ftype, dict) or ftype.get("type") != "elf":
            return

        parsed = _parse_with_pyelftools(data)
        if parsed is None:
            parsed = _parse_builtin(data)
        if parsed is None:
            report.add_warning("elf: file claims ELF magic but headers are malformed")
            report.sections[self.name] = {"error": "malformed ELF headers"}
            return

        report.sections[self.name] = parsed


register(ELFAnalyzer())
