from ghostbox.analyzers.elf import ELFAnalyzer, _parse_builtin
from ghostbox.analyzers.filetype import FiletypeAnalyzer
from ghostbox.report import Report


def _report_for(data: bytes) -> Report:
    report = Report(path="x", size=len(data))
    FiletypeAnalyzer().analyze(data, report)
    return report


def test_builtin_elf_header_parse(elf_bytes):
    parsed = _parse_builtin(elf_bytes)
    assert parsed is not None
    assert parsed["class"] == "ELF64"
    assert parsed["endian"] == "little"
    assert parsed["machine"] == "x86-64"
    assert parsed["type"] == "EXEC"
    assert parsed["entry_point"] == 0x400000


def test_builtin_elf_sections(elf_bytes):
    parsed = _parse_builtin(elf_bytes)
    names = {s["name"] for s in parsed["sections"]}
    assert ".text" in names
    assert ".shstrtab" in names


def test_elf_analyzer_runs(elf_bytes):
    report = _report_for(elf_bytes)
    ELFAnalyzer().analyze(elf_bytes, report)
    elf = report.get("elf")
    assert elf is not None
    assert elf["entry_point"] == 0x400000


def test_elf_analyzer_skips_non_elf(pe_bytes):
    report = _report_for(pe_bytes)
    ELFAnalyzer().analyze(pe_bytes, report)
    assert report.get("elf") is None


def test_elf_truncated_handled():
    data = b"\x7fELF" + b"\x00" * 4  # too short for full header
    report = _report_for(data)
    ELFAnalyzer().analyze(data, report)
    elf = report.get("elf")
    assert elf is None or "error" in elf
