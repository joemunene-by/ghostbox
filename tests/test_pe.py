from ghostbox.analyzers.filetype import FiletypeAnalyzer
from ghostbox.analyzers.pe import PEAnalyzer, _parse_builtin
from ghostbox.report import Report
from tests import fixtures


def _report_for(data: bytes) -> Report:
    report = Report(path="x", size=len(data))
    FiletypeAnalyzer().analyze(data, report)
    return report


def test_builtin_pe_header_parse(pe_bytes):
    parsed = _parse_builtin(pe_bytes)
    assert parsed is not None
    assert parsed["backend"] == "builtin"
    assert parsed["machine"] == 0x014C
    assert parsed["number_of_sections"] == 1
    assert parsed["entry_point"] == 0x1000


def test_builtin_pe_section_parse(pe_bytes):
    parsed = _parse_builtin(pe_bytes)
    assert len(parsed["sections"]) == 1
    section = parsed["sections"][0]
    assert section["name"] == ".text"
    assert section["virtual_address"] == 0x1000
    assert section["raw_size"] >= 0x200
    assert "entropy" in section


def test_pe_analyzer_runs(pe_bytes):
    report = _report_for(pe_bytes)
    PEAnalyzer().analyze(pe_bytes, report)
    pe = report.get("pe")
    assert pe is not None
    assert "sections" in pe


def test_pe_analyzer_skips_non_pe(elf_bytes):
    report = _report_for(elf_bytes)
    PEAnalyzer().analyze(elf_bytes, report)
    assert report.get("pe") is None


def test_pe_truncated_is_handled():
    # Valid MZ + e_lfanew pointing past EOF.
    data = fixtures.make_pe()[:0x40]
    report = _report_for(data)
    # Filetype still says PE due to MZ; analyzer must not raise.
    PEAnalyzer().analyze(data, report)
    pe = report.get("pe")
    assert pe is None or "error" in pe
