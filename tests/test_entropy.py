from ghostbox.analyzers.entropy import EntropyAnalyzer
from ghostbox.analyzers.filetype import FiletypeAnalyzer
from ghostbox.report import Report
from ghostbox.utils import shannon_entropy
from tests import fixtures


def test_entropy_zero_for_uniform_byte():
    assert shannon_entropy(b"\x00" * 1000) == 0.0


def test_entropy_max_for_all_bytes():
    data = bytes(range(256))
    assert abs(shannon_entropy(data) - 8.0) < 1e-9


def test_entropy_empty():
    assert shannon_entropy(b"") == 0.0


def test_entropy_known_two_symbol():
    # Equal counts of two symbols -> 1.0 bit/byte.
    data = b"\x00\x01" * 500
    assert abs(shannon_entropy(data) - 1.0) < 1e-9


def test_high_entropy_signal():
    data = fixtures.make_high_entropy(8192)
    report = Report(path="x", size=len(data))
    FiletypeAnalyzer().analyze(data, report)
    EntropyAnalyzer().analyze(data, report)
    section = report.get("entropy")
    assert section["overall"] > 7.2
    names = {s.name for s in report.signals}
    assert "high-overall-entropy" in names


def test_packer_section_detection():
    # Simulate a parsed PE with a UPX section.
    report = Report(path="x", size=4096)
    report.sections["pe"] = {
        "sections": [{"name": "UPX0", "entropy": 7.9, "raw_size": 1000}]
    }
    EntropyAnalyzer().analyze(b"\x00" * 4096, report)
    assert "UPX" in report.get("entropy")["packers"]
    assert any(s.name == "known-packer" for s in report.signals)
