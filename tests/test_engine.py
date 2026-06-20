import json

from ghostbox.engine import analyze_bytes, analyze_file
from tests import fixtures


def test_analyze_pe_end_to_end(pe_bytes):
    report = analyze_bytes(pe_bytes, path="sample.exe")
    assert report.error is None
    assert report.get("filetype")["type"] == "pe"
    assert report.get("hashing")["sha256"]
    assert "pe" in report.sections
    # Internal scratch key removed.
    assert "_strings_full" not in report.sections


def test_analyze_script_scores_suspicious(script_bytes):
    report = analyze_bytes(script_bytes, path="sample.sh")
    assert report.score >= 25
    assert report.band in {"suspicious", "malicious"}


def test_json_round_trip(pe_bytes):
    report = analyze_bytes(pe_bytes, path="sample.exe")
    text = report.to_json()
    parsed = json.loads(text)
    assert parsed["path"] == "sample.exe"
    assert parsed["score"] == report.score
    assert "sections" in parsed
    assert isinstance(parsed["signals"], list)


def test_corrupt_file_handled():
    # MZ header then garbage; engine must not raise.
    data = b"MZ" + b"\xff" * 32
    report = analyze_bytes(data, path="corrupt.bin")
    assert report.error is None  # graceful
    # PE analyzer should have flagged a malformed-header warning or error.
    pe = report.get("pe")
    assert pe is None or "error" in pe


def test_analyze_file_missing(tmp_path):
    report = analyze_file(tmp_path / "nope.bin")
    assert report.error is not None


def test_analyze_file_reads_from_disk(tmp_path):
    p = tmp_path / "sample.elf"
    p.write_bytes(fixtures.make_elf())
    report = analyze_file(p)
    assert report.error is None
    assert report.get("filetype")["type"] == "elf"


def test_empty_file(tmp_path):
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")
    report = analyze_file(p)
    assert report.error is None
    assert report.get("filetype")["type"] == "empty"
