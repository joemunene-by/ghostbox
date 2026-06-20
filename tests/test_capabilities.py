from ghostbox.analyzers.capabilities import CapabilitiesAnalyzer
from ghostbox.analyzers.strings_ioc import StringsIOCAnalyzer
from ghostbox.engine import analyze_bytes
from ghostbox.report import Report


def _tags(report: Report):
    caps = report.get("capabilities", {})
    return {t["tag"] for t in caps.get("tags", [])}


def test_capability_tags_from_strings(script_bytes):
    report = Report(path="x", size=len(script_bytes))
    StringsIOCAnalyzer().analyze(script_bytes, report)
    CapabilitiesAnalyzer().analyze(script_bytes, report)
    tags = _tags(report)
    # Script contains powershell, schtasks, encrypted message, http URL.
    assert "networking" in tags
    assert "persistence" in tags
    assert "process-execution" in tags
    assert "crypto-ransomware" in tags


def test_capability_from_pe_imports():
    report = Report(path="x", size=100)
    report.sections["pe"] = {
        "imports": {"kernel32.dll": ["WriteProcessMemory", "CreateRemoteThread"]}
    }
    CapabilitiesAnalyzer().analyze(b"", report)
    assert "process-injection" in _tags(report)


def test_no_capabilities_for_benign():
    data = b"just some harmless plain text content here"
    report = analyze_bytes(data, path="benign.txt")
    assert _tags(report) == set()
