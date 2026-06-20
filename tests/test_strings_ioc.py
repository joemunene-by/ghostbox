from ghostbox.analyzers.strings_ioc import StringsIOCAnalyzer, extract_iocs, extract_strings
from ghostbox.report import Report


def test_extract_ascii_strings():
    data = b"\x00\x01hello world\x00\x02ghostbox\x00"
    strings = extract_strings(data, 100)
    assert "hello world" in strings
    assert "ghostbox" in strings


def test_extract_utf16_strings():
    data = "secret".encode("utf-16-le")
    strings = extract_strings(b"\x00\x00" + data + b"\x00\x00", 100)
    assert "secret" in strings


def test_ioc_url_ip_domain(script_bytes):
    strings = extract_strings(script_bytes, 1000)
    iocs = extract_iocs(strings)
    assert any("malicious.example.com" in u for u in iocs["urls"])
    assert "203.0.113.45" in iocs["ipv4"]
    assert any("evil-domain.top" in d for d in iocs["domains"])
    assert any("@" in e for e in iocs["emails"])
    assert any("HKLM" in r for r in iocs["registry_keys"])


def test_trivial_ip_excluded():
    iocs = extract_iocs(["127.0.0.1 and 0.0.0.0 and 8.8.8.8"])
    assert "8.8.8.8" in iocs["ipv4"]
    assert "127.0.0.1" not in iocs["ipv4"]
    assert "0.0.0.0" not in iocs["ipv4"]


def test_ioc_analyzer_signals(script_bytes):
    report = Report(path="x", size=len(script_bytes))
    StringsIOCAnalyzer().analyze(script_bytes, report)
    assert report.get("strings_ioc")["string_count"] > 0
    assert any(s.name == "network-iocs" for s in report.signals)


def test_max_strings_cap():
    data = b"\x00".join(f"string{i:04d}".encode() for i in range(500))
    strings = extract_strings(data, 10)
    assert len(strings) <= 10
