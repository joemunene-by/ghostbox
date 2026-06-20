import hashlib

from ghostbox.analyzers.hashing import HashingAnalyzer
from ghostbox.report import Report


def test_hashing_correctness():
    data = b"ghostbox benign test vector"
    report = Report(path="x", size=len(data))
    HashingAnalyzer().analyze(data, report)
    section = report.get("hashing")
    assert section["md5"] == hashlib.md5(data).hexdigest()
    assert section["sha1"] == hashlib.sha1(data).hexdigest()
    assert section["sha256"] == hashlib.sha256(data).hexdigest()
    assert section["size"] == len(data)


def test_hashing_empty():
    report = Report(path="x", size=0)
    HashingAnalyzer().analyze(b"", report)
    assert report.get("hashing")["sha256"] == hashlib.sha256(b"").hexdigest()
