from ghostbox.report import Report
from ghostbox.scoring import band_for, finalize_score


def test_band_thresholds():
    assert band_for(0) == "clean"
    assert band_for(24) == "clean"
    assert band_for(25) == "suspicious"
    assert band_for(59) == "suspicious"
    assert band_for(60) == "malicious"
    assert band_for(100) == "malicious"


def test_finalize_clamps_to_100():
    report = Report(path="x")
    report.add_signal("a", 80)
    report.add_signal("b", 80)
    finalize_score(report)
    assert report.score == 100
    assert report.band == "malicious"


def test_finalize_sums_weights():
    report = Report(path="x")
    report.add_signal("a", 10)
    report.add_signal("b", 20)
    finalize_score(report)
    assert report.score == 30
    assert report.band == "suspicious"


def test_clean_when_no_signals():
    report = Report(path="x")
    finalize_score(report)
    assert report.score == 0
    assert report.band == "clean"


def test_negative_weights_ignored():
    report = Report(path="x")
    report.add_signal("a", -5)
    report.add_signal("b", 10)
    finalize_score(report)
    assert report.score == 10
