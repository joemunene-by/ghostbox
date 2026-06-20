import pytest

# YARA is optional. Skip the whole module cleanly if the library is absent.
yara = pytest.importorskip("yara")

from ghostbox.analyzers.yara_scan import YaraAnalyzer, compile_rules, list_rules  # noqa: E402
from ghostbox.report import Report  # noqa: E402

RULE = """
rule ghostbox_test_marker
{
    strings:
        $a = "GHOSTBOX_MARKER"
    condition:
        $a
}
"""


@pytest.fixture
def rules_dir(tmp_path):
    (tmp_path / "marker.yar").write_text(RULE)
    return str(tmp_path)


def test_list_rules(rules_dir):
    assert "marker.yar" in list_rules(rules_dir)


def test_compile_and_match(rules_dir):
    compiled = compile_rules(rules_dir)
    assert compiled is not None
    matches = compiled.match(data=b"prefix GHOSTBOX_MARKER suffix")
    assert any(m.rule == "ghostbox_test_marker" for m in matches)


def test_yara_analyzer_signal(rules_dir):
    report = Report(path="x", size=32)
    analyzer = YaraAnalyzer(yara_dir=rules_dir)
    analyzer.analyze(b"data GHOSTBOX_MARKER data", report)
    section = report.get("yara")
    assert section["enabled"] is True
    assert any(m["rule"] == "ghostbox_test_marker" for m in section["matches"])
    assert any(s.name == "yara-match" for s in report.signals)
