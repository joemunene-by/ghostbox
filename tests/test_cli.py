import json

from typer.testing import CliRunner

from ghostbox.cli import app
from tests import fixtures

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "ghostbox" in result.stdout


def test_cli_analyze_console(tmp_path):
    p = tmp_path / "sample.sh"
    p.write_bytes(fixtures.make_script_with_iocs())
    result = runner.invoke(app, ["analyze", str(p)])
    assert result.exit_code == 0
    assert "Threat score" in result.stdout


def test_cli_analyze_json(tmp_path):
    p = tmp_path / "sample.exe"
    p.write_bytes(fixtures.make_pe(with_import_name=b"VirtualAlloc"))
    result = runner.invoke(app, ["analyze", str(p), "--format", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["path"] == str(p)
    assert parsed["sections"]["filetype"]["type"] == "pe"


def test_cli_analyze_missing_file(tmp_path):
    result = runner.invoke(app, ["analyze", str(tmp_path / "nope")])
    assert result.exit_code == 2


def test_cli_scan_json(tmp_path):
    (tmp_path / "a.sh").write_bytes(fixtures.make_script_with_iocs())
    (tmp_path / "b.elf").write_bytes(fixtures.make_elf())
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)
    assert len(parsed) == 2


def test_cli_scan_min_score(tmp_path):
    (tmp_path / "a.sh").write_bytes(fixtures.make_script_with_iocs())
    (tmp_path / "b.txt").write_bytes(b"totally benign text file")
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--format", "json", "--min-score", "25"]
    )
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    # Only the script should clear the threshold.
    assert len(parsed) == 1


def test_cli_analyze_output_json(tmp_path):
    p = tmp_path / "sample.elf"
    p.write_bytes(fixtures.make_elf())
    out = tmp_path / "report.json"
    result = runner.invoke(
        app, ["analyze", str(p), "--format", "json", "--output", str(out)]
    )
    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["sections"]["filetype"]["type"] == "elf"


def test_cli_rules_no_dir():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
