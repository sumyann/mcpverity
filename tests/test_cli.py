from pathlib import Path

from typer.testing import CliRunner

from mcpverity.cli import app

runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "mcpverity" in result.stdout


def test_rules():
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    for rid in [f"W00{i}" for i in range(1, 8)]:
        assert rid in result.stdout


def test_scan_local_file_exits_1_on_high_by_default(tmp_path):
    f = tmp_path / "server.py"
    f.write_text('import subprocess\nsubprocess.run("ls", shell=True)\n')
    result = runner.invoke(app, ["scan", str(f)])
    assert result.exit_code == 1
    assert "W004" in result.stdout


def test_scan_local_file_fail_on_none_always_exits_0(tmp_path):
    f = tmp_path / "server.py"
    f.write_text('import subprocess\nsubprocess.run("ls", shell=True)\n')
    result = runner.invoke(app, ["scan", str(f), "--fail-on", "none"])
    assert result.exit_code == 0


def test_scan_clean_file_exits_0(tmp_path):
    f = tmp_path / "server.py"
    f.write_text("def add(a, b):\n    return a + b\n")
    result = runner.invoke(app, ["scan", str(f)])
    assert result.exit_code == 0


def test_scan_missing_path_exits_2():
    result = runner.invoke(app, ["scan", "/no/such/path"])
    assert result.exit_code == 2


def test_scan_no_path_no_github_exits_2():
    result = runner.invoke(app, ["scan"])
    assert result.exit_code == 2


def test_scan_json_output_writes_file(tmp_path):
    src = tmp_path / "server.py"
    src.write_text('API_KEY = "sk-abc123def456ghi789jkl012mno345pqr"\n')
    out = tmp_path / "out.json"
    result = runner.invoke(app, ["scan", str(src), "-o", "json", "--output-file", str(out), "--fail-on", "none"])
    assert result.exit_code == 0
    assert out.exists()
    assert "W003" in out.read_text()


def test_scan_llm_check_without_api_key_exits_2_cleanly(tmp_path, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    f = tmp_path / "server.py"
    f.write_text("x = 1\n")
    result = runner.invoke(app, ["scan", str(f), "--llm-check"])
    assert result.exit_code == 2


def test_scan_vulnerable_demo_directory():
    demo = Path(__file__).resolve().parent.parent / "examples" / "vulnerable-demo"
    result = runner.invoke(app, ["scan", str(demo), "--fail-on", "none"])
    assert result.exit_code == 0
    for rid in ["W001", "W002", "W003", "W004", "W005", "W007"]:
        assert rid in result.stdout, f"{rid} missing from vulnerable-demo scan"
