"""Regression tests for silent coverage gaps.

Each block pins one fix: plugin rules that were discovered but never run,
plugin load failures that vanished, file types and lockfiles a local scan
never read, and files dropped without a word (oversize, GitHub file cap).
"""
import importlib.metadata
import io
import json
import tarfile

from typer.testing import CliRunner

from mcpverity import github_fetch
from mcpverity.cli import app
from mcpverity.models import Finding
from mcpverity.rules.base import Rule

runner = CliRunner()


# ---------- plugin rules ----------

def _todo_check(parsed):
    for f in parsed.files:
        if "TODO(security)" in f["content"]:
            yield Finding(rule_id="CUSTOM001", title="Unresolved security TODO", severity="HIGH",
                          file_path=f["path"], message="m", remediation="r")


PLUGIN_RULE = Rule(id="CUSTOM001", title="Unresolved Security TODO", severity="HIGH",
                   description="Flags TODO(security) markers.", _check=_todo_check)


class _EntryPoint:
    def __init__(self, name, value, loader):
        self.name, self.value, self._loader = name, value, loader

    def load(self):
        return self._loader()


def _install_entry_points(monkeypatch, *eps):
    def fake_entry_points(group=None):
        return list(eps) if group == "mcpverity.rules" else []
    monkeypatch.setattr(importlib.metadata, "entry_points", fake_entry_points)


def _boom():
    raise ImportError("No module named 'gone'")


GOOD = _EntryPoint("todo", "pkg.rules:RULE", lambda: PLUGIN_RULE)
BROKEN = _EntryPoint("broken", "gone.rules:RULE", _boom)
NOT_A_RULE = _EntryPoint("wrong", "pkg.rules:check", lambda: _todo_check)


def test_installed_plugin_rule_runs_during_scan(scan_files, monkeypatch):
    _install_entry_points(monkeypatch, GOOD)
    scan = scan_files([{"path": "a.py", "content": "# TODO(security): validate input\n"}])
    assert [f.rule_id for f in scan.findings] == ["CUSTOM001"]


def test_broken_plugins_become_info_findings_and_scan_continues(scan_files, monkeypatch):
    _install_entry_points(monkeypatch, BROKEN, NOT_A_RULE, GOOD)
    scan = scan_files([{"path": "a.py", "content": "# TODO(security)\n"}])
    errs = [f for f in scan.findings if f.rule_id == "PLUGIN-ERR"]
    assert len(errs) == 2  # one per plugin, not deduped into one
    assert all(f.severity == "INFO" for f in errs)
    assert any("gone.rules:RULE" in f.message and "ImportError" in f.message for f in errs)
    assert any("pkg.rules:check" in f.message and "not a mcpverity.rules.base.Rule" in f.message for f in errs)
    assert "CUSTOM001" in [f.rule_id for f in scan.findings]


def test_rules_command_lists_plugin_rules(monkeypatch):
    from mcpverity import cli
    _install_entry_points(monkeypatch, GOOD)
    monkeypatch.setattr(cli.console, "width", 200)  # don't let a narrow terminal fold the IDs
    result = runner.invoke(app, ["rules"])
    assert result.exit_code == 0
    assert "CUSTOM001" in result.stdout and "W007" in result.stdout


def test_cli_warns_on_stderr_when_plugin_fails_to_load(tmp_path, monkeypatch):
    _install_entry_points(monkeypatch, BROKEN)
    (tmp_path / "a.py").write_text("x = 1\n")
    result = runner.invoke(app, ["scan", str(tmp_path), "-o", "json"])
    assert result.exit_code == 0
    assert "Plugin rule failed to load" in result.stderr and "gone.rules:RULE" in result.stderr
    json.loads(result.stdout)  # stdout stays valid JSON


# ---------- file types a local scan never read ----------

def _scan_json(path, *extra):
    result = runner.invoke(app, ["scan", str(path), "-o", "json", "--fail-on", "none", *extra])
    assert result.exit_code == 0, result.output
    return json.loads(result.stdout), result


def test_js_module_variants_are_scanned(tmp_path):
    for name in ("server.mjs", "worker.cjs", "tool.mts", "util.cts"):
        (tmp_path / name).write_text('const cp = require("child_process");\ncp.exec("x");\n')
    data, _ = _scan_json(tmp_path)
    assert sorted(data["files_scanned"]) == ["server.mjs", "tool.mts", "util.cts", "worker.cjs"]
    flagged = {f["file_path"] for f in data["findings"] if f["rule_id"] == "W004"}
    assert flagged == {"server.mjs", "tool.mts", "util.cts", "worker.cjs"}


def test_committed_dotenv_files_are_scanned_and_redacted(tmp_path):
    key = "sk-abc123def456ghi789jkl012mno345pqr"
    (tmp_path / ".env").write_text(f"OPENAI_API_KEY={key}\n")
    (tmp_path / ".env.production").write_text(f"OPENAI_API_KEY={key}\n")
    data, result = _scan_json(tmp_path)
    w003 = {f["file_path"] for f in data["findings"] if f["rule_id"] == "W003"}
    assert w003 == {".env", ".env.production"}
    assert key not in result.stdout


def test_lockfiles_count_locally_even_when_large(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies": {"zod": "^3.0.0"}}')
    (tmp_path / "package-lock.json").write_text('{"x": "' + "a" * 250_000 + '"}')
    (tmp_path / "requirements.txt").write_text("requests\n")
    (tmp_path / "poetry.lock").write_text("# lock\n")
    data, result = _scan_json(tmp_path)
    assert {"package-lock.json", "poetry.lock"} <= set(data["files_scanned"])
    w005 = [f for f in data["findings"] if f["rule_id"] == "W005"]
    # Lockfiles present: no "no lockfile is committed" semver note, and the
    # unpinned requirement is informational only.
    assert not any("no lockfile" in f["message"] for f in w005)
    assert all(f["severity"] == "INFO" for f in w005)
    assert "not scanned" not in result.stderr  # a big lockfile is a marker, not a skip


# ---------- files dropped without a word ----------

def test_oversize_source_file_is_reported(tmp_path):
    (tmp_path / "server.py").write_text("x = 1\n")
    (tmp_path / "huge_tools.py").write_text("# pad\n" * 40_000)
    data, result = _scan_json(tmp_path)
    assert data["files_scanned"] == ["server.py"]
    assert "1 file(s) were not scanned" in result.stderr
    assert "huge_tools.py (240 KB) -- over the 200 KB limit" in result.stderr


def _tarball(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(f"repo-main/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class _Resp:
    def __init__(self, content):
        self.status_code, self.content = 200, content


def _serve(monkeypatch, members):
    blob = _tarball(members)
    monkeypatch.setattr(github_fetch.requests, "get", lambda *a, **k: _Resp(blob))


def test_github_fetch_matches_local_selection_and_reports_skips(monkeypatch):
    _serve(monkeypatch, {
        "src/server.mjs": b"x",
        ".env": b"A=1",
        "uv.lock": b"x" * 300_000,
        "node_modules/dep/index.js": b"x",
        "dist/bundle.js": b"x",
        "logo.png": b"x",
        "big.py": b"#" * 300_000,
    })
    res = github_fetch.fetch_repo_files_detailed("https://github.com/o/r")
    assert sorted(f["path"] for f in res.files) == [".env", "src/server.mjs", "uv.lock"]
    assert res.oversized == ["big.py (300 KB)"]
    assert not res.truncated


def test_github_scan_warns_when_file_cap_truncates(monkeypatch):
    _serve(monkeypatch, {f"f{i:03}.py": b"x = 1\n" for i in range(github_fetch.MAX_TOTAL_FILES + 5)})
    res = github_fetch.fetch_repo_files_detailed("https://github.com/o/r")
    assert len(res.files) == github_fetch.MAX_TOTAL_FILES and res.candidates == github_fetch.MAX_TOTAL_FILES + 5
    result = runner.invoke(app, ["scan", "--github", "https://github.com/o/r", "-o", "json", "--fail-on", "none"])
    assert result.exit_code == 0
    assert "only the first 200 of 205 scannable files were scanned" in result.stderr


def test_skip_warning_escapes_markup_in_file_names(tmp_path):
    (tmp_path / "server.py").write_text("x = 1\n")
    (tmp_path / "[bold]x.py").write_text("#" * 250_000)
    _, result = _scan_json(tmp_path)
    assert "[bold]x.py (250 KB)" in result.stderr
