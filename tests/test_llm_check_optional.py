"""Per amendment: mcpverity.llm_check must import cleanly, and run_llm_check must
degrade to [] rather than raise, even when the `anthropic` package is not
installed. This is the guarantee that lets `pip install mcpverity` (no
[llm] extra) work with zero risk of an ImportError surfacing to the user.
"""
import asyncio
import builtins
import importlib
import sys


def test_llm_check_module_imports_without_anthropic_installed(monkeypatch):
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "anthropic" or name.startswith("anthropic."):
            raise ImportError(f"No module named {name!r}")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    for mod in ("mcpverity.llm_check", "anthropic"):
        sys.modules.pop(mod, None)

    llm_check = importlib.import_module("mcpverity.llm_check")
    assert callable(llm_check.run_llm_check)


def test_run_llm_check_no_api_key_returns_empty(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    from mcpverity.llm_check import run_llm_check
    result = asyncio.run(run_llm_check([{"tool_name": "x", "description": "y", "source": "z.py"}], "demo"))
    assert result == []


def test_run_llm_check_no_anthropic_package_returns_empty(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key-for-test")
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError("simulated: anthropic not installed")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    from mcpverity.llm_check import run_llm_check
    result = asyncio.run(run_llm_check([{"tool_name": "x", "description": "y", "source": "z.py"}], "demo"))
    assert result == []


def test_run_llm_check_empty_descriptions_short_circuits(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "fake-key-for-test")
    from mcpverity.llm_check import run_llm_check
    result = asyncio.run(run_llm_check([], "demo"))
    assert result == []
