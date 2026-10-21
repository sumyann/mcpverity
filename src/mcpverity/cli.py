"""MCPVerity CLI -- `mcpverity scan`, `mcpverity rules`, `mcpverity version`."""
import asyncio
import json as json_module
import os
from pathlib import Path

import typer
from rich.console import Console

from . import __version__
from .engine import run_scan
from .models import ScanInputFile
from .report import scan_to_json, scan_to_sarif
from .report.human import print_scan
from .rules import ALL_RULES

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Static security scanner for MCP servers.")
console = Console()
# Warnings go to stderr so they never corrupt `-o json|sarif` written to stdout.
err_console = Console(stderr=True)

SCAN_EXTENSIONS = {".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".toml", ".yaml", ".yml", ".txt", ".md"}
MAX_FILE_BYTES = 200_000
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache", ".pytest_cache"}


def _collect_local_files(root: Path) -> list[ScanInputFile]:
    files: list[ScanInputFile] = []
    if root.is_file():
        candidates = [root]
        base = root.parent
    else:
        # Match SKIP_DIRS against the path *below* the scan root only -- an
        # ancestor named build/ or dist/ must not silently skip every file.
        candidates = [p for p in root.rglob("*")
                      if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(root).parts)]
        base = root
    for p in candidates:
        if p.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
                continue
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(p.relative_to(base)) if root.is_dir() else p.name
        files.append(ScanInputFile(path=rel, content=content))
    return files


@app.command()
def scan(
    path: str | None = typer.Argument(None, help="Local file or directory to scan."),
    github: str | None = typer.Option(None, "--github", help="Scan a public GitHub repo URL instead of a local path."),
    server_name: str = typer.Option("Untitled MCP Server", "--name", help="Label for this scan."),
    llm_check: bool = typer.Option(False, "--llm-check", help="Run an optional Claude-assisted second pass (requires ANTHROPIC_API_KEY and `pip install mcpverity[llm]`)."),
    output: str = typer.Option("human", "--output", "-o", help="Output format: human | json | sarif."),
    output_file: str | None = typer.Option(None, "--output-file", help="Write output to a file instead of stdout (human format always prints to stdout)."),
    fail_on: str = typer.Option("high", "--fail-on", help="Exit 1 if a finding meets this severity: critical | high | medium | low | none. Exit 2 if nothing was scanned or --llm-check did not complete."),
):
    """Scan a local path or a GitHub repo for MCP security issues."""
    if not path and not github:
        console.print("[red]Provide a local PATH or --github <url>.[/red]")
        raise typer.Exit(2)
    if path and github:
        console.print("[red]Pass either a local PATH or --github, not both.[/red]")
        raise typer.Exit(2)

    if llm_check and not os.environ.get("ANTHROPIC_API_KEY"):
        console.print("[red]--llm-check requires ANTHROPIC_API_KEY to be set.[/red]")
        raise typer.Exit(2)
    if llm_check:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            console.print("[red]--llm-check requires the `anthropic` package: pip install 'mcpverity[llm]'.[/red]")
            raise typer.Exit(2) from None

    if github:
        from .github_fetch import GitHubFetchError, fetch_repo_files
        try:
            raw_files = fetch_repo_files(github)
        except GitHubFetchError as e:
            console.print(f"[red]Failed to fetch {github}: {e}[/red]")
            raise typer.Exit(1) from e
        files = [{"path": f["path"], "content": f["content"]} for f in raw_files]
        mode = "github"
        repo_url = github
    else:
        root = Path(path)
        if not root.exists():
            console.print(f"[red]Path not found: {path}[/red]")
            raise typer.Exit(2)
        files = [f.model_dump() for f in _collect_local_files(root)]
        mode = "paste"
        repo_url = None

    if not files:
        # Scanning nothing must not look like a clean pass in CI.
        err_console.print(f"[red]No scannable files found under {path or github} -- nothing was scanned.[/red]")
        raise typer.Exit(0 if fail_on.lower() == "none" else 2)

    scan_result = asyncio.run(run_scan(server_name, files, mode, repo_url, llm_check))

    if output == "human":
        print_scan(scan_result, console)
    elif output == "json":
        text = json_module.dumps(scan_to_json(scan_result), indent=2)
        _write_output(text, output_file)
    elif output == "sarif":
        text = json_module.dumps(scan_to_sarif(scan_result), indent=2)
        _write_output(text, output_file)
    else:
        console.print(f"[red]Unknown --output '{output}'. Use human, json, or sarif.[/red]")
        raise typer.Exit(2)

    code = _exit_code(scan_result, fail_on)
    if scan_result.error:
        err_console.print(f"[red]Scan incomplete: {scan_result.error}[/red]")
        if fail_on.lower() != "none":
            code = 2
    raise typer.Exit(code)


def _write_output(text: str, output_file: str | None) -> None:
    if output_file:
        Path(output_file).write_text(text)
    else:
        print(text)


def _exit_code(scan_result, fail_on: str) -> int:
    order = ["critical", "high", "medium", "low", "info"]
    fail_on = fail_on.lower()
    if fail_on == "none":
        return 0
    if fail_on not in order:
        console.print(f"[red]Unknown --fail-on '{fail_on}'. Use critical, high, medium, low, or none.[/red]")
        return 2
    threshold = order.index(fail_on)
    counts = {
        "critical": scan_result.summary.critical,
        "high": scan_result.summary.high,
        "medium": scan_result.summary.medium,
        "low": scan_result.summary.low,
        "info": scan_result.summary.info,
    }
    for i in range(threshold + 1):
        if counts[order[i]] > 0:
            return 1
    return 0


@app.command()
def rules():
    """List all built-in detection rules."""
    from rich.table import Table
    table = Table(show_lines=False)
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Default Severity")
    table.add_column("Description", overflow="fold")
    for rule in ALL_RULES:
        table.add_row(rule.id, rule.title, rule.severity, rule.description)
    console.print(table)


@app.command()
def version():
    """Print the mcpverity version."""
    console.print(f"mcpverity {__version__}")


if __name__ == "__main__":
    app()
