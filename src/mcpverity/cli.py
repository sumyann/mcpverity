"""MCPVerity CLI -- `mcpverity scan`, `mcpverity rules`, `mcpverity version`."""
import asyncio
import json as json_module
import os
from pathlib import Path

import typer
from rich.console import Console
from rich.markup import escape

from . import __version__
from .engine import run_scan
from .file_filter import MAX_FILE_BYTES, MAX_TOTAL_FILES, classify, oversize_note
from .models import ScanInputFile
from .report import scan_to_json, scan_to_sarif
from .report.human import print_scan
from .rules import all_rules

app = typer.Typer(add_completion=False, no_args_is_help=True, help="Static security scanner for MCP servers.")
console = Console()
# Warnings go to stderr so they never corrupt `-o json|sarif` written to stdout.
# soft_wrap: never hard-wrap them at terminal width -- CI logs get grepped.
err_console = Console(stderr=True, soft_wrap=True)


def _collect_local_files(root: Path) -> tuple[list[ScanInputFile], list[str]]:
    """Return (files to scan, notes on scannable files that were skipped)."""
    files: list[ScanInputFile] = []
    skipped: list[str] = []
    if root.is_file():
        candidates = [root]
        base = root.parent
    else:
        candidates = sorted(p for p in root.rglob("*") if p.is_file())
        base = root
    for p in candidates:
        rel = p.relative_to(base).as_posix()
        kind = classify(rel)
        if kind is None:
            continue
        if kind == "lockfile":
            files.append(ScanInputFile(path=rel, content=""))
            continue
        try:
            size = p.stat().st_size
            if size > MAX_FILE_BYTES:
                skipped.append(oversize_note(rel, size) + f" -- over the {MAX_FILE_BYTES // 1000} KB limit")
                continue
            content = p.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            skipped.append(f"{rel} -- unreadable ({type(e).__name__})")
            continue
        files.append(ScanInputFile(path=rel, content=content))
    return files, skipped


def _warn_skipped(skipped: list[str]) -> None:
    if not skipped:
        return
    shown = ", ".join(skipped[:5]) + (f", +{len(skipped) - 5} more" if len(skipped) > 5 else "")
    # escape(): file names come from the scanned repo and must not inject markup.
    err_console.print(f"[yellow]Warning: {len(skipped)} file(s) were not scanned: {escape(shown)}[/yellow]")


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
        from .github_fetch import GitHubFetchError, fetch_repo_files_detailed
        try:
            fetched = fetch_repo_files_detailed(github)
        except GitHubFetchError as e:
            console.print(f"[red]Failed to fetch {github}: {e}[/red]")
            raise typer.Exit(1) from e
        files = [{"path": f["path"], "content": f["content"]} for f in fetched.files]
        _warn_skipped([f"{n} -- over the {MAX_FILE_BYTES // 1000} KB limit" for n in fetched.oversized]
                      + [f"{n} -- unreadable" for n in fetched.unreadable])
        if fetched.truncated:
            err_console.print(f"[yellow]Warning: only the first {len(fetched.files)} of {fetched.candidates} "
                              f"scannable files were scanned (GitHub scans stop at {MAX_TOTAL_FILES}). "
                              f"Clone the repo and scan it locally for full coverage.[/yellow]")
        mode = "github"
        repo_url = github
    else:
        root = Path(path)
        if not root.exists():
            console.print(f"[red]Path not found: {path}[/red]")
            raise typer.Exit(2)
        collected, skipped = _collect_local_files(root)
        files = [f.model_dump() for f in collected]
        _warn_skipped(skipped)
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

    for f in scan_result.findings:
        if f.rule_id.endswith("-ERR"):
            err_console.print(f"[yellow]Warning: {escape(f.title)}: {escape(f.message)}[/yellow]")

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
    """List all detection rules: built-ins, then any installed plugin rules."""
    from rich.table import Table
    table = Table(show_lines=False)
    table.add_column("ID")
    table.add_column("Title")
    table.add_column("Default Severity")
    table.add_column("Description", overflow="fold")
    for rule in all_rules():
        table.add_row(rule.id, rule.title, rule.severity, rule.description)
    console.print(table)


@app.command()
def version():
    """Print the mcpverity version."""
    console.print(f"mcpverity {__version__}")


if __name__ == "__main__":
    app()
