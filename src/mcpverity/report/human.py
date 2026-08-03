"""Human-readable terminal rendering of a Scan, using rich."""
from rich.console import Console
from rich.table import Table

from ..models import Scan

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "cyan",
    "INFO": "dim",
}

VERDICT_STYLE = {
    "vulnerable": "bold red",
    "at_risk": "yellow",
    "clean": "bold green",
}


def print_scan(scan: Scan, console: Console = None) -> None:
    console = console or Console()
    verdict_style = VERDICT_STYLE.get(scan.summary.verdict, "white")
    console.print(
        f"\n[bold]{scan.server_name}[/bold] -- "
        f"[{verdict_style}]{scan.summary.verdict.upper()}[/{verdict_style}] "
        f"(risk score {scan.summary.risk_score}/100, {scan.summary.total} findings)"
    )

    if not scan.findings:
        console.print("[green]No findings.[/green]\n")
        return

    table = Table(show_lines=False)
    table.add_column("Rule", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Confidence", no_wrap=True)
    table.add_column("File", overflow="fold")
    table.add_column("Title", overflow="fold")

    for f in scan.findings:
        style = SEVERITY_STYLE.get(f.severity, "white")
        location = f.file_path + (f":{f.line}" if f.line else "")
        table.add_row(
            f.rule_id,
            f"[{style}]{f.severity}[/{style}]",
            f"{f.confidence:.2f}",
            location,
            f.title,
        )
    console.print(table)
    console.print()
