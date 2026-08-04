"""MCPVerity — static security scanner for MCP (Model Context Protocol) servers."""

__version__ = "0.1.0"

from .engine import run_scan, summarize_findings
from .identity import suppression_hash
from .models import Finding, RuleInfo, Scan, ScanSummary

__all__ = [
    "__version__",
    "Finding",
    "RuleInfo",
    "Scan",
    "ScanSummary",
    "run_scan",
    "summarize_findings",
    "suppression_hash",
]
