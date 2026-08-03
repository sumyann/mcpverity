"""W007 -- Covert / auto-invoked tool paths.

Tightened: only fires in MCP-context files; broad signals additionally
require a write/exec op in the same file.
"""
from collections.abc import Iterable

from ..models import Finding
from .base import (
    COVERT_SIGNALS,
    DOCS_BASE,
    ParsedServer,
    Rule,
    confidence,
    find_line,
    has_write_or_exec,
    is_mcp_file,
    snippet,
)


def _check(parsed: ParsedServer) -> Iterable[Finding]:
    for f in parsed.files:
        is_mcp = is_mcp_file(f["content"])
        has_exec = has_write_or_exec(f["content"])
        if not is_mcp:
            continue  # skip utilities, tests, and unrelated modules
        for pat, label, base, needs_exec in COVERT_SIGNALS:
            if needs_exec and not has_exec:
                continue
            for m in pat.finditer(f["content"]):
                line = find_line(f["content"], m.start())
                yield Finding(
                    rule_id="W007",
                    title=f"Covert invocation path: {label}",
                    severity="MEDIUM",
                    file_path=f["path"], line=line,
                    snippet=snippet(f["content"], line, 2),
                    message=(f"Code path `{label}` can fire without visible user confirmation. "
                             f"Attackers exploit these to trigger tools silently."),
                    remediation="Require explicit user consent for sensitive tools; log every invocation with tool name + args; do not disable confirmation flags for write/exec tools.",
                    doc_link=f"{DOCS_BASE}#w007-covert-invocation-paths",
                    tags=["covert", "consent"],
                    confidence=confidence(base, f["path"]),
                )
    for m in parsed.manifests:
        for tool in m.get("tools", []):
            if tool.get("requires_confirmation") == False or tool.get("auto_execute") == True:  # noqa: E712
                yield Finding(
                    rule_id="W007",
                    title="Manifest tool marked auto-execute / no-confirmation",
                    severity="MEDIUM",
                    file_path=m["_path"], line=None,
                    snippet=str(tool)[:200],
                    message=f"Tool '{tool.get('name','?')}' declares auto-execute / requires_confirmation=false.",
                    remediation="Default sensitive tools to confirmation-required; whitelist only truly read-only tools for auto-run.",
                    doc_link=f"{DOCS_BASE}#w007-covert-invocation-paths",
                    tags=["covert"],
                    confidence=confidence(0.95, m["_path"]),
                )


RULE = Rule(
    id="W007",
    title="Covert Invocation Paths",
    severity="MEDIUM",
    description="Tools or file operations that can be triggered without user-visible consent (auto-execute, confirmation disabled, on-load hooks).",
    _check=_check,
    doc_link=f"{DOCS_BASE}#w007-covert-invocation-paths",
)
