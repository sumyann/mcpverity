"""W006 -- Session / multi-server hijack surfaces.

Tightened: only fires on files that look like HTTP/MCP transports, and each
signal has its own base confidence. Test/example paths get -0.35.
"""
from collections.abc import Iterable

from ..models import Finding
from .base import (
    DOCS_BASE,
    SESSION_SIGNALS,
    ParsedServer,
    Rule,
    confidence,
    find_line,
    is_http_server_file,
    is_mcp_file,
    snippet,
)


def _check(parsed: ParsedServer) -> Iterable[Finding]:
    for f in parsed.files:
        # Gate: must look like an HTTP-transport MCP file -- otherwise the
        # word "session" is almost always a false positive.
        if not (is_http_server_file(f["content"]) or is_mcp_file(f["content"])):
            continue
        for pat, label, base in SESSION_SIGNALS:
            for m in pat.finditer(f["content"]):
                line = find_line(f["content"], m.start())
                yield Finding(
                    rule_id="W006",
                    title=f"Session risk: {label}",
                    severity="HIGH",
                    file_path=f["path"], line=line,
                    snippet=snippet(f["content"], line, 2),
                    message=(f"Detected `{label}`. Stateful HTTP MCP transports are vulnerable "
                             f"to session-hijack + cross-server injection if session IDs are "
                             f"guessable or shared."),
                    remediation="Bind session IDs to authenticated principal, rotate on privilege change, use HTTPS-only cookies, and never trust client-supplied session state.",
                    doc_link=f"{DOCS_BASE}#w006-session--multi-server-risks",
                    tags=["session", "transport"],
                    confidence=confidence(base, f["path"]),
                )


RULE = Rule(
    id="W006",
    title="Session / Multi-Server Risks",
    severity="HIGH",
    description="Stateful HTTP MCP transports vulnerable to session hijack, shared-session-ID injection, or cross-server contamination.",
    _check=_check,
    doc_link=f"{DOCS_BASE}#w006-session--multi-server-risks",
)
