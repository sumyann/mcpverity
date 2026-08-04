"""W002 -- Indirect prompt injection (XPIA): tools that ingest external content."""
import re
from collections.abc import Iterable

from ..models import Finding
from .base import DOCS_BASE, UNTRUSTED_INGEST_RE, ParsedServer, Rule, confidence, find_line, is_mcp_file, snippet


def _check(parsed: ParsedServer) -> Iterable[Finding]:
    for f in parsed.files:
        content = f["content"]
        if not UNTRUSTED_INGEST_RE.search(content):
            continue
        if not re.search(r"return\s+.*(text|content|body|html|response\.text)", content, re.IGNORECASE):
            continue
        m = UNTRUSTED_INGEST_RE.search(content)
        line = find_line(content, m.start())
        # Higher confidence when file is clearly an MCP tool.
        delta = 0.05 if is_mcp_file(content) else -0.15
        yield Finding(
            rule_id="W002",
            title="Indirect prompt-injection surface (XPIA)",
            severity="HIGH",
            file_path=f["path"],
            line=line,
            snippet=snippet(content, line, 2),
            message="Tool fetches external content and returns it into model context without wrapping it as untrusted. External bodies (web, email, files) can carry attacker-controlled instructions.",
            remediation="Wrap tool output as untrusted: prepend an <untrusted-content> boundary marker, escape angle brackets, and instruct the model to treat wrapped content as data, not instructions.",
            doc_link=f"{DOCS_BASE}#w002-indirect-prompt-injection-surface-xpia",
            tags=["xpia", "prompt-injection"],
            confidence=confidence(0.75, f["path"], delta),
        )


RULE = Rule(
    id="W002",
    title="Indirect Prompt-Injection Surface (XPIA)",
    severity="HIGH",
    description="Tools that return external, untrusted content (web, files, email) into model context without a trust boundary.",
    _check=_check,
    doc_link=f"{DOCS_BASE}#w002-indirect-prompt-injection-surface-xpia",
)
