"""W001 -- Tool poisoning: injection patterns embedded in tool descriptions/metadata."""
import re
from collections.abc import Iterable

from ..models import Finding
from .base import DOCS_BASE, POISONING_RE, ParsedServer, Rule, confidence, find_line, snippet


def _check(parsed: ParsedServer) -> Iterable[Finding]:
    files, manifests = parsed.files, parsed.manifests
    # Track paths that were AST-analysed to avoid a duplicate regex hit.
    ast_covered = set()

    for m in manifests:
        for tool in m.get("tools", []):
            for field in ("description", "instructions", "prompt", "notes", "hidden"):
                val = tool.get(field)
                if not isinstance(val, str):
                    continue
                match = POISONING_RE.search(val)
                if not match:
                    continue
                yield Finding(
                    rule_id="W001",
                    title="Tool poisoning in tool description",
                    severity="CRITICAL",
                    file_path=m["_path"],
                    line=None,
                    snippet=val[:300],
                    message=f"Tool '{tool.get('name', '?')}' field '{field}' contains an injection-style phrase: '{match.group(0)}'. LLMs will treat this as trusted instruction.",
                    remediation="Remove injection-style directives from tool descriptions. Keep descriptions purely factual about what the tool does. Never embed 'ignore previous', 'system:', or exfil instructions.",
                    doc_link=f"{DOCS_BASE}#w001-tool-poisoning",
                    tags=["poisoning", "prompt-injection"],
                    confidence=confidence(0.95, m["_path"]),
                )

    # Python: prefer AST (eliminates matches inside comments/docstrings)
    from ..py_ast import analyze_python_file
    for f in files:
        if f["path"].endswith(".py"):
            ast_findings = analyze_python_file(f["path"], f["content"])
            if ast_findings is not None:
                ast_covered.add(f["path"])
                for ff in ast_findings:
                    if ff.rule_id == "W001":
                        yield ff

    # Regex fallback for non-Python or Python files that failed to parse.
    for f in files:
        if f["path"] in ast_covered:
            continue
        for m in re.finditer(r"(?:description|prompt|instructions)\s*=\s*(['\"])(.+?)\1",
                              f["content"], re.IGNORECASE | re.DOTALL):
            val = m.group(2)
            hit = POISONING_RE.search(val)
            if not hit:
                continue
            line = find_line(f["content"], m.start())
            yield Finding(
                rule_id="W001",
                title="Tool poisoning in tool description",
                severity="CRITICAL",
                file_path=f["path"],
                line=line,
                snippet=snippet(f["content"], line, 2),
                message=f"Injection-style phrase '{hit.group(0)}' found in tool description string.",
                remediation="Strip prompt-injection language from description= arguments. Descriptions are model-visible and trusted.",
                doc_link=f"{DOCS_BASE}#w001-tool-poisoning",
                tags=["poisoning"],
                confidence=confidence(0.9, f["path"]),
            )


RULE = Rule(
    id="W001",
    title="Tool Poisoning",
    severity="CRITICAL",
    description="Malicious or manipulative instructions embedded in tool description/metadata fields -- invisible to human review but read as trusted by the model.",
    _check=_check,
    doc_link=f"{DOCS_BASE}#w001-tool-poisoning",
)
