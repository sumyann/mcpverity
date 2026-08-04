"""W004 -- Over-broad filesystem / network / shell scope."""
import re
from collections.abc import Iterable

from ..models import Finding
from .base import DOCS_BASE, OVER_PRIVILEGE_SIGNALS, ParsedServer, Rule, confidence, find_line, is_mcp_file, snippet


def _check(parsed: ParsedServer) -> Iterable[Finding]:
    files, manifests = parsed.files, parsed.manifests
    from ..py_ast import analyze_python_file
    ast_covered = set()

    # AST pass for Python files.
    for f in files:
        if f["path"].endswith(".py"):
            ast_findings = analyze_python_file(f["path"], f["content"])
            if ast_findings is not None:
                ast_covered.add(f["path"])
                for ff in ast_findings:
                    if ff.rule_id == "W004":
                        yield ff

    # Regex fallback: non-Python files, or Python files that failed to parse.
    for f in files:
        if f["path"] in ast_covered:
            continue
        is_mcp = is_mcp_file(f["content"])
        for pat, label in OVER_PRIVILEGE_SIGNALS:
            for m in pat.finditer(f["content"]):
                line = find_line(f["content"], m.start())
                delta = 0.05 if is_mcp else -0.20
                yield Finding(
                    rule_id="W004",
                    title=f"Over-privileged operation: {label}",
                    severity="HIGH",
                    file_path=f["path"],
                    line=line,
                    snippet=snippet(f["content"], line, 2),
                    message=f"Tool implementation uses {label}. This grants scope far beyond a typical MCP tool's stated function.",
                    remediation="Constrain the operation: whitelist commands, avoid shell=True, sandbox filesystem access, and document the elevated capability in the tool description.",
                    doc_link=f"{DOCS_BASE}#w004-over-privileged-tools",
                    tags=["least-privilege"],
                    confidence=confidence(0.8, f["path"], delta),
                )

    for m in manifests:
        # mcpServers-specific over-privilege signals.
        if m.get("_kind") == "mcpServers":
            for srv in m.get("servers", []):
                args = srv.get("args") or []
                arg_str = " ".join(str(a) for a in args)
                for pat, label in [
                    (r"--allow-(net|read|write|run|env)=\*", "runtime allow-*= wildcard"),
                    (r"--allow-all\b", "runtime --allow-all"),
                    (r"--dangerously-", "dangerously-prefixed flag"),
                    (r"--privileged\b", "docker --privileged"),
                    (r"-v\s+/:/", "docker mounts host root"),
                    (r"--network[= ]host\b", "docker --network host"),
                ]:
                    if re.search(pat, arg_str, re.IGNORECASE):
                        yield Finding(
                            rule_id="W004",
                            title=f"Over-privileged launcher: {label}",
                            severity="HIGH",
                            file_path=m["_path"],
                            line=None,
                            snippet=f"{srv.get('command')} {arg_str}"[:200],
                            message=f"Server '{srv.get('name')}' is launched with `{label}`. The runner (uvx/npx/docker) then executes with those elevated capabilities inside the MCP host.",
                            remediation="Drop the wildcard flag. Whitelist only the specific hosts / paths / capabilities the server actually needs.",
                            doc_link=f"{DOCS_BASE}#w004-over-privileged-tools",
                            tags=["least-privilege", "mcp-servers"],
                            confidence=confidence(0.9, m["_path"]),
                        )
        perms = m.get("permissions") or m.get("scopes") or []
        if isinstance(perms, list):
            broad = [p for p in perms if isinstance(p, str)
                     and any(k in p.lower() for k in ["*", "all", "root", "admin", "shell", "fs.write", "network.*"])]
            for p in broad:
                yield Finding(
                    rule_id="W004",
                    title="Over-broad manifest permission",
                    severity="HIGH",
                    file_path=m["_path"],
                    line=None,
                    snippet=str(p),
                    message=f"Manifest declares wide scope `{p}`.",
                    remediation="Narrow the scope to the minimum required (e.g. specific paths, HTTP hosts). Wildcards give agents keys to the kingdom.",
                    doc_link=f"{DOCS_BASE}#w004-over-privileged-tools",
                    tags=["least-privilege"],
                    confidence=confidence(0.95, m["_path"]),
                )


RULE = Rule(
    id="W004",
    title="Over-Privileged Tools",
    severity="HIGH",
    description="Tools requesting filesystem, network, or shell scope broader than their stated function -- least-privilege violations.",
    _check=_check,
    doc_link=f"{DOCS_BASE}#w004-over-privileged-tools",
)
