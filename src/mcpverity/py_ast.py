"""AST-based Python analysis for W001 (tool poisoning) and W004 (over-privileged).

AST walks skip strings inside comments (Python has none) and docstrings
(unless assigned to a variable), which eliminates the "matched inside a
comment" false-positive class that plain regex hits. When the file doesn't
parse (syntax error, Python 2, etc.), we return None so the caller falls
back to regex.
"""
import ast
from collections.abc import Iterable

from .models import Finding
from .rules.base import DOCS_BASE, POISONING_RE, confidence, snippet

DANGEROUS_CALLS = {
    "subprocess.run": ("spawns subprocess", 0.85),
    "subprocess.call": ("spawns subprocess", 0.85),
    "subprocess.Popen": ("spawns subprocess", 0.85),
    "subprocess.check_output": ("spawns subprocess", 0.85),
    "subprocess.check_call": ("spawns subprocess", 0.85),
    "os.system": ("invokes shell", 0.95),
    "os.popen": ("invokes shell", 0.95),
    "os.execv": ("invokes shell", 0.9),
    "os.execvp": ("invokes shell", 0.9),
    "os.execve": ("invokes shell", 0.9),
    "eval": ("dynamic code evaluation", 0.9),
    "exec": ("dynamic code evaluation", 0.9),
    "shutil.rmtree": ("recursive filesystem delete", 0.85),
}


def _qname(node) -> str | None:
    """Return a dotted attribute/name for an AST call target, or None."""
    if isinstance(node, ast.Attribute):
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
            return ".".join(reversed(parts))
        return None
    if isinstance(node, ast.Name):
        return node.id
    return None


class _Visitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source: str):
        self.file_path = file_path
        self.source_lines = source.splitlines()
        self.findings: list[Finding] = []

    def _line(self, node) -> int:
        return getattr(node, "lineno", 1)

    def _snip(self, node) -> str:
        return snippet("\n".join(self.source_lines), self._line(node), 2)

    # ---- W001: tool description containing an injection phrase ---- #

    def _check_desc_string(self, s: str, lineno: int):
        hit = POISONING_RE.search(s)
        if not hit:
            return
        self.findings.append(Finding(
            rule_id="W001",
            title="Tool poisoning in tool description",
            severity="CRITICAL",
            file_path=self.file_path,
            line=lineno,
            snippet=snippet("\n".join(self.source_lines), lineno, 2),
            message=(f"Injection-style phrase '{hit.group(0)}' found in a "
                     f"`description`/`prompt`/`instructions` string. Descriptions "
                     f"are model-visible and trusted."),
            remediation="Rewrite the description to be purely factual; remove any 'ignore previous', 'system:', or exfil-style language.",
            doc_link=f"{DOCS_BASE}#w001-tool-poisoning",
            tags=["poisoning", "ast"],
            confidence=confidence(0.95, self.file_path),
        ))

    def visit_Assign(self, node: ast.Assign):
        # description = "..." / prompt = "..." / instructions = "..."
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id.lower()
            if name in {"description", "prompt", "instructions"} and isinstance(node.value, ast.Constant) \
                    and isinstance(node.value.value, str):
                self._check_desc_string(node.value.value, self._line(node))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        # keyword args: description=..., prompt=..., instructions=...
        for kw in node.keywords:
            if kw.arg and kw.arg.lower() in {"description", "prompt", "instructions"} \
                    and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                self._check_desc_string(kw.value.value, self._line(node))
        # W004 -- dangerous call
        qn = _qname(node.func)
        if qn:
            label_conf = DANGEROUS_CALLS.get(qn)
            if label_conf:
                label, base = label_conf
                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if shell_true and qn.startswith("subprocess."):
                    label, base = "shell=True subprocess", 0.95
                self.findings.append(Finding(
                    rule_id="W004",
                    title=f"Over-privileged operation: {label}",
                    severity="HIGH",
                    file_path=self.file_path,
                    line=self._line(node),
                    snippet=self._snip(node),
                    message=(f"AST walk identified `{qn}(...)` — {label}. This grants "
                             f"scope well beyond a typical MCP tool's stated function."),
                    remediation="Constrain the operation: whitelist commands, avoid shell=True, sandbox filesystem access.",
                    doc_link=f"{DOCS_BASE}#w004-over-privileged-tools",
                    tags=["least-privilege", "ast"],
                    confidence=confidence(base, self.file_path),
                ))
        self.generic_visit(node)


def analyze_python_file(file_path: str, source: str) -> Iterable[Finding] | None:
    """Return AST-derived findings for a .py file, or None if it doesn't parse."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    v = _Visitor(file_path, source)
    v.visit(tree)
    return v.findings
