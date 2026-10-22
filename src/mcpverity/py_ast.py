"""AST-based Python analysis for W001 (tool poisoning) and W004 (over-privileged).

AST walks skip strings inside comments (Python has none) and docstrings
(unless assigned to a variable, or the docstring of an @tool/@prompt/
@resource-decorated function, which FastMCP exposes as the tool
description), which eliminates the "matched inside a comment"
false-positive class that plain regex hits. When the file doesn't
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
    "subprocess.getoutput": ("invokes shell", 0.95),
    "subprocess.getstatusoutput": ("invokes shell", 0.95),
    "asyncio.create_subprocess_shell": ("invokes shell", 0.95),
    "asyncio.subprocess.create_subprocess_shell": ("invokes shell", 0.95),
    "asyncio.create_subprocess_exec": ("spawns subprocess", 0.85),
    "asyncio.subprocess.create_subprocess_exec": ("spawns subprocess", 0.85),
    "pty.spawn": ("spawns subprocess", 0.85),
    "os.posix_spawn": ("spawns subprocess", 0.85),
    "os.posix_spawnp": ("spawns subprocess", 0.85),
    **{f"os.exec{v}": ("invokes shell", 0.9) for v in ("l", "le", "lp", "lpe", "vpe")},
    **{f"os.spawn{v}": ("spawns subprocess", 0.85) for v in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe")},
}
# Modules whose dangerous functions a `from <module> import *` brings into scope.
_STAR_MODULES = {qn.rsplit(".", 1)[0] for qn in DANGEROUS_CALLS if "." in qn}
SENSITIVE_PATH_PREFIXES = ("/etc", "/root", "/home", "/var", "/usr")
WORLD_WRITABLE = 0o777


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


def _collect_aliases(tree: ast.AST) -> dict[str, str]:
    """Map local names to the dotted names they were imported as.

    `import subprocess as sp` -> {"sp": "subprocess"}
    `from os import system as s` -> {"s": "os.system"}
    `from os import *` -> {"system": "os.system", ...} for known dangerous calls
    Scope-insensitive on purpose: an import anywhere in the file counts.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.asname:
                    aliases[a.asname] = a.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for a in node.names:
                if a.name == "*":
                    if node.module in _STAR_MODULES:
                        for qn in DANGEROUS_CALLS:
                            mod, _, fn = qn.rpartition(".")
                            if mod == node.module:
                                aliases.setdefault(fn, qn)
                else:
                    aliases[a.asname or a.name] = f"{node.module}.{a.name}"
    return aliases


def _const_str(node) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


TOOL_DECORATOR_NAMES = {"tool", "prompt", "resource"}


def _is_tool_decorator(node) -> bool:
    """True for @tool, @mcp.tool, @mcp.tool(), @server.prompt(...), etc."""
    target = node.func if isinstance(node, ast.Call) else node
    qn = _qname(target)
    return bool(qn) and qn.rsplit(".", 1)[-1] in TOOL_DECORATOR_NAMES


def _overrides_description(node) -> bool:
    """True when a decorator call sets description= to anything but None."""
    if not isinstance(node, ast.Call):
        return False
    return any(
        kw.arg == "description" and not (isinstance(kw.value, ast.Constant) and kw.value.value is None)
        for kw in node.keywords
    )


class _Visitor(ast.NodeVisitor):
    def __init__(self, file_path: str, source: str, aliases: dict[str, str] | None = None):
        self.file_path = file_path
        self.source_lines = source.splitlines()
        self.findings: list[Finding] = []
        self.aliases = aliases or {}

    def _resolve(self, node) -> str | None:
        """Dotted name a call target really refers to, through imports and indirection.

        Handles `sp.run` (import alias), `run` (from-import), `getattr(os, "system")`,
        `__import__("os").system`, `importlib.import_module("os").system`, and
        `builtins.eval`. Returns None for anything it can't pin to a name.
        """
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._resolve(node.value)
            return f"{base}.{node.attr}" if base else None
        if isinstance(node, ast.Call) and node.args:
            fn = self._resolve(node.func)
            if fn == "getattr" and len(node.args) >= 2:
                base, attr = self._resolve(node.args[0]), _const_str(node.args[1])
                return f"{base}.{attr}" if base and attr else None
            if fn in {"__import__", "importlib.import_module"}:
                return _const_str(node.args[0])
        return None

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

    def _visit_function(self, node):
        # FastMCP / @server.tool: the function docstring *is* the tool
        # description the model sees, so it gets the same check -- unless the
        # decorator passes its own description=, which replaces the docstring.
        tool_decorators = [d for d in node.decorator_list if _is_tool_decorator(d)]
        if tool_decorators and not any(_overrides_description(d) for d in tool_decorators):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                self._check_desc_string(doc, self._line(node.body[0]))
        self.generic_visit(node)

    visit_FunctionDef = _visit_function
    visit_AsyncFunctionDef = _visit_function

    def visit_Dict(self, node: ast.Dict):
        # {"description": "..."} -- e.g. tool schemas returned from list_tools.
        for k, v in zip(node.keys, node.values, strict=True):
            if isinstance(k, ast.Constant) and isinstance(k.value, str) \
                    and k.value.lower() in {"description", "prompt", "instructions"} \
                    and isinstance(v, ast.Constant) and isinstance(v.value, str):
                self._check_desc_string(v.value, self._line(v))
        self.generic_visit(node)

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
        written = _qname(node.func)
        qn = self._resolve(node.func)
        if qn and qn.startswith("builtins."):
            qn = qn[len("builtins."):]
        if qn:
            label_conf = DANGEROUS_CALLS.get(qn) or self._risky_args(qn, node)
            if label_conf:
                label, base = label_conf
                shell_true = any(
                    kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                    for kw in node.keywords
                )
                if shell_true and qn.startswith("subprocess."):
                    label, base = "shell=True subprocess", 0.95
                via = f" (written as `{written or ast.unparse(node.func)}`)" if written != qn else ""
                self.findings.append(Finding(
                    rule_id="W004",
                    title=f"Over-privileged operation: {label}",
                    severity="HIGH",
                    file_path=self.file_path,
                    line=self._line(node),
                    snippet=self._snip(node),
                    message=(f"AST walk identified `{qn}(...)`{via} — {label}. This grants "
                             f"scope well beyond a typical MCP tool's stated function."),
                    remediation="Constrain the operation: whitelist commands, avoid shell=True, sandbox filesystem access.",
                    doc_link=f"{DOCS_BASE}#w004-over-privileged-tools",
                    tags=["least-privilege", "ast"],
                    confidence=confidence(base, self.file_path),
                ))
        self.generic_visit(node)

    @staticmethod
    def _risky_args(qn: str, node: ast.Call) -> tuple[str, float] | None:
        """Calls that are only over-privileged with certain literal arguments."""
        if qn in {"open", "io.open"} and node.args:
            path = _const_str(node.args[0])
            if path and path.startswith(SENSITIVE_PATH_PREFIXES):
                return "reads sensitive filesystem path", 0.8
        if qn in {"os.chmod", "os.fchmod", "os.lchmod"} and len(node.args) >= 2:
            mode = node.args[1]
            if isinstance(mode, ast.Constant) and mode.value == WORLD_WRITABLE:
                return "sets world-writable permissions", 0.8
        return None


def analyze_python_file(file_path: str, source: str) -> Iterable[Finding] | None:
    """Return AST-derived findings for a .py file, or None if it doesn't parse."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    v = _Visitor(file_path, source, _collect_aliases(tree))
    v.visit(tree)
    return v.findings
