"""W003 -- Hardcoded credentials / secrets."""
import re
from collections.abc import Iterable

from ..models import Finding
from .base import DOCS_BASE, SECRET_PATTERNS, ParsedServer, Rule, confidence, find_line, snippet


def _check(parsed: ParsedServer) -> Iterable[Finding]:
    for f in parsed.files:
        for label, pat in SECRET_PATTERNS:
            for m in pat.finditer(f["content"]):
                line = find_line(f["content"], m.start())
                secret = m.group(0)
                # Generic-secret regex is the noisy one -- lower base.
                base = 0.65 if label == "Generic secret assignment" else 0.95
                # Common false positives: obvious placeholders like `xxx`, `changeme`, `example`.
                if re.search(r"(?i)(xxx|changeme|example|dummy|placeholder|<[A-Z_]+>)", secret):
                    base -= 0.35
                yield Finding(
                    rule_id="W003",
                    title=f"Hardcoded secret: {label}",
                    severity="CRITICAL",
                    file_path=f["path"],
                    line=line,
                    snippet=snippet(f["content"], line, 1),
                    message=f"{label} appears hardcoded (`{secret[:12]}...`). This value ships with the code and is model-visible if injected into context.",
                    remediation="Move the secret to an environment variable, load it via os.environ, and rotate the exposed key immediately.",
                    doc_link=f"{DOCS_BASE}#w003-credential--secret-exposure",
                    tags=["secret", "credential"],
                    confidence=confidence(base, f["path"]),
                )

    for m in parsed.manifests:
        # Explicit env-block scan for mcpServers launch configs (Claude Desktop / Cursor / .mcp.json).
        if m.get("_kind") == "mcpServers":
            for srv in m.get("servers", []):
                env_obj = srv.get("env") or {}
                if not isinstance(env_obj, dict):
                    continue
                for env_name, env_val in env_obj.items():
                    if not isinstance(env_val, str):
                        continue
                    # Skip env-var reference placeholders like ${API_KEY}.
                    if re.fullmatch(r"\$\{[A-Z0-9_]+\}", env_val.strip()):
                        continue
                    if len(env_val) < 16:
                        continue
                    # Any long literal value in an env with a secret-y name -> CRITICAL.
                    if re.search(r"(?i)(key|token|secret|password|passwd|auth|api)", env_name):
                        yield Finding(
                            rule_id="W003",
                            title=f"Hardcoded secret in mcpServers env: {env_name}",
                            severity="CRITICAL",
                            file_path=m["_path"],
                            line=None,
                            snippet=f"env.{env_name} = \"{env_val[:24]}...\"",
                            message=f"Server '{srv.get('name')}' has literal env var `{env_name}` embedded in the mcpServers config. Anyone with read access to the config gets the key.",
                            remediation="Replace the literal with a placeholder like `${" + env_name + "}` and load it from the host environment or a secrets manager.",
                            doc_link=f"{DOCS_BASE}#w003-credential--secret-exposure",
                            tags=["secret", "mcp-servers", "credential"],
                            confidence=confidence(0.95, m["_path"]),
                        )
        s = str(m.get("_raw", ""))
        for label, pat in SECRET_PATTERNS:
            for mt in pat.finditer(s):
                yield Finding(
                    rule_id="W003",
                    title=f"Hardcoded secret in manifest: {label}",
                    severity="CRITICAL",
                    file_path=m["_path"],
                    line=None,
                    snippet=mt.group(0)[:80],
                    message=f"{label} embedded in MCP manifest.",
                    remediation="Reference secrets via env placeholder (e.g. ${API_KEY}), never literal values.",
                    doc_link=f"{DOCS_BASE}#w003-credential--secret-exposure",
                    tags=["secret"],
                    confidence=confidence(0.95, m["_path"]),
                )


RULE = Rule(
    id="W003",
    title="Credential & Secret Exposure",
    severity="CRITICAL",
    description="API keys, tokens, or secrets hardcoded in server source or config, or leaking into model-visible context.",
    _check=_check,
    doc_link=f"{DOCS_BASE}#w003-credential--secret-exposure",
)
