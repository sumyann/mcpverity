"""Shared regex signals, scoring helpers, and the Rule interface.

Every rule in this package is a pure function of (files, manifests) -> list
of Findings — no I/O, no network, no persistence. That's a deliberate
invariant: `pip install mcpverity` plus `mcpverity scan ./some-dir` must never
make a network call. See docs/architecture.md.
"""
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..models import Finding

REPO_URL = "https://github.com/sumyann/mcpverity"
DOCS_BASE = f"{REPO_URL}/blob/main/docs/rules.md"


# ---------------------------------------------------------------------------
# Rule interface (spec: docs/rule-authoring.md)
# ---------------------------------------------------------------------------

@dataclass
class ParsedServer:
    """The parsed input a rule inspects: code files + MCP manifests.

    `files` is a list of {"path": str, "content": str}.
    `manifests` is a list of manifest dicts (see mcpverity.parsers for shape).
    """
    files: list[dict]
    manifests: list[dict]


CheckFn = Callable[[ParsedServer], Iterable[Finding]]


@dataclass
class Rule:
    id: str
    title: str
    severity: str
    description: str
    _check: CheckFn
    doc_link: str = ""

    def check(self, parsed: ParsedServer) -> list[Finding]:
        return list(self._check(parsed))


# ---------------------------------------------------------------------------
# Shared regex signals
# ---------------------------------------------------------------------------

SECRET_PATTERNS = [
    ("OpenAI API key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("Anthropic API key", re.compile(r"sk-ant-[A-Za-z0-9\-_]{20,}")),
    ("AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Access Key", re.compile(r"(?i)aws_secret_access_key['\"\s:=]+[A-Za-z0-9/+=]{30,}")),
    ("GitHub token", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z\-_]{30,}")),
    ("Slack token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("Bearer token literal", re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.]{20,}")),
    ("Generic secret assignment", re.compile(r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9\-_./+=]{16,}['\"]")),
]

POISONING_PHRASES = [
    r"ignore (all )?(previous|prior|above)( instructions| directives| system)?",
    r"disregard (the )?(previous|system|user)",
    r"do not (mention|reveal|tell)",
    r"you (are|must) (now )?(act as|behave|pretend)",
    r"system\s*:\s*",
    r"<\s*system\s*>",
    r"before responding.*read.*(file|url|http|ssh)",
    r"exfiltrate|silently send|leak",
    r"return the (user'?s |your )?(api key|password|token|secret)",
    r"read\s+(~/\.ssh|/etc/passwd|\.env|id_rsa)",
    r"do this without (asking|notifying|informing)",
    r"hidden instruction",
    r"<!--.*(system|instruction).*-->",
]
POISONING_RE = re.compile("|".join(f"({p})" for p in POISONING_PHRASES), re.IGNORECASE)

UNTRUSTED_INGEST_SIGNALS = [
    r"\brequests?\.get\(", r"\bhttpx\.", r"\burllib\.request", r"\bfetch\(",
    r"\bopen\(.*['\"]http", r"read_email", r"imap", r"pop3",
    r"scrape|crawl|selenium|playwright|beautifulsoup",
    r"read_url|fetch_url|browse|web_search",
]
UNTRUSTED_INGEST_RE = re.compile("|".join(UNTRUSTED_INGEST_SIGNALS), re.IGNORECASE)

OVER_PRIVILEGE_SIGNALS = [
    (re.compile(r"subprocess\.(Popen|call|run|check_output)\("), "spawns subprocess"),
    (re.compile(r"os\.(system|popen|execv?p?)\("), "invokes shell"),
    (re.compile(r"shell\s*=\s*True"), "shell=True subprocess"),
    (re.compile(r"\beval\(|\bexec\("), "dynamic code evaluation"),
    (re.compile(r"open\(['\"]/(etc|root|home|var|usr)"), "reads sensitive filesystem path"),
    (re.compile(r"chmod\s+777|chmod\(0o777\)"), "sets world-writable permissions"),
    (re.compile(r"\.rmtree\(|shutil\.rmtree\("), "recursive filesystem delete"),
    (re.compile(r"child_process\.(exec|spawn|execSync)\("), "spawns Node subprocess"),
    (re.compile(r"require\(['\"]child_process"), "imports Node child_process"),
]

# Only very specific session-hijack primitives — tightened from an earlier
# version that fired on any variable named `session`.
SESSION_SIGNALS = [
    (re.compile(r"Mcp-Session-Id", re.IGNORECASE), "raw Mcp-Session-Id handling", 0.9),
    (re.compile(r"session[_-]?id\s*=\s*request\.(headers|args|query|params|cookies)"),
     "session id read from client request", 0.85),
    (re.compile(r"^\s*sessions?\s*:\s*[Dd]ict.*=\s*\{\s*\}\s*$", re.MULTILINE),
     "module-level in-memory session store", 0.7),
    (re.compile(r"stateful[_-]?http|streamable[_-]?http", re.IGNORECASE),
     "stateful HTTP MCP transport", 0.85),
]

# Covert-invocation signals — each has a base confidence and (optionally) a
# requirement that the same file must also contain a write/exec op.
COVERT_SIGNALS = [
    (re.compile(r"requires_confirmation\s*[:=]\s*(false|False|0)"),
     "confirmation disabled", 0.9, False),
    (re.compile(r"auto[_-]?execute\s*[:=]\s*(true|True|1)"),
     "auto-execute flag enabled", 0.9, False),
    (re.compile(r"\bfire_and_forget\b|\bbackground_task\b"),
     "fire-and-forget invocation", 0.75, True),
    (re.compile(r"@server\.startup|@app\.on_event\(['\"]startup"),
     "runs on server startup", 0.7, True),
    (re.compile(r"\bsilently\b(?!\s+ignored?\b)"),
     "silent-invocation keyword", 0.6, True),
]

# File-content markers that identify an MCP server / tool implementation.
# Used to gate noisy rules (W006, W007) so they don't fire on random utilities.
MCP_CONTEXT_RE = re.compile(
    r"\b(from\s+mcp|import\s+mcp|@server\.tool|@mcp\.tool|list_tools|call_tool|"
    r"CallToolRequest|ListToolsRequest|@tool\b|McpServer\b|Model[Cc]ontext[Pp]rotocol)",
)
# HTTP-transport markers — files that expose the MCP over HTTP are the ones
# where session risks matter.
HTTP_SERVER_RE = re.compile(
    r"\b(FastAPI|starlette|@app\.(get|post|route)|express\(\)|http\.createServer|"
    r"http\.Server\(|BaseHTTPRequestHandler|StreamableHTTPServer)",
)

# Paths that indicate example / test / mock code — findings there get de-prioritized.
LOW_CONF_PATH_RE = re.compile(
    r"(?i)(^|/)(tests?|__tests__|specs?|mocks?|examples?|fixtures?|samples?|"
    r"demo(s)?|docs|documentation|node_modules|dist|build|vendor|third_party)($|/)"
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def snippet(content: str, line: int, ctx: int = 1) -> str:
    lines = content.splitlines()
    lo, hi = max(0, line - 1 - ctx), min(len(lines), line + ctx)
    return "\n".join(lines[lo:hi])


def find_line(content: str, match_start: int) -> int:
    return content.count("\n", 0, match_start) + 1


def in_low_conf_path(path: str) -> bool:
    return bool(LOW_CONF_PATH_RE.search(path))


def confidence(base: float, file_path: str, delta: float = 0.0) -> float:
    c = base
    if in_low_conf_path(file_path):
        c -= 0.35
    c += delta
    return max(0.05, min(1.0, round(c, 2)))


def is_mcp_file(content: str) -> bool:
    return bool(MCP_CONTEXT_RE.search(content))


def is_http_server_file(content: str) -> bool:
    return bool(HTTP_SERVER_RE.search(content))


def has_write_or_exec(content: str) -> bool:
    for pat, _ in OVER_PRIVILEGE_SIGNALS:
        if pat.search(content):
            return True
    return False
