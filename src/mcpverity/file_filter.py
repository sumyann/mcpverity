"""Which files a scan reads -- one definition for local and GitHub scans.

`mcpverity scan ./dir` and `mcpverity scan --github <url>` must see the same
files, and a file passed over for a reason a user would care about (too large
to read, past the GitHub file cap) is reported by the caller instead of being
silently dropped.
"""

SCAN_EXTENSIONS = {
    ".py",
    ".ts", ".tsx", ".mts", ".cts",
    ".js", ".jsx", ".mjs", ".cjs",
    ".json", ".toml", ".yaml", ".yml", ".txt", ".md",
}
# Kept as empty-content presence markers: W005 only checks that one exists,
# and real lockfiles routinely exceed MAX_FILE_BYTES.
LOCKFILE_NAMES = {"yarn.lock", "pnpm-lock.yaml", "bun.lockb", "package-lock.json",
                  "poetry.lock", "Pipfile.lock", "uv.lock", "requirements.lock", "npm-shrinkwrap.json"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".mypy_cache", ".pytest_cache"}
MAX_FILE_BYTES = 200_000
MAX_TOTAL_FILES = 200


def is_dotenv(name: str) -> bool:
    """`.env`, `.env.local`, `.env.production`, ... -- a committed one is a W003 finding."""
    return name == ".env" or name.startswith(".env.")


def classify(rel_path: str) -> str | None:
    """Return "lockfile", "source", or None (not scanned) for a path relative to the scan root.

    Only directories *below* the scan root are matched against SKIP_DIRS -- an
    ancestor named build/ or dist/ must not skip every file.
    """
    parts = rel_path.replace("\\", "/").split("/")
    if any(part in SKIP_DIRS for part in parts[:-1]):
        return None
    name = parts[-1]
    if name in LOCKFILE_NAMES:
        return "lockfile"
    ext = name[name.rfind("."):].lower() if "." in name else ""
    if ext in SCAN_EXTENSIONS or is_dotenv(name):
        return "source"
    return None


def oversize_note(rel_path: str, size: int) -> str:
    return f"{rel_path} ({size // 1000} KB)"
