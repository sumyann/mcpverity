"""Fetch a public GitHub repo tarball and extract relevant files.

This is the one module in mcpverity's core that talks to the network. It is
never imported by `engine.py`, `rules/`, or `parsers.py` at module scope --
only `cli.py` imports it, and only inside the `--github` code path. Nothing
here runs unless a user explicitly asks to scan a remote repo.
"""
import io
import re
import tarfile

import requests

ALLOWED_EXT = {".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".toml", ".yaml", ".yml", ".txt", ".md"}
LOCKFILE_NAMES = {"yarn.lock", "pnpm-lock.yaml", "bun.lockb", "package-lock.json",
                  "poetry.lock", "Pipfile.lock", "uv.lock", "requirements.lock", "npm-shrinkwrap.json"}
MAX_FILE_BYTES = 200_000
MAX_TOTAL_FILES = 200


class GitHubFetchError(Exception):
    pass


def parse_repo_url(url: str) -> tuple[str, str, str]:
    """Return (owner, repo, ref)."""
    m = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)(?:/tree/([^/#?]+))?", url.strip())
    if not m:
        raise GitHubFetchError("Not a valid github.com repo URL")
    owner, repo, ref = m.group(1), m.group(2).replace(".git", ""), m.group(3) or "HEAD"
    return owner, repo, ref


def fetch_repo_files(url: str) -> list[dict]:
    owner, repo, ref = parse_repo_url(url)
    for candidate in ([ref] if ref != "HEAD" else ["main", "master"]):
        tar_url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/refs/heads/{candidate}"
        r = requests.get(tar_url, timeout=25, stream=True)
        if r.status_code == 200:
            break
    else:
        # last chance: try as tag/sha
        tar_url = f"https://codeload.github.com/{owner}/{repo}/tar.gz/{ref}"
        r = requests.get(tar_url, timeout=25, stream=True)
        if r.status_code != 200:
            raise GitHubFetchError(f"GitHub returned {r.status_code} for {url}")

    buf = io.BytesIO(r.content)
    files: list[dict] = []
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            path_parts = member.name.split("/", 1)
            rel = path_parts[1] if len(path_parts) > 1 else member.name
            basename = rel.rsplit("/", 1)[-1]
            ext = "." + rel.rsplit(".", 1)[-1].lower() if "." in rel else ""
            is_lockfile = basename in LOCKFILE_NAMES

            if is_lockfile:
                # Include lockfile as a marker (empty content is fine -- rules only check presence).
                files.append({"path": rel, "content": ""})
            else:
                if member.size > MAX_FILE_BYTES:
                    continue
                if ext not in ALLOWED_EXT:
                    continue
                try:
                    data = tf.extractfile(member).read().decode("utf-8", errors="replace")
                except Exception:
                    continue
                files.append({"path": rel, "content": data})
            if len(files) >= MAX_TOTAL_FILES:
                break
    return files
