"""Fetch a public GitHub repo tarball and extract relevant files.

This is the one module in mcpverity's core that talks to the network. It is
never imported by `engine.py`, `rules/`, or `parsers.py` at module scope --
only `cli.py` imports it, and only inside the `--github` code path. Nothing
here runs unless a user explicitly asks to scan a remote repo.
"""
import io
import re
import tarfile
from dataclasses import dataclass, field

import requests

from .file_filter import LOCKFILE_NAMES, MAX_FILE_BYTES, MAX_TOTAL_FILES, SCAN_EXTENSIONS, classify, oversize_note

# Re-exported for benchmark/refresh_fixtures.py.
ALLOWED_EXT = SCAN_EXTENSIONS
__all__ = ["ALLOWED_EXT", "LOCKFILE_NAMES", "MAX_FILE_BYTES", "MAX_TOTAL_FILES",
           "FetchResult", "GitHubFetchError", "fetch_repo_files", "fetch_repo_files_detailed", "parse_repo_url"]


class GitHubFetchError(Exception):
    pass


def parse_repo_url(url: str) -> tuple[str, str, str]:
    """Return (owner, repo, ref)."""
    m = re.match(r"https?://github\.com/([^/]+)/([^/#?]+)(?:/tree/([^/#?]+))?", url.strip())
    if not m:
        raise GitHubFetchError("Not a valid github.com repo URL")
    owner, repo, ref = m.group(1), m.group(2).replace(".git", ""), m.group(3) or "HEAD"
    return owner, repo, ref


@dataclass
class FetchResult:
    files: list[dict] = field(default_factory=list)
    oversized: list[str] = field(default_factory=list)  # scannable files over MAX_FILE_BYTES
    unreadable: list[str] = field(default_factory=list)
    candidates: int = 0  # scannable files in the repo, including any past MAX_TOTAL_FILES

    @property
    def truncated(self) -> bool:
        return self.candidates > len(self.files)


def fetch_repo_files(url: str) -> list[dict]:
    return fetch_repo_files_detailed(url).files


def fetch_repo_files_detailed(url: str) -> FetchResult:
    """Fetch a repo's scannable files and record which ones were passed over and why."""
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
    result = FetchResult()
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            path_parts = member.name.split("/", 1)
            rel = path_parts[1] if len(path_parts) > 1 else member.name
            kind = classify(rel)
            if kind is None:
                continue
            if kind == "source" and member.size > MAX_FILE_BYTES:
                result.oversized.append(oversize_note(rel, member.size))
                continue
            result.candidates += 1
            # Keep counting past the cap so the caller can say how much was left out.
            if len(result.files) >= MAX_TOTAL_FILES:
                continue
            if kind == "lockfile":
                # Presence marker (empty content is fine -- rules only check presence).
                result.files.append({"path": rel, "content": ""})
                continue
            try:
                data = tf.extractfile(member).read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001 - recorded, reported by the caller
                result.unreadable.append(rel)
                result.candidates -= 1
                continue
            result.files.append({"path": rel, "content": data})
    return result
