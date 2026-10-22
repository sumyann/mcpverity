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
from urllib.parse import quote

import requests

from .file_filter import LOCKFILE_NAMES, MAX_FILE_BYTES, MAX_TOTAL_FILES, SCAN_EXTENSIONS, classify, oversize_note

MAX_TARBALL_BYTES = 100_000_000  # compressed; refuse rather than buffer an unbounded download
MAX_REF_SEGMENTS = 10  # `/tree/a/b/c/...`: how many prefixes to try as the ref

# Re-exported for benchmark/refresh_fixtures.py.
ALLOWED_EXT = SCAN_EXTENSIONS
__all__ = ["ALLOWED_EXT", "LOCKFILE_NAMES", "MAX_FILE_BYTES", "MAX_TOTAL_FILES",
           "FetchResult", "GitHubFetchError", "fetch_repo_files", "fetch_repo_files_detailed", "parse_repo_url"]


class GitHubFetchError(Exception):
    pass


_REPO_URL_RE = re.compile(
    r"https?://(?:www\.)?github\.com/(?P<owner>[A-Za-z0-9-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?"
    r"(?:/tree/(?P<rest>[^?#]+?))?/?(?:[?#].*)?"
)


def parse_repo_url(url: str) -> tuple[str, str, str]:
    """Return (owner, repo, ref_path).

    ref_path is "HEAD" (the repo's default branch) or everything after
    `/tree/`, which may be a slash-containing branch name followed by a
    subdirectory -- `fetch_repo_files_detailed` works out where the ref ends.
    """
    m = _REPO_URL_RE.fullmatch(url.strip())
    if not m:
        raise GitHubFetchError("Not a valid github.com repo URL (expected https://github.com/<owner>/<repo>[/tree/<ref>[/<dir>]])")
    return m["owner"], m["repo"], m["rest"] or "HEAD"


def _download(tar_url: str) -> bytes | None:
    """Return the tarball bytes, None on 404, or raise on any other failure or oversize."""
    r = requests.get(tar_url, timeout=25, stream=True)
    if r.status_code == 404:
        return None
    if r.status_code != 200:
        raise GitHubFetchError(f"GitHub returned {r.status_code} for {tar_url}")
    buf = bytearray()
    for chunk in r.iter_content(chunk_size=1 << 16):
        buf += chunk
        if len(buf) > MAX_TARBALL_BYTES:
            r.close()
            raise GitHubFetchError(f"Repo tarball exceeds {MAX_TARBALL_BYTES // 1_000_000} MB; "
                                   "clone it and scan locally instead.")
    return bytes(buf)


def _fetch_tarball(owner: str, repo: str, ref_path: str) -> tuple[bytes, str]:
    """Return (tarball, subdir). Tries ref prefixes shortest-first, since branch names may contain '/'."""
    segments = ref_path.split("/")
    for i in range(1, min(len(segments), MAX_REF_SEGMENTS) + 1):
        ref = "/".join(segments[:i])
        blob = _download(f"https://codeload.github.com/{owner}/{repo}/tar.gz/{quote(ref, safe='/')}")
        if blob is not None:
            return blob, "/".join(segments[i:])
    raise GitHubFetchError(f"GitHub returned 404 for {owner}/{repo} at '{ref_path}' "
                           "(repo is private or missing, or the branch/tag/commit doesn't exist)")


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
    owner, repo, ref_path = parse_repo_url(url)
    blob, subdir = _fetch_tarball(owner, repo, ref_path)
    prefix = f"{subdir}/" if subdir else ""

    buf = io.BytesIO(blob)
    result = FetchResult()
    with tarfile.open(fileobj=buf, mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            path_parts = member.name.split("/", 1)
            rel = path_parts[1] if len(path_parts) > 1 else member.name
            if prefix:
                # /tree/<ref>/<dir>: scan that directory as the root, like a local subdir scan.
                if not rel.startswith(prefix):
                    continue
                rel = rel[len(prefix):]
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
