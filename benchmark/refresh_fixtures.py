"""Dev-only: re-pin the benchmark fixtures from the labeled repos' current HEAD.

This is NOT run in CI and NOT part of the installed package -- it exists so a
maintainer can periodically refresh benchmark/servers/<slug>/ to track the
labeled upstream repos, re-verify each one's license still permits
redistribution, and re-write NOTICE.md with the new commit SHA.

Requires `git` on PATH and network access to github.com. Usage:

    python benchmark/refresh_fixtures.py                # refresh all labeled servers
    python benchmark/refresh_fixtures.py github/github-mcp-server   # just one

After running, review the diff under benchmark/servers/ before committing --
a refresh can change which findings the benchmark expects, so re-run
`python benchmark/run_benchmark.py` and update labels.yaml if needed.
"""
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from mcpverity.github_fetch import ALLOWED_EXT, LOCKFILE_NAMES, MAX_FILE_BYTES, MAX_TOTAL_FILES  # noqa: E402

PERMISSIVE_LICENSE_MARKERS = (
    "mit license", "apache license", "bsd license", "the mit license",
    "isc license", "mozilla public license",
)


def slugify(server_name: str) -> str:
    return server_name.replace("/", "__")


def find_license_text(repo_dir: Path) -> str:
    for candidate in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING"):
        p = repo_dir / candidate
        if p.exists():
            return p.read_text(encoding="utf-8", errors="replace")
    return ""


def is_redistribution_permitted(license_text: str) -> bool:
    lowered = license_text.lower()
    return any(marker in lowered for marker in PERMISSIVE_LICENSE_MARKERS)


def clone(repo_url: str, dest: Path) -> str:
    subprocess.run(["git", "clone", "--depth", "1", repo_url, str(dest)], check=True, capture_output=True)
    sha = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], check=True, capture_output=True, text=True).stdout.strip()
    return sha


def extract_files(repo_dir: Path) -> list:
    files = []
    for p in sorted(repo_dir.rglob("*")):
        if not p.is_file() or ".git" in p.parts:
            continue
        rel = p.relative_to(repo_dir)
        basename = p.name
        ext = p.suffix.lower()
        if basename in LOCKFILE_NAMES:
            files.append({"path": str(rel), "content": ""})
        else:
            if ext not in ALLOWED_EXT:
                continue
            try:
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
                content = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            files.append({"path": str(rel), "content": content})
        if len(files) >= MAX_TOTAL_FILES:
            break
    return files


def refresh_one(server_name: str, repo_url: str) -> None:
    slug = slugify(server_name)
    out_dir = HERE / "servers" / slug
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp) / "repo"
        print(f"[{server_name}] cloning {repo_url} ...")
        sha = clone(repo_url, tmp_path)
        license_text = find_license_text(tmp_path)
        if not license_text:
            print(f"[{server_name}] WARNING: no LICENSE file found -- skipping fixture pin.")
            return
        if not is_redistribution_permitted(license_text):
            print(f"[{server_name}] WARNING: license does not look redistribution-permissive -- "
                  f"skipping fixture pin. Use a SHA-pinned live fetch instead.")
            return

        files = extract_files(tmp_path)

        if out_dir.exists():
            shutil.rmtree(out_dir)
        files_dir = out_dir / "files"
        files_dir.mkdir(parents=True)
        for f in files:
            dest = files_dir / f["path"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(f["content"], encoding="utf-8")

        (out_dir / "LICENSE").write_text(license_text, encoding="utf-8")
        notice = (
            f"# NOTICE for {server_name}\n\n"
            f"This fixture is a pinned subset of source files from:\n\n"
            f"- Repository: {repo_url}\n"
            f"- Commit: {sha}\n"
            f"- Pinned: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}\n\n"
            f"Redistributed here under the upstream license (see LICENSE in this "
            f"directory) solely as a fixed benchmark fixture for the MCPVerity scanner's "
            f"precision/recall benchmark. Only files matching MCPVerity's scan allowlist "
            f"({', '.join(sorted(ALLOWED_EXT))}) plus lockfiles are included; binary and "
            f"unrelated assets were dropped. This is not a full mirror of the project.\n"
        )
        (out_dir / "NOTICE.md").write_text(notice, encoding="utf-8")
        print(f"[{server_name}] pinned {len(files)} files at {sha[:12]} -> {out_dir}")


def main():
    labels = yaml.safe_load((HERE / "labels.yaml").read_text())
    only = sys.argv[1] if len(sys.argv) > 1 else None
    for entry in labels.get("servers", []):
        name = entry["server_name"]
        if only and name != only:
            continue
        repo_url = f"https://github.com/{name}.git"
        refresh_one(name, repo_url)


if __name__ == "__main__":
    main()
