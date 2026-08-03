"""W005 -- Unpinned / unverified tool provenance."""
import re
from collections.abc import Iterable

from ..models import Finding
from .base import DOCS_BASE, ParsedServer, Rule, confidence, find_line


def _check(parsed: ParsedServer) -> Iterable[Finding]:
    files, manifests = parsed.files, parsed.manifests
    lockfile_names = ("yarn.lock", "package-lock.json", "pnpm-lock.yaml", "bun.lockb", "npm-shrinkwrap.json")
    has_js_lockfile = any(f["path"].endswith(lockfile_names) for f in files)
    has_py_lockfile = any(f["path"].endswith(("poetry.lock", "Pipfile.lock", "uv.lock", "requirements.lock")) for f in files)

    for f in files:
        if f["path"].endswith("requirements.txt"):
            for i, line in enumerate(f["content"].splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if "git+" in stripped and "@" not in stripped.split("git+")[1]:
                    yield Finding(
                        rule_id="W005",
                        title="Unpinned git+ dependency",
                        severity="MEDIUM",
                        file_path=f["path"], line=i, snippet=stripped,
                        message="Dependency pulled from git without commit / tag pin. A future push to main can silently alter behaviour.",
                        remediation="Pin to a commit SHA or a signed tag: git+https://.../repo@<sha>.",
                        doc_link=f"{DOCS_BASE}#w005-unsigned--unverified-provenance",
                        tags=["provenance", "supply-chain"],
                        confidence=confidence(0.9, f["path"]),
                    )
                elif "==" not in stripped and ">=" not in stripped and "@" not in stripped and stripped and not stripped.startswith("-"):
                    sev = "INFO" if has_py_lockfile else "LOW"
                    yield Finding(
                        rule_id="W005",
                        title="Unpinned dependency version",
                        severity=sev,
                        file_path=f["path"], line=i, snippet=stripped,
                        message=f"Dependency `{stripped}` has no version pin"
                                + (" (lockfile committed -- informational only)." if has_py_lockfile else "; installs will drift."),
                        remediation="Pin exact version with `==` and consider a hash-locked lockfile.",
                        doc_link=f"{DOCS_BASE}#w005-unsigned--unverified-provenance",
                        tags=["provenance"],
                        confidence=confidence(0.6, f["path"]),
                    )
        if f["path"].endswith("package.json"):
            for m in re.finditer(r'"([^"]+)"\s*:\s*"([\^~][^"]*|\*|latest|>=?[^"]*)"', f["content"]):
                spec = m.group(2)
                is_semver_range = spec.startswith(("^", "~"))
                if is_semver_range:
                    if has_js_lockfile:
                        continue
                    sev = "INFO"
                    msg = (f"`{m.group(1)}` uses semver range `{spec}`. This is JS convention, "
                           f"but no lockfile (yarn.lock / package-lock.json) is committed.")
                    remed = "Commit a lockfile to freeze the resolved dependency graph."
                    conf = 0.5
                else:
                    sev = "LOW"
                    msg = f"`{m.group(1)}` uses floating version (`{spec}`)."
                    remed = "Pin exact versions and commit a lockfile (yarn.lock / package-lock.json)."
                    conf = 0.85
                line = find_line(f["content"], m.start())
                yield Finding(
                    rule_id="W005",
                    title="Unpinned npm dependency" if not is_semver_range else "Semver-range npm dependency",
                    severity=sev,
                    file_path=f["path"], line=line, snippet=m.group(0),
                    message=msg,
                    remediation=remed,
                    doc_link=f"{DOCS_BASE}#w005-unsigned--unverified-provenance",
                    tags=["provenance"],
                    confidence=confidence(conf, f["path"]),
                )
    for m in manifests:
        # mcpServers launcher provenance -- the whole point of the format is
        # to download-and-execute a package, so pinning matters a lot.
        if m.get("_kind") == "mcpServers":
            for srv in m.get("servers", []):
                cmd = (srv.get("command") or "").lower()
                args = srv.get("args") or []
                first_pkg = str(args[0]) if args else ""

                # uvx / pipx / npx / bunx runners fetch a package by name; without
                # a version constraint they resolve to whatever is "latest" on
                # the registry.
                if cmd in {"uvx", "pipx", "npx", "bunx"} and first_pkg:
                    if not re.search(r"[@=]", first_pkg) and not first_pkg.startswith("./") \
                            and not first_pkg.startswith("/") and "git+" not in first_pkg:
                        yield Finding(
                            rule_id="W005",
                            title=f"Unpinned {cmd} launcher package",
                            severity="MEDIUM",
                            file_path=m["_path"],
                            line=None,
                            snippet=f"{cmd} {first_pkg}",
                            message=(f"Server '{srv.get('name')}' launches via `{cmd} {first_pkg}` "
                                     f"with no version constraint. Every restart pulls whatever the "
                                     f"registry currently serves -- a hijacked package or a benign "
                                     f"breaking change both ship silently."),
                            remediation=(f"Pin the version: `{cmd} {first_pkg}==<version>` "
                                         f"(uvx/pipx) or `{cmd} {first_pkg}@<version>` (npx). "
                                         f"For maximum assurance, vendor the wheel/tarball."),
                            doc_link=f"{DOCS_BASE}#w005-unsigned--unverified-provenance",
                            tags=["provenance", "mcp-servers", "supply-chain"],
                            confidence=confidence(0.9, m["_path"]),
                        )
                # docker image:latest or no tag at all
                if cmd == "docker":
                    for a in args:
                        s = str(a)
                        if "/" in s and (":latest" in s or (":" not in s and not s.startswith("-"))):
                            yield Finding(
                                rule_id="W005",
                                title="Unpinned Docker image tag",
                                severity="MEDIUM",
                                file_path=m["_path"],
                                line=None,
                                snippet=f"docker ... {s}",
                                message=(f"Server '{srv.get('name')}' launches image `{s}` which is "
                                         f"either untagged or pinned to `:latest`. Docker pulls the "
                                         f"newest image on every restart."),
                                remediation="Pin to an immutable digest: `image@sha256:...`, or at minimum a specific version tag.",
                                doc_link=f"{DOCS_BASE}#w005-unsigned--unverified-provenance",
                                tags=["provenance", "mcp-servers", "supply-chain"],
                                confidence=confidence(0.9, m["_path"]),
                            )
                            break
                # git+ launches without a commit sha
                if "git+" in first_pkg and "@" not in first_pkg.split("git+")[-1]:
                    yield Finding(
                        rule_id="W005",
                        title="Unpinned git+ launcher package",
                        severity="MEDIUM",
                        file_path=m["_path"],
                        line=None,
                        snippet=f"{cmd} {first_pkg}",
                        message=("Launcher pulls the server directly from a git repo without pinning "
                                 "to a commit or tag. A push to main can silently swap the server."),
                        remediation="Append `@<commit-sha>` or `@<signed-tag>` to the git+ URL.",
                        doc_link=f"{DOCS_BASE}#w005-unsigned--unverified-provenance",
                        tags=["provenance", "mcp-servers"],
                        confidence=confidence(0.95, m["_path"]),
                    )
        if not (m.get("signature") or m.get("integrity") or m.get("checksum") or m.get("_kind") == "mcpServers"):
            yield Finding(
                rule_id="W005",
                title="Manifest lacks integrity / signature field",
                severity="LOW",
                file_path=m["_path"], line=None, snippet="",
                message="MCP manifest has no `signature`, `integrity`, or `checksum` field -- clients cannot verify provenance.",
                remediation="Publish a signed manifest (sigstore, minisign) or include a SHA256 integrity of the server bundle.",
                doc_link=f"{DOCS_BASE}#w005-unsigned--unverified-provenance",
                tags=["provenance"],
                confidence=confidence(0.85, m["_path"]),
            )


RULE = Rule(
    id="W005",
    title="Unsigned / Unverified Provenance",
    severity="MEDIUM",
    description="Tools pulled from unlocked sources, unpinned dependencies, or manifests without signature/integrity fields.",
    _check=_check,
    doc_link=f"{DOCS_BASE}#w005-unsigned--unverified-provenance",
)
