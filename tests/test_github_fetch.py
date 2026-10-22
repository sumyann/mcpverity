import io
import tarfile

import pytest

from mcpverity import github_fetch
from mcpverity.github_fetch import GitHubFetchError, parse_repo_url


def test_parse_repo_url_basic():
    assert parse_repo_url("https://github.com/octocat/Hello-World") == ("octocat", "Hello-World", "HEAD")


def test_parse_repo_url_with_git_suffix():
    assert parse_repo_url("https://github.com/octocat/Hello-World.git") == ("octocat", "Hello-World", "HEAD")


def test_parse_repo_url_with_tree_ref():
    owner, repo, ref = parse_repo_url("https://github.com/octocat/Hello-World/tree/develop")
    assert (owner, repo, ref) == ("octocat", "Hello-World", "develop")


def test_parse_repo_url_invalid_raises():
    with pytest.raises(GitHubFetchError):
        parse_repo_url("not a url")


# ---------- URL forms that used to be mangled ----------

@pytest.mark.parametrize("url,expected", [
    ("https://github.com/o/my.github.io", ("o", "my.github.io", "HEAD")),  # was "myhub.io"
    ("https://github.com/o/r/tree/feature/login-fix", ("o", "r", "feature/login-fix")),  # was "feature"
    ("https://github.com/o/r/tree/main/servers/fetch", ("o", "r", "main/servers/fetch")),
    ("https://www.github.com/o/r", ("o", "r", "HEAD")),  # was rejected
    ("https://github.com/o/r/", ("o", "r", "HEAD")),
    ("https://github.com/o/r?tab=readme-ov-file", ("o", "r", "HEAD")),
    ("https://github.com/o/r/tree/v1.2/?x=1", ("o", "r", "v1.2")),
])
def test_parse_repo_url_forms(url, expected):
    assert parse_repo_url(url) == expected


def test_parse_repo_url_rejects_file_links():
    with pytest.raises(GitHubFetchError, match="expected https://github.com/<owner>/<repo>"):
        parse_repo_url("https://github.com/o/r/blob/main/server.py")


# ---------- ref resolution, subdir scoping, download cap ----------

def _tarball(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(f"r-sha/{name}")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class _Resp:
    def __init__(self, content=b"", status_code=200):
        self.status_code, self.content = status_code, content

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def close(self):
        pass


def _serve(monkeypatch, refs: dict[str, bytes]):
    """Fake codeload: 200 with the tarball for known refs, 404 otherwise. Returns the requested URLs."""
    requested = []

    def fake_get(url, **kwargs):
        requested.append(url)
        ref = url.split("/tar.gz/", 1)[1]
        return _Resp(refs[ref]) if ref in refs else _Resp(status_code=404)

    monkeypatch.setattr(github_fetch.requests, "get", fake_get)
    return requested


REPO = _tarball({"server.py": b"x = 1\n", "servers/fetch/tool.py": b"y = 2\n", "servers/fetch/README.md": b"z"})


def test_default_branch_uses_head_not_a_main_master_guess(monkeypatch):
    requested = _serve(monkeypatch, {"HEAD": REPO})
    files = github_fetch.fetch_repo_files("https://github.com/o/r")
    assert requested == ["https://codeload.github.com/o/r/tar.gz/HEAD"]
    assert len(files) == 3


def test_slash_branch_and_subdir_are_resolved(monkeypatch):
    requested = _serve(monkeypatch, {"feature/login-fix": REPO})
    res = github_fetch.fetch_repo_files_detailed("https://github.com/o/r/tree/feature/login-fix/servers/fetch")
    assert requested == ["https://codeload.github.com/o/r/tar.gz/feature",
                         "https://codeload.github.com/o/r/tar.gz/feature/login-fix"]
    assert sorted(f["path"] for f in res.files) == ["README.md", "tool.py"]  # relative to the subdir


def test_unknown_ref_raises_clear_error(monkeypatch):
    _serve(monkeypatch, {})
    with pytest.raises(GitHubFetchError, match="404 for o/r at 'nope'"):
        github_fetch.fetch_repo_files("https://github.com/o/r/tree/nope")


def test_oversized_tarball_is_refused(monkeypatch):
    monkeypatch.setattr(github_fetch, "MAX_TARBALL_BYTES", 1000)
    _serve(monkeypatch, {"HEAD": b"\0" * 5000})
    with pytest.raises(GitHubFetchError, match="exceeds"):
        github_fetch.fetch_repo_files("https://github.com/o/r")


def test_non_404_error_is_not_retried_as_another_ref(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return _Resp(status_code=403)

    monkeypatch.setattr(github_fetch.requests, "get", fake_get)
    with pytest.raises(GitHubFetchError, match="403"):
        github_fetch.fetch_repo_files("https://github.com/o/r/tree/a/b/c")
    assert len(calls) == 1
