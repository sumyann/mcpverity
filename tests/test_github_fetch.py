import pytest

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
