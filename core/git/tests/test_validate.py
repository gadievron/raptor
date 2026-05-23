"""URL-allowlist tests."""

import pytest

from core.git.validate import validate_repo_url


def test_github_https_accepted() -> None:
    assert validate_repo_url("https://github.com/torvalds/linux")
    assert validate_repo_url("https://github.com/torvalds/linux/")
    assert validate_repo_url("https://github.com/foo-bar/baz_qux.git")


def test_gitlab_https_accepted() -> None:
    assert validate_repo_url("https://gitlab.com/foo/bar")


def test_ssh_form_accepted() -> None:
    assert validate_repo_url("git@github.com:foo/bar.git")
    assert validate_repo_url("git@gitlab.com:foo/bar.git")


def test_other_hosts_rejected() -> None:
    assert not validate_repo_url("https://bitbucket.org/foo/bar")
    assert not validate_repo_url("https://example.com/repo")
    assert not validate_repo_url("https://github.com.evil.com/foo/bar")


def test_protocol_smuggling_rejected() -> None:
    """Allowlist regex anchors prevent prefix-smuggling attacks."""
    assert not validate_repo_url("ftp://github.com/foo/bar")
    assert not validate_repo_url("file:///etc/passwd")
    assert not validate_repo_url("https://github.com/foo/bar; rm -rf /")


def test_empty_or_malformed_rejected() -> None:
    assert not validate_repo_url("")
    assert not validate_repo_url("not a url")
    assert not validate_repo_url("https://github.com")     # no path
    assert not validate_repo_url("https://github.com/foo")  # no repo


# Regression coverage for the `..`-rejection fix documented at
# core/git/validate.py:27-36. Pre-fix the looser repo-name body
# accepted `..` because `[\w.\-]*` matched two consecutive dots.
# The `\.(?!\.)` lookahead now forbids any double-dot run.
@pytest.mark.parametrize("url", [
    # Trailing double-dot on repo
    "https://github.com/foo/bar..",
    "https://github.com/foo/bar...",
    # Leading double-dot on repo (also rejected because repo body
    # must START with `\w`)
    "https://github.com/foo/..bar",
    # Embedded `..` mid-repo
    "https://github.com/foo/ba..r",
    # Owner contains `..` (owner regex `\w[\w\-]*` doesn't allow `.`
    # at all, so this is double-rejected; included for completeness)
    "https://github.com/foo../bar",
    # Same patterns on gitlab https
    "https://gitlab.com/foo/bar..",
    "https://gitlab.com/foo/ba..r",
    # SCP-style ssh form
    "git@github.com:foo/bar...git",
    "git@gitlab.com:foo/ba..r.git",
])
def test_double_dot_in_repo_name_rejected(url: str) -> None:
    assert not validate_repo_url(url), f"validator wrongly accepted {url!r}"


def test_single_dot_in_repo_name_still_accepted() -> None:
    # The negative lookahead must not block legitimate single-dot
    # uses (e.g. `repo.name`, `foo.bar.git`).
    assert validate_repo_url("https://github.com/foo/bar.name")
    assert validate_repo_url("https://github.com/foo/foo.bar.git")
    assert validate_repo_url("https://gitlab.com/foo/foo.bar")


def test_length_limit_boundary() -> None:
    # validator caps URLs at 2048 chars (DoS guard at validate.py:51).
    # Construct a length-2048 URL by padding the repo name.
    base = "https://github.com/owner/"
    pad_len = 2048 - len(base)
    at_limit = base + ("a" * pad_len)
    over_limit = base + ("a" * (pad_len + 1))
    assert len(at_limit) == 2048
    assert len(over_limit) == 2049
    assert validate_repo_url(at_limit)
    assert not validate_repo_url(over_limit)
