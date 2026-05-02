"""Clone- and fetch-wrapper tests - subprocess + sandbox stubbed."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from core.git.clone import clone_repository, fetch_commit


_VALID_SHA = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


def _completed(rc: int, stderr: str = "",
               stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=rc, stdout=stdout, stderr=stderr,
    )


def test_invalid_url_raises_before_subprocess(tmp_path: Path) -> None:
    """URL that fails allowlist must NOT reach the sandboxed runner."""
    with patch("core.sandbox.run_untrusted") as mock_run:
        with pytest.raises(ValueError):
            clone_repository("https://evil.example.com/repo",
                              tmp_path / "out")
        mock_run.assert_not_called()


def test_successful_clone_calls_sandbox(tmp_path: Path) -> None:
    """Allowlisted URL flows through ``run_untrusted`` with the right
    flags - depth, no-tags, target/output set, proxy hosts pinned."""
    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(0)
        ok = clone_repository(
            "https://github.com/foo/bar", tmp_path / "out",
        )
        assert ok is True
        assert mock_run.called
        cmd = mock_run.call_args.args[0]
        assert cmd[:4] == ["git", "clone", "--depth", "1"]
        kwargs = mock_run.call_args.kwargs
        proxy_hosts = set(kwargs.get("proxy_hosts", []))
        assert {"github.com", "codeload.github.com"} <= proxy_hosts


def test_clone_failure_raises_runtime_error(tmp_path: Path) -> None:
    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(128, stderr="fatal: not found")
        with pytest.raises(RuntimeError, match="not found"):
            clone_repository("https://github.com/foo/bar",
                              tmp_path / "out")


def test_clone_engages_egress_proxy(tmp_path: Path) -> None:
    """``proxy_hosts=[...]`` only engages the egress proxy when paired
    with ``use_egress_proxy=True``. Without the flag, the sandbox keeps
    ``block_network=True`` and the child has no network at all — clones
    silently fail. Pin both kwargs so future refactors can't drop one."""
    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(0)
        clone_repository("https://github.com/foo/bar", tmp_path / "out")
        kwargs = mock_run.call_args.kwargs
        assert kwargs.get("use_egress_proxy") is True
        assert "github.com" == kwargs.get("proxy_hosts", [])[0]


# ---------------------------------------------------------------------------
# Writable-path validator (shared by both functions)
# ---------------------------------------------------------------------------
#
# The sandbox grants the child write access to ``target.parent``
# (clone) / ``repo_dir.parent`` (fetch). Pathological inputs would
# silently widen that scope to the entire filesystem.

@pytest.mark.parametrize("bad_path", [
    Path(""),               # empty → "." (not absolute)
    Path("."),              # cwd → not absolute
    Path("relative/repo"),  # not absolute
    Path("/"),              # filesystem root itself
    Path("/foo"),           # parent is filesystem root
    Path("/etc"),           # parent is filesystem root
])
def test_clone_rejects_unsafe_target_path_before_subprocess(
    bad_path: Path,
) -> None:
    with patch("core.sandbox.run_untrusted") as mock_run:
        with pytest.raises(ValueError):
            clone_repository("https://github.com/foo/bar", bad_path)
        mock_run.assert_not_called()


@pytest.mark.parametrize("bad_path", [
    Path(""),
    Path("."),
    Path("relative/repo"),
    Path("/"),
    Path("/foo"),
    Path("/etc"),
])
def test_fetch_rejects_unsafe_repo_dir_before_subprocess(
    bad_path: Path,
) -> None:
    with patch("core.sandbox.run_untrusted") as mock_run:
        with pytest.raises(ValueError):
            fetch_commit(bad_path,
                         "https://github.com/foo/bar", _VALID_SHA)
        mock_run.assert_not_called()


def test_full_clone_drops_depth_flag(tmp_path: Path) -> None:
    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(0)
        clone_repository("https://github.com/foo/bar",
                          tmp_path / "out", depth=None)
        cmd = mock_run.call_args.args[0]
        assert "--depth" not in cmd
        assert "--no-tags" not in cmd


# ---------------------------------------------------------------------------
# fetch_commit
# ---------------------------------------------------------------------------

def test_fetch_invalid_url_raises_before_subprocess(tmp_path: Path) -> None:
    """Untrusted URL must NOT reach the sandboxed runner."""
    with patch("core.sandbox.run_untrusted") as mock_run:
        with pytest.raises(ValueError):
            fetch_commit(tmp_path / "repo",
                         "https://evil.example.com/repo",
                         _VALID_SHA)
        mock_run.assert_not_called()


def test_fetch_into_fresh_dir_runs_init_then_remote_then_fetch(
    tmp_path: Path,
) -> None:
    """Fresh repo_dir → init, remote add, fetch in that order with the
    expected flags. Network call (fetch) carries proxy_hosts; local
    calls (init / remote) do not."""
    repo = tmp_path / "repo"
    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(0)
        ok = fetch_commit(repo, "https://github.com/foo/bar",
                           _VALID_SHA, depth=5)
        assert ok is True

    cmds = [c.args[0] for c in mock_run.call_args_list]
    assert cmds[0][:4] == ["git", "-C", str(repo), "init"]
    assert cmds[1][:4] == ["git", "-C", str(repo), "remote"]
    assert cmds[1][4:] == ["add", "origin", "https://github.com/foo/bar"]
    assert cmds[2][:5] == ["git", "-C", str(repo), "fetch", "--depth"]
    assert cmds[2][5] == "5"
    assert cmds[2][-2:] == ["origin", _VALID_SHA]

    # Network step engages the egress proxy via use_egress_proxy=True
    # paired with proxy_hosts; local steps don't engage either kwarg.
    # ``proxy_hosts`` without ``use_egress_proxy=True`` is a no-op (the
    # sandbox keeps block_network=True), so both must travel together.
    init_kwargs = mock_run.call_args_list[0].kwargs
    fetch_kwargs = mock_run.call_args_list[2].kwargs
    assert "proxy_hosts" not in init_kwargs
    assert "use_egress_proxy" not in init_kwargs
    assert fetch_kwargs.get("use_egress_proxy") is True
    fetch_proxy_hosts = set(fetch_kwargs.get("proxy_hosts", []))
    assert {"github.com", "codeload.github.com"} <= fetch_proxy_hosts


def test_fetch_into_existing_repo_skips_init(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(0)
        fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)

    cmds = [c.args[0] for c in mock_run.call_args_list]
    # First call should be ``remote add``, not ``init`` —
    # the ``.git`` dir already exists.
    assert "init" not in cmds[0]
    assert cmds[0][3] == "remote"


def test_fetch_existing_origin_remote_falls_back_to_set_url(
    tmp_path: Path,
) -> None:
    """``remote add origin`` collides on a re-used repo; fetch_commit
    must fall through to ``remote set-url`` so the caller can re-aim
    a repo_dir at a different URL."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    def _side_effect(cmd, **kwargs):
        if cmd[3:5] == ["remote", "add"]:
            return _completed(128, stderr="error: remote origin already exists")
        return _completed(0)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect) as mock_run:
        ok = fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)
        assert ok is True

    cmds = [c.args[0] for c in mock_run.call_args_list]
    add_seen = any(c[3:5] == ["remote", "add"] for c in cmds)
    set_url_seen = any(c[3:5] == ["remote", "set-url"] for c in cmds)
    assert add_seen and set_url_seen


def test_fetch_failure_raises_runtime_error(tmp_path: Path) -> None:
    def _side_effect(cmd, **kwargs):
        if cmd[3] == "fetch":
            return _completed(128, stderr="fatal: couldn't find remote ref")
        return _completed(0)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect):
        with pytest.raises(RuntimeError, match="couldn't find remote ref"):
            fetch_commit(tmp_path / "repo",
                         "https://github.com/foo/bar", _VALID_SHA)


def test_fetch_init_failure_raises_runtime_error(tmp_path: Path) -> None:
    def _side_effect(cmd, **kwargs):
        if "init" in cmd:
            return _completed(1, stderr="permission denied")
        return _completed(0)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect):
        with pytest.raises(RuntimeError, match="git init failed"):
            fetch_commit(tmp_path / "repo",
                         "https://github.com/foo/bar", _VALID_SHA)


@pytest.mark.parametrize("bad_sha", [
    "--upload-pack=evil",
    "-X",
    "--exec=cmd",
    "",
    "not-hex-zzz",
    "deadbeef--upload-pack=evil",
    "deadbeef ",        # trailing whitespace
    "0123456789abcdef0123456789abcdef0123456701234567",  # >40 chars
    "abc",              # <4 chars
    "../../etc/passwd",
    "deadbeef\n",       # `$` slips trailing newline through; fullmatch rejects
    "\ndeadbeef",       # leading newline
    "dead\nbeef",       # embedded newline
    "deadbeef\x00",     # NUL byte
])
def test_fetch_rejects_bad_sha_before_subprocess(
    tmp_path: Path, bad_sha: str,
) -> None:
    """Tainted SHA must NOT reach ``git fetch`` — flag-position
    injection (``--upload-pack=...``) would otherwise be parsed as a
    fetch flag and, on SSH transport, run a chosen command remotely
    (CVE-2017-1000117 family)."""
    with patch("core.sandbox.run_untrusted") as mock_run:
        with pytest.raises(ValueError, match="SHA"):
            fetch_commit(tmp_path / "repo",
                         "https://github.com/foo/bar", bad_sha)
        mock_run.assert_not_called()


def test_fetch_accepts_short_sha(tmp_path: Path) -> None:
    """Git allows abbreviated SHAs of 4+ chars; we must too."""
    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(0)
        fetch_commit(tmp_path / "repo",
                     "https://github.com/foo/bar", "deadbe")


def test_fetch_remote_add_failure_surfaces_both_errors(
    tmp_path: Path,
) -> None:
    """When remote add AND set-url both fail, the raised RuntimeError
    must include both stderrs so the operator sees the real cause
    (disk full / FS error / etc.) rather than only the echo from
    set-url."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    def _side_effect(cmd, **kwargs):
        if cmd[3:5] == ["remote", "add"]:
            return _completed(128, stderr="error: cannot create file (disk full)")
        if cmd[3:5] == ["remote", "set-url"]:
            return _completed(128, stderr="error: No such remote 'origin'")
        return _completed(0)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect):
        with pytest.raises(RuntimeError) as exc:
            fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)
        msg = str(exc.value)
        assert "disk full" in msg
        assert "No such remote" in msg


def test_fetch_sandbox_writable_dir_is_parent_not_repo(
    tmp_path: Path,
) -> None:
    """The sandbox ``output`` (writable allowlist + fake HOME root)
    must be ``repo_dir.parent``, not ``repo_dir`` itself.

    Reason: ``run_untrusted`` defaults to ``fake_home=True`` which
    materialises ``{output}/.home/`` for the child's HOME. If we
    passed ``output=str(repo_dir)``, ``.home/`` would land *inside*
    the fetched repo, polluting the caller's working tree. Matches
    ``clone_repository``'s pattern (which has the same constraint
    when target.parent is its writable scope)."""
    repo = tmp_path / "work" / "repo"
    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(0)
        fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)

    expected_parent = str(repo.parent)
    for call in mock_run.call_args_list:
        kwargs = call.kwargs
        assert kwargs["output"] == expected_parent
        assert kwargs["target"] == expected_parent


def test_fetch_passes_sanitised_env_and_timeout(tmp_path: Path) -> None:
    """Every call uses ``get_safe_git_env`` and the bounded
    ``GIT_CLONE_TIMEOUT`` — no caller-controlled bypass."""
    from core.config import RaptorConfig

    with patch("core.sandbox.run_untrusted") as mock_run:
        mock_run.return_value = _completed(0)
        fetch_commit(tmp_path / "repo",
                     "https://github.com/foo/bar", _VALID_SHA)

    for call in mock_run.call_args_list:
        kwargs = call.kwargs
        assert "GIT_TERMINAL_PROMPT" in kwargs["env"]
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
        assert kwargs["timeout"] == RaptorConfig.GIT_CLONE_TIMEOUT
