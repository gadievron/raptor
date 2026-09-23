"""Clone- and fetch-wrapper tests - subprocess + sandbox stubbed."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from core.git.clone import clone_repository, fetch_commit, ls_remote

_VALID_SHA = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"


def _strip_pins(cmd: list) -> list:
    """Drop the ``-c key=val`` hardening pairs between ``git`` and the
    subcommand so positional assertions target the semantic argv."""
    assert cmd[0] == "git"
    out = ["git"]
    i = 1
    while i < len(cmd):
        if cmd[i] == "-c":
            i += 2
            continue
        if cmd[i] == "--no-pager":
            i += 1
            continue
        out.append(cmd[i])
        i += 1
    return out


def _completed(rc: int, stderr: str = "",
               stdout: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        args=[], returncode=rc, stdout=stdout, stderr=stderr,
    )


def _local_ok(cmd, **kwargs) -> subprocess.CompletedProcess:
    """side_effect for mocked local git steps under fetch_commit: the
    post-fetch verification resolves FETCH_HEAD via rev-parse, so a
    successful run must echo the requested OID, not empty stdout."""
    if "rev-parse" in cmd:
        return _completed(0, stdout=_VALID_SHA + "\n")
    return _completed(0)


def _clone_materialises(cmd, **kwargs) -> subprocess.CompletedProcess:
    """side_effect for a mocked successful clone: create the destination
    directory (last argv token) like real git would. clone_repository
    verifies host-side materialisation after a zero exit, so a bare
    ``return_value = _completed(0)`` no longer models success."""
    Path(cmd[-1]).mkdir(parents=True, exist_ok=True)
    return _completed(0)


def test_invalid_url_raises_before_subprocess(tmp_path: Path) -> None:
    """URL that fails allowlist must NOT reach the sandboxed runner."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        with pytest.raises(ValueError):
            clone_repository("https://evil.example.com/repo",
                              tmp_path / "out")
        mock_run.assert_not_called()


def test_successful_clone_calls_sandbox(tmp_path: Path) -> None:
    """Allowlisted URL flows through ``run_untrusted_networked`` with the
    right flags - depth, no-tags, target/output set, proxy hosts pinned."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.side_effect = _clone_materialises
        ok = clone_repository(
            "https://github.com/foo/bar", tmp_path / "out",
        )
        assert ok is True
        assert mock_run.called
        cmd = _strip_pins(mock_run.call_args.args[0])
        assert cmd[:4] == ["git", "clone", "--depth", "1"]
        # "--" separates options from the URL: the option/positional
        # boundary must hold even if the URL allowlist ever widens to
        # shapes git could parse as flags.
        assert cmd[-3:] == ["--", "https://github.com/foo/bar",
                            cmd[-1]]
        kwargs = mock_run.call_args.kwargs
        proxy_hosts = set(kwargs.get("proxy_hosts", []))
        assert {"github.com", "codeload.github.com"} <= proxy_hosts


def test_mirror_clone_passes_mirror_flag(tmp_path: Path) -> None:
    """``mirror=True`` produces ``git clone --mirror`` with no shallow
    flags — the git-forensics shape (dangling/force-pushed history
    needs refs a plain clone never fetches)."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.side_effect = _clone_materialises
        ok = clone_repository(
            "https://github.com/foo/bar", tmp_path / "out.git",
            depth=None, mirror=True,
        )
        assert ok is True
        cmd = _strip_pins(mock_run.call_args.args[0])
        assert cmd[:3] == ["git", "clone", "--mirror"]
        assert "--depth" not in cmd
        assert "--no-tags" not in cmd


def test_mirror_with_depth_is_refused(tmp_path: Path) -> None:
    """A shallow mirror would betray the forensic purpose; the
    contradictory combination fails closed before any subprocess."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        with pytest.raises(ValueError):
            clone_repository("https://github.com/foo/bar",
                             tmp_path / "out.git", depth=1, mirror=True)
        mock_run.assert_not_called()


def test_clone_failure_raises_runtime_error(tmp_path: Path) -> None:
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(128, stderr="fatal: not found")
        with pytest.raises(RuntimeError, match="not found"):
            clone_repository("https://github.com/foo/bar",
                              tmp_path / "out")


def test_clone_proxy_hosts_follow_isolated_override(tmp_path: Path) -> None:
    """The conftest fixture redirects the operator proxy-hosts
    override to a per-test path — writing an override THERE must steer
    ``clone_repository``'s allowlist. This pins both the resolution
    seam and the suite's hermeticity: a real operator override (e.g. a
    private-mirror config that bans github.com) can no longer leak
    into these tests."""
    import json

    from core.git import _proxy_hosts as mod

    mod._OVERRIDE_CONFIG_PATH.write_text(
        json.dumps({"hosts": ["mirror.example.test"]}), encoding="utf-8",
    )
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.side_effect = _clone_materialises
        # Any allowlisted-shape URL; the override governs proxy_hosts,
        # not URL validation.
        clone_repository("https://github.com/foo/bar", tmp_path / "out")
        kwargs = mock_run.call_args.kwargs
        assert kwargs.get("proxy_hosts") == ["mirror.example.test"]


def test_clone_engages_egress_proxy(tmp_path: Path) -> None:
    """``run_untrusted_networked`` implicitly engages the egress proxy.
    Pin ``proxy_hosts`` so future refactors can't drop it."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.side_effect = _clone_materialises
        clone_repository("https://github.com/foo/bar", tmp_path / "out")
        kwargs = mock_run.call_args.kwargs
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
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
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
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.side_effect = _clone_materialises
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
    expected flags. Network call (fetch) goes through
    ``run_untrusted_networked``; local calls (init / remote) go through
    ``run_untrusted``."""
    repo = tmp_path / "repo"
    with patch("core.sandbox.run_untrusted") as mock_local, \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_local.side_effect = _local_ok
        mock_net.return_value = _completed(0)
        ok = fetch_commit(repo, "https://github.com/foo/bar",
                           _VALID_SHA, depth=5)
        assert ok is True

    local_cmds = [_strip_pins(c.args[0]) for c in mock_local.call_args_list]
    net_cmds = [_strip_pins(c.args[0]) for c in mock_net.call_args_list]
    assert local_cmds[0][:4] == ["git", "-C", str(repo), "init"]
    assert local_cmds[1][:4] == ["git", "-C", str(repo), "remote"]
    assert local_cmds[1][4:] == ["add", "origin", "https://github.com/foo/bar"]
    assert net_cmds[0][:5] == ["git", "-C", str(repo), "fetch", "--depth"]
    assert net_cmds[0][5] == "5"
    assert net_cmds[0][-2:] == ["origin", _VALID_SHA]

    # Local calls don't carry proxy_hosts.
    init_kwargs = mock_local.call_args_list[0].kwargs
    assert "proxy_hosts" not in init_kwargs

    # Network call carries proxy_hosts via run_untrusted_networked.
    fetch_kwargs = mock_net.call_args.kwargs
    fetch_proxy_hosts = set(fetch_kwargs.get("proxy_hosts", []))
    assert {"github.com", "codeload.github.com"} <= fetch_proxy_hosts


def test_fetch_into_existing_repo_skips_init(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    with patch("core.sandbox.run_untrusted") as mock_local, \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_local.side_effect = _local_ok
        mock_net.return_value = _completed(0)
        fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)

    cmds = [_strip_pins(c.args[0]) for c in mock_local.call_args_list]
    # No ``init`` — the ``.git`` dir already exists. The first local
    # call is the pre-existing-config audit (config --local -z --list),
    # then ``remote add``.
    assert not any("init" in c for c in cmds)
    assert cmds[0][3] == "config"
    assert "--local" in cmds[0]
    # ... then the history-rewrite audit (replace refs + grafts),
    # then ``remote add``.
    assert cmds[1][3] == "for-each-ref"
    assert cmds[3][3] == "remote"


def test_fetch_existing_origin_remote_falls_back_to_set_url(
    tmp_path: Path,
) -> None:
    """``remote add origin`` collides on a re-used repo; fetch_commit
    must fall through to ``remote set-url`` so the caller can re-aim
    a repo_dir at a different URL."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    def _side_effect(cmd, **kwargs):
        if _strip_pins(cmd)[3:5] == ["remote", "add"]:
            return _completed(128, stderr="error: remote origin already exists")
        return _local_ok(cmd, **kwargs)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect) as mock_local, \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_net.return_value = _completed(0)
        ok = fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)
        assert ok is True

    cmds = [_strip_pins(c.args[0]) for c in mock_local.call_args_list]
    add_seen = any(c[3:5] == ["remote", "add"] for c in cmds)
    set_url_seen = any(c[3:5] == ["remote", "set-url"] for c in cmds)
    assert add_seen and set_url_seen


def test_fetch_failure_raises_runtime_error(tmp_path: Path) -> None:
    with patch("core.sandbox.run_untrusted") as mock_local, \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_local.return_value = _completed(0)
        mock_net.return_value = _completed(
            128, stderr="fatal: couldn't find remote ref")
        with pytest.raises(RuntimeError, match="couldn't find remote ref"):
            fetch_commit(tmp_path / "repo",
                         "https://github.com/foo/bar", _VALID_SHA)


def test_fetch_init_failure_raises_runtime_error(tmp_path: Path) -> None:
    def _side_effect(cmd, **kwargs):
        if "init" in cmd:
            return _completed(1, stderr="permission denied")
        return _completed(0)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect), \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_net.return_value = _completed(0)
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
    with patch("core.sandbox.run_untrusted") as mock_local, \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_local.return_value = _completed(0)
        mock_net.return_value = _completed(0)
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
        if _strip_pins(cmd)[3:5] == ["remote", "add"]:
            return _completed(128, stderr="error: cannot create file (disk full)")
        if _strip_pins(cmd)[3:5] == ["remote", "set-url"]:
            return _completed(128, stderr="error: No such remote 'origin'")
        return _completed(0)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect), \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_net.return_value = _completed(0)
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

    Reason: ``fake_home=True`` materialises ``{output}/.home/`` for
    the child's HOME. If we passed ``output=str(repo_dir)``,
    ``.home/`` would land *inside* the fetched repo, polluting the
    caller's working tree. Matches ``clone_repository``'s pattern
    (which has the same constraint when target.parent is its writable
    scope)."""
    repo = tmp_path / "work" / "repo"
    with patch("core.sandbox.run_untrusted") as mock_local, \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_local.side_effect = _local_ok
        mock_net.return_value = _completed(0)
        fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)

    expected_parent = str(repo.parent)
    for call in list(mock_local.call_args_list) + list(mock_net.call_args_list):
        kwargs = call.kwargs
        assert kwargs["output"] == expected_parent
        assert kwargs["target"] == expected_parent


def test_fetch_passes_sanitised_env_and_timeout(tmp_path: Path) -> None:
    """Every call uses ``get_safe_git_env`` and the bounded
    ``GIT_CLONE_TIMEOUT`` — no caller-controlled bypass."""
    from core.config import RaptorConfig

    with patch("core.sandbox.run_untrusted") as mock_local, \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_local.return_value = _completed(0)
        mock_net.return_value = _completed(0)
        fetch_commit(tmp_path / "repo",
                     "https://github.com/foo/bar", _VALID_SHA)

    for call in list(mock_local.call_args_list) + list(mock_net.call_args_list):
        kwargs = call.kwargs
        assert "GIT_TERMINAL_PROMPT" in kwargs["env"]
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"
        assert kwargs["timeout"] == RaptorConfig.GIT_CLONE_TIMEOUT


# ---------------------------------------------------------------------------
# ls_remote
# ---------------------------------------------------------------------------

_KERNEL_HOSTS = ("git.kernel.org", "git.savannah.gnu.org")


def test_ls_remote_rejects_empty_proxy_hosts() -> None:
    """``proxy_hosts`` must be non-empty — the proxy would refuse
    every connection otherwise, so we surface a clear ValueError
    rather than a confusing transport failure."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        with pytest.raises(ValueError, match="proxy_hosts"):
            ls_remote("https://git.kernel.org/foo", proxy_hosts=[])
        mock_run.assert_not_called()


@pytest.mark.parametrize("bad_url", [
    "ssh://git@github.com/foo/bar",       # SSH unsupported (proxy is HTTPS)
    "git://git.kernel.org/foo",            # git protocol unsupported
    "file:///etc/passwd",                  # file scheme blocked
    "ftp://example.com/foo",               # arbitrary non-http
    "http://git.kernel.org/foo",           # plain HTTP rejected (proxy
                                            # is HTTPS-CONNECT exclusively)
    "https://user:pass@git.kernel.org/x",  # userinfo
    "https://user@git.kernel.org/x",       # bare username
    "https:///no-host/path",               # missing host
    "not a url",                           # not parseable
])
def test_ls_remote_rejects_bad_url_shapes(bad_url: str) -> None:
    """URL must be ``https://<host>/...`` with no userinfo. ``http://``
    is also rejected because the in-process egress proxy is
    HTTPS-CONNECT exclusively."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        with pytest.raises(ValueError):
            ls_remote(bad_url, proxy_hosts=_KERNEL_HOSTS)
        mock_run.assert_not_called()


def test_ls_remote_rejects_url_host_outside_allowlist() -> None:
    """Pre-check is defence-in-depth — proxy enforces too — but we
    surface a clear error before the subprocess fires."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        with pytest.raises(ValueError, match="not in proxy_hosts"):
            ls_remote(
                "https://evil.example.com/foo",
                proxy_hosts=_KERNEL_HOSTS,
            )
        mock_run.assert_not_called()


def test_ls_remote_host_match_is_case_insensitive() -> None:
    """Hostnames are case-insensitive per RFC 1035; uppercase variants
    of allowlisted hosts must still pass."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0, stdout="")
        ls_remote(
            "https://Git.Kernel.Org/foo",
            proxy_hosts=_KERNEL_HOSTS,
        )
        assert mock_run.called


def test_ls_remote_engages_egress_proxy(tmp_path: Path) -> None:
    """``run_untrusted_networked`` implicitly engages the egress proxy.
    Pin ``proxy_hosts`` so future refactors can't drop it."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0)
        ls_remote("https://git.kernel.org/foo", proxy_hosts=_KERNEL_HOSTS)
        kwargs = mock_run.call_args.kwargs
        assert "git.kernel.org" == kwargs.get("proxy_hosts", [])[0]
        assert kwargs.get("timeout") == 20  # default


def test_ls_remote_parses_refs() -> None:
    """Each ``<sha>\\t<ref>`` line is parsed; malformed lines are
    skipped defensively (a hostile remote could craft them).

    The SHA-shape check is strict 40 hex (not the 4-40 input
    validator) — git always emits full SHAs in ls-remote output;
    abbreviated "SHAs" from a remote are malformed.
    """
    stdout = (
        "abc1234567890abc1234567890abc1234567890a\trefs/heads/main\n"
        "def1234567890def1234567890def1234567890b\trefs/tags/v1.0\n"
        "garbage_line_no_tab\n"
        "not-a-sha\trefs/heads/funny\n"
        "0000\trefs/heads/short-sha\n"  # too short — strict regex rejects
        "12345678901234567890123456789012345678901234\trefs/x\n"  # too long
    )
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0, stdout=stdout)
        refs = ls_remote(
            "https://git.kernel.org/foo",
            proxy_hosts=_KERNEL_HOSTS,
        )
    assert refs == [
        ("abc1234567890abc1234567890abc1234567890a", "refs/heads/main"),
        ("def1234567890def1234567890def1234567890b", "refs/tags/v1.0"),
    ]


def test_ls_remote_failure_raises_runtime_error() -> None:
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(
            128, stderr="fatal: repository not found",
        )
        with pytest.raises(RuntimeError, match="repository not found"):
            ls_remote(
                "https://git.kernel.org/foo",
                proxy_hosts=_KERNEL_HOSTS,
            )


def test_ls_remote_passes_sanitised_env() -> None:
    """``GIT_TERMINAL_PROMPT=0`` and the rest of ``get_git_env``
    must reach the subprocess so a malformed credential prompt
    can't hang the run."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0, stdout="")
        ls_remote("https://git.kernel.org/foo", proxy_hosts=_KERNEL_HOSTS)
        kwargs = mock_run.call_args.kwargs
        assert kwargs["env"]["GIT_TERMINAL_PROMPT"] == "0"


def test_ls_remote_custom_timeout_propagates() -> None:
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0, stdout="")
        ls_remote(
            "https://git.kernel.org/foo",
            proxy_hosts=_KERNEL_HOSTS,
            timeout=60,
        )
        assert mock_run.call_args.kwargs["timeout"] == 60


def test_ls_remote_propagates_filenotfounderror() -> None:
    """If ``git`` isn't installed in the sandbox,
    ``run_untrusted_networked`` surfaces ``FileNotFoundError`` and the
    helper lets it propagate. Caller-trusted (raptor's CI environment
    always has git); test pins the propagation contract so a future
    change that swallows the exception is caught."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.side_effect = FileNotFoundError("git: command not found")
        with pytest.raises(FileNotFoundError):
            ls_remote(
                "https://git.kernel.org/foo",
                proxy_hosts=_KERNEL_HOSTS,
            )


def test_ls_remote_propagates_timeout_expired() -> None:
    """``subprocess.TimeoutExpired`` propagates from
    ``run_untrusted_networked`` unchanged. Same contract as
    ``clone_repository`` and ``fetch_commit``."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd=["git", "ls-remote"], timeout=20,
        )
        with pytest.raises(subprocess.TimeoutExpired):
            ls_remote(
                "https://git.kernel.org/foo",
                proxy_hosts=_KERNEL_HOSTS,
            )


def test_ls_remote_resilient_to_non_utf8_replacement_chars() -> None:
    """``errors="replace"`` plus the strict 40-char SHA regex means a
    hostile remote returning non-UTF-8 bytes (here represented as
    U+FFFD replacement chars) can't crash the helper — malformed
    lines just fail the SHA-shape check and are skipped."""
    # Real subprocess decode would have already replaced; simulate
    # the post-decode shape directly.
    stdout = (
        "abc1234567890abc1234567890abc1234567890a\trefs/heads/main\n"
        "\ufffd\ufffd\ufffdabc1234567890abc1234567890abc1234567\trefs/garbage\n"
    )
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0, stdout=stdout)
        refs = ls_remote(
            "https://git.kernel.org/foo",
            proxy_hosts=_KERNEL_HOSTS,
        )
    assert refs == [
        ("abc1234567890abc1234567890abc1234567890a", "refs/heads/main"),
    ]


def test_ls_remote_uses_strict_40char_sha_regex() -> None:
    """Caller-supplied SHAs (``fetch_commit``) accept 4-40 hex; the
    ls-remote parser is strict 40 because git always emits full
    SHAs and a shorter "SHA" from a remote is malformed (or hostile)."""
    # SHA at the lower bound the caller-input regex would accept (8
    # chars) MUST be rejected by the output parser.
    stdout = "deadbeef\trefs/heads/short\n"
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0, stdout=stdout)
        refs = ls_remote(
            "https://git.kernel.org/foo",
            proxy_hosts=_KERNEL_HOSTS,
        )
    assert refs == []  # nothing parsed


def test_safe_git_command_pins_signature_and_diff_programs() -> None:
    """Ordinary target-repo git ops must never execute a program named by
    the repo's own config: the safety overrides pin every ``gpg.*.program``
    to the no-op ``true`` and clear ``diff.external``."""
    from core.git.clone import safe_git_command
    joined = " ".join(safe_git_command("log", "-1"))
    assert "gpg.program=true" in joined
    assert "gpg.x509.program=true" in joined
    assert "gpg.ssh.program=true" in joined
    assert "diff.external=" in joined


def test_signature_probe_overrides_resolve_system_binaries() -> None:
    """The opt-in signature probe re-enables verification through
    PATH-resolved system binaries only — never a repo-named program — and
    emits well-formed ``-c key=value`` pairs."""
    import shutil

    from core.git.clone import signature_probe_overrides
    pairs = signature_probe_overrides()
    assert len(pairs) % 2 == 0
    keys = []
    for flag, kv in zip(pairs[::2], pairs[1::2]):
        assert flag == "-c"
        key, _, value = kv.partition("=")
        keys.append(key)
        assert Path(value).is_absolute()
    assert set(keys) <= {"gpg.program", "gpg.x509.program", "gpg.ssh.program"}
    if shutil.which("gpg"):
        assert "gpg.program" in keys


def test_get_safe_git_env_preserve_proxy_contract(monkeypatch) -> None:
    """Default strips operator proxy vars (same as get_git_env);
    ``preserve_proxy=True`` keeps them for git invocations that dial a
    remote outside the sandbox egress proxy — while still applying the
    GIT_ENV_VARS pins (terminal-prompt / askpass) in both modes."""
    from core.config import RaptorConfig
    from core.git.clone import get_safe_git_env

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    env_default = get_safe_git_env()
    env_proxy = get_safe_git_env(preserve_proxy=True)
    assert "HTTPS_PROXY" not in env_default
    assert env_proxy.get("HTTPS_PROXY") == "http://proxy.invalid:3128"
    for key, value in RaptorConfig.GIT_ENV_VARS.items():
        assert env_default.get(key) == value
        assert env_proxy.get(key) == value


def test_safe_git_readonly_command_layers_strict_pins_last() -> None:
    """The strict read-only variant is the full safe_git_command posture
    PLUS transport refusal. git honours the LAST ``-c`` occurrence per
    key, so every strict pin must land after its base counterpart."""
    from core.git.clone import (
        _SAFE_GIT_OVERRIDES,
        safe_git_command,
        safe_git_readonly_command,
    )
    cmd = safe_git_readonly_command("rev-parse", "HEAD")
    assert cmd[0] == "git"
    assert cmd[1] == "--no-pager"
    assert cmd[-2:] == ["rev-parse", "HEAD"]
    # Base posture fully present (superset relation with safe_git_command).
    base = safe_git_command()[1:]
    assert cmd[2:2 + len(base)] == base
    for kv in _SAFE_GIT_OVERRIDES[1::2]:
        assert kv in cmd
    # Strict pins present and AFTER the base pins they override.
    assert cmd.index("protocol.allow=never") > cmd.index("protocol.file.allow=user")
    assert cmd.index("protocol.file.allow=never") > cmd.index("protocol.file.allow=user")
    assert cmd.index("core.sshCommand=false") > cmd.index("core.sshCommand=ssh")
    # Well-formed: every override value is preceded by ``-c``.
    for key in ("protocol.allow=never", "protocol.file.allow=never",
                "core.sshCommand=false"):
        assert cmd[cmd.index(key) - 1] == "-c"


def test_readonly_overrides_constant_is_single_source_of_truth() -> None:
    """Consumers (core.audit.git_oracle) and tests assert the strict
    posture via ``_SAFE_GIT_READONLY_OVERRIDES`` — the helper must emit
    exactly that tuple, so there is one place to extend it."""
    from core.git.clone import (
        _SAFE_GIT_OVERRIDES,
        _SAFE_GIT_READONLY_OVERRIDES,
        safe_git_readonly_command,
    )
    assert safe_git_readonly_command() == [
        "git", "--no-pager", *_SAFE_GIT_READONLY_OVERRIDES,
    ]
    # Strict tuple embeds the base tuple unchanged (no drift).
    assert _SAFE_GIT_READONLY_OVERRIDES[:len(_SAFE_GIT_OVERRIDES)] == \
        _SAFE_GIT_OVERRIDES


@pytest.mark.skipif(
    __import__("shutil").which("git") is None, reason="git not installed",
)
def test_readonly_command_refuses_local_path_fetch(tmp_path: Path) -> None:
    """Functional pin of the precedence subtlety: ``protocol.allow=never``
    alone would NOT refuse the file protocol because the base tuple's
    per-protocol ``protocol.file.allow=user`` takes precedence over the
    catch-all. The strict variant re-pins ``protocol.file.allow=never``;
    a local-path fetch must fail under it while the network-capable
    ``safe_git_command`` posture permits it."""
    import os
    import shutil

    from core.git.clone import safe_git_command, safe_git_readonly_command

    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(tmp_path),
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def run(cmd):
        return subprocess.run(
            cmd, capture_output=True, text=True, env=env, check=False,
        )

    src = tmp_path / "src"
    src.mkdir()
    assert run(["git", "init", "-q", str(src)]).returncode == 0
    (src / "f.txt").write_text("x\n")
    assert run([
        "git", "-C", str(src),
        "-c", "user.name=t", "-c", "user.email=t@example.invalid",
        "-c", "commit.gpgsign=false",
        "add", ".",
    ]).returncode == 0
    assert run([
        "git", "-C", str(src),
        "-c", "user.name=t", "-c", "user.email=t@example.invalid",
        "-c", "commit.gpgsign=false",
        "commit", "-q", "-m", "one",
    ]).returncode == 0

    for dest_name, argv_builder, expect_ok in (
        ("dest-open", safe_git_command, True),
        ("dest-strict", safe_git_readonly_command, False),
    ):
        dest = tmp_path / dest_name
        dest.mkdir()
        assert run(["git", "init", "-q", str(dest)]).returncode == 0
        proc = run(argv_builder(
            "-C", str(dest), "fetch", str(src), "HEAD",
        ))
        assert (proc.returncode == 0) is expect_ok, proc.stderr
    shutil.rmtree(tmp_path / "src", ignore_errors=True)


def test_signature_probe_overrides_take_precedence() -> None:
    """git honours the LAST ``-c`` occurrence, so the probe pairs must land
    after the neutral pins for re-enablement to take effect."""
    from core.git.clone import safe_git_command, signature_probe_overrides
    probe = signature_probe_overrides()
    if not probe:
        pytest.skip("no signature programs installed on this host")
    cmd = safe_git_command(*probe, "log")
    neutral = cmd.index("gpg.program=true")
    real = [i for i, v in enumerate(cmd)
            if v.startswith("gpg.program=") and v != "gpg.program=true"]
    assert real and real[0] > neutral


class TestSafeGitCommandExecutes:
    """Execute git THROUGH the safety overrides against a real repo.

    The string-level assertions above can't catch a config pin that git
    interprets differently than intended (the empty ``diff.external=``
    value means "run this command", not "disabled" — which is why diff
    callers must pass --no-ext-diff and why forgetting it fails loudly).
    These tests pin both halves of that contract with a live git.
    """

    @staticmethod
    def _two_commit_repo(tmp_path: Path) -> Path:
        repo = tmp_path / "repo"
        repo.mkdir()

        def g(*args: str) -> subprocess.CompletedProcess:
            return subprocess.run(
                ["git", "-C", str(repo), *args],
                capture_output=True, text=True, check=True,
            )

        g("init", "-q")
        g("config", "user.email", "t@example.com")
        g("config", "user.name", "T")
        (repo / "a.txt").write_text("one\n")
        g("add", "a.txt")
        g("commit", "-q", "-m", "c1")
        (repo / "a.txt").write_text("two\n")
        g("add", "a.txt")
        g("commit", "-q", "-m", "c2")
        return repo

    def test_diff_with_no_ext_diff_succeeds(self, tmp_path: Path) -> None:
        from core.git.clone import safe_git_command
        repo = self._two_commit_repo(tmp_path)
        proc = subprocess.run(
            safe_git_command(
                "-C", str(repo), "diff", "--no-ext-diff",
                "HEAD~1..HEAD",
            ),
            capture_output=True, text=True, check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "-one" in proc.stdout and "+two" in proc.stdout

    def test_diff_without_no_ext_diff_fails_loudly(
        self, tmp_path: Path,
    ) -> None:
        # The deliberate trap: a diff caller that forgot --no-ext-diff
        # must fail closed, not silently honour a repo-named driver.
        from core.git.clone import safe_git_command
        repo = self._two_commit_repo(tmp_path)
        proc = subprocess.run(
            safe_git_command("-C", str(repo), "diff", "HEAD~1..HEAD"),
            capture_output=True, text=True, check=False,
        )
        assert proc.returncode != 0
        assert "external diff" in proc.stderr or "cannot run" in proc.stderr

    def test_status_probe_shape_succeeds(self, tmp_path: Path) -> None:
        # The refresh-free provenance probe shape stays green end-to-end.
        from core.git.clone import safe_git_command
        repo = self._two_commit_repo(tmp_path)
        for args in (
            ("rev-parse", "HEAD"),
            ("diff-index", "--no-ext-diff", "HEAD"),
            ("ls-files", "--others", "--exclude-standard"),
        ):
            proc = subprocess.run(
                safe_git_command("-C", str(repo), *args),
                capture_output=True, text=True, check=False,
            )
            assert proc.returncode == 0, (args, proc.stderr)

# ---------------------------------------------------------------------------
# Config-pin posture: clone / fetch / ls-remote argv
# ---------------------------------------------------------------------------

def _pin_pairs(cmd: list) -> set:
    """Extract the ``-c key=val`` pin values from an argv."""
    return {cmd[i + 1] for i, tok in enumerate(cmd) if tok == "-c"}


def test_clone_argv_carries_safe_git_pins(tmp_path: Path) -> None:
    """clone must run with the per-invocation neutralisation pins
    (fsmonitor / hooksPath / credential.helper / ...) but NOT the
    strict transport refusal, which would break the https clone."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.side_effect = _clone_materialises
        clone_repository("https://github.com/foo/bar", tmp_path / "out")
    pins = _pin_pairs(mock_run.call_args.args[0])
    assert "core.fsmonitor=" in pins
    assert "core.hooksPath=/dev/null" in pins
    assert "credential.helper=" in pins
    assert "protocol.allow=never" not in pins


def test_fetch_local_steps_carry_strict_pins(tmp_path: Path) -> None:
    """init / remote add never touch a transport, so they get the
    strict read-only posture — including protocol.allow=never — to
    neutralise a pre-existing untrusted .git/config."""
    repo = tmp_path / "repo"
    with patch("core.sandbox.run_untrusted") as mock_local, \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_local.side_effect = _local_ok
        mock_net.return_value = _completed(0)
        fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)

    for call in mock_local.call_args_list:
        pins = _pin_pairs(call.args[0])
        assert "core.fsmonitor=" in pins
        assert "protocol.allow=never" in pins

    # The network fetch keeps the base posture only.
    net_pins = _pin_pairs(mock_net.call_args.args[0])
    assert "core.fsmonitor=" in net_pins
    assert "protocol.allow=never" not in net_pins


def test_ls_remote_argv_carries_safe_git_pins() -> None:
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(
            0, stdout=f"{_VALID_SHA}\trefs/heads/main\n")
        ls_remote("https://github.com/foo/bar",
                  proxy_hosts=["github.com"])
    pins = _pin_pairs(mock_run.call_args.args[0])
    assert "core.fsmonitor=" in pins
    assert "core.hooksPath=/dev/null" in pins
    assert "protocol.allow=never" not in pins


# ---------------------------------------------------------------------------
# ls_remote: ref patterns + bearer-token env mechanism
# ---------------------------------------------------------------------------


def test_ls_remote_patterns_follow_end_of_options_separator() -> None:
    """Ref patterns land after ``--`` so neither the URL nor a pattern
    can ever be parsed as a git option."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0, stdout="")
        ls_remote(
            "https://github.com/foo/bar.git",
            proxy_hosts=["github.com"],
            patterns=("v4", "refs/tags/v4", "refs/heads/v4"),
        )
    cmd = _strip_pins(mock_run.call_args.args[0])
    i = cmd.index("--")
    assert cmd[i + 1] == "https://github.com/foo/bar.git"
    assert cmd[i + 2:] == ["v4", "refs/tags/v4", "refs/heads/v4"]


@pytest.mark.parametrize("bad_pattern", ["-v4", "--upload-pack=x", ""])
def test_ls_remote_rejects_dash_or_empty_patterns(bad_pattern: str) -> None:
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        with pytest.raises(ValueError, match="pattern"):
            ls_remote(
                "https://github.com/foo/bar.git",
                proxy_hosts=["github.com"],
                patterns=(bad_pattern,),
            )
        mock_run.assert_not_called()


def test_ls_remote_bearer_token_env_not_argv() -> None:
    """The bearer credential must ride the ``GIT_CONFIG_*`` env
    mechanism — NEVER argv (argv is same-uid world-readable via
    /proc/<pid>/cmdline)."""
    token = "ghp_SECRETSECRETSECRETSECRET"  # noqa: S105 — test fixture
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0, stdout="")
        ls_remote(
            "https://github.com/foo/bar.git",
            proxy_hosts=["github.com"],
            bearer_token=token,
        )
    cmd = mock_run.call_args.args[0]
    assert all(token not in arg for arg in cmd), (
        f"bearer token leaked onto argv: {cmd}"
    )
    assert all("extraheader" not in arg for arg in cmd)
    env = mock_run.call_args.kwargs["env"]
    assert env["GIT_CONFIG_COUNT"] == "1"
    assert env["GIT_CONFIG_KEY_0"] == "http.extraheader"
    assert env["GIT_CONFIG_VALUE_0"] == f"Authorization: bearer {token}"


def test_ls_remote_no_token_leaves_env_unaugmented() -> None:
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0, stdout="")
        ls_remote(
            "https://github.com/foo/bar.git",
            proxy_hosts=["github.com"],
        )
    env = mock_run.call_args.kwargs["env"]
    assert "GIT_CONFIG_COUNT" not in env
    assert "GIT_CONFIG_KEY_0" not in env


# ---------------------------------------------------------------------------
# Host-side materialisation post-check
# ---------------------------------------------------------------------------
#
# git's exit status reports what happened INSIDE the sandbox. Under the
# mount-ns backend the child gets a private tmpfs /tmp; a destination
# not covered by the bind tree gets written into that tmpfs, git exits
# 0, and the tree vanishes with the sandbox. clone_repository must not
# report success for a clone the caller cannot see.

def test_clone_zero_exit_without_host_tree_raises(tmp_path: Path) -> None:
    """Sandbox says success but the destination never appeared on the
    host → loud RuntimeError, never a phantom True."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0)  # deliberately no mkdir
        with pytest.raises(RuntimeError,
                           match="does not exist on the host"):
            clone_repository("https://github.com/foo/bar",
                             tmp_path / "out")


@pytest.mark.integration
@pytest.mark.skipif(
    __import__("sys").platform != "linux",
    reason="exercises the Linux sandbox backends (mount-ns / Landlock)",
)
def test_clone_through_real_sandbox_materialises_on_host(
    tmp_path: Path, monkeypatch,
) -> None:
    """Regression for the mount-ns /tmp-shadowing class: a sandboxed
    clone to a host /tmp destination must materialise on the HOST, not
    inside the sandbox's private tmpfs. Clones a local scratch repo
    through the real clone_repository path (URL allowlist stubbed —
    it only admits remote forges); the scratch repo lives inside
    ``target.parent`` so the bind tree covers the read side too."""
    src = tmp_path / "srcrepo"
    src.mkdir()
    env = {"GIT_TERMINAL_PROMPT": "0", "HOME": str(tmp_path),
           "PATH": "/usr/bin:/bin",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    for argv in (["git", "init", "-q"],
                 ["git", "add", "f.txt"],
                 ["git", "commit", "-q", "-m", "seed"]):
        if argv[1] == "add":
            (src / "f.txt").write_text("seed\n", encoding="utf-8")
        subprocess.run(argv, cwd=src, env=env, check=True, timeout=30)

    monkeypatch.setattr("core.git.clone.validate_repo_url",
                        lambda url: True)
    dst = tmp_path / "dst"
    assert clone_repository(str(src), dst, depth=None) is True
    # The point of the test: host-visible materialisation.
    assert (dst / "f.txt").read_text(encoding="utf-8") == "seed\n"
    assert (dst / ".git").is_dir()


# ---------------------------------------------------------------------------
# fetch_commit post-fetch OID verification
# ---------------------------------------------------------------------------

def _fetch_with_resolved(tmp_path: Path, requested: str,
                         resolved_stdout: str,
                         rev_parse_rc: int = 0) -> bool:
    """Run fetch_commit with mocked sandbox calls where the post-fetch
    ``rev-parse FETCH_HEAD^{commit}`` yields ``resolved_stdout``."""
    def _side_effect(cmd, **kwargs):
        if "rev-parse" in cmd:
            return _completed(rev_parse_rc, stdout=resolved_stdout)
        return _completed(0)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect), \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_net.return_value = _completed(0)
        return fetch_commit(tmp_path / "repo",
                            "https://github.com/foo/bar", requested)


def test_fetch_full_sha_mismatch_returns_false(tmp_path: Path) -> None:
    """Transport success is NOT commit success: a remote answering the
    want with a different object must be refused."""
    other = "cafebabe" * 5
    assert _fetch_with_resolved(tmp_path, _VALID_SHA,
                                other + "\n") is False


def test_fetch_full_sha_exact_match_returns_true(tmp_path: Path) -> None:
    assert _fetch_with_resolved(tmp_path, _VALID_SHA,
                                _VALID_SHA + "\n") is True


def test_fetch_abbreviated_sha_requires_prefix_match(
    tmp_path: Path,
) -> None:
    """An abbreviated SHA is remote-resolved; the returned OID must
    start with the requested prefix."""
    assert _fetch_with_resolved(tmp_path, "deadbeef",
                                _VALID_SHA + "\n") is True
    assert _fetch_with_resolved(tmp_path, "cafebabe",
                                _VALID_SHA + "\n") is False


def test_fetch_unresolvable_fetch_head_returns_false(
    tmp_path: Path,
) -> None:
    """FETCH_HEAD not resolving to a commit after a zero-exit fetch is
    a failure, never a success."""
    assert _fetch_with_resolved(tmp_path, _VALID_SHA, "",
                                rev_parse_rc=128) is False


def test_fetch_garbage_rev_parse_output_returns_false(
    tmp_path: Path,
) -> None:
    assert _fetch_with_resolved(tmp_path, _VALID_SHA,
                                "not-a-sha\n") is False


def test_fetch_uppercase_request_matches_case_insensitively(
    tmp_path: Path,
) -> None:
    """The SHA shape check accepts uppercase hex; verification must
    compare case-insensitively against git's lowercase output."""
    assert _fetch_with_resolved(tmp_path, _VALID_SHA.upper(),
                                _VALID_SHA + "\n") is True


# ---------------------------------------------------------------------------
# _validate_writable_path — pseudo-fs denylist on the RESOLVED path
# ---------------------------------------------------------------------------

def test_writable_path_denylist_catches_dotdot_traversal() -> None:
    from core.git.clone import _validate_writable_path

    with pytest.raises(ValueError, match="pseudo-fs"):
        _validate_writable_path(
            Path("/tmp/x/../../dev/shm/evil"), role="output")


def test_writable_path_denylist_catches_symlink(tmp_path: Path) -> None:
    from core.git.clone import _validate_writable_path

    link = tmp_path / "innocuous"
    link.symlink_to("/dev/shm")
    with pytest.raises(ValueError, match="pseudo-fs"):
        _validate_writable_path(link / "evil", role="output")


def test_writable_path_denylist_literal_still_refused() -> None:
    from core.git.clone import _validate_writable_path

    with pytest.raises(ValueError, match="pseudo-fs"):
        _validate_writable_path(Path("/proc/self/environ"), role="output")


def test_writable_path_ordinary_tmp_dir_accepted(tmp_path: Path) -> None:
    from core.git.clone import _validate_writable_path

    _validate_writable_path(tmp_path / "clone-target", role="output")


# ---------------------------------------------------------------------------
# fetch_commit pre-existing-config audit
# ---------------------------------------------------------------------------

def test_foreign_local_config_keys_detects_transport_class() -> None:
    """Every member of the unpinnable transport class must surface:
    proxy keys, URL-scoped http keys, insteadOf rewrites, URL-scoped
    credential helpers, per-remote proxy/vcs."""
    from core.git.clone import _foreign_local_config_keys
    listing = "\0".join([
        "http.proxy\nhttp://attacker.example:8080",
        "http.https://github.com/.sslverify\nfalse",
        "url.https://evil.example/.insteadof\nhttps://github.com/",
        "credential.https://github.com.helper\n!curl attacker",
        "remote.origin.proxy\nhttp://attacker.example:8080",
        "remote.origin.vcs\next",
        "core.repositoryformatversion\n0",       # benign — must NOT surface
        "remote.origin.url\nhttps://github.com/foo/bar",  # benign
    ]) + "\0"
    foreign = _foreign_local_config_keys(listing)
    assert "http.proxy" in foreign
    assert "http.https://github.com/.sslverify" in foreign
    assert "url.https://evil.example/.insteadof" in foreign
    assert "credential.https://github.com.helper" in foreign
    assert "remote.origin.proxy" in foreign
    assert "remote.origin.vcs" in foreign
    assert "core.repositoryformatversion" not in foreign
    assert "remote.origin.url" not in foreign


def test_foreign_local_config_keys_passes_own_footprint() -> None:
    """The exact key set fetch_commit's init + remote-add steps write
    (including the platform-dependent init defaults) audits clean."""
    from core.git.clone import _foreign_local_config_keys
    listing = "\0".join([
        "core.repositoryformatversion\n0",
        "core.filemode\ntrue",
        "core.bare\nfalse",
        "core.logallrefupdates\ntrue",
        "core.ignorecase\ntrue",
        "core.precomposeunicode\ntrue",
        "core.symlinks\nfalse",
        "remote.origin.url\nhttps://github.com/foo/bar",
        "remote.origin.fetch\n+refs/heads/*:refs/remotes/origin/*",
    ]) + "\0"
    assert _foreign_local_config_keys(listing) == []


def test_foreign_local_config_keys_nul_framing_defeats_value_injection() -> None:
    """A hostile VALUE containing key-looking lines stays one NUL-framed
    entry — it can neither forge a benign entry nor hide a hostile key
    (line-wise parsing of the non-``-z`` form could be steered)."""
    from core.git.clone import _foreign_local_config_keys
    # Benign key whose value embeds what LOOKS like a hostile key line:
    # stays benign (it is one entry; the audit reads only the key).
    listing = "remote.origin.url\nhttps://x\nhttp.proxy=evil\0"
    assert _foreign_local_config_keys(listing) == []
    # The hostile key as its OWN entry is always caught.
    listing = (
        "remote.origin.url\nhttps://x\0"
        "http.proxy\nhttp://attacker.example:8080\0"
    )
    assert _foreign_local_config_keys(listing) == ["http.proxy"]


def test_fetch_preexisting_repo_hostile_config_refused(tmp_path: Path) -> None:
    """A pre-existing repo_dir whose local config carries transport-
    altering keys (insteadOf redirect + attacker proxy) must refuse
    BEFORE the network step — no finite ``-c`` pin list covers the
    URL-scoped key class, so the fetch never runs over it."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    hostile = (
        "url.https://evil.example/.insteadof\nhttps://github.com/\0"
        "http.proxy\nhttp://attacker.example:8080\0"
    )

    def _side_effect(cmd, **kwargs):
        if "config" in cmd:
            return _completed(0, stdout=hostile)
        return _local_ok(cmd, **kwargs)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect), \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        with pytest.raises(RuntimeError, match="never writes"):
            fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)
        mock_net.assert_not_called()


def test_fetch_preexisting_repo_unreadable_config_refused(
    tmp_path: Path,
) -> None:
    """Config listing failure = unverifiable configuration → refuse
    (fail closed), never fetch blind."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    def _side_effect(cmd, **kwargs):
        if "config" in cmd:
            return _completed(128, stderr="fatal: unable to read config")
        return _local_ok(cmd, **kwargs)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect), \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        with pytest.raises(RuntimeError, match="unverifiable"):
            fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)
        mock_net.assert_not_called()


def test_fetch_preexisting_repo_own_footprint_still_fetches(
    tmp_path: Path,
) -> None:
    """Two-direction: a repo_dir whose config is exactly fetch_commit's
    own footprint (the cve_diff re-fetch loop shape) keeps working."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    own = (
        "core.repositoryformatversion\n0\0"
        "core.filemode\ntrue\0"
        "core.bare\nfalse\0"
        "core.logallrefupdates\ntrue\0"
        "remote.origin.url\nhttps://github.com/foo/bar\0"
        "remote.origin.fetch\n+refs/heads/*:refs/remotes/origin/*\0"
    )

    def _side_effect(cmd, **kwargs):
        if "config" in cmd:
            return _completed(0, stdout=own)
        return _local_ok(cmd, **kwargs)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect), \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_net.return_value = _completed(0)
        ok = fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)
        assert ok is True
        assert mock_net.called


def test_foreign_local_config_keys_non_origin_remotes_surface() -> None:
    """fetch_commit writes ONLY remote.origin — a planted foreign
    remote (e.g. an ``ext::`` URL waiting for an out-of-band
    ``git fetch --all``) must surface as foreign."""
    from core.git.clone import _foreign_local_config_keys
    listing = (
        "remote.origin.url\nhttps://github.com/foo/bar\0"
        "remote.evil.url\next::sh -c whoami\0"
        "remote.evil.fetch\n+refs/*:refs/*\0"
    )
    foreign = _foreign_local_config_keys(listing)
    assert "remote.evil.url" in foreign
    assert "remote.evil.fetch" in foreign
    assert "remote.origin.url" not in foreign


def test_fetch_preexisting_repo_replace_refs_refused(tmp_path: Path) -> None:
    """A pre-existing repo_dir carrying ``refs/replace/*`` must refuse
    BEFORE the network step: with a correctly-hashed attacker object
    planted, the fetch succeeds from the REAL upstream, FETCH_HEAD
    verifies the requested SHA — and every reader without the
    ``core.useReplaceRefs=false`` pin gets the replacement content.
    The config audit cannot see it (a ref is not a config key)."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    def _side_effect(cmd, **kwargs):
        if "config" in cmd:
            return _completed(0, stdout="")
        if "for-each-ref" in cmd:
            return _completed(
                0,
                stdout=("0123456789abcdef0123456789abcdef01234567 commit\t"
                        "refs/replace/deadbeef\n"),
            )
        return _local_ok(cmd, **kwargs)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect), \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        with pytest.raises(RuntimeError, match="refs/replace"):
            fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)
        mock_net.assert_not_called()


def test_fetch_preexisting_repo_grafts_refused(tmp_path: Path) -> None:
    """``info/grafts`` rewrites parent links for every reader and has
    NO config off-switch — a pre-existing plant must refuse before
    the network step."""
    repo = tmp_path / "repo"
    (repo / ".git" / "info").mkdir(parents=True)
    (repo / ".git" / "info" / "grafts").write_text(
        "0123456789abcdef0123456789abcdef01234567\n")

    def _side_effect(cmd, **kwargs):
        if "config" in cmd:
            return _completed(0, stdout="")
        if "for-each-ref" in cmd:
            return _completed(0, stdout="")
        if "--git-path" in cmd:
            return _completed(0, stdout=".git/info/grafts\n")
        return _local_ok(cmd, **kwargs)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect), \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        with pytest.raises(RuntimeError, match="info/grafts"):
            fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)
        mock_net.assert_not_called()


def test_fetch_preexisting_repo_rewrite_audit_unreadable_refused(
    tmp_path: Path,
) -> None:
    """The history-rewrite audit fails closed like the unreadable-
    config arm: an unreadable ref listing refuses, never fetches
    blind."""
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)

    def _side_effect(cmd, **kwargs):
        if "config" in cmd:
            return _completed(0, stdout="")
        if "for-each-ref" in cmd:
            return _completed(128, stderr="fatal: not a git repository")
        return _local_ok(cmd, **kwargs)

    with patch("core.sandbox.run_untrusted", side_effect=_side_effect), \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        with pytest.raises(RuntimeError, match="unverifiable"):
            fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)
        mock_net.assert_not_called()


def test_safe_git_overrides_pin_replace_refs_off() -> None:
    """Posture pin: every safe git command must carry the replace-ref
    off-switch — object substitution behind a verified SHA otherwise
    reaches every log/show/diff over a target repo."""
    from core.git.clone import (
        _SAFE_GIT_OVERRIDES,
        _SAFE_GIT_READONLY_OVERRIDES,
    )
    assert "core.useReplaceRefs=false" in _SAFE_GIT_OVERRIDES
    assert "core.useReplaceRefs=false" in _SAFE_GIT_READONLY_OVERRIDES


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_replace_ref_substitution_neutralised_live(tmp_path: Path) -> None:
    """Live repro of the object-substitution vector: a planted
    ``refs/replace/<sha>`` makes bare ``git show`` return attacker
    content for the REAL commit OID; the ``core.useReplaceRefs=false``
    pin in the safe overrides restores the real content."""
    from core.git.clone import safe_git_readonly_command

    repo = tmp_path / "repo"
    repo.mkdir()
    env = {"GIT_TERMINAL_PROMPT": "0", "HOME": str(tmp_path),
           "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
           "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
           "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}

    def _git(*args: str) -> str:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args], env=env,
            capture_output=True, text=True, timeout=30, check=True,
        )
        return proc.stdout.strip()

    _git("init", "-q")
    (repo / "f.txt").write_text("real\n", encoding="utf-8")
    _git("add", "f.txt")
    _git("commit", "-q", "-m", "real")
    real_sha = _git("rev-parse", "HEAD")
    (repo / "f.txt").write_text("attacker\n", encoding="utf-8")
    _git("add", "f.txt")
    _git("commit", "-q", "-m", "attacker")
    evil_sha = _git("rev-parse", "HEAD")
    _git("replace", real_sha, evil_sha)

    # The vector: default git substitutes the attacker object.
    substituted = _git("show", f"{real_sha}:f.txt")
    assert substituted == "attacker"
    # The pin: safe overrides read the real object.
    pinned = subprocess.run(
        safe_git_readonly_command(
            "-C", str(repo), "show", f"{real_sha}:f.txt",
        ) + ["--no-ext-diff"],
        env=env, capture_output=True, text=True, timeout=30, check=True,
    ).stdout.strip()
    assert pinned == "real"


def test_writable_path_refuses_system_state_prefixes() -> None:
    """The writable scope is target.parent — a target under persistent
    system state hands a hostile git server write access to host
    configuration (/etc/cron.d, ld.so.conf.d, /var/spool/cron) with
    the rest of the isolation engaged."""
    from core.git.clone import _validate_writable_path
    for bad in (
        Path("/etc/clone"),
        Path("/boot/kernels/x"),
        Path("/usr/bin/x"),
        Path("/var/spool/cron/x"),
        Path("/var/tmp"),   # parent (= writable scope) would be /var
    ):
        with pytest.raises(ValueError, match="pseudo-fs|system-state|root"):
            _validate_writable_path(bad, role="target")


def test_writable_path_allows_var_tmp_children(tmp_path: Path) -> None:
    """Two-direction: /var/tmp/<child> is the documented operator
    scratch location and must keep validating (alongside /tmp)."""
    from core.git.clone import _validate_writable_path
    _validate_writable_path(Path("/var/tmp/raptor-wt/repo"), role="target")
    _validate_writable_path(tmp_path / "repo", role="target")


def test_git_failure_messages_escape_remote_controlled_bytes(
    tmp_path: Path,
) -> None:
    """git relays server-controlled ``remote:`` banners verbatim into
    stderr; the RuntimeError message flows to consumer logs/terminals,
    so ESC/C1 control bytes must be neutralised at the message-builder
    (and hostile banners length-capped)."""
    hostile = "remote: \x1b]0;pwned\x07\x1b[2J fatal: nope"
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(128, stderr=hostile)
        with pytest.raises(RuntimeError) as exc_info:
            clone_repository("https://github.com/foo/bar", tmp_path / "out")
    msg = str(exc_info.value)
    assert "\x1b" not in msg and "\x07" not in msg
    assert "fatal: nope" in msg          # the useful part survives

    with patch("core.sandbox.run_untrusted") as mock_local, \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_local.side_effect = _local_ok
        mock_net.return_value = _completed(128, stderr=hostile)
        with pytest.raises(RuntimeError) as exc_info:
            fetch_commit(tmp_path / "repo",
                         "https://github.com/foo/bar", _VALID_SHA)
    msg = str(exc_info.value)
    assert "\x1b" not in msg and "\x07" not in msg


def test_git_failure_messages_are_length_capped(tmp_path: Path) -> None:
    """A hostile remote can stream an arbitrarily long banner; the
    message must stay bounded (and still identify the operation)."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(128, stderr="A" * 100_000)
        with pytest.raises(RuntimeError) as exc_info:
            clone_repository("https://github.com/foo/bar", tmp_path / "out")
    msg = str(exc_info.value)
    assert len(msg) < 3000
    assert msg.startswith("git clone failed:")


def test_writable_path_refuses_opt_srv_root_prefixes() -> None:
    """The denylist's own rationale ("not in system-state locations")
    covers /opt, /srv, and /root exactly as much as the listed
    members: add-on package trees, served content, and the superuser
    home are host state a hostile git server must not gain write scope
    over."""
    from core.git.clone import _validate_writable_path
    for bad in (
        Path("/opt/scratch/clone"),
        Path("/opt/clone"),      # writable scope would be /opt itself
        Path("/srv/www/clone"),
        Path("/root/work/clone"),
    ):
        with pytest.raises(ValueError, match="pseudo-fs|system-state|root"):
            _validate_writable_path(bad, role="target")
