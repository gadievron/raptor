"""Clone- and fetch-wrapper tests - subprocess + sandbox stubbed."""

from __future__ import annotations

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
        mock_run.return_value = _completed(0)
        ok = clone_repository(
            "https://github.com/foo/bar", tmp_path / "out",
        )
        assert ok is True
        assert mock_run.called
        cmd = _strip_pins(mock_run.call_args.args[0])
        assert cmd[:4] == ["git", "clone", "--depth", "1"]
        kwargs = mock_run.call_args.kwargs
        proxy_hosts = set(kwargs.get("proxy_hosts", []))
        assert {"github.com", "codeload.github.com"} <= proxy_hosts


def test_clone_failure_raises_runtime_error(tmp_path: Path) -> None:
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(128, stderr="fatal: not found")
        with pytest.raises(RuntimeError, match="not found"):
            clone_repository("https://github.com/foo/bar",
                              tmp_path / "out")


def test_clone_engages_egress_proxy(tmp_path: Path) -> None:
    """``run_untrusted_networked`` implicitly engages the egress proxy.
    Pin ``proxy_hosts`` so future refactors can't drop it."""
    with patch("core.sandbox.run_untrusted_networked") as mock_run:
        mock_run.return_value = _completed(0)
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
    expected flags. Network call (fetch) goes through
    ``run_untrusted_networked``; local calls (init / remote) go through
    ``run_untrusted``."""
    repo = tmp_path / "repo"
    with patch("core.sandbox.run_untrusted") as mock_local, \
         patch("core.sandbox.run_untrusted_networked") as mock_net:
        mock_local.return_value = _completed(0)
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
        mock_local.return_value = _completed(0)
        mock_net.return_value = _completed(0)
        fetch_commit(repo, "https://github.com/foo/bar", _VALID_SHA)

    cmds = [_strip_pins(c.args[0]) for c in mock_local.call_args_list]
    # First local call should be ``remote add``, not ``init`` —
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
        if _strip_pins(cmd)[3:5] == ["remote", "add"]:
            return _completed(128, stderr="error: remote origin already exists")
        return _completed(0)

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
        mock_local.return_value = _completed(0)
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
        mock_run.return_value = _completed(0)
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
        mock_local.return_value = _completed(0)
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
