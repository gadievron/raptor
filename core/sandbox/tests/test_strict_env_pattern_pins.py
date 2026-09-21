"""Per-site behavioral pins for the strict_env sweeps.

Each strict_env sweep site must PROVE, with a real child process, that
it strips credential-env pattern members (CARGO_TARGET_<triple>_RUNNER
-shaped names have no enumerable spelling, so no exact-name set can
carry them) and exact blocklist members, while keeping the inert git
pins and benign caller vars. Source-token locks alone are
comment-satisfiable and cannot distinguish "the detection list
consults the predicate" from "the FILTER consults the predicate" — a
single-site filter regression leaks into live children while the log
claims a strip. These pins spawn through each site:

  * ``context.run(strict_env=True)`` — the main run() lane's rebuild
    filter (the one every sandboxed caller crosses).
  * ``_spawn.run_sandboxed(strict_env=True)`` — the direct-caller
    re-strip (defense-in-depth for callers bypassing run()).
  * ``_macos_spawn.run_sandboxed(strict_env=True)`` — the Darwin
    backend twin (skips off-platform; the closure suite's
    comment-stripped code lock covers it on Linux CI).
"""

import sys

import pytest

from core.sandbox.tests.capability import requires_userns

_PATTERN_MEMBER = "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER"
_BUNDLE_PATTERN = "BUNDLE_BUILD__NOKOGIRI"
_CMAKE_PATTERN = "CMAKE_C_COMPILER_LAUNCHER"


def _hostile_env(tmp_path):
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": str(tmp_path),
        "MY_LEGITIMATE_VAR": "kept",
        # Exact blocklist member — the pre-existing strip direction.
        "LD_PRELOAD": "/tmp/attacker.so",
        # Pattern members — no exact-name set can carry these.
        _PATTERN_MEMBER: "/tmp/evil-runner",
        _BUNDLE_PATTERN: "--with-cflags=-fplugin=/tmp/e.so",
        _CMAKE_PATTERN: "/tmp/evil-launcher",
        # Inert git neutraliser pin — must SURVIVE the sweep.
        "GIT_CONFIG_GLOBAL": "/dev/null",
    }


def _assert_swept(stdout: str):
    assert "MY_LEGITIMATE_VAR=kept" in stdout
    assert "GIT_CONFIG_GLOBAL=/dev/null" in stdout
    for name in (
        "LD_PRELOAD", _PATTERN_MEMBER, _BUNDLE_PATTERN, _CMAKE_PATTERN,
    ):
        assert f"{name}=" not in stdout, name


@requires_userns
def test_context_run_strict_env_strips_pattern_members(tmp_path):
    """The run() lane: a real child's environment proves the rebuild
    filter (not just the detection/log list) consults the
    pattern-aware predicate."""
    from core.sandbox import run as sandbox_run
    out = tmp_path / "out"
    out.mkdir()
    r = sandbox_run(
        ["env"], target=str(out), output=str(out),
        env=_hostile_env(tmp_path),
        strict_env=True,
        capture_output=True, text=True, timeout=15,
    )
    assert r.returncode == 0, (r.returncode, r.stderr)
    _assert_swept(r.stdout)


@requires_userns
def test_spawn_run_sandboxed_direct_strict_env_strips_pattern_members(
    tmp_path,
):
    """The _spawn.run_sandboxed direct-caller lane: the re-strip that
    protects callers bypassing run() must prove the same sweep on a
    real child."""
    from core.sandbox._spawn import run_sandboxed
    out = tmp_path / "out"
    out.mkdir()
    r = run_sandboxed(
        ["/usr/bin/env"],
        target=str(out), output=str(out),
        block_network=True, nproc_limit=0, limits={},
        writable_paths=[], readable_paths=None,
        allowed_tcp_ports=None,
        seccomp_profile="full", seccomp_block_udp=False,
        env=_hostile_env(tmp_path), cwd=None, timeout=15,
        strict_env=True,
        capture_output=True, text=True,
    )
    assert r.returncode == 0, (r.returncode, r.stderr)
    _assert_swept(r.stdout)


@pytest.mark.skipif(sys.platform != "darwin", reason="Darwin backend")
def test_macos_run_sandboxed_strict_env_strips_pattern_members(tmp_path):
    """The Darwin backend twin of the direct-caller pin."""
    from core.sandbox._macos_spawn import run_sandboxed
    out = tmp_path / "out"
    out.mkdir()
    r = run_sandboxed(
        ["/usr/bin/env"],
        target=str(out), output=str(out),
        block_network=True, nproc_limit=0, limits={},
        writable_paths=[], readable_paths=None,
        allowed_tcp_ports=None,
        seccomp_profile=None, seccomp_block_udp=False,
        env=_hostile_env(tmp_path), cwd=None, timeout=15,
        strict_env=True,
        capture_output=True, text=True,
    )
    assert r.returncode == 0, (r.returncode, r.stderr)
    _assert_swept(r.stdout)
