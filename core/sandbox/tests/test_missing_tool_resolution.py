"""The missing-tool contract: a command that resolves nowhere raises
the subprocess-parity FileNotFoundError before any lane dispatch.

The demotion machinery exists for CONTAINMENT setup failures. A binary
that is simply not installed is diagnosable pre-spawn on every
non-rootfs lane (the sandbox's filesystem views are subsets of the
host namespace), and the historical cross-lane contract — the plain
subprocess lane natively, and every tool-missing caller arm
(``except FileNotFoundError: <tool> not installed``) — is
FileNotFoundError. Routing the shape into the spawn backend instead
produced two doomed spawn attempts, a speculative-failure cache entry
steering LATER calls for the same name onto the mountless backend,
and a BaseException-grade category-'X' refusal that no tool-missing
arm can catch.
"""

import errno
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="linux lane routing")

_NOWHERE = "raptor-test-tool-missing-everywhere"


def _simulate_spawn_capable_probes(monkeypatch):
    """Patch the capability probes at their module seams so run()
    routes to the (stubbed) spawn backend on any host. The engagement
    probe seam is load-bearing: on a userns-denied runner the REAL
    ``check_unshare_engages`` refuses the flag-set and run() raises
    its loud engagement error before the stub is ever reached."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox import probes as _probes_mod
    monkeypatch.setattr(_ctx, "check_net_available", lambda: True)
    monkeypatch.setattr(_ctx, "check_mount_available", lambda: True)
    monkeypatch.setattr(_spawn_mod, "mount_ns_available", lambda: True)
    monkeypatch.setattr(_probes_mod, "check_unshare_engages",
                        lambda flags: (True, ""))


def test_bare_name_resolving_nowhere_raises_filenotfound(
        tmp_path, monkeypatch):
    """No spawn attempt, no speculative-cache write, subprocess-parity
    exception with the command name and ENOENT."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox import state
    monkeypatch.setattr(state, "_speculative_failure_cache", {})
    spawns: list = []

    def counting_spawn(cmd, **kwargs):
        spawns.append(1)
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", counting_spawn)
    with pytest.raises(FileNotFoundError) as excinfo:
        _ctx.run([_NOWHERE, "arg"], target=str(tmp_path),
                 output=str(tmp_path), timeout=30)
    assert excinfo.value.errno == errno.ENOENT
    assert _NOWHERE in str(excinfo.value)
    assert not spawns, "a missing tool must not reach the spawn backend"
    assert state._speculative_failure_cache == {}, (
        "a missing tool must not pollute the speculative-failure cache")


def test_absolute_missing_path_raises_filenotfound(tmp_path, monkeypatch):
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx

    def counting_spawn(cmd, **kwargs):  # pragma: no cover — must not run
        pytest.fail("spawned for a missing absolute path")

    monkeypatch.setattr(_spawn_mod, "run_sandboxed", counting_spawn)
    missing = tmp_path / "bin" / "not-here"
    with pytest.raises(FileNotFoundError):
        _ctx.run([str(missing)], target=str(tmp_path),
                 output=str(tmp_path), timeout=30)


def test_child_path_only_resolution_is_honoured(tmp_path, monkeypatch):
    """A name resolvable ONLY through the child env's PATH is not a
    missing tool — the check consults both the caller's and the
    child's PATH before refusing."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    tool_dir = tmp_path / "toolbin"
    tool_dir.mkdir()
    tool = tool_dir / _NOWHERE
    tool.write_text("#!/bin/sh\nexit 0\n")
    tool.chmod(0o755)
    ran: list = []

    def ok_spawn(cmd, **kwargs):
        ran.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    # Same probe-seam simulation as the X-shape test above: on a
    # userns-less runner the real probes would route this call to the
    # plain-subprocess lane and execute the real script instead of
    # the stub.
    _simulate_spawn_capable_probes(monkeypatch)
    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    import os as _os
    env = {"PATH": f"{tool_dir}:{_os.environ.get('PATH', '/usr/bin')}"}
    r = _ctx.run([_NOWHERE], target=str(tmp_path),
                 output=str(tmp_path), timeout=30, env=env,
                 env_caller_filtered=True)
    assert r.returncode == 0
    assert ran, "the child-PATH-resolvable tool never dispatched"


def test_host_resolvable_but_bind_invisible_keeps_the_loud_x_shape(
        tmp_path, monkeypatch):
    """A binary that EXISTS on the host but cannot exec inside the
    sandbox view (bind set too narrow) is a genuinely lane-level
    failure — the typed category-'X' refusal after the mountless
    retry stays, unweakened by the missing-tool pre-check."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError

    def x_spawn(cmd, **kwargs):
        cp = subprocess.CompletedProcess(cmd, returncode=127,
                                         stdout="", stderr="")
        cp._setup_status = ("X", "exec: file not found")
        return cp

    # Simulate a spawn-capable host at the probe seams (hermetic on
    # userns-less runners, where the real probes would route the call
    # to the plain-subprocess lane and never reach the stub — the
    # rootfs test below uses the same pattern).
    _simulate_spawn_capable_probes(monkeypatch)
    monkeypatch.setattr(_spawn_mod, "run_sandboxed", x_spawn)
    with pytest.raises(SandboxSetupError) as excinfo:
        _ctx.run(["true"], target=str(tmp_path),
                 output=str(tmp_path), timeout=30)
    assert excinfo.value.setup_category == "X"
    assert "bind-tree fallback failed" in str(excinfo.value)


def test_rootfs_commands_are_exempt_from_host_resolution(
        tmp_path, monkeypatch):
    """rootfs commands resolve inside the IMAGE tree — a host-missing
    absolute cmd[0] must reach the spawn backend, not raise a
    host-derived FileNotFoundError."""
    from core.sandbox import _spawn as _spawn_mod
    from core.sandbox import context as _ctx
    rootfs = tmp_path / "image"
    (rootfs / "bin").mkdir(parents=True)
    ran: list = []

    def ok_spawn(cmd, **kwargs):
        ran.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode=0,
                                           stdout="", stderr="")

    _simulate_spawn_capable_probes(monkeypatch)
    monkeypatch.setattr(_spawn_mod, "run_sandboxed", ok_spawn)
    r = _ctx.run(["/bin/only-in-the-image"], rootfs=str(rootfs),
                 target=str(tmp_path), output=str(tmp_path), timeout=30)
    assert r.returncode == 0
    assert ran, "rootfs command never reached the spawn backend"


def test_missing_tool_shape_matches_the_plain_subprocess_lane(
        tmp_path):
    """Cross-lane parity pin: subprocess.run itself raises exactly this
    exception type for the same input — callers keep one arm."""
    with pytest.raises(FileNotFoundError):
        subprocess.run([_NOWHERE], check=False)


def test_tool_missing_caller_arm_contract(tmp_path, monkeypatch):
    """The consumer contract end to end: a caller with the canonical
    ``except FileNotFoundError: tool not installed`` arm degrades
    gracefully instead of dying on a BaseException-grade refusal —
    the exploit-feasibility seccomp probe's exact shape."""
    from core.sandbox import context as _ctx
    probed = {}
    try:
        _ctx.run([_NOWHERE, "dump", "/bin/true"], profile="debug",
                 target="/bin", output=str(tmp_path),
                 restrict_reads=True, readable_paths=["/bin"],
                 capture_output=True, text=True, timeout=30,
                 stdin=subprocess.DEVNULL, skip_pid_ns=True,
                 skip_mount_ns=True)
    except FileNotFoundError:
        probed["result"] = None  # tool not installed — graceful skip
    assert probed == {"result": None}
