"""Namespace-creation denial on every reachable lane.

A sandboxed payload that can create namespaces — a nested user
namespace above all — reaches the kernel code paths behind most
container-escape CVEs even though uid_map writes are refused. The
fork backend's filter installs AFTER the sandbox's own namespace
setup, so denying namespace creation there costs legitimate
workloads nothing. On the subprocess side the PLAIN lane (the only
preexec lane since the unshare-CLI bootstrap was deleted) takes the
ns-blocking rules unconditionally — its payload never legitimately
unshares. On that lane the rules are LOAD-BEARING, not defence in
depth: a userns-permissive kernel would grant an unprivileged
unshare(CLONE_NEWUSER) but for the filter. The denies stay hard
(ERRNO) under audit mode too — SCMP_ACT_TRACE resumes (i.e. grants)
the syscall, and namespace creation is an escape primitive, not an
observable.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]

# Shared in-sandbox probe: every unshare(CLONE_NEW*) is EPERM, setns
# is EPERM, clone3 is ENOSYS (blanket — its flags hide in user
# memory), and fork/exec/multiprocessing keep working. Each unshare
# attempt runs in a fresh fork so a hypothetical success cannot
# pollute later attempts (a payload that enters a new userns gains a
# full capability set over it and changes every subsequent verdict).
_NS_PROBE_SH = r"""
python3 - <<'PY'
import ctypes, os
libc = ctypes.CDLL(None, use_errno=True)
flags = {"NEWUSER":0x10000000,"NEWNS":0x00020000,"NEWPID":0x20000000,
         "NEWNET":0x40000000,"NEWIPC":0x08000000,"NEWUTS":0x04000000,
         "NEWCGROUP":0x02000000,"NEWTIME":0x00000080}
denied = 0
for fl in flags.values():
    pid = os.fork()
    if pid == 0:
        try:
            r = libc.unshare(fl)
            os._exit(0 if r == 0 else ctypes.get_errno())
        except BaseException:
            os._exit(101)  # probe crash — never counted as a denial
    _, st = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(st) == 1:  # EPERM, exactly
        denied += 1
print("unshare-denied:", denied)
r = libc.setns(3, 0)
print("setns-eperm:", r != 0 and ctypes.get_errno() == 1)
r = libc.syscall(435, 0, 0)  # clone3 (x86_64/aarch64 share 435)
print("clone3-enosys:", r != 0 and ctypes.get_errno() == 38)
import subprocess
print("exec-ok:", subprocess.run(["true"]).returncode == 0)
print("uid-map:", open("/proc/self/uid_map").read().split())
PY
"""

# multiprocessing workload control — asserted on the mount-ns lanes
# only: the fork-context Queue's SemLock needs /dev/shm writes, which
# the per-sandbox tmpfs provides there but the plain lane's mountless
# write policy legitimately walls off.
_MP_PROBE_SH = r"""
python3 - <<'PY'
import multiprocessing as mp
q = mp.get_context("fork").Queue()
p = mp.get_context("fork").Process(target=q.put, args=(7,))
p.start(); p.join()
print("mp-ok:", q.get(timeout=10) == 7)
PY
"""

# clone(2) is an independent kernel entry point to the same
# primitive, filtered by its own per-flag MASKED_EQ rules — plus the
# CLONE_UNTRACED deny (a kernel-reserved flag that suppresses the
# ptrace clone event, blinding the audit tracer to the new task).
# clone(2) cannot genuinely request CLONE_NEWTIME: 0x80 lands in the
# exit-signal byte, so a bare kernel reads clone(0x80|SIGCHLD) as a
# plain fork with a nonstandard exit signal (observed to SUCCEED,
# the child unwaitable by a plain waitpid). In-sandbox the MASKED_EQ
# rule fires before any of that, so EPERM is still the verdict. The
# raw-clone child shares nothing (no CLONE_VM) and exits immediately
# via os._exit; a probe crash exits 101 so it can never masquerade
# as an EPERM denial.
_CLONE_PROBE_SH = r"""
python3 - <<'PY'
import ctypes, os, platform
libc = ctypes.CDLL(None, use_errno=True)
SYS_CLONE = {"x86_64": 56, "aarch64": 220}.get(platform.machine())
if SYS_CLONE is None:
    print("clone-arch-unsupported")
    raise SystemExit(0)
SIGCHLD = 17
flags = {"NEWUSER":0x10000000,"NEWNS":0x00020000,"NEWPID":0x20000000,
         "NEWNET":0x40000000,"NEWIPC":0x08000000,"NEWUTS":0x04000000,
         "NEWCGROUP":0x02000000,"NEWTIME":0x00000080,
         "UNTRACED":0x00800000}
def attempt(fl):
    pid = os.fork()
    if pid == 0:
        try:
            ctypes.set_errno(0)
            rc = libc.syscall(SYS_CLONE, ctypes.c_ulong(fl | SIGCHLD),
                              0, 0, 0, 0)
            if rc == 0:
                os._exit(0)  # the raw-clone child
            if rc > 0:
                try:
                    os.waitpid(rc, 0)
                except OSError:
                    pass  # nonstandard exit signal: unwaitable
                os._exit(0)  # the clone itself succeeded
            os._exit(ctypes.get_errno())
        except BaseException:
            os._exit(101)  # probe crash — never counted as a denial
    _, st = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(st)
print("clone-denied:", sum(1 for fl in flags.values()
                           if attempt(fl) == 1))  # EPERM
print("clone-control-ok:", attempt(0) == 0)
PY
"""


def test_ns_block_lane_contract_source_pin():
    """Source pin on the per-lane contract: _spawn's grandchild-
    installed filter always blocks; the plain subprocess lane — the
    ONLY lane that execs through a preexec since the unshare-CLI
    bootstrap was deleted — takes the ns-blocking rules
    unconditionally (its payload never legitimately unshares), and
    the per-call demoted preexec rebuild carries them too. The
    Landlock-only audit fallback also gets the block, but its filter
    is BUILT in context.py and handed in — _landlock_audit itself
    must never grow its own enablement, or filter construction gains
    a second, unpinned call site."""
    spawn = (_REPO_ROOT / "core" / "sandbox" / "_spawn.py").read_text(
        encoding="utf-8")
    assert "block_ns_creation=True" in spawn
    ctx = (_REPO_ROOT / "core" / "sandbox" / "context.py").read_text(
        encoding="utf-8")
    assert ctx.count("seccomp_block_ns_creation=True") >= 2, (
        "context must build BOTH ns-blocking preexecs (the plain-lane "
        "baseline and the demoted per-call rebuild)")
    assert 'kwargs["preexec_fn"] = preexec_ns_blocked' in ctx, (
        "the plain lane must take the ns-blocking preexec "
        "unconditionally — no lane needs the permissive variant now")
    assert "preexec if need_unshare else" not in ctx, (
        "the deleted unshare-CLI lane's permissive preexec selection "
        "must not resurface")
    la = (_REPO_ROOT / "core" / "sandbox" /
          "_landlock_audit.py").read_text(encoding="utf-8")
    assert "block_ns_creation" not in la, (
        "_landlock_audit must not build the ns block itself — "
        "context.py owns the audit-fallback filter (and enables the "
        "block there); a second builder call site here would escape "
        "the lane pins")


def test_ns_flags_cover_every_clone_namespace():
    from core.sandbox.seccomp import _CLONE_NS_FLAGS
    assert set(_CLONE_NS_FLAGS) == {
        "NEWUSER", "NEWNS", "NEWPID", "NEWNET", "NEWIPC", "NEWUTS",
        "NEWCGROUP", "NEWTIME",
    }


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_payload_cannot_create_namespaces(tmp_path):
    """Inside run_untrusted: every unshare(CLONE_NEW*) and setns is
    EPERM; clone3 is ENOSYS; fork/exec and multiprocessing keep
    working (the sh wrapper keeps cmd[0] inside the bind tree on
    hosts whose driver python lives in a venv)."""
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    try:
        r = _ctx.run_untrusted(
            ["sh", "-c", _NS_PROBE_SH + _MP_PROBE_SH],
            target=str(tmp_path), output=str(tmp_path), timeout=120,
            capture_output=True, text=True,
        )
    # SandboxSetupError subclasses BaseException by design and sails
    # past `except Exception` — name it so a host where the sandbox
    # cannot engage skips rather than errors.
    except (Exception, SandboxSetupError) as e:  # noqa: BLE001
        pytest.skip(f"sandbox unavailable: {e}")
    out = _skip_or_fail_probe(r)
    _assert_ns_probe_denied(out)
    assert "mp-ok: True" in out, out


def _assert_ns_probe_denied(out: str) -> None:
    """The _NS_PROBE_SH verdict block, shared by every lane variant."""
    assert "unshare-denied: 8" in out, out
    assert "setns-eperm: True" in out, out
    assert "clone3-enosys: True" in out, out
    assert "exec-ok: True" in out, out


def _skip_or_fail_probe(r: "subprocess.CompletedProcess[str]") -> str:
    """Honour the unavailability skip only when the probe never
    started; a probe that produced output and THEN died is a mid-run
    crash a regression can cause (e.g. an overbroad rule breaking
    fork/waitpid inside the sandbox) — fail loud on that shape."""
    if r.returncode != 0:
        assert not (r.stdout or "").strip(), (
            "probe crashed mid-run:\n" + (r.stdout or "")
            + "\n--- stderr tail ---\n" + (r.stderr or "")[-500:])
        pytest.skip(f"probe did not run: {(r.stderr or '')[-200:]}")
    return r.stdout or ""


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_payload_cannot_clone_namespaces(tmp_path: Path) -> None:
    """clone(2) is filtered by its own rules — a regression that
    dropped just the clone arm of the per-flag loop would leave the
    primitive open while the unshare assertions stay green. All eight
    CLONE_NEW* flags and CLONE_UNTRACED are EPERM; a plain
    clone(SIGCHLD) (fork) keeps working."""
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    try:
        r = _ctx.run_untrusted(
            ["sh", "-c", _CLONE_PROBE_SH], target=str(tmp_path),
            output=str(tmp_path), timeout=120,
            capture_output=True, text=True,
        )
    except (Exception, SandboxSetupError) as e:  # noqa: BLE001
        pytest.skip(f"sandbox unavailable: {e}")
    out = _skip_or_fail_probe(r)
    if "clone-arch-unsupported" in out:
        pytest.skip("no raw-clone encoding for this architecture")
    assert "clone-denied: 9" in out, out
    assert "clone-control-ok: True" in out, out


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_ns_denials_survive_audit_mode(tmp_path: Path) -> None:
    """Audit mode must keep the namespace denies as hard ERRNO rules:
    SCMP_ACT_TRACE resumes (i.e. grants) the traced syscall, so
    converting these to allow-and-log would hand an AUDITED payload
    the escape primitive the enforcement run refuses. The audit
    branches build their own filters, so the enforcement-mode test
    cannot cover them. audit_required=True proves SOME audit tier
    engaged, not which one: on a mount-capable host (CI's shape) the
    fork-backend tracer attaches; a demoted host satisfies it with
    the Landlock-tier audit instead. The regression cannot hide
    either way — a TRACE rule with no tracer attached returns
    ENOSYS, not the EPERM these assertions demand."""
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    try:
        r = _ctx.run_untrusted(
            ["sh", "-c", _NS_PROBE_SH + _MP_PROBE_SH],
            target=str(tmp_path), output=str(tmp_path), timeout=120,
            capture_output=True, text=True,
            audit=True, audit_required=True,
            audit_run_dir=str(tmp_path),
        )
    except (Exception, SandboxSetupError) as e:  # noqa: BLE001
        pytest.skip(f"audited sandbox unavailable: {e}")
    out = _skip_or_fail_probe(r)
    _assert_ns_probe_denied(out)
    assert "mp-ok: True" in out, out


def _host_grants_unprivileged_userns() -> bool:
    """Outside-sandbox baseline. Kernel EPERM and filter EPERM are
    indistinguishable from inside the sandbox, so the load-bearing
    claim is only testable where the UNSANDBOXED caller can create a
    user namespace. Container runtimes' seccomp profiles and
    userns-restricting LSM knobs reproduce every denial sentinel on
    their own — on such hosts the lane test must skip, not pass
    vacuously. Probed in a fresh fork: a success must not leave the
    test process in a new userns."""
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    pid = os.fork()
    if pid == 0:
        try:
            os._exit(0 if libc.unshare(0x10000000) == 0 else 1)
        except BaseException:
            os._exit(1)
    _, st = os.waitpid(pid, 0)
    return os.waitstatus_to_exitcode(st) == 0


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_plain_lane_blocks_namespace_creation(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """On the plain subprocess lane the preexec's ns rules are
    LOAD-BEARING: a userns-permissive kernel grants an unprivileged
    unshare(CLONE_NEWUSER), so without the filter the payload walks
    straight into a fresh capability set. Force the lane by failing
    both mount probes (the degraded-host shape) and prove the denies
    hold there too. The uid-map echo pins the lane: the payload must
    still be in the CALLER'S user namespace — the mount-ns backend
    would have moved it into the sandbox's own."""
    from core.sandbox import context as _ctx
    from core.sandbox import state
    from core.sandbox.errors import SandboxSetupError
    if not _host_grants_unprivileged_userns():
        pytest.skip("host already denies unprivileged userns outside "
                    "the sandbox — kernel EPERM is indistinguishable "
                    "from the filter's, the test would be vacuous")
    monkeypatch.setattr(state, "_mount_available_cache", False)
    monkeypatch.setattr(state, "_mount_ns_available_cache", False)
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    try:
        r = _ctx.run_untrusted(
            ["sh", "-c", _NS_PROBE_SH + _CLONE_PROBE_SH],
            target=str(tmp_path), output=str(tmp_path), timeout=120,
            capture_output=True, text=True,
        )
    except (Exception, SandboxSetupError) as e:  # noqa: BLE001
        pytest.skip(f"landlock-only lane unavailable: {e}")
    out = _skip_or_fail_probe(r)
    _assert_ns_probe_denied(out)
    if "clone-arch-unsupported" not in out:
        assert "clone-denied: 9" in out, out
        assert "clone-control-ok: True" in out, out
    caller_map = Path("/proc/self/uid_map").read_text(
        encoding="utf-8").split()
    assert f"uid-map: {caller_map}" in out, (
        "payload left the caller's user namespace — the forced "
        "plain lane did not engage\n" + out)


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_plain_lane_ns_denials_survive_audit_mode(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The Landlock-only audit fallback builds its own filter at a
    THIRD call site (context.py constructs it and hands it to
    _landlock_audit), so neither the mount-ns audit test nor the
    enforcement-mode plain-lane test covers it. Force the demoted
    shape AND audit mode together: the namespace denies must stay
    hard ERRNO rules there too. The uid-map echo pins the plain
    lane; the evidence JSONL under <run_dir>/.audit/ pins audit
    engagement."""
    from core.sandbox import context as _ctx
    from core.sandbox import state
    from core.sandbox.errors import SandboxSetupError
    if not _host_grants_unprivileged_userns():
        pytest.skip("host already denies unprivileged userns outside "
                    "the sandbox — kernel EPERM is indistinguishable "
                    "from the filter's, the test would be vacuous")
    monkeypatch.setattr(state, "_mount_available_cache", False)
    monkeypatch.setattr(state, "_mount_ns_available_cache", False)
    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    try:
        r = _ctx.run_untrusted(
            ["sh", "-c", _NS_PROBE_SH + _CLONE_PROBE_SH],
            target=str(tmp_path), output=str(tmp_path), timeout=120,
            capture_output=True, text=True,
            audit=True, audit_required=True,
            audit_run_dir=str(tmp_path),
        )
    except (Exception, SandboxSetupError) as e:  # noqa: BLE001
        pytest.skip(f"audited landlock-only lane unavailable: {e}")
    out = _skip_or_fail_probe(r)
    _assert_ns_probe_denied(out)
    if "clone-arch-unsupported" not in out:
        assert "clone-denied: 9" in out, out
        assert "clone-control-ok: True" in out, out
    caller_map = Path("/proc/self/uid_map").read_text(
        encoding="utf-8").split()
    assert f"uid-map: {caller_map}" in out, (
        "payload left the caller's user namespace — the forced "
        "plain lane did not engage\n" + out)
    assert (tmp_path / ".audit" / ".sandbox-denials.jsonl").exists(), (
        "audit evidence JSONL missing — the audit tier did not engage")


@pytest.mark.integration
@pytest.mark.skipif(sys.platform != "linux", reason="namespace sandbox")
def test_out_of_tree_tool_refuses_untrusted_run(tmp_path, monkeypatch):
    """The containment-floor contract covers the tool-visibility
    pre-flight: an untrusted cmd[0] that resolves OUTSIDE the mount-ns
    bind tree (a venv python is the everyday shape) routes to the
    mountless namespace backend, whose floor check must refuse rather
    than silently run on a host-procfs-visible lane; tool_paths= is
    the named remedy and the operator override restores the degrade."""
    from core.sandbox import context as _ctx
    from core.sandbox.errors import SandboxSetupError
    bindir = tmp_path / "outside-bin"
    bindir.mkdir()
    tool = bindir / "sbx-out-of-tree-tool"
    tool.write_text("#!/bin/sh\necho tool-ran\n", encoding="utf-8")
    tool.chmod(0o755)
    monkeypatch.setenv("PATH",
                       f"{bindir}:{os.environ.get('PATH', '/usr/bin')}")
    monkeypatch.delenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", raising=False)
    workdir = tmp_path / "w"
    workdir.mkdir()
    try:
        with pytest.raises(SandboxSetupError,
                           match="outside the mount-ns bind tree"):
            _ctx.run_untrusted(["sbx-out-of-tree-tool"],
                               target=str(workdir), output=str(workdir),
                               timeout=60, capture_output=True, text=True)
    except (pytest.skip.Exception, pytest.fail.Exception,
            AssertionError):
        # A refusal with the WRONG message is a failure, not a host
        # without the lane — pytest.raises reports the regex mismatch
        # as AssertionError, which the generic skip below must never
        # swallow.
        raise
    except Exception as e:  # noqa: BLE001 — host without the lane
        pytest.skip(f"mount-ns lane unavailable: {e}")

    r = _ctx.run_untrusted(["sbx-out-of-tree-tool"],
                           target=str(workdir), output=str(workdir),
                           timeout=60, capture_output=True, text=True,
                           tool_paths=[str(bindir)])
    assert "tool-ran" in (r.stdout or ""), (
        "tool_paths= remedy did not restore the mount-ns lane")

    monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")
    # The override's promise is narrow: the GATE stops refusing. The
    # fallback lane then applies its own posture (here: Landlock's
    # read allowlist still denies the out-of-tree binary, so the exec
    # itself fails — surfaced either as a nonzero CompletedProcess or
    # as the lane's own fail-loud SandboxSetupError) — that is the
    # lane's business, not the gate's.
    try:
        r = _ctx.run_untrusted(["sbx-out-of-tree-tool"],
                               target=str(workdir), output=str(workdir),
                               timeout=60, capture_output=True, text=True)
    except SandboxSetupError as e:
        assert "outside the mount-ns bind tree" not in str(e), (
            "override did not lift the floor refusal: " + str(e))
        assert "containment floor violated" not in str(e), (
            "override did not lift the floor refusal: " + str(e))
    else:
        assert isinstance(r.returncode, int), (
            "override run did not execute")
