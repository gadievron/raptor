"""Fileless-exec deny: memfd_create + execveat(AT_EMPTY_PATH) are
refused for restricted-reads (untrusted / strict) children; trusted
read-everywhere lanes are untouched.

The gap: inside run_untrusted a payload could memfd_create an
anonymous inode, write an arbitrary ELF into it, and
execve("/proc/self/fd/<memfd>") — the sandboxed interpreter became an
arbitrary in-memory process image (live-proven). Landlock can
never close that spelling: a memfd's inode lives on a kernel-internal
SB_NOUSER mount that Landlock exempts from ALL rules (verified live —
a ruleset with a handled EXECUTE bit and zero grants still permits
memfd exec), and seccomp cannot inspect the execve path pointer. The
sound chokepoint is refusing memfd CREATION (wholesale, no argument
gating — MFD_* flags are attacker-chosen, so argument filters are
bypassable by construction) plus the execveat AT_EMPTY_PATH fd-exec
spelling, both keyed on the restrict_reads posture.

Two directions, per the deny doctrine:
  * restricted-reads children: memfd_create -> EPERM,
    execveat(fd, "", AT_EMPTY_PATH) -> EPERM, and the denials hold
    under audit mode (hard_deny — escape primitives never downgrade
    to allow-and-log);
  * everything legitimate keeps working: path-carrying execveat,
    ordinary execve, compile-and-run of a PoC under output (the
    caller-inventory toolchain shape), and TRUSTED read-everywhere
    lanes still get memfd_create.

Plus the frida-profile carve-out (TestFridaProfileCarveOut): under
``profile == "frida"`` only, memfd_create stays permitted (frida's
agent injection is memfd-based) while the execveat AT_EMPTY_PATH arm
still installs; every other profile — including the ptrace-granting
"debug" — keeps the full two-arm deny. Rationale in the
_make_seccomp_preexec docstring (seccomp.py).

PROBE-ENVIRONMENT CAVEAT for future editors: an environment-level
security agent on some hosts SIGKILLs fork+exec-of-memfd patterns
even outside any sandbox (exit 137, race-losable). These tests are
deliberately shaped so no memfd is ever exec'd — the deny direction
refuses creation before any exec, and the trusted direction only
creates and closes the fd. A denial from THIS change is a syscall
errno (EPERM from seccomp, EACCES from Landlock), never a SIGKILL;
never assert on -9 shapes.
"""

from __future__ import annotations

import errno
import platform
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if __name__ == "__main__":
    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))

from core.sandbox import check_seccomp_available  # noqa: E402
from core.sandbox.tests.capability import (  # noqa: E402
    requires_landlock,
    requires_userns,
)

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux seccomp"),
    pytest.mark.skipif(
        not check_seccomp_available(),
        reason="libseccomp / seccomp filter unavailable on this host",
    ),
]

# execveat syscall numbers for the arches the sandbox supports (the
# probe child issues the raw syscall so glibc wrapper availability
# doesn't decide the test outcome).
_EXECVEAT_NR = {"x86_64": 322, "aarch64": 281}

_PROBE = textwrap.dedent("""
    import ctypes, ctypes.util, errno, os, sys
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    execveat_nr = int(sys.argv[1])
    failures = []

    # 1. memfd_create — the deny direction expects EPERM; the trusted
    #    and frida directions expect success. Decided by argv[2]. The
    #    fd is NEVER exec'd (see the module-docstring probe caveat).
    want_memfd_denied = sys.argv[2] == "deny"
    # The frida carve-out relaxes ONLY memfd_create: the execveat
    # AT_EMPTY_PATH arm must still be installed on that lane.
    want_fd_exec_denied = sys.argv[2] in ("deny", "frida")
    try:
        fd = os.memfd_create("probe", 0)
    except OSError as e:
        if not want_memfd_denied:
            failures.append("memfd_create denied on trusted lane"
                            " errno=%d" % e.errno)
        elif e.errno != errno.EPERM:
            failures.append("memfd_create wrong errno=%d" % e.errno)
        else:
            print("memfd_create DENIED EPERM", flush=True)
    else:
        os.close(fd)
        if want_memfd_denied:
            failures.append("memfd_create SUCCEEDED under deny")
        else:
            print("memfd_create OK", flush=True)

    # 2. execveat(fd, "", AT_EMPTY_PATH) on an fd of a legitimate
    #    on-disk binary — the fd-exec spelling. Forked so a
    #    successful exec cannot replace the probe.
    AT_EMPTY_PATH = 0x1000
    bfd = os.open("/bin/echo", os.O_RDONLY)
    pid = os.fork()
    if pid == 0:
        libc.syscall(execveat_nr, bfd, b"", None, None, AT_EMPTY_PATH)
        os._exit(ctypes.get_errno())
    _, st = os.waitpid(pid, 0)
    code = os.WEXITSTATUS(st) if os.WIFEXITED(st) else 200
    if want_fd_exec_denied:
        if code != errno.EPERM:
            failures.append("execveat AT_EMPTY_PATH not EPERM"
                            " (child exit=%d)" % code)
        else:
            print("execveat-empty-path DENIED EPERM", flush=True)
    # (trusted direction: outcome recorded but not asserted here —
    #  a successful exec makes the fork child echo and exit 0)
    os.close(bfd)

    # 3. Path-carrying execveat stays allowed in BOTH directions —
    #    the rule matches AT_EMPTY_PATH, not the syscall.
    dfd = os.open("/bin", os.O_RDONLY)
    pid = os.fork()
    if pid == 0:
        libc.syscall(execveat_nr, dfd, b"echo", None, None, 0)
        os._exit(ctypes.get_errno())
    _, st = os.waitpid(pid, 0)
    code = os.WEXITSTATUS(st) if os.WIFEXITED(st) else 200
    if code == errno.EPERM:
        failures.append("path-carrying execveat got EPERM")
    else:
        print("execveat-with-path OK", flush=True)
    os.close(dfd)

    # 4. Ordinary execve control.
    import subprocess
    r = subprocess.run(["/bin/echo", "control"], capture_output=True)
    if r.returncode != 0:
        failures.append("plain execve control failed")
    else:
        print("execve-control OK", flush=True)

    for f in failures:
        print("FAILURE: " + f, flush=True)
    sys.exit(1 if failures else 0)
""")


def _execveat_nr() -> int | None:
    return _EXECVEAT_NR.get(platform.machine())


requires_execveat_nr = pytest.mark.skipif(
    _execveat_nr() is None,
    reason="execveat syscall number not tabulated for this arch",
)


def _probe_cmd(direction: str) -> list[str]:
    return [sys.executable, "-c", _PROBE, str(_execveat_nr()), direction]


def _py_tool_paths() -> list[str] | None:
    # Non-system interpreter installs (venv, pyenv) need their runtime
    # dirs granted; None when the interpreter is fully under the
    # system prefixes (test_e2e_sandbox pattern).
    from core.sandbox import python_runtime_tool_paths
    return python_runtime_tool_paths() or None


@requires_execveat_nr
class TestSeccompLayerAlone:
    """The adjunct with Landlock absent by construction: the seccomp
    preexec is applied directly (no Landlock preexec in the chain), so
    the fd-exec spellings are denied even below the Landlock floor."""

    def _run_under_filter(self, deny_fd_exec: bool, direction: str):
        from core.sandbox.seccomp import _make_seccomp_preexec

        fn = _make_seccomp_preexec("full", deny_fd_exec=deny_fd_exec)
        assert fn is not None
        return subprocess.run(
            _probe_cmd(direction),
            preexec_fn=fn, capture_output=True, text=True, timeout=60,
        )

    def test_deny_engaged_without_landlock(self):
        r = self._run_under_filter(True, "deny")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "memfd_create DENIED EPERM" in r.stdout
        assert "execveat-empty-path DENIED EPERM" in r.stdout
        assert "execveat-with-path OK" in r.stdout
        assert "execve-control OK" in r.stdout

    def test_default_filter_unchanged(self):
        # deny_fd_exec defaults False: the trusted filter still
        # permits memfd_create — byte-identical trusted lanes.
        r = self._run_under_filter(False, "allow")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "memfd_create OK" in r.stdout


@requires_execveat_nr
class TestFridaProfileCarveOut:
    """The frida-profile memfd carve-out, both directions.

    frida-core's agent injection writes frida-agent.so into a memfd
    (frida_memory_file_descriptor_from_bytes) and the target maps it
    via dlopen("/proc/self/fd/N") — the fd is never exec'd — so the
    wholesale memfd_create deny aborted every sandboxed frida
    spawn/attach at injection time. Under ``profile == "frida"`` the
    memfd arm is skipped (consented instrumentation: that profile
    already grants ptrace/process_vm_*, i.e. in-memory code injection
    is the lane's granted capability) while the execveat AT_EMPTY_PATH
    arm still installs. Scope-tightness: the carve-out is keyed on the
    frida seccomp-profile string alone, so every other profile —
    including "debug", the OTHER ptrace-granting profile — must build
    the full two-arm deny unchanged.
    """

    def _run_under_filter(self, profile: str, direction: str):
        from core.sandbox.seccomp import _make_seccomp_preexec

        fn = _make_seccomp_preexec(profile, deny_fd_exec=True)
        assert fn is not None
        return subprocess.run(
            _probe_cmd(direction),
            preexec_fn=fn, capture_output=True, text=True, timeout=60,
        )

    def test_frida_profile_relaxes_memfd_keeps_fd_exec_deny(self):
        r = self._run_under_filter("frida", "frida")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "memfd_create OK" in r.stdout
        assert "execveat-empty-path DENIED EPERM" in r.stdout
        assert "execveat-with-path OK" in r.stdout
        assert "execve-control OK" in r.stdout

    @pytest.mark.parametrize("profile", ["full", "debug"])
    def test_carve_out_unreachable_from_other_profiles(self, profile):
        # "full" is the untrusted/strict lane; "debug" is the adjacent
        # ptrace-granting profile — ptrace consent alone must NOT
        # relax the memfd deny.
        r = self._run_under_filter(profile, "deny")
        assert r.returncode == 0, r.stdout + r.stderr
        assert "memfd_create DENIED EPERM" in r.stdout
        assert "execveat-empty-path DENIED EPERM" in r.stdout

    def test_untrusted_contract_cannot_select_frida_profile(
            self, tmp_path, monkeypatch):
        # The untrusted contract can never reach the carve-out via the
        # kwarg route: the profile ratchet rejects everything but
        # full/strict, so no run_untrusted CALLER can weaken the memfd
        # deny by naming the frida profile. (The operator's --sandbox
        # CLI flag remains authoritative over profiles everywhere, as
        # documented at the resolution site — an operator override is
        # consent, not a caller-reachable relaxation; it already
        # grants ptrace, which dwarfs memfd.) The userns floor gate
        # runs before the
        # ratchet and would mask the TypeError with its own refusal
        # on userns-denied hosts — neutralise it (the established
        # pattern for pinning run_untrusted's argument contract, see
        # test_untrusted_failclosed_gates); the floor refusal has its
        # own pins.
        from core.sandbox import context as ctx
        from core.sandbox import run_untrusted

        monkeypatch.setattr(ctx, "_require_userns_or_optin",
                            lambda *a, **k: False)
        with pytest.raises(TypeError, match="frida"):
            run_untrusted(["/bin/true"], target=str(tmp_path),
                          profile="frida")

    def test_carve_out_composes_with_audit_mode(self):
        # frida composes with --audit; the carve-out must survive the
        # audit filter build (memfd permitted) while the execveat arm
        # keeps its hard-deny ERRNO action. Same fork/probe discipline
        # as TestAuditModeHardDeny: the audit filter TRACEs
        # open/connect, and a TRACE rule firing without an attached
        # tracer SIGSYS-kills — resolve everything in the parent, raw
        # syscalls only after the filter installs.
        import ctypes
        import os as _os

        from core.sandbox.seccomp import _make_seccomp_preexec

        fn = _make_seccomp_preexec(
            "frida", audit_mode=True, deny_fd_exec=True,
        )
        assert fn is not None
        nr = _execveat_nr()
        libc = ctypes.CDLL(None, use_errno=True)
        bfd = _os.open("/bin/echo", _os.O_RDONLY)
        r, w = _os.pipe()
        pid = _os.fork()
        if pid == 0:
            try:
                _os.close(r)
                fn()
                code = 0
                try:
                    mfd = _os.memfd_create("x", 0)
                    _os.close(mfd)   # created, never exec'd
                except OSError:
                    code = 4         # carve-out lost under audit
                if code == 0:
                    libc.syscall(nr, bfd, b"", None, None, 0x1000)
                    if ctypes.get_errno() != errno.EPERM:
                        code = 5     # fd-exec arm lost on frida lane
                _os.write(w, bytes([code]))
            except BaseException:
                try:
                    _os.write(w, bytes([9]))
                except OSError:
                    pass
            _os._exit(0)
        _os.close(w)
        _os.close(bfd)
        try:
            data = _os.read(r, 1)
        finally:
            _os.close(r)
            _os.waitpid(pid, 0)
        assert data == b"\x00", f"frida audit carve-out probe code={data!r}"

    @pytest.mark.usefixtures("degraded_floor_consent_if_mountless")
    @requires_landlock
    @requires_userns
    def test_frida_posture_end_to_end(self, tmp_path):
        # The exact sandbox posture packages/frida/sandboxed.py runs
        # the CLI under (frida profile + restrict_reads) — the memfd
        # relaxation must survive whichever builder site the host
        # dispatches, and the fd-exec arm must still bite there.
        from core.sandbox import run

        out = tmp_path / "o"
        out.mkdir()
        r = run(
            _probe_cmd("frida"),
            profile="frida",
            skip_pid_ns=True,
            skip_mount_ns=True,
            fake_home=True,
            block_network=True,
            output=str(out),
            restrict_reads=True,
            tool_paths=_py_tool_paths(),
            capture_output=True, text=True, timeout=120,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert "memfd_create OK" in r.stdout
        assert "execveat-empty-path DENIED EPERM" in r.stdout
        assert "execveat-with-path OK" in r.stdout
        assert "execve-control OK" in r.stdout


@pytest.fixture()
def degraded_floor_consent_if_mountless(monkeypatch):
    """Let the untrusted-run tests dispatch on mount-denied hosts.

    run_untrusted's default floor is the fresh-procfs contract, which
    needs the mount-namespace backend; a host that denies mount
    operations inside a user namespace (the no-mount matrix shape)
    refuses the run before any child exists, so the posture deny under
    test is never observed. The deny is keyed on the restrict_reads
    POSTURE, not on the backend — on such hosts this fixture grants
    the refusal's own documented consent so the run dispatches the
    achievable degraded lane and the deny is witnessed THERE. On
    mount-capable hosts the env stays untouched and dispatch is
    byte-identical to before. Keyed on the same cached probe the
    production degradation lattice keys on, and composes with
    conftest's _consent_env_guard (strip, then set, LIFO restore).
    """
    from core.sandbox.probes import check_mount_available

    if not check_mount_available():
        monkeypatch.setenv("RAPTOR_ALLOW_DEGRADED_UNTRUSTED", "1")


@requires_execveat_nr
@requires_landlock
@requires_userns
class TestUntrustedPosture:
    """End-to-end through run_untrusted / run — the restrict_reads
    posture carries the deny on whichever lane the host dispatches
    (including the degraded lane a mount-denied host dispatches under
    the documented floor consent — see
    degraded_floor_consent_if_mountless)."""

    @pytest.mark.usefixtures("degraded_floor_consent_if_mountless")
    def test_untrusted_denies_fd_exec(self, tmp_path):
        from core.sandbox import run_untrusted

        tgt = tmp_path / "t"
        out = tmp_path / "o"
        tgt.mkdir()
        out.mkdir()
        r = run_untrusted(
            _probe_cmd("deny"),
            target=str(tgt), output=str(out),
            tool_paths=_py_tool_paths(),
            capture_output=True, text=True, timeout=120,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert "memfd_create DENIED EPERM" in r.stdout
        assert "execveat-empty-path DENIED EPERM" in r.stdout
        assert "execveat-with-path OK" in r.stdout
        assert "execve-control OK" in r.stdout

    def test_trusted_run_keeps_memfd(self, tmp_path):
        # The default (read-everywhere) posture must be untouched:
        # same probe, memfd_create succeeds. Direction 2 of the
        # byte-identical-trusted-lanes contract.
        from core.sandbox import run

        r = run(
            _probe_cmd("allow"),
            block_network=True,
            target=str(tmp_path), output=str(tmp_path),
            tool_paths=_py_tool_paths(),
            capture_output=True, text=True, timeout=120,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert "memfd_create OK" in r.stdout

    @pytest.mark.skipif(
        shutil.which("cc") is None and shutil.which("gcc") is None,
        reason="no C compiler for the toolchain-shape direction",
    )
    @pytest.mark.usefixtures("degraded_floor_consent_if_mountless")
    def test_compile_and_run_poc_under_output_still_works(self, tmp_path):
        # The caller-inventory toolchain shape (dark_verify /
        # exploit_verify / dynamic_sweep): compile a PoC under the
        # writable output tree and execute it — the deny must not
        # break on-disk compile-and-run.
        from core.sandbox import run_untrusted

        tgt = tmp_path / "t"
        out = tmp_path / "o"
        tgt.mkdir()
        out.mkdir()
        cc = shutil.which("cc") or shutil.which("gcc")
        child = textwrap.dedent(f"""
            import os, subprocess, sys
            out = {str(out)!r}
            src = os.path.join(out, "p.c")
            binp = os.path.join(out, "p.bin")
            with open(src, "w") as f:
                f.write('#include <stdio.h>\\n'
                        'int main(){{puts("POC-RAN");return 0;}}\\n')
            c = subprocess.run([{cc!r}, src, "-o", binp],
                               capture_output=True, text=True)
            if c.returncode != 0:
                print("COMPILE-FAILED: " + c.stderr[-400:])
                sys.exit(1)
            r = subprocess.run([binp], capture_output=True, text=True)
            print(r.stdout)
            sh = os.path.join(out, "s.sh")
            with open(sh, "w") as f:
                f.write("#!/bin/sh\\necho SHEBANG-RAN\\n")
            os.chmod(sh, 0o700)
            s = subprocess.run([sh], capture_output=True, text=True)
            print(s.stdout)
            sys.exit(0 if ("POC-RAN" in r.stdout
                           and "SHEBANG-RAN" in s.stdout) else 1)
        """)
        r = run_untrusted(
            [sys.executable, "-c", child],
            target=str(tgt), output=str(out),
            tool_paths=_py_tool_paths(),
            capture_output=True, text=True, timeout=180,
        )
        assert r.returncode == 0, r.stdout + r.stderr
        assert "POC-RAN" in r.stdout
        assert "SHEBANG-RAN" in r.stdout


@requires_execveat_nr
class TestAuditModeHardDeny:
    """Escape primitives never downgrade to allow-and-log: with
    audit_mode=True the fd-exec rules keep the ERRNO action. Probed at
    the filter level with a child that ONLY issues the denied calls —
    the audit filter's TRACE rules (open/connect) would SIGSYS without
    an attached tracer, so the probe must not touch the traced set
    after the filter engages; raw syscalls only, no imports."""

    def test_hard_deny_under_audit_filter(self):
        import ctypes
        import os as _os

        from core.sandbox.seccomp import _make_seccomp_preexec

        fn = _make_seccomp_preexec(
            "full", audit_mode=True, deny_fd_exec=True,
        )
        assert fn is not None
        nr = _execveat_nr()
        # Everything the child needs is resolved in the PARENT: the
        # audit filter TRACEs open/openat, and a TRACE rule firing
        # with no attached tracer SIGSYS-kills the process — so the
        # fork child must not open files or import modules after the
        # filter installs. memfd_create / execveat / write / _exit
        # are not in the trace set.
        libc = ctypes.CDLL(None, use_errno=True)
        bfd = _os.open("/bin/echo", _os.O_RDONLY)
        r, w = _os.pipe()
        pid = _os.fork()
        if pid == 0:
            try:
                _os.close(r)
                fn()
                code = 0
                try:
                    _os.memfd_create("x", 0)
                    code = 4      # created under audit = downgrade bug
                except OSError as e:
                    if e.errno != errno.EPERM:
                        code = 3  # denied, but not the hard_deny errno
                if code == 0:
                    libc.syscall(nr, bfd, b"", None, None, 0x1000)
                    if ctypes.get_errno() != errno.EPERM:
                        code = 5
                _os.write(w, bytes([code]))
            except BaseException:
                try:
                    _os.write(w, bytes([9]))
                except OSError:
                    pass
            _os._exit(0)
        _os.close(w)
        _os.close(bfd)
        try:
            data = _os.read(r, 1)
        finally:
            _os.close(r)
            _os.waitpid(pid, 0)
        assert data == b"\x00", f"audit hard-deny probe code={data!r}"
