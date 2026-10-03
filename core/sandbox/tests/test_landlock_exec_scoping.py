"""Landlock EXECUTE scoping under restrict_reads: exec is an explicit
policy — granted on readable DIRECTORY rules and writable grants,
denied on per-file read grants and everywhere else — instead of a side
effect of the exec-open's FMODE_READ check.

Kernel semantics this encodes (all live-verified on ABI 8):
  * a path_beneath directory rule's EXECUTE grant covers the subtree,
    including unlinked and O_TMPFILE inodes whose f_path hierarchy
    still sits beneath the granted directory — the on-filesystem
    "fileless" spellings follow their directory's exec policy;
  * a per-FILE read rule without EXECUTE leaves the file readable but
    NOT executable — the new deny direction this change introduces
    (previously exec needed only the read right, so any readable
    binary was executable);
  * memfd inodes are on a kernel-internal SB_NOUSER mount that
    Landlock EXEMPTS from all rules — EXECUTE handling can never deny
    them. That spelling is closed at the seccomp layer
    (test_fd_exec_deny.py); this file only pins the exemption fact so
    a future kernel change is noticed.

Read-everywhere rulesets (trusted lanes) keep EXECUTE unhandled —
byte-identical behavior, pinned by the trusted-direction test.

PROBE-ENVIRONMENT CAVEAT: an environment-level security agent on some
hosts SIGKILLs fork+exec-of-memfd patterns (exit 137). The memfd
pinning test uses IN-PLACE execv in a fork child and asserts only on
the errno/success split, tolerating an environment kill as a skip —
a Landlock denial is EACCES on the exec, never a SIGKILL.
"""

from __future__ import annotations

import atexit
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from core.sandbox.tests.capability import requires_landlock  # noqa: E402

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="Linux Landlock"),
    requires_landlock,
]


def _build_standalone_echo() -> str:
    """Build a minimal echo binary immune to multi-call argv[0] checks.

    Ubuntu 26.04 ships coreutils as a single multi-call binary; copying
    or renaming it triggers "Security violation: Requested utility `X`
    does not match executable name".  A standalone binary avoids this.
    """
    d = tempfile.mkdtemp(prefix="raptor_test_echo_")
    atexit.register(shutil.rmtree, d, True)
    src = os.path.join(d, "e.c")
    with open(src, "w") as f:
        f.write(
            "#include <unistd.h>\n"
            "#include <string.h>\n"
            "int main(int c, char **v) {\n"
            "    int i;\n"
            "    for (i = 1; i < c; i++) {\n"
            "        if (i > 1) write(1, \" \", 1);\n"
            "        write(1, v[i], strlen(v[i]));\n"
            "    }\n"
            "    write(1, \"\\n\", 1);\n"
            "    return 0;\n"
            "}\n"
        )
    out = os.path.join(d, "echo")
    for extra in (["-static"], []):
        r = subprocess.run(
            ["cc", *extra, "-o", out, src],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            os.chmod(out, 0o755)
            return out
    return "/bin/echo"


_ECHO = _build_standalone_echo()

# System read set mirroring the context.py restricted default, plus
# the running interpreter's runtime dirs (venv/pyenv layouts).
def _system_readable() -> list[str]:
    from core.sandbox.python_paths import python_runtime_tool_paths
    paths = [p for p in ("/usr", "/lib", "/lib64", "/bin", "/sbin",
                         "/etc", "/proc", "/sys") if os.path.exists(p)]
    return paths + python_runtime_tool_paths()


def _preexec(writable: list[str], readable: list[str] | None):
    from core.sandbox.landlock import _make_landlock_preexec
    return _make_landlock_preexec(writable, None, readable_paths=readable)


_PROBE = textwrap.dedent("""
    import errno, os, sys
    mode = os.environ["PROBE_MODE"]

    def try_exec(path, argv0="echo"):
        pid = os.fork()
        if pid == 0:
            try:
                os.execv(path, [argv0, "RAN"])
            except OSError as e:
                os._exit(e.errno)
            os._exit(99)
        _, st = os.waitpid(pid, 0)
        if os.WIFSIGNALED(st):
            return -os.WTERMSIG(st)
        return os.WEXITSTATUS(st)

    if mode == "dir-grant":
        code = try_exec(os.environ["PROBE_BIN"])
        print("dir-grant exec exit=%d" % code)
        sys.exit(0 if code == 0 else 1)
    elif mode == "file-grant":
        p = os.environ["PROBE_BIN"]
        # Control: the per-file READ grant works.
        with open(p, "rb") as f:
            assert f.read(4) == b"\\x7fELF"
        print("file-grant read OK")
        code = try_exec(p)
        print("file-grant exec exit=%d" % code)
        # EACCES = EXECUTE handled and withheld on file rules.
        sys.exit(0 if code == errno.EACCES else 1)
    elif mode == "writable-grant":
        code = try_exec(os.environ["PROBE_BIN"])
        print("writable-grant exec exit=%d" % code)
        sys.exit(0 if code == 0 else 1)
    elif mode == "ungranted":
        code = try_exec(os.environ["PROBE_BIN"])
        print("ungranted exec exit=%d" % code)
        sys.exit(0 if code == errno.EACCES else 1)
    elif mode == "unlinked-under-grant":
        d = os.environ["PROBE_DIR"]
        p = os.path.join(d, "unl.bin")
        with open(os.environ["PROBE_SRC"], "rb") as s, \\
                open(p, "wb") as f:
            f.write(s.read())
        os.chmod(p, 0o700)
        fd = os.open(p, os.O_RDONLY)
        os.unlink(p)
        code = try_exec("/proc/self/fd/%d" % fd)
        print("unlinked-under-grant exec exit=%d" % code)
        # Hierarchy semantics: still beneath the exec-granted
        # writable dir, so it runs — the documented on-filesystem
        # residual (auditable tree, swept at teardown).
        sys.exit(0 if code == 0 else 1)
    elif mode == "trusted-anywhere":
        code = try_exec(os.environ["PROBE_BIN"])
        print("trusted-anywhere exec exit=%d" % code)
        sys.exit(0 if code == 0 else 1)
    else:
        sys.exit(2)
""")


def _run_probe(mode: str, writable: list[str],
               readable: list[str] | None, env_extra: dict) -> str:
    env = {
        "PATH": "/usr/bin:/bin",
        "PROBE_MODE": mode,
        **env_extra,
    }
    r = subprocess.run(
        [sys.executable, "-S", "-c", _PROBE],
        preexec_fn=_preexec(writable, readable),
        capture_output=True, text=True, timeout=60, env=env, cwd="/",
    )
    assert r.returncode == 0, (
        f"mode={mode} rc={r.returncode}\n{r.stdout}\n{r.stderr}"
    )
    return r.stdout


class TestExecScopingUnderRestrictReads:
    def test_exec_allowed_under_readable_dir_grant(self, tmp_path):
        rdir = tmp_path / "r"
        rdir.mkdir()
        binp = rdir / "echo.bin"
        shutil.copy2(_ECHO, binp)
        wdir = tmp_path / "w"
        wdir.mkdir()
        out = _run_probe(
            "dir-grant", [str(wdir)],
            [*_system_readable(), str(rdir)],
            {"PROBE_BIN": str(binp)},
        )
        assert "exec exit=0" in out

    def test_exec_denied_on_per_file_read_grant(self, tmp_path):
        # THE new deny direction: a binary granted per-FILE read is
        # readable but no longer executable (pre-change, exec needed
        # only the read right).
        rdir = tmp_path / "r"
        rdir.mkdir()
        binp = rdir / "echo.bin"
        shutil.copy2(_ECHO, binp)
        wdir = tmp_path / "w"
        wdir.mkdir()
        out = _run_probe(
            "file-grant", [str(wdir)],
            [*_system_readable(), str(binp)],  # FILE grant, not dir
            {"PROBE_BIN": str(binp)},
        )
        assert "file-grant read OK" in out
        assert f"exec exit={13}" in out  # EACCES

    def test_exec_allowed_under_writable_grant(self, tmp_path):
        wdir = tmp_path / "w"
        wdir.mkdir()
        binp = wdir / "echo.bin"
        shutil.copy2(_ECHO, binp)
        out = _run_probe(
            "writable-grant", [str(wdir)], _system_readable(),
            {"PROBE_BIN": str(binp)},
        )
        assert "exec exit=0" in out

    def test_exec_denied_outside_grants(self, tmp_path):
        # Non-granted tree: still EACCES (previously via the read
        # right; now doubly via EXECUTE — the direction must hold).
        odir = tmp_path / "outside"
        odir.mkdir()
        binp = odir / "echo.bin"
        shutil.copy2(_ECHO, binp)
        wdir = tmp_path / "w"
        wdir.mkdir()
        out = _run_probe(
            "ungranted", [str(wdir)], _system_readable(),
            {"PROBE_BIN": str(binp)},
        )
        assert f"exec exit={13}" in out

    def test_unlinked_inode_follows_directory_grant(self, tmp_path):
        # On-filesystem "fileless" spelling: unlinked file whose
        # hierarchy sits beneath the exec-granted writable dir still
        # runs — documented residual (see module docstring).
        wdir = tmp_path / "w"
        wdir.mkdir()
        src = wdir / "src.bin"
        shutil.copy2(_ECHO, src)
        out = _run_probe(
            "unlinked-under-grant", [str(wdir)], _system_readable(),
            {"PROBE_DIR": str(wdir), "PROBE_SRC": str(src)},
        )
        assert "exec exit=0" in out


class TestTrustedLanesUnchanged:
    def test_read_everywhere_ruleset_keeps_exec_wide(self, tmp_path):
        # readable_paths=None (trusted shape): EXECUTE stays
        # unhandled; exec from an arbitrary non-granted dir works.
        odir = tmp_path / "outside"
        odir.mkdir()
        binp = odir / "echo.bin"
        shutil.copy2(_ECHO, binp)
        wdir = tmp_path / "w"
        wdir.mkdir()
        out = _run_probe(
            "trusted-anywhere", [str(wdir)], None,
            {"PROBE_BIN": str(binp)},
        )
        assert "exec exit=0" in out


class TestMemfdLandlockExemptionPinned:
    """Pins the kernel fact the two-layer split rests on: Landlock
    (EXECUTE handled, zero exec grants for the memfd) does NOT deny
    memfd exec — the seccomp layer is load-bearing for that spelling.
    If a future kernel starts denying it, this test fails and the
    comment map (landlock.py / seccomp.py deny_fd_exec) should be
    revisited — the deny would then be double-covered, not broken."""

    def test_memfd_exec_not_denied_by_landlock(self, tmp_path):
        wdir = tmp_path / "w"
        wdir.mkdir()
        echo_copy = wdir / "echo"
        shutil.copy2(_ECHO, echo_copy)
        probe = textwrap.dedent("""
            import os, sys
            fd = os.memfd_create("x", 0)
            with open(os.environ["ECHO_BIN"], "rb") as f:
                os.write(fd, f.read())
            r2 = os.open("/proc/self/fd/%d" % fd, os.O_RDONLY)
            os.close(fd)
            try:
                os.execv("/proc/self/fd/%d" % r2, ["echo", "MEMFD-RAN"])
            except OSError as e:
                print("DENIED errno=%d" % e.errno)
                sys.exit(1)
        """)
        r = subprocess.run(
            [sys.executable, "-S", "-c", probe],
            preexec_fn=_preexec([str(wdir)], _system_readable()),
            capture_output=True, text=True, timeout=60,
            env={"PATH": "/usr/bin:/bin", "ECHO_BIN": str(echo_copy)},
            cwd="/",
        )
        if r.returncode < 0:
            pytest.skip(
                "probe killed by an environment-level agent "
                f"(signal {-r.returncode}) — cannot observe the "
                "Landlock verdict on this host",
            )
        assert "MEMFD-RAN" in r.stdout, (
            "Landlock began denying memfd exec — revisit the "
            f"deny_fd_exec comment map: {r.stdout} {r.stderr}"
        )
