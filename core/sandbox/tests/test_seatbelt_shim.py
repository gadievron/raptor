"""POSIX-core tests for libexec/raptor-seatbelt-shim (the macOS backend's
outer fail-loud + orphan-teardown watcher).

The shim is the OUTER, unsandboxed watcher; the in-sandbox readiness signal
is a /bin/sh trampoline (`printf K >&3; exec 3>&-; exec "$@"`) that the shim
wires to fd 3. These tests exercise the shim's platform-agnostic machinery —
status-pipe wiring through to fd 3, exit-status mirroring, and death-pipe
teardown — WITHOUT a real `sandbox-exec` (the sh trampoline stands in for
the `sandbox-exec -p PROFILE -- ...` command directly). The real sandbox-exec
integration (profile application, fd inheritance through sandbox-exec, killpg
under macOS) is covered by the darwin-only tests in test_macos_spawn.py and
must be smoke-tested on a real macOS host.

Linux-gated because the teardown assertion tracks descendant PIDs via /proc.
"""

import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="seatbelt-shim POSIX-core tests use /proc; integration is darwin-only",
)

SHIM_PATH = Path(__file__).resolve().parents[3] / "libexec" / "raptor-seatbelt-shim"
_READY_BYTE = b"K"

# The in-sandbox trampoline _macos_spawn builds. On Linux (no sandbox-exec)
# we run it directly as the shim's child — the "$@" args become the target.
_TRAMPOLINE = ['/bin/sh', '-c', 'printf K >&3; exec 3>&-; exec "$@"',
               'raptor-seatbelt-rdy']


def _env(**extra):
    return dict(os.environ, _RAPTOR_TRUSTED="1", **extra)


def _outer(target):
    """Build the outer-shim argv: shim + (trampoline + target)."""
    return [sys.executable, "-I", str(SHIM_PATH), *_TRAMPOLINE, *target]


def _descendants(root):
    """All live descendant PIDs of `root`, read from /proc (no name match)."""
    kids = {}
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            ppid = int(open(f"/proc/{d}/stat").read().split(")")[1].split()[1])
        except (OSError, IndexError):
            continue
        kids.setdefault(ppid, []).append(int(d))
    out, stack = [], [root]
    while stack:
        for c in kids.get(stack.pop(), []):
            out.append(c)
            stack.append(c)
    return out


def _alive(pid):
    try:
        st = open(f"/proc/{pid}/stat").read().split(")")[1].split()[0]
    except (OSError, IndexError):
        return False
    return "Z" not in st  # a zombie is not "alive"


class TestSeatbeltShim:
    def test_trust_marker_required(self):
        """Without CLAUDECODE/_RAPTOR_TRUSTED the shim refuses to run."""
        env = {k: v for k, v in os.environ.items()
               if k not in ("CLAUDECODE", "_RAPTOR_TRUSTED")}
        p = subprocess.run([sys.executable, str(SHIM_PATH), "/bin/true"],
                           capture_output=True, text=True, env=env, timeout=10)
        assert p.returncode == 2
        assert "internal dispatch script" in p.stderr

    def test_status_byte_relayed_and_exit_mirrored(self):
        """outer shim -> (trampoline stands in for sandbox-exec) -> target.
        The shim wires the status pipe to fd 3; the trampoline writes the
        readiness byte there, and the shim mirrors the target's exit code."""
        sr, sw = os.pipe()
        dr, dw = os.pipe()
        p = subprocess.Popen(
            _outer(["/bin/sh", "-c", "echo DEEP; exit 5"]),
            pass_fds=(sw, dr),
            env=_env(_RAPTOR_STATUS_FD=str(sw), _RAPTOR_DEATH_FD=str(dr)),
            stdout=subprocess.PIPE, text=True,
        )
        os.close(sw)
        os.close(dr)
        out, _ = p.communicate(timeout=10)
        byte = os.read(sr, 8)
        os.close(sr)
        os.close(dw)
        assert byte == _READY_BYTE
        assert out.strip() == "DEEP"
        assert p.returncode == 5

    def test_target_does_not_inherit_status_fd(self):
        """The trampoline closes fd 3 (`exec 3>&-`) before exec'ing the
        target, so the untrusted target must NOT hold the status pipe."""
        sr, sw = os.pipe()
        # Target prints whether fd 3 is open to it.
        probe = "import os\ntry:\n os.fstat(3); print('FD3_OPEN')\nexcept OSError:\n print('FD3_CLOSED')"
        p = subprocess.Popen(
            _outer([sys.executable, "-c", probe]),
            pass_fds=(sw,),
            env=_env(_RAPTOR_STATUS_FD=str(sw)),
            stdout=subprocess.PIPE, text=True,
        )
        os.close(sw)
        out, _ = p.communicate(timeout=10)
        byte = os.read(sr, 8)
        os.close(sr)
        assert byte == _READY_BYTE
        assert "FD3_CLOSED" in out
        assert "FD3_OPEN" not in out

    def test_target_does_not_inherit_raptor_markers(self):
        """The shim strips _RAPTOR_* markers before exec'ing into the sandbox,
        so the untrusted target must NOT see the trust marker (which authorizes
        the outer dispatch shim only) or the fd markers."""
        sr, sw = os.pipe()
        probe = ("import os;"
                 "print('TRUST=' + os.environ.get('_RAPTOR_TRUSTED','<unset>'));"
                 "print('SFD=' + os.environ.get('_RAPTOR_STATUS_FD','<unset>'));"
                 "print('DFD=' + os.environ.get('_RAPTOR_DEATH_FD','<unset>'))")
        p = subprocess.Popen(
            _outer([sys.executable, "-c", probe]),
            pass_fds=(sw,),
            env=_env(_RAPTOR_STATUS_FD=str(sw)),
            stdout=subprocess.PIPE, text=True,
        )
        os.close(sw)
        out, _ = p.communicate(timeout=10)
        byte = os.read(sr, 8)
        os.close(sr)
        assert byte == _READY_BYTE
        assert "TRUST=<unset>" in out
        assert "SFD=<unset>" in out
        assert "DFD=<unset>" in out

    def test_normal_completion_with_death_pipe(self):
        """With a death pipe configured and a quick target, the shim reaps
        normally and mirrors exit — the death watch must not interfere with
        a healthy run."""
        sr, sw = os.pipe()
        dr, dw = os.pipe()
        p = subprocess.Popen(
            _outer(["/bin/sh", "-c", "exit 0"]),
            pass_fds=(sw, dr),
            env=_env(_RAPTOR_STATUS_FD=str(sw), _RAPTOR_DEATH_FD=str(dr)),
        )
        os.close(sw)
        os.close(dr)
        rc = p.wait(timeout=10)
        os.close(sr)
        os.close(dw)
        assert rc == 0

    def test_death_pipe_teardown(self):
        """When the death-pipe write end closes (orchestrator died), the
        shim SIGKILLs the whole sandbox process group and exits with the
        teardown code — leaving no descendant alive."""
        sr, sw = os.pipe()
        dr, dw = os.pipe()
        p = subprocess.Popen(
            _outer(["/bin/sh", "-c", "echo go; sleep 60"]),
            pass_fds=(sw, dr),
            env=_env(_RAPTOR_STATUS_FD=str(sw), _RAPTOR_DEATH_FD=str(dr)),
        )
        os.close(sw)
        os.close(dr)
        try:
            time.sleep(0.7)  # let the target start
            tree = [q for q in _descendants(p.pid) if _alive(q)]
            assert tree, "expected a running sandbox subtree"
            os.close(dw)  # orchestrator "dies" -> EOF
            rc = p.wait(timeout=5)
            time.sleep(0.5)
            survivors = [q for q in tree if _alive(q)]
            byte = os.read(sr, 8)
            assert rc == 137, f"expected teardown exit, got {rc}"
            assert byte == _READY_BYTE
            assert survivors == [], f"leaked sandbox procs: {survivors}"
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            for q in _descendants(p.pid):
                try:
                    os.kill(q, 9)
                except OSError:
                    pass
            for fd in (sr, dw):
                try:
                    os.close(fd)
                except OSError:
                    pass
