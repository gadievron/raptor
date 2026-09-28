"""``libexec/raptor-frida`` / ``raptor-frida-patch-verify`` signal and
lifecycle-disposition contracts.

The signal trap must not write the run disposition: the child's exit
status after the signal decides it exactly once (a duration-bounded
capture ends gracefully on SIGTERM and must complete, not fail — the
old trap wrote fail and the close-out wrote complete, leaving the
final status to last-write timing). And the kill must reach the whole
child tree (sandbox wrapper → frida CLI → instrumented target), not
just the direct child.

Runs the real wrappers from a fixture RAPTOR tree whose
raptor-run-lifecycle is a logging stub, with python3 PATH-stubbed.
"""

from __future__ import annotations

import contextlib
import os
import shutil
import signal
import stat
import subprocess
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="bash wrappers",
)


def _make_fake_tree(tmp_path: Path, wrapper: str) -> Path:
    """Fixture RAPTOR dir: real wrapper + logging lifecycle stub."""
    root = tmp_path / "fakeraptor"
    (root / "libexec").mkdir(parents=True)
    (root / "core" / "security").mkdir(parents=True)
    (root / "outdir").mkdir()
    (root / "raptor.py").write_text("", encoding="utf-8")
    shutil.copy2(REPO_ROOT / "core" / "security"
                 / "_dangerous_env_strip.sh",
                 root / "core" / "security" / "_dangerous_env_strip.sh")
    shutil.copy2(REPO_ROOT / "libexec" / wrapper,
                 root / "libexec" / wrapper)
    stub = root / "libexec" / "raptor-run-lifecycle"
    stub.write_text(
        '#!/bin/sh\n'
        'ROOT="$(cd "$(dirname "$0")/.." && pwd)"\n'
        'echo "$@" >> "$ROOT/lifecycle.log"\n'
        'if [ "$1" = "start" ]; then\n'
        '  echo "OUTPUT_DIR=$ROOT/outdir"\n'
        'fi\n'
        'exit 0\n',
        encoding="utf-8",
    )
    for p in (root / "libexec" / wrapper, stub):
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return root


def _stub_python(tmp_path: Path, body: str) -> dict:
    """PATH with a python3 stub whose behavior is *body* (sh)."""
    stub_dir = tmp_path / "stub-bin"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "python3"
    stub.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    stub.chmod(stub.stat().st_mode | stat.S_IXUSR)
    env = dict(os.environ)
    env["_RAPTOR_TRUSTED"] = "1"
    env["PATH"] = f"{stub_dir}:{env['PATH']}"
    return env


def _wait_for(predicate, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return False


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # kill(pid, 0) also reaches dead-but-unreaped processes: a killed
    # grandchild whose parent died with it stays signal-visible until
    # an ancestor reaps it, and when the inheriting ancestor never
    # waits on orphans (a plain process serving as a pid-namespace
    # init) that is forever. Dead-but-unreaped IS dead for these
    # tests — the signal provably landed. A missed kill leaves the
    # process running (state R/S/D), which still reads as alive.
    return _proc_state(pid) != "Z"


def _proc_state(pid: int) -> str | None:
    """Process state letter from ``/proc/<pid>/stat``, None where
    unreadable (off-Linux, or the pid vanished) — callers then keep
    the plain kill-0 answer."""
    try:
        stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except OSError:
        return None
    return stat_text[stat_text.rfind(")") + 2:].split()[0]


def _read_pid(path: Path) -> int | None:
    """Pid recorded in *path*, or None while the file is unusable as
    a readiness signal.

    ``echo $! > file`` is two observable steps — create/truncate,
    then write — so a reader gating on file EXISTENCE alone can catch
    the file created but still empty and crash on ``int("")``.
    Readiness is therefore CONTENT: a pid only comes back once the
    file holds a complete int-parseable value.
    """
    try:
        text = path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not text:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def _reap_stub_tree(proc: subprocess.Popen, pid_file: Path) -> None:
    """Best-effort janitor for the spawned wrapper tree, registered
    right after the spawn so a failing assertion (or any other
    exception exit) cannot leak the stub processes (wrapper →
    python3 stub → sleep grandchild).

    Verified pids only: the roots are the live ``Popen`` handle's pid
    and the stub-recorded grandchild pid, descendants come from a
    ``pgrep -P`` walk of those roots, nothing with pid <= 1 is ever
    signaled, and every kill is gated on a kill-0 liveness probe
    immediately before it.
    """
    pids: list[int] = []
    if proc.pid is not None and proc.pid > 1:
        pids.append(proc.pid)
    recorded = _read_pid(pid_file)
    if recorded is not None and recorded > 1 and recorded not in pids:
        pids.append(recorded)
    # Collect the whole tree BEFORE killing anything: killing a parent
    # first would orphan still-running children before pgrep sees them.
    seen = set(pids)
    frontier = list(pids)
    while frontier:
        parent = frontier.pop()
        res = subprocess.run(
            ["pgrep", "-P", str(parent)],
            capture_output=True, text=True, check=False,
        )
        for token in res.stdout.split():
            try:
                child = int(token)
            except ValueError:
                continue
            if child > 1 and child not in seen:
                seen.add(child)
                pids.append(child)
                frontier.append(child)
    for pid in pids:
        if pid <= 1:
            continue
        try:
            os.kill(pid, 0)  # liveness gate: only verified-live pids
        except OSError:
            continue
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=10)


class TestGracefulSignalDisposition:
    def test_sigterm_with_clean_child_exit_completes(self, tmp_path):
        """Child exits 0 on TERM (graceful duration-bounded capture)
        → the run must complete, and fail must never be written."""
        root = _make_fake_tree(tmp_path, "raptor-frida")
        marker = tmp_path / "child-running"
        # Arm the trap BEFORE signaling readiness: a TERM delivered
        # in the gap hits sh's default disposition (exit 143) and the
        # trapped verdict path never runs — observed under host load.
        env = _stub_python(tmp_path, (
            "trap 'exit 0' TERM\n"
            f'touch "{marker}"\n'
            "sleep 30 &\n"
            "wait $!\n"
            "exit 0\n"
        ))
        proc = subprocess.Popen(
            ["bash", str(root / "libexec" / "raptor-frida"),
             "--target", "someprocess", "--template", "syscalls"],
            env=env, cwd=str(tmp_path),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert _wait_for(marker.is_file), "child never started"
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=30)

        log = (root / "lifecycle.log").read_text().splitlines()
        assert any(line.startswith("start ") for line in log)
        assert any(line.startswith("complete ") for line in log), log
        assert not any(line.startswith("fail ") for line in log), log

    def test_sigterm_with_failing_child_fails_once(self, tmp_path):
        """Child exits nonzero after TERM → exactly one fail record,
        naming the signal."""
        root = _make_fake_tree(tmp_path, "raptor-frida")
        marker = tmp_path / "child-running"
        # Trap armed before readiness — see the clean-exit test above.
        env = _stub_python(tmp_path, (
            "trap 'exit 17' TERM\n"
            f'touch "{marker}"\n'
            "sleep 30 &\n"
            "wait $!\n"
            "exit 17\n"
        ))
        proc = subprocess.Popen(
            ["bash", str(root / "libexec" / "raptor-frida"),
             "--target", "someprocess", "--template", "syscalls"],
            env=env, cwd=str(tmp_path),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert _wait_for(marker.is_file), "child never started"
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=30)

        log = (root / "lifecycle.log").read_text().splitlines()
        fails = [line for line in log if line.startswith("fail ")]
        assert len(fails) == 1, log
        assert "TERM" in fails[0]
        assert not any(line.startswith("complete ") for line in log)


@pytest.mark.skipif(shutil.which("setsid") is None,
                    reason="setsid required for group kill")
class TestProcessGroupKill:
    def test_grandchild_killed_on_sigterm(self, tmp_path, request):
        """SIGTERM to the wrapper must reach the child's descendants
        (the instrumented target), not just the direct child."""
        root = _make_fake_tree(tmp_path, "raptor-frida")
        pid_file = tmp_path / "grandchild.pid"
        # Trap armed before readiness (the pid file) — see
        # TestGracefulSignalDisposition.
        env = _stub_python(tmp_path, (
            "trap 'exit 0' TERM\n"
            "sleep 30 &\n"
            f'echo $! > "{pid_file}"\n'
            "wait\n"
        ))
        proc = subprocess.Popen(
            ["bash", str(root / "libexec" / "raptor-frida"),
             "--target", "someprocess", "--template", "syscalls"],
            env=env, cwd=str(tmp_path),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        # Registered before the first assertion: an assertion or
        # exception exit must reap the tree, not leak it.
        request.addfinalizer(lambda: _reap_stub_tree(proc, pid_file))
        # Readiness = pid-file CONTENT, not existence: `echo $! > f`
        # creates the file before writing it, and reading the empty
        # window raised int("") — ValueError under load.
        assert _wait_for(lambda: _read_pid(pid_file) is not None), (
            "grandchild never started"
        )
        grandchild = _read_pid(pid_file)
        assert grandchild is not None
        assert _pid_alive(grandchild)
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=30)
        assert _wait_for(lambda: not _pid_alive(grandchild)), (
            "instrumented-target stand-in survived the wrapper kill"
        )


class TestDashDashPassthrough:
    def test_out_after_separator_not_consumed(self, tmp_path):
        """`--out` after `--` is positional payload — consuming it as
        the wrapper's own flag silently bypassed the lifecycle."""
        root = _make_fake_tree(tmp_path, "raptor-frida")
        env = _stub_python(tmp_path, "exit 0\n")
        res = subprocess.run(
            ["bash", str(root / "libexec" / "raptor-frida"),
             "--target", "someprocess", "--template", "syscalls",
             "--", "--out", "/nope"],
            env=env, cwd=str(tmp_path), capture_output=True,
            text=True, check=False, timeout=60,
        )
        assert res.returncode == 0, res.stderr
        log = (root / "lifecycle.log").read_text().splitlines()
        assert any(line.startswith("start ") for line in log), (
            "lifecycle bypassed: --out after -- was consumed"
        )

    def test_wrapper_out_lands_before_separator(self, tmp_path):
        """The wrapper's own --out must be inserted BEFORE the
        operator's `--` tail: appended after it, the CLI reads
        `--out DIR` as positional payload and the documented
        separator form is unusable."""
        root = _make_fake_tree(tmp_path, "raptor-frida")
        argv_log = tmp_path / "argv.log"
        env = _stub_python(tmp_path, (
            f'printf \'%s\\n\' "$@" > "{argv_log}"\n'
            "exit 0\n"
        ))
        res = subprocess.run(
            ["bash", str(root / "libexec" / "raptor-frida"),
             "--target", "someprocess", "--template", "syscalls",
             "--", "positional-payload"],
            env=env, cwd=str(tmp_path), capture_output=True,
            text=True, check=False, timeout=60,
        )
        assert res.returncode == 0, res.stderr
        argv = argv_log.read_text().splitlines()
        # The stub captures the sandbox wrapper's argv; the inner CLI
        # argv follows "packages.frida.cli". Inside it, the wrapper's
        # --out must precede the operator's -- separator.
        cli = argv[argv.index("packages.frida.cli") + 1:]
        sep = cli.index("--")
        assert "--out" in cli[:sep], cli
        assert cli[sep + 1:] == ["positional-payload"], cli



class TestPatchVerifyDisposition:
    def test_sigterm_with_verdict_exit_completes(self, tmp_path):
        """patch-verify: verdict exits (0/1/3) after TERM complete
        exactly once — the old trap pre-wrote fail."""
        root = _make_fake_tree(tmp_path, "raptor-frida-patch-verify")
        before = tmp_path / "before.bin"
        before.write_bytes(b"\x7fELF")
        marker = tmp_path / "child-running"
        # Trap armed before readiness — see
        # TestGracefulSignalDisposition (this stub is where the
        # unarmed-window TERM was observed live: child died 143 and
        # the wrapper recorded an interrupt instead of the verdict).
        env = _stub_python(tmp_path, (
            "trap 'exit 1' TERM\n"
            f'touch "{marker}"\n'
            "sleep 30 &\n"
            "wait $!\n"
            "exit 1\n"
        ))
        proc = subprocess.Popen(
            ["bash", str(root / "libexec" / "raptor-frida-patch-verify"),
             "--before", str(before)],
            env=env, cwd=str(tmp_path),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        assert _wait_for(marker.is_file), "child never started"
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=30)

        log = (root / "lifecycle.log").read_text().splitlines()
        assert any(line.startswith("complete ") for line in log), log
        assert not any(line.startswith("fail ") for line in log), log
