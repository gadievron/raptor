"""Failed inherited-writer sweeps cannot resume an at-fork child."""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group

_ROOT = Path(__file__).resolve().parents[3]

_PROBE = r'''"""Owned at-fork interruption control; no sandbox policy or shared OS mutation."""
import contextlib
import errno
import json
import os
import select
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import pytest
from core.sandbox import _spawn
from core.testing.module_bindings import patch_module_attribute

fault = sys.argv[2]
held = sys.argv[3] == "held"
parent = os.getpid()
native_close = os.close
native_list = list
pairs = []
report_r = report_w = None
child = 0

def wait_child(pid):
    deadline = time.monotonic() + 2
    while True:
        found, status = os.waitpid(pid, os.WNOHANG)
        if found:
            return status
        if time.monotonic() >= deadline:
            raise TimeoutError("owned child did not exit")
        time.sleep(0.005)

try:
    pairs.append(_spawn.open_death_pipe())
    pairs.append(_spawn.open_death_pipe())
    owned_writes = {pair[1] for pair in pairs}
    assert _spawn._LIVE_DEATH_W == owned_writes
    first = next(iter(_spawn._LIVE_DEATH_W))
    report_r, report_w = os.pipe()

    def mark_fault():
        os.write(report_w, b"F")

    def close(fd):
        child_fault = os.getpid() != parent and fd == first
        if child_fault and fault == "before-interrupt":
            mark_fault()
            raise KeyboardInterrupt("owned before-close interruption")
        native_close(fd)
        if child_fault and fault in ("after-interrupt", "after-memory", "after-exit", "already-closed", "replace-exit"):
            mark_fault()
            if fault in ("after-interrupt", "replace-exit"):
                raise KeyboardInterrupt("owned after-close interruption")
            if fault == "after-memory":
                raise MemoryError("owned after-close failure")
            if fault == "after-exit":
                raise SystemExit("owned after-close exit")
            raise OSError(errno.EBADF, "owned end already physically closed")

    def snapshot(items):
        if os.getpid() != parent:
            mark_fault()
            raise MemoryError("owned inherited registry snapshot failure")
        return native_list(items)

    with pytest.MonkeyPatch.context() as patcher:
        patch_module_attribute(patcher, _spawn, "os", "close", close)
        if fault == "snapshot-memory":
            patcher.setattr(_spawn, "list", snapshot, raising=False)
        if fault == "replace-sweep":
            patcher.setattr(_spawn, "_close_inherited_death_w_post_fork", lambda: None)
        if fault == "replace-exit":
            def replaced_exit(code):
                raise RuntimeError("mutable exit binding must not be used by the hook")
            patch_module_attribute(patcher, _spawn, "os", "_exit", replaced_exit)
        with _spawn._DEATH_W_LOCK if held else contextlib.nullcontext():
            child = os.fork()
        if child == 0:
            # Reaching this branch means the registered callback returned to
            # fork despite its exception. Do not run the sweep a second time.
            remaining = 0
            for fd in owned_writes:
                try:
                    os.fstat(fd)
                except OSError:
                    continue
                remaining += 1
            message = json.dumps({"child_continued": True,
                                  "remaining_owned_writers": remaining,
                                  "inherited_registry_entries": len(_spawn._LIVE_DEATH_W)})
            os.write(report_w, b"C" + message.encode())
            os._exit(0)
    native_close(report_w)
    report_w = None
    ready, _, _ = select.select([report_r], [], [], 2)
    assert ready, "owned child did not report"
    raw = os.read(report_r, 4096)
    status = wait_child(child)
    child = 0
    while True:
        chunk = os.read(report_r, 4096)
        if not chunk:
            break
        raw += chunk
        assert len(raw) <= 4096
    observed = raw.startswith(b"F")
    if observed:
        raw = raw[1:]
    result = json.loads(raw[1:]) if raw.startswith(b"C") else {"child_continued": False}
    result["fault_observed"] = observed
    result["exit_code"] = os.waitstatus_to_exitcode(status)
    result["raw_wait_status"] = status
    print(json.dumps(result))
finally:
    if child:
        with contextlib.suppress(ProcessLookupError):
            os.kill(child, signal.SIGKILL)
        with contextlib.suppress(ChildProcessError):
            os.waitpid(child, 0)
    for read, write in pairs:
        _spawn.close_death_w(write)
        native_close(read)
    for fd in (report_r, report_w):
        if fd is not None:
            native_close(fd)
'''


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX at-fork callbacks")
@pytest.mark.parametrize("fault", [
    "none", "already-closed", "before-interrupt", "after-interrupt",
    "snapshot-memory", "after-memory", "after-exit", "replace-sweep", "replace-exit",
])
@pytest.mark.parametrize("held", [False, True], ids=["unlocked", "locked"])
def test_atfork_cleanup_failure_cannot_resume_child(fault, held):
    result = run_in_process_group(
        [sys.executable, "-I", "-B", "-c", _PROBE, str(_ROOT), fault,
         "held" if held else "unlocked"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, start_new_session=True,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    report = json.loads(result.stdout)
    assert report["fault_observed"] is (fault not in ("none", "replace-sweep"))
    if fault in ("none", "already-closed", "replace-sweep"):
        assert report["child_continued"] is True
        assert report["remaining_owned_writers"] == 0
        assert report["inherited_registry_entries"] == 0
        assert report["exit_code"] == 0
    else:
        assert report["child_continued"] is False
        assert report["exit_code"] == 126
    assert b"Exception ignored in atfork callback" not in result.stderr
