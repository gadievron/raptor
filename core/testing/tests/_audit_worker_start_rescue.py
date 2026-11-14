from pathlib import Path
import os, socket, subprocess, sys, threading
from types import ModuleType

root, scratch = map(Path, sys.argv[1:3])
mode, kind, expectation, index = sys.argv[3:7]
attempts = []


def denied(*args, **kwargs):
    attempts.append("secondary execution or transport")
    raise AssertionError(attempts[-1])


subprocess.Popen = denied
for name in (
    "fork",
    "forkpty",
    "system",
    "posix_spawn",
    "posix_spawnp",
    "execl",
    "execle",
    "execv",
    "execve",
    "execvp",
    "execvpe",
):
    if hasattr(os, name):
        setattr(os, name, denied)
socket.socket.connect = denied
socket.socket.connect_ex = denied
sys.path.insert(0, str(root))
from core.testing.tests import test_audit_shutdown_fixture as native
from types import FunctionType

failure = {"interrupt": KeyboardInterrupt, "error": RuntimeError}[kind](
    "owned worker start failure"
)
workers = []


class Worker(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        workers.append(self)

    def start(self):
        if mode == "before":
            raise failure
        super().start()
        if mode == "after":
            raise failure


private = ModuleType("threading")
vars(private).update(vars(threading))
private.Thread = Worker
observed = []
prepare = native._prepare


def preparing(*args, **kwargs):
    result = prepare(*args, **kwargs)
    fixture, owner, snapshot = result
    # Native helper reads its real_thread from this consumer-owned binding.
    owner._threading = private
    snapshot["_threading"] = private
    observed.append((owner, snapshot))
    return result


original = native.test_shutdown_fixture_finishes_workers_before_restoring_state
invoke = FunctionType(
    original.__code__,
    dict(original.__globals__, threading=private, _prepare=preparing),
    original.__name__,
    original.__defaults__,
    original.__closure__,
)
caught = None
try:
    invoke(native.CASES[int(index)])
except BaseException as error:
    caught = error
assert len(workers) == 1
assert not workers[0].is_alive()
for owner, snapshot in observed:
    native._restored(owner, snapshot, "clear")
assert not attempts
if expectation == "baseline":
    assert mode == "before" and caught is not failure
    assert isinstance(
        caught, RuntimeError
    ) and "cannot join thread before it is started" in str(caught)
    assert caught.__context__ is failure
    print("AUDIT_START_MASK_BASELINE_CONFIRMED")
else:
    assert expectation == "candidate"
    if mode == "normal":
        assert caught is None
    else:
        assert caught is failure, repr(caught)
    assert (workers[0].ident is None) == (mode == "before")
    print("AUDIT_START_RESCUE_OK")
