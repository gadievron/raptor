from pathlib import Path
import os, socket, subprocess, sys
from types import FunctionType

root, scratch = map(Path, sys.argv[1:3])
scratch.mkdir(parents=True, exist_ok=True)
expectation = sys.argv[3]
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
import ctypes.util
from unittest.mock import patch

with patch.object(
    ctypes.util,
    "find_library",
    side_effect=lambda name: None if name == "c" else denied(),
):
    from core.sandbox import preexec

    assert preexec._get_libc() is not None
from core.config import RaptorConfig

RaptorConfig.LOG_DIR = scratch / "logs"
from core.testing.tests import test_tool_fixture_ownership as native

prepared = []
owned = []
rescued = []
failure = OSError("owned scratch body write failed")
prepare = native._prepare


def preparing(*args, **kwargs):
    values = prepare(*args, **kwargs)
    prepared.append(values)
    namespace, owner, patch_type, snapshot, restored, cleanup = values

    def cleaning():
        rescued.append(True)
        cleanup()

    return namespace, owner, patch_type, snapshot, restored, cleaning


class FaultPath(type(Path())):
    def write_text(self, *args, **kwargs):
        assert self.name == "owned.txt"
        owned.append(Path(self.parent))
        namespace, owner, *_ = prepared[0]
        namespace["cleanup_failure"]["path"] = Path(self.parent)
        owner.rmtree_hardened = lambda path: False
        raise failure


original = native.test_tool_fixture_restores_borrowed_state
invoke = FunctionType(
    original.__code__,
    dict(original.__globals__, Path=FaultPath, _prepare=preparing),
    original.__name__,
    original.__defaults__,
    original.__closure__,
)
caught = None
try:
    try:
        invoke(native.CASES[0], "normal", False, scratch)
    except BaseException as error:
        caught = error
    assert isinstance(
        caught, AssertionError
    ) and "scanner scratch cleanup failed" in str(caught), repr(caught)
    assert len(owned) == 1 and not attempts
    prepared[0][4]()
    if expectation == "baseline":
        assert not rescued and owned[0].exists()
        print("TOOL_FINAL_RESCUE_SKIPPED_BASELINE")
    else:
        assert expectation == "candidate" and rescued == [True]
        assert not owned[0].exists()
        print("TOOL_FINAL_RESCUE_OK")
finally:
    if prepared:
        prepared[0][-1]()
assert not owned[0].exists()
assert (
    scratch / "semgrep-sbx-borrowed" / "caller.txt"
).read_bytes() == b"caller scratch must survive"
