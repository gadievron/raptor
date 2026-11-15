"""The trusted child reports its group without depending on watcher progress."""

import ast
from pathlib import Path
import re
from types import SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("mapped", 9, 8, False, False),
    ("mapped-write-fault", 9, 8, True, False),
    ("fixed", 3, 8, False, False),
    ("fixed-write-fault", 3, 8, True, False),
    ("death-slot", 9, 3, False, False),
    ("death-slot-write-fault", 9, 3, True, False),
    ("no-status", None, 8, False, False),
    ("mapped-remap-fault", 9, 8, False, True),
    ("fixed-remap-fault", 3, 8, False, True),
]


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
def test_child_reports_group_before_exec_without_parent_progress(case):
    _, status_fd, death_fd, write_fails, remap_fails = case
    tree = ast.parse((ROOT / "libexec/raptor-seatbelt-shim").read_text())
    child = next(n for n in ast.walk(tree) if isinstance(n, ast.If)
                 and isinstance(n.test, ast.Compare)
                 and isinstance(n.test.left, ast.Name) and n.test.left.id == "child"
                 and isinstance(n.test.comparators[0], ast.Constant)
                 and n.test.comparators[0].value == 0)
    events = []
    failure = OSError("owned status operation failed")
    stopped = BaseException("inert exec boundary")

    def write(fd, payload):
        events.append(("write", fd, payload))
        if write_fails:
            raise failure
        return len(payload)

    def remap(*args, **kwargs):
        events.append(("remap", args))
        if remap_fails:
            raise failure

    def execute(path, argv):
        events.append(("exec", path))
        assert path == "inert-sandbox-exec" and argv == [path]
        raise stopped

    def forbidden_exit(code):
        raise AssertionError(f"unexpected child exit {code}")

    owned_os = SimpleNamespace(environ={"_RAPTOR_TRUSTED": "1"},
                               close=lambda fd: events.append(("close", fd)),
                               dup2=remap, set_inheritable=remap,
                               setpgid=lambda *args: events.append(("group", args)),
                               getpid=lambda: 31337, write=write, execvp=execute,
                               _exit=forbidden_exit)
    namespace = dict(os=owned_os, child=0, status_fd=status_fd, death_fd=death_fd,
                     _STATUS_CHILD_FD=3, grant_pins=None, keep_trust_markers=False,
                     argv=["inert-sandbox-exec"])
    # Only the actual trusted child branch executes. No parent branch,
    # module bootstrap, fork, descriptor, process or target is invoked.
    with pytest.raises(BaseException) as caught:
        exec(compile(ast.Module(body=[child], type_ignores=[]),
                     "<actual-shim-child>", "exec"), namespace)
    assert caught.value is stopped
    assert "_RAPTOR_TRUSTED" not in owned_os.environ
    writes = [event for event in events if event[0] == "write"]
    expected = [] if status_fd is None else [("write", status_fd, b"G31337\n")]
    assert writes == expected
    if expected:
        report = events.index(expected[0])
        assert events.index(("group", (0, 0))) < report < len(events) - 1
        if status_fd != 3:
            # The original owned FD carries the report before remapping can
            # close it or fail, rather than guessing that fd 3 is now owned.
            first_remap = next(i for i, event in enumerate(events) if event[0] == "remap")
            assert report < first_remap


@pytest.mark.parametrize("wire", [b"G31337\n", b"KG31337\n", b"G31337\nK"])
def test_group_report_reader_keeps_existing_wire(wire):
    tree = ast.parse((ROOT / "core/sandbox/_macos_spawn.py").read_text())
    parser = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                  and n.name == "_parse_group_report")
    namespace = {"re": re}
    exec(compile(ast.Module(body=[parser], type_ignores=[]),
                 "<actual-group-parser>", "exec"), namespace)
    assert namespace["_parse_group_report"](wire) == 31337


def test_inner_trampoline_closes_status_writer_before_target_exec():
    tree = ast.parse((ROOT / "core/sandbox/_macos_spawn.py").read_text())
    inner = next(n for n in ast.walk(tree) if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "_inner" for t in n.targets))
    assert isinstance(inner.value, ast.BinOp) and isinstance(inner.value.op, ast.Add)
    assert isinstance(inner.value.left, ast.List)
    tail = inner.value.right
    assert isinstance(tail, ast.Call) and isinstance(tail.func, ast.Name)
    assert tail.func.id == "list" and len(tail.args) == 1
    assert isinstance(tail.args[0], ast.Name) and tail.args[0].id == "cmd"
    script = inner.value.left.elts[2]
    assert isinstance(script, ast.Constant)
    assert script.value.index("exec 3>&-") < script.value.index('exec "$@"')
