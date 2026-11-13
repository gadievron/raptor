"""Parent cleanup callbacks report evidence failures to their enclosing owner."""

import ast
import errno
import os
from pathlib import Path

import pytest

from core.sandbox import evidence, summary
from core.sandbox._retirement import retire_parent_resources
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def handle(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    monkeypatch.setattr(summary, "_evidence_write_failures", dict(summary._evidence_write_failures))
    monkeypatch.setattr(summary, "_evidence_inode_mismatches", dict(summary._evidence_inode_mismatches))
    run = tmp_path / "run"
    run.mkdir()
    owned = evidence.EvidenceFile.open(run, "owned.jsonl")
    try:
        assert owned.write_record({"type": "owned-control"})
        yield owned, run
    finally:
        owned.close(verify=False)


def _callback(backend, handle):
    # Extract the exact owner callback, not the backend's execution path.
    # No backend import, setup probe, fork, target or tracer is performed.
    source = Path(evidence.__file__).with_name(backend + ".py")
    tree = ast.parse(source.read_text())
    callbacks = [node for node in ast.walk(tree)
                 if isinstance(node, ast.FunctionDef) and node.name == "_retire_evidence"]
    assert len(callbacks) == 1
    factory = ast.parse("""def make(handle, module):
    _evidence_file = handle
    evidence_file = handle
    _evidence_mod = module
    verify_evidence = True
""").body[0]
    factory.body.append(callbacks[0])
    factory.body.append(ast.Return(value=ast.Name(id="_retire_evidence", ctx=ast.Load())))
    namespace = {}
    exec(compile(ast.fix_missing_locations(ast.Module(body=[factory], type_ignores=[])),
                 str(source), "exec"), namespace)
    return namespace["make"](handle, evidence)


def _exercise(handle, monkeypatch, *, backend, ambient, failure_type, primary=None):
    owned, run = handle
    close_error = failure_type("owned capture close failure") if failure_type else None
    closed = []
    real_close = os.close

    def close(fd):
        assert fd == owned.fd
        real_close(fd)
        closed.append(fd)
        with pytest.raises(OSError) as released:
            os.fstat(fd)
        assert released.value.errno == errno.EBADF
        if close_error is not None:
            raise close_error

    callback = _callback(backend, owned)
    patch_module_attribute(monkeypatch, evidence, "os", "close", close)

    def retire():
        if primary is None:
            retire_parent_resources(callback, primary_error=None)
        else:
            try:
                raise primary
            except BaseException:
                retire_parent_resources(callback, primary_error=primary)
                raise

    def caller():
        if not ambient:
            return retire()
        try:
            raise LookupError("unrelated caller exception")
        except LookupError:
            return retire()

    caught = None
    try:
        caller()
    except BaseException as error:
        caught = error
    assert caught is (primary if primary is not None else close_error)
    if primary is not None and close_error is not None:
        assert "parent owner cleanup: " + type(close_error).__name__ in primary.__notes__
    assert closed == [owned.fd]
    assert owned._fd_released is True
    assert summary.get_evidence_write_failure(run) is (close_error is not None)
    # Both actual callbacks consumed the handle before finalization; re-entry
    # must not close it or publish an additional failure.
    assert callback() is None
    assert closed == [owned.fd]


@pytest.mark.parametrize("backend", ["_spawn", "_landlock_audit"])
@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("failure_type", [None, KeyboardInterrupt, SystemExit])
def test_callback_reports_its_own_finalization_failure(handle, monkeypatch, backend, ambient, failure_type):
    _exercise(handle, monkeypatch, backend=backend, ambient=ambient, failure_type=failure_type)


@pytest.mark.parametrize("backend", ["_spawn", "_landlock_audit"])
@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("primary_type", [OSError, KeyboardInterrupt])
def test_outer_owner_preserves_its_local_primary(handle, monkeypatch, backend, ambient, primary_type):
    _exercise(handle, monkeypatch, backend=backend, ambient=ambient,
              failure_type=SystemExit, primary=primary_type("owned operation failure"))
