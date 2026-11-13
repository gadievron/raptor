"""Parent job close reports locally failing owners without native teardown."""

import json
import os
from types import SimpleNamespace

import pytest

from core.sandbox import job_budget
from core.sandbox._retirement import retire_parent_resources
from core.security import cgroup_scope
from core.testing.module_views import module_function_view


def _exercise(tmp_path, *, ambient, stage, protocol_error=False, finish_error=None):
    owned = set()
    roles = {}
    events = []
    cancellation = KeyboardInterrupt("owned job close retirement")
    watcher = 7654321

    def remember(fd, role):
        owned.add(fd)
        roles[fd] = role
        return fd

    def pipe(first, second):
        pair = os.pipe()
        owned.update(pair)
        roles.update(zip(pair, (first, second)))
        return pair

    def check(fd):
        assert fd in owned, ("unowned descriptor", fd)

    def close(fd):
        check(fd)
        owned.remove(fd)
        os.close(fd)
        role = roles[fd]
        events.append(role)
        if role == stage:
            raise cancellation

    def write(fd, data):
        check(fd)
        assert roles[fd] == "writer" and data == b"S"
        return os.write(fd, data)

    def read(fd, size):
        check(fd)
        assert roles[fd] == "reader"
        return os.read(fd, size)

    def blocking(fd, value):
        check(fd)
        assert roles[fd] == "reader" and value is False
        os.set_blocking(fd, value)

    def waitpid(pid, flags):
        assert (pid, flags) == (watcher, os.WNOHANG)
        events.append("reaped")
        return watcher, 0

    def finish(scope):
        assert scope is raw_scope
        if finish_error is not None:
            raise finish_error
        return {"cleanup": "complete"}

    def forbidden(*args, **kwargs):
        raise AssertionError("unreviewed process or cgroup operation")

    imports = {
        (1, ""): SimpleNamespace(_spawn=SimpleNamespace(close_death_w=close)),
        (1, "_retirement"): SimpleNamespace(retire_parent_resources=retire_parent_resources),
    }

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        key = (level, name)
        assert key in imports, ("unreviewed import", key)
        return imports[key]

    try:
        node = remember(os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY), "node")
        parent = remember(os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY), "parent")
        raw_scope = cgroup_scope.Scope(tmp_path, node, parent)
        scope_view = module_function_view(cgroup_scope, bindings={
            "_owned_close": cgroup_scope.Scope.close, "os": SimpleNamespace(close=close),
        })
        raw_scope.close = lambda: scope_view._owned_close(raw_scope)
        job = job_budget.Job(None, namespace_backend=False)
        job.scope = raw_scope
        stop_reader, writer = pipe("stop-reader", "writer")
        reader, reply = pipe("reader", "reply")
        report = {"cleanup": "failed" if protocol_error else "complete"}
        os.write(reply, json.dumps(report).encode())
        close(reply)
        job.writer, job.reader, job.watcher = writer, reader, watcher
        private_os = SimpleNamespace(
            write=write, read=read, set_blocking=blocking, close=close,
            waitpid=waitpid, WNOHANG=os.WNOHANG,
            waitstatus_to_exitcode=os.waitstatus_to_exitcode, kill=forbidden,
        )
        private = module_function_view(job_budget, bindings={
            "_close_job": job_budget.Job.close, "os": private_os,
            "select": SimpleNamespace(select=lambda fds, *args: (fds, [], [])),
            "_finish_scope": finish,
        }, import_hook=import_local)

        def caller():
            if not ambient:
                return private._close_job(job)
            try:
                raise LookupError("unrelated caller exception")
            except LookupError:
                return private._close_job(job)

        caught = None
        try:
            caller()
        except BaseException as error:
            caught = error
        if finish_error is not None:
            assert caught is finish_error
        elif protocol_error:
            assert isinstance(caught, job_budget.JobBudgetError)
            assert isinstance(caught.__cause__, ValueError)
        else:
            assert caught is (cancellation if stage is not None else None)
        if protocol_error and stage is not None:
            assert "parent owner cleanup: KeyboardInterrupt" in caught.__notes__
        assert job.writer is job.reader is job.watcher is job.scope is None
        assert raw_scope.node is raw_scope.parent is None
        assert events.count("reader") == events.count("node") == events.count("parent") == 1
        assert owned == {stop_reader}
        assert job.record["cleanup"] == ("failed" if protocol_error or stage else "complete")
    finally:
        for fd in tuple(owned):
            owned.remove(fd)
            os.close(fd)


@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("stage", ["reader", "node"])
def test_successful_job_close_reports_cleanup_cancellation(tmp_path, ambient, stage):
    _exercise(tmp_path, ambient=ambient, stage=stage)


@pytest.mark.parametrize("ambient", [False, True])
def test_successful_job_close_retires_all_owners(tmp_path, ambient):
    _exercise(tmp_path, ambient=ambient, stage=None)


@pytest.mark.parametrize("ambient", [False, True])
def test_protocol_failure_keeps_wrapped_error_and_cleanup_note(tmp_path, ambient):
    _exercise(tmp_path, ambient=ambient, stage="reader", protocol_error=True)


@pytest.mark.parametrize("ambient", [False, True])
def test_fallback_failure_keeps_identity_and_cleanup_note(tmp_path, ambient):
    _exercise(tmp_path, ambient=ambient, stage="reader", protocol_error=True,
              finish_error=SystemExit("owned fallback retirement"))
