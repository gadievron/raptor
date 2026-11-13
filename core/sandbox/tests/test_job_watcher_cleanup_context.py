"""Watcher startup cleanup owns its local exception context."""

import contextlib
import errno
import os
from types import SimpleNamespace

import pytest

from core.sandbox import job_budget
from core.sandbox._retirement import retire_parent_resources
from core.security.cgroup_scope import Scope
from core.testing.module_views import module_function_view


@pytest.fixture
def prepared_job(tmp_path):
    # Only the Scope's owned directory metadata is used. No admission, control
    # files, cgroup construction or watcher process is involved.
    with contextlib.ExitStack() as owners:
        node = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        owners.callback(os.close, node)
        parent = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
        owners.callback(os.close, parent)
        scope = Scope(tmp_path, node, parent)
        job = job_budget.Job(None, namespace_backend=False)
        job.budget = job_budget.Budget.parse({"pids_max": 1})
        job.scope = scope
        try:
            yield job
        finally:
            job.scope = None
            scope.node = scope.parent = None


def _exercise(job, *, ambient, stage, cancellation_type, startup_failure=False):
    owned = set()
    roles = {}
    events = []
    cancellation = cancellation_type("owned startup retirement") if cancellation_type else None
    primary = OSError(errno.EAGAIN, "owned fork refusal") if startup_failure else None
    watcher = 7654321

    def pipe(first, second):
        pair = os.pipe()
        owned.update(pair)
        roles.update(zip(pair, (first, second)))
        return pair

    def close(fd):
        assert fd in owned
        owned.remove(fd)
        os.close(fd)
        role = roles[fd]
        events.append(role)
        if role == stage and cancellation is not None:
            raise cancellation

    def close_writer(fd):
        assert roles[fd] == "writer"
        close(fd)
        return True

    def fork():
        if primary is not None:
            raise primary
        events.append("handoff")
        return watcher

    def forbidden(*args, **kwargs):
        raise AssertionError("unreviewed process or control operation")

    private_spawn = SimpleNamespace(
        open_death_pipe=lambda: pipe("lifetime", "writer"),
        close_death_w=close_writer, _DEATH_W_LOCK=contextlib.nullcontext(),
    )
    imports = {
        (1, ""): SimpleNamespace(_spawn=private_spawn),
        (1, "_fd_sweep"): SimpleNamespace(close_fds_except=forbidden),
        (1, "_retirement"): SimpleNamespace(retire_parent_resources=retire_parent_resources),
    }

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        key = (level, name)
        assert key in imports, ("unreviewed import", key)
        return imports[key]

    private = module_function_view(job_budget, bindings={
        "_startup": job_budget.Job._start_watcher,
        "os": SimpleNamespace(getpid=lambda: 1234, pipe=lambda: pipe("reader", "reply"),
                              fork=fork, close=close),
        "_watch": forbidden,
    }, import_hook=import_local)

    def caller():
        if not ambient:
            return private._startup(job)
        try:
            raise LookupError("unrelated caller exception")
        except LookupError:
            return private._startup(job)

    try:
        caught = None
        try:
            caller()
        except BaseException as error:
            caught = error
        assert caught is (primary if primary is not None else cancellation)
        assert events.count("lifetime") == events.count("reply") == 1
        if primary is not None:
            assert not owned
            assert job.writer is job.reader is job.watcher is None
            if cancellation is not None:
                assert "parent owner cleanup: " + type(cancellation).__name__ in primary.__notes__
        else:
            assert events[0] == "handoff"
            assert job.watcher == watcher
            assert {job.writer, job.reader} == owned
            assert {roles[fd] for fd in owned} == {"writer", "reader"}
    finally:
        # The test owns transferred handles; never reap or signal the fake PID.
        for fd in tuple(owned):
            owned.remove(fd)
            os.close(fd)
        job.writer = job.reader = job.watcher = None


@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("stage", ["lifetime", "reply"])
@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_successful_handoff_reports_cleanup_cancellation(prepared_job, ambient, stage, cancellation_type):
    _exercise(prepared_job, ambient=ambient, stage=stage, cancellation_type=cancellation_type)


@pytest.mark.parametrize("ambient", [False, True])
@pytest.mark.parametrize("stage", ["lifetime", "reply"])
@pytest.mark.parametrize("cancellation_type", [KeyboardInterrupt, SystemExit])
def test_startup_error_keeps_precedence_during_retirement(prepared_job, ambient, stage, cancellation_type):
    _exercise(prepared_job, ambient=ambient, stage=stage, cancellation_type=cancellation_type,
              startup_failure=True)


@pytest.mark.parametrize("ambient", [False, True])
def test_successful_handoff_transfers_only_parent_owners(prepared_job, ambient):
    _exercise(prepared_job, ambient=ambient, stage=None, cancellation_type=None)
