"""A failed later pipe or fork must not strand earlier pipe descriptors."""

import errno
import importlib
import os

import pytest

_CASES = [
    ("contract", "test_arm_timeout_is_actually_bounded", 2),
    ("contract", "test_supervisor_never_forwards_to_a_reaped_pid", 2),
    ("forwarder", "test_unarmed_waiter_fails_closed", 2),
    ("forwarder", "test_arm_timeout_fails_closed", 2),
    ("forwarder", "test_armed_exit_mirrored_and_tier_reported", 3),
    ("forwarder", "test_signalled_waiter_mirrored_as_128_plus_signum", 2),
    ("forwarder", "test_no_tier_report_before_arm", 3),
]
_FAULTS = [
    (module, name, count, position)
    for module, name, count in _CASES
    for position in [*range(2, count + 1), "fork"]
]


def _still_owned(fd, identity):
    try:
        stat = os.fstat(fd)
    except OSError as exc:
        if exc.errno == errno.EBADF:
            return False
        raise
    return (stat.st_dev, stat.st_ino) == identity


@pytest.mark.skipif(not hasattr(os, "fork"), reason="fork-based pipe fixtures")
@pytest.mark.parametrize("kind,name,count,position", _FAULTS)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_pipe_or_fork_failure_closes_acquired_descriptors(
    kind, name, count, position, error, monkeypatch
):
    module = importlib.import_module(f"packages.joern.tests.test_pidns_{kind}")
    pipes, descriptors = [], []
    real_pipe = os.pipe

    def fail():
        raise error("injected pipe/fork setup failure")

    def pipe():
        if len(pipes) + 1 == position:
            return fail()
        pair = real_pipe()
        pipes.append(pair)
        for fd in pair:
            stat = os.fstat(fd)
            descriptors.append((fd, (stat.st_dev, stat.st_ino)))
        return pair

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(os, "pipe", pipe)
            # Never fork in the fault matrix: every child boundary is inert.
            patcher.setattr(os, "fork", fail)
            kwargs = {"restore_signal_handlers": None}
            if "reaped_pid" in name:
                kwargs["monkeypatch"] = patcher
            function = (
                getattr(module, name)
                if kind == "contract"
                else getattr(module.TestSuperviseNsInit(), name)
            )
            with pytest.raises(error, match="injected pipe/fork setup failure"):
                function(**kwargs)
        assert len(pipes) == (count if position == "fork" else position - 1)
        assert descriptors
        assert not any(_still_owned(fd, identity) for fd, identity in descriptors), (
            "setup failure left acquired pipe descriptors open"
        )
    finally:
        # Close only the exact pipe objects created above, never a descriptor
        # number that may have since been reused by another resource owner.
        for fd, identity in descriptors:
            if _still_owned(fd, identity):
                os.close(fd)
