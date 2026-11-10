"""Native crash-recovery fixture owns its spawned holder and process handle."""

import signal

import pytest

from core.project.tests import test_oplock as native


@pytest.mark.parametrize("operation,after,error", [
    (operation, after, error)
    for operation in ("start", "ready", "kill", "join")
    for after in (False, True)
    for error in (OSError, KeyboardInterrupt, SystemExit)
] + [(None, False, None)])
def test_native_crash_probe_reaps_and_closes_its_holder(
    monkeypatch, operation, after, error,
):
    holders, closed = [], []
    failure = error("owned crash-probe boundary failure") if error else None
    fired = False

    def boundary(name, action):
        nonlocal fired
        selected = name == operation and not fired
        if selected:
            fired = True
            if not after:
                raise failure
        value = action()
        if selected:
            raise failure
        return value

    class Holder(native._Holder):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            holders.append(self)
            self.raw_process = process = self.proc
            acquired = self.acquired

            class EventView:
                def wait(self, *args, **kwargs):
                    return boundary("ready", lambda: acquired.wait(*args, **kwargs))

            class ProcessView:
                def __getattr__(self, name):
                    return getattr(process, name)

                def start(self):
                    return boundary("start", process.start)

                def kill(self):
                    return boundary("kill", process.kill)

                def join(self, *args, **kwargs):
                    return boundary("join", lambda: process.join(*args, **kwargs))

                def close(self):
                    # Observe completion before closing hides the native handle.
                    record = {"pid": process.pid, "exitcode": process.exitcode,
                              "alive": process.is_alive()}
                    value = process.close()
                    closed.append(record)
                    return value

            # The real Process already holds the original event in its args.
            # These views remain in the parent; no observer is pickled into
            # the child and no multiprocessing module/class is patched.
            self.acquired = EventView()
            self.proc = ProcessView()

    case = native.OpLockPrimitiveTest("test_crashed_holder_recovery")
    with monkeypatch.context() as patch:
        patch.setattr(native, "_Holder", Holder)
        try:
            case.setUp()
            if error:
                with pytest.raises(error) as caught:
                    case.test_crashed_holder_recovery()
                assert caught.value is failure
                assert fired
            else:
                case.test_crashed_holder_recovery()
            assert len(holders) == 1
            assert holders[0].raw_process._closed
            assert len(closed) == 1 and not closed[0]["alive"]
            if closed[0]["pid"] is not None:
                assert closed[0]["exitcode"] is not None
            if error is None:
                assert closed[0]["exitcode"] == -signal.SIGKILL
        finally:
            # Assertions above observe native ownership. Safety cleanup stays
            # before native unittest fixture cleanup even on a regression.
            for holder in holders:
                process = holder.raw_process
                if not process._closed:
                    if process.pid is not None:
                        if process.exitcode is None:
                            process.kill()
                        process.join(10)
                        assert not process.is_alive()
                    process.close()
            case.doCleanups()
