from pathlib import Path
import os, socket, subprocess, sys

root, scratch = map(Path, sys.argv[1:3])
phase, kind, expectation = sys.argv[3:6]
scratch.mkdir(parents=True, exist_ok=True)
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
import logging, pytest
from core.testing.tests import test_logging_level_ownership as native

borrowed = native.logging_state.logging
failure = {"error": RuntimeError, "interrupt": KeyboardInterrupt}[kind](
    "owned handler close fault"
)
seen = []
first = logging.NullHandler()
second = logging.NullHandler()
close = first.close


def failing():
    seen.append("first")
    if phase == "before":
        raise failure
    close()
    if phase == "after":
        raise failure


first.close = failing
state = None
try:
    with pytest.MonkeyPatch.context() as patch:
        generator = native.state.__wrapped__(scratch, patch)
        state = next(generator)
        for handler in (first, second):
            state.instrument(handler)
            state.root.addHandler(handler)
            state.named["raptor"].addHandler(handler)
        caught = None
        try:
            next(generator)
        except StopIteration:
            pass
        except BaseException as error:
            caught = error
        assert seen == ["first"]
        if phase == "normal":
            assert caught is None
        else:
            assert caught is failure
        if expectation == "baseline":
            assert phase == "after" and state.created[0][1].closed
            assert not state.created[1][1].closed
            assert not second._closed
            print("LOGGING_FIXTURE_TEARDOWN_LEAK_CONFIRMED")
        else:
            assert expectation == "candidate"
            assert all(stream.closed for handler, stream in state.created)
            assert second._closed
            assert first._closed == (phase != "before")
            assert state.root.handlers == [state.root.handlers[0]]
            assert state.root.handlers[0]._closed
            assert all(not logger.handlers for logger in state.named.values())
            print("LOGGING_FIXTURE_TEARDOWN_OK")
        assert not attempts
finally:
    if state is not None:
        for handler, stream in state.created:
            logging.Logger.removeHandler(state.root, handler)
            for logger in state.named.values():
                logging.Logger.removeHandler(logger, handler)
            logging.Handler.close(handler)
            stream.close()
            handler.close = lambda _handler=handler: logging.Handler.close(_handler)
        for handler in state.root.handlers:
            logging.Handler.close(handler)
assert native.logging_state.logging is borrowed
