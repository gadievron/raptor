from pathlib import Path
import os, socket, subprocess, sys, json, hashlib

root, scratch = map(Path, sys.argv[1:3])
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
import logging
import pytest

kind, phase, outcome, expectation = sys.argv[3:7]
from core.testing.tests import test_inline_log_ownership as inline
from core.testing.tests import test_remaining_log_owners as remaining

failure = {"error": RuntimeError, "interrupt": KeyboardInterrupt}[outcome](
    "owned logging fixture close fault"
)
patch = pytest.MonkeyPatch()
if kind == "owners":
    native = inline
    generator = inline.owners.__wrapped__(scratch)
elif kind == "private-log":
    native = inline
    generator = inline.private_log.__wrapped__(patch)
else:
    assert kind == "private-logs"
    native = remaining
    generator = remaining.private_logs.__wrapped__(patch, scratch)
state = next(generator)
if kind == "private-log":
    handlers = [
        logging.FileHandler(scratch / "first.log"),
        logging.FileHandler(scratch / "second.log"),
    ]
    streams = [handler.stream for handler in handlers]
    for handler in handlers:
        state.logger.addHandler(handler)
    borrowed = [state.borrowed]
else:
    handlers = [logging.NullHandler(), logging.NullHandler()]
    for handler in handlers:
        state.instrument(handler)
    streams = [stream for handler, stream in state.created]
    borrowed = [] if kind == "owners" else [row[0] for row in state.borrowed.values()]
    if kind == "private-logs":
        for handler in handlers:
            state.root.addHandler(handler)
original = handlers[0].close
seen = []


def failing():
    seen.append("first")
    if phase == "before":
        raise failure
    original()
    if phase == "after":
        raise failure


handlers[0].close = failing
try:
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
        assert phase == "after" and handlers[0]._closed and streams[0].closed
        assert not handlers[1]._closed and not streams[1].closed
    else:
        assert expectation == "candidate"
        assert streams[1].closed
        assert streams[0].closed == (not (kind == "private-log" and phase == "before"))
        assert handlers[1]._closed
        assert all(handler._closed for handler in borrowed)
    assert not attempts
    result = {
        "result": "LOG_FIXTURE_BASELINE_CONFIRMED"
        if expectation == "baseline"
        else "LOG_FIXTURE_TEARDOWN_OK",
        "kind": kind,
        "phase": phase,
        "forbidden_attempts": attempts,
        "source_sha256": hashlib.sha256(Path(native.__file__).read_bytes()).hexdigest(),
    }

finally:
    for handler, stream in zip(handlers, streams):
        if isinstance(handler, logging.FileHandler):
            logging.FileHandler.close(handler)
        else:
            logging.Handler.close(handler)
        stream.close()
        handler.close = lambda h=handler: logging.Handler.close(h)
    for handler in borrowed:
        logging.Handler.close(handler)
    generator.close()
    patch.undo()

result["independent_raw_rescue_complete"] = True
print(json.dumps(result, sort_keys=True))
