"""Actual file/pipe acquisition component only, before HTTP transport or workers."""

import ast
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
PINS = {
    "_identity": "7cdb0864fe0f8ccf81a584d161ec276778daa4d1a50e5ceec8596759a44769f6",
    "test_worker_scope_releases_unread_token_and_restores_state": "14f140ece397157669f6a25a819f9073168124593e09351a112b781160f6d842",
}


def _exercise(tmp_path, refusal, expected_closed, reuse):
    source = ROOT / "core/llm/tests/test_worker_session_cleanup.py"
    text = source.read_text()
    tree = ast.parse(text)
    method = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef)
        and n.name == "test_worker_scope_releases_unread_token_and_restores_state"
    )
    identity = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_identity"
    )
    for n in [method, identity]:
        assert (
            hashlib.sha256(ast.get_source_segment(text, n).encode()).hexdigest()
            == PINS[n.name]
        )
    assert (
        method.decorator_list
    )  # Native parametrisation remains source, not copied/executed.
    component = copy.deepcopy(method.body[0])
    assert isinstance(component, ast.With)
    read_owner = component.body[-1]
    assert isinstance(read_owner, ast.Try)
    stop = next(
        i
        for i, n in enumerate(read_owner.body)
        if isinstance(n, ast.Assign) and ast.unparse(n.targets[0]) == "transport"
    )
    read_owner.body = [*read_owner.body[:stop], *ast.parse("boundary()").body]
    statements = [component]
    streams = []
    pairs = []
    writes = []
    foreign = tempfile.TemporaryFile(dir=tmp_path) if reuse else None
    failure = OSError("owned worker fixture first write refusal")

    class ReadyBoundary(Exception):
        pass

    def temporary(*args, **kwargs):
        assert not args and not kwargs
        stream = tempfile.TemporaryFile(dir=tmp_path)
        streams.append((stream, stream.fileno()))
        return stream

    def pipe():
        pair = os.pipe()
        pairs.append(pair)
        return pair

    def write(fd, data):
        assert pairs == [(pairs[0][0], fd)] and data == b"fixture-worker-token"
        writes.append(data)
        if refusal:
            raise failure
        return os.write(fd, data)

    def boundary():
        if reuse:
            os.dup2(foreign.fileno(), pairs[0][0])
        raise ReadyBoundary("setup complete before HTTPTransport")

    namespace = {
        "os": SimpleNamespace(pipe=pipe, write=write, close=os.close, fstat=os.fstat),
        "errno": errno,
        "tempfile": SimpleNamespace(TemporaryFile=temporary),
        "boundary": boundary,
    }
    exec(
        compile(ast.Module(body=[identity], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    try:
        with pytest.raises(OSError if refusal else ReadyBoundary) as caught:
            exec(
                compile(
                    ast.Module(body=statements, type_ignores=[]), str(source), "exec"
                ),
                namespace,
            )
        assert (
            (caught.value is failure)
            if refusal
            else isinstance(caught.value, ReadyBoundary)
        )
        assert len(streams) == len(pairs) == len(writes) == 1
        stream, fd = streams[0]
        read, writer = pairs[0]
        assert stream.closed is expected_closed
        states = {}
        for name, value in [("stream", fd), ("reader", read), ("writer", writer)]:
            try:
                os.fstat(value)
            except OSError as exc:
                assert exc.errno == errno.EBADF
                states[name] = True
            else:
                states[name] = False
        if expected_closed:
            assert states == {"stream": True, "reader": not reuse, "writer": True}
            if reuse:
                info = os.fstat(read)
                kept = os.fstat(foreign.fileno())
                assert (info.st_dev, info.st_ino) == (kept.st_dev, kept.st_ino)
        else:
            assert states == {"stream": False, "reader": False, "writer": False}
        (tmp_path / "observation.json").write_text(
            json.dumps(
                {
                    "refusal": refusal,
                    "reused_reader_preserved": reuse,
                    "closed_before_rescue": states,
                    "scope": "exact actual TemporaryFile/pipe setup only; supplied firstwrite refusal or controlled postsetup boundary before HTTPTransport/provider/nativeworker; no defaultIO/concurrency/fullfixture proof",
                }
            )
            + "\n"
        )
    finally:
        for stream, fd in streams:
            stream.close()
        for pair in pairs:
            for fd in pair:
                try:
                    os.close(fd)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise
        if foreign is not None:
            foreign.close()


@pytest.mark.parametrize(
    "refusal,reuse",
    [(False, False), (True, False), (False, True)],
    ids=["ready-boundary", "write-error", "reused-reader"],
)
def test_worker_acquisition_fixture_ownership(tmp_path, refusal, reuse):
    _exercise(tmp_path, refusal, True, reuse)
