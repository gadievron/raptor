"""Real unconnected socket/pipe setup only, before SDK or dispatcher work."""

import ast
import copy
import errno
import hashlib
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
PINS = {
    "_owned": "fedb394512c4be4f59d0647858a562a7bde03fb388c081ada49621a71719c675",
    "test_wire_failure_releases_resources_and_partial_state": "e45b45d02e305f9952e36796d4d4af0c71b26bf48011109092178cebf586a958",
}


def _exercise(tmp_path, refusal, expected_closed, reuse):
    source = ROOT / "core/llm/tests/test_consumed_setup_cleanup.py"
    text = source.read_text()
    tree = ast.parse(text)
    method = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef)
        and n.name == "test_wire_failure_releases_resources_and_partial_state"
    )
    helper = next(
        n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_owned"
    )
    for n in [method, helper]:
        assert (
            hashlib.sha256(ast.get_source_segment(text, n).encode()).hexdigest()
            == PINS[n.name]
        )
    assert (
        method.decorator_list
    )  # Native parametrisation/SDK guard not copied or evaluated.
    component = copy.deepcopy(method.body[0])
    assert isinstance(component, ast.With)
    reader = component.body[-1]
    assert isinstance(reader, ast.Try)
    stop = next(
        i
        for i, n in enumerate(reader.body)
        if isinstance(n, ast.Assign) and ast.unparse(n.targets[0]) == "allocated"
    )
    reader.body = [*reader.body[:stop], *ast.parse("boundary()").body]
    statements = [component]
    sockets = []
    pairs = []
    writes = []
    foreign = tempfile.TemporaryFile(dir=tmp_path) if reuse else None
    failure = OSError("owned consumed fixture first write refusal")

    class ReadyBoundary(Exception):
        pass

    def opened(*args, **kwargs):
        assert not args and not kwargs
        current = socket.socket()
        sockets.append((current, current.fileno()))
        assert current.getsockname()[1] == 0
        return current

    def pipe():
        pair = os.pipe()
        pairs.append(pair)
        return pair

    def write(fd, data):
        assert len(pairs) == 1 and fd == pairs[0][1] and data == b"owned-token"
        writes.append(data)
        if refusal:
            raise failure
        return os.write(fd, data)

    def boundary():
        if reuse:
            os.dup2(foreign.fileno(), pairs[0][0])
        raise ReadyBoundary("acquisition ends before dispatcher setup")

    namespace = {
        "socket": SimpleNamespace(socket=opened),
        "os": SimpleNamespace(pipe=pipe, write=write, close=os.close, fstat=os.fstat),
        "errno": errno,
        "boundary": boundary,
    }
    exec(
        compile(ast.Module(body=[helper], type_ignores=[]), str(source), "exec"),
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
        assert len(sockets) == len(pairs) == len(writes) == 1
        current, fd = sockets[0]
        read, writer = pairs[0]
        states = {}
        for name, value in [("socket", fd), ("reader", read), ("writer", writer)]:
            try:
                os.fstat(value)
            except OSError as exc:
                assert exc.errno == errno.EBADF
                states[name] = True
            else:
                states[name] = False
        assert (current.fileno() == -1) is expected_closed
        assert states == {
            "socket": expected_closed,
            "reader": expected_closed and not reuse,
            "writer": expected_closed,
        }
        if reuse:
            actual = os.fstat(read)
            kept = os.fstat(foreign.fileno())
            assert (actual.st_dev, actual.st_ino) == (kept.st_dev, kept.st_ino)
        (tmp_path / "observation.json").write_text(
            json.dumps(
                {
                    "refusal": refusal,
                    "reused_reader_preserved": reuse,
                    "closed_before_rescue": states,
                    "scope": "exact unbound/unconnected socket andpipe acquisition only, suppliedfirstwrite refusal; no SDK/nativefixture admission, dispatcher/provider/network/worker/concurrency/defaultIO proof",
                }
            )
            + "\n"
        )
    finally:
        for current, fd in sockets:
            current.close()
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
def test_consumed_acquisition_fixture_ownership(tmp_path, refusal, reuse):
    _exercise(tmp_path, refusal, True, reuse)
