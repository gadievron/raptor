"""Exact JSON pipe fixture resource ownership before parser execution."""

import ast
import errno
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import pytest

ROOT = Path(__file__).resolve().parents[3]
PINS = {
    "_Borrowed": "124c664d41a89a03541297924c74bdfe4139f03d5cb4bc480142eefe2137d87f",
    "test_non_regular_descriptor_is_refused_before_read": "826ca79a94efbf5a145ca2ba93031c6efa718eb5e80c05180b829e71c738e563",
}


def _exercise(tmp_path, refusal, expected_closed):
    source = ROOT / "core/json/tests/test_bounded_stream.py"
    text = source.read_text()
    tree = ast.parse(text)
    nodes = [
        n
        for n in tree.body
        if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in PINS
    ]
    assert len(nodes) == 2
    for n in nodes:
        assert (
            hashlib.sha256(ast.get_source_segment(text, n).encode()).hexdigest()
            == PINS[n.name]
        )
    pairs = []
    writes = []
    boundaries = []
    failure = OSError("owned JSON pipe first write refusal")

    class ParserBoundary(Exception):
        pass

    def pipe():
        pair = os.pipe()
        pairs.append(pair)
        return pair

    def write(fd, data):
        assert fd == pairs[0][1] and data == b"{}"
        writes.append(data)
        if refusal:
            raise failure
        return os.write(fd, data)

    def boundary():
        assert not refusal and len(pairs) == 1
        read, write = pairs[0]
        os.fstat(read)
        with pytest.raises(OSError) as caught:
            os.fstat(write)
        assert caught.value.errno == errno.EBADF
        boundaries.append(True)
        raise ParserBoundary("owned pipe ready before JSON parser")

    namespace = {
        "os": SimpleNamespace(pipe=pipe, write=write, close=os.close, fdopen=os.fdopen),
        "pytest": pytest,
        "_api": boundary,
    }
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace
    )
    try:
        with pytest.raises(OSError if refusal else ParserBoundary) as caught:
            namespace["test_non_regular_descriptor_is_refused_before_read"]()
        assert (caught.value is failure) if refusal else boundaries == [True]
        assert len(pairs) == 1 and writes == [b"{}"]
        read, write = pairs[0]
        with pytest.raises(OSError) as closed:
            os.fstat(write)
        assert closed.value.errno == errno.EBADF
        if expected_closed:
            with pytest.raises(OSError) as closed:
                os.fstat(read)
            assert closed.value.errno == errno.EBADF
        else:
            os.fstat(read)
        (tmp_path / "observation.json").write_text(
            json.dumps(
                {
                    "refusal": refusal,
                    "read_closed_before_rescue": expected_closed,
                    "write_closed_before_rescue": True,
                    "parser_boundary": bool(boundaries),
                    "scope": "real owned pipe setup only; supplied write refusal, no actual EPIPE/default fault or parser execution",
                }
            )
            + "\n"
        )
    finally:
        for pair in pairs:
            for fd in pair:
                try:
                    os.close(fd)
                except OSError as exc:
                    if exc.errno != errno.EBADF:
                        raise


@pytest.mark.parametrize(
    "refusal", [False, True], ids=["ready-boundary", "write-error"]
)
def test_json_pipe_setup_ownership(tmp_path, refusal):
    _exercise(tmp_path, refusal, True)
