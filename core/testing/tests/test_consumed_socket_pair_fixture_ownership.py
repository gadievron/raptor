"""Real socket pair acquisition ownership before SDK or caller execution."""

import ast
import copy
import errno
import hashlib
import json
from pathlib import Path
import socket
from types import SimpleNamespace
import pytest

SOURCE = (
    Path(__file__).resolve().parents[3]
    / "core/llm/tests/test_consumed_setup_cleanup.py"
)
PIN = "a32dcaa3b9bc11485e5c0177e772c019782cf8bdce9b6d824360979c8fec04a7"


@pytest.mark.parametrize(
    "refusal", [False, True], ids=["ready-boundary", "second-refusal"]
)
def test_socket_pair_acquisition_ownership(tmp_path, refusal):
    text = SOURCE.read_text()
    method = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.FunctionDef)
        and n.name == "test_consumed_caller_failure_releases_acquired_resources"
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, method).encode()).hexdigest() == PIN
    )
    component = copy.deepcopy(method.body[1])
    assert isinstance(component, ast.With) and len(component.items) == 2
    assert [ast.unparse(item.optional_vars) for item in component.items] == [
        "upstream_socket",
        "dispatcher_socket",
    ]
    component.body = ast.parse("boundary()").body
    statements = [component]
    owned = []
    calls = []
    failure = OSError(errno.EMFILE, "supplied second socket allocation refusal")

    def opened():
        calls.append(True)
        if len(calls) == 2 and refusal:
            raise failure
        current = socket.socket()
        owned.append(current)
        assert current.getsockname()[1] == 0
        return current

    class ReadyBoundary(Exception):
        pass

    def boundary():
        raise ReadyBoundary("before native caller setup")

    try:
        with pytest.raises(OSError if refusal else ReadyBoundary) as caught:
            exec(
                compile(
                    ast.Module(body=statements, type_ignores=[]), str(SOURCE), "exec"
                ),
                {"socket": SimpleNamespace(socket=opened), "boundary": boundary},
            )
        assert (
            (caught.value is failure)
            if refusal
            else isinstance(caught.value, ReadyBoundary)
        )
        assert len(calls) == 2 and len(owned) == (1 if refusal else 2)
        assert all(current.fileno() == -1 for current in owned)
        (tmp_path / "observation.json").write_text(
            json.dumps(
                {
                    "second_allocation_refused": refusal,
                    "sockets_acquired": len(owned),
                    "all_sockets_closed_before_rescue": True,
                }
            )
            + "\n"
        )
    finally:
        for current in owned:
            current.close()
