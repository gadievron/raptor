"""Exact API fixture setup owns files across IO refusals; APIs stay tripwired."""

import ast
from contextlib import ExitStack
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace

import pytest

CASES = [
    {
        "class": "TestLoadExploitContext",
        "method": "test_load_returns_dict",
        "method_sha256": "c2af69a9558cd0236d7e66c287d7015d87b22c442588b95adbe1d4bc64dcf7c4",
    },
    {
        "class": "TestLoadExploitContext",
        "method": "test_load_preserves_all_data",
        "method_sha256": "0507510ef7a64bf4a3a55af74cff071a14b1d9daa3074073da05cacd5960b54c",
    },
    {
        "class": "TestPrintExploitContext",
        "method": "test_print_returns_string",
        "method_sha256": "14ab4fa84be0a180e58e395585da2342f9228a2d0ff85309bde1e234ab294f05",
    },
    {
        "class": "TestPrintExploitContext",
        "method": "test_print_includes_verdict",
        "method_sha256": "737192fa41bcce32f634205ed3ac535eb25ad091856b5d335262c5a4c4fe187c",
    },
    {
        "class": "TestPrintExploitContext",
        "method": "test_print_includes_protections",
        "method_sha256": "4bfc2a02925cd399a4bd00be7d945949fdd081016274a7e4aac6e113741fd826",
    },
    {
        "class": "TestPrintExploitContext",
        "method": "test_print_includes_libc_offsets",
        "method_sha256": "f7651e25f6357ef090886f29178eb79a6f9db519e452b82c22acd3409aedf3b3",
    },
    {
        "class": "TestPrintExploitContext",
        "method": "test_print_includes_rop_gadgets",
        "method_sha256": "5f405540683882c4b0f1596e2957c206719b04b1830f5ab00f62058f699f93b2",
    },
]


@pytest.mark.parametrize("mode", ["error", "interrupt"])
@pytest.mark.parametrize("stage", ["write", "flush"])
@pytest.mark.parametrize(
    "case", CASES, ids=lambda row: row["class"] + "." + row["method"]
)
def test_io_refusal_retires_api_fixture_file(case, stage, mode, tmp_path):
    source = (
        Path(__file__).resolve().parents[3]
        / "packages/exploit_feasibility/tests/test_api_persistence.py"
    )
    text = source.read_text()
    cls = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.ClassDef) and n.name == case["class"]
    )
    method = next(
        n
        for n in cls.body
        if isinstance(n, ast.FunctionDef) and n.name == case["method"]
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, method).encode()).hexdigest()
        == case["method_sha256"]
    )
    assert not cls.bases and not method.decorator_list
    files, writes, refusals, unlinks, denied = [], [], [], [], []
    failure = (
        KeyboardInterrupt("owned API fixture IO interruption")
        if mode == "interrupt"
        else OSError(errno.ENOSPC, "owned API fixture IO refusal")
    )

    class Handle:
        def __init__(self, stream):
            self.stream, self.name, self.fd = stream, stream.name, stream.fileno()

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *exc):
            return self.stream.__exit__(*exc)

        def write(self, value):
            writes.append(True)
            if stage == "write":
                refusals.append("write")
                raise failure
            return self.stream.write(value)

        def flush(self):
            assert stage == "flush"
            refusals.append("flush")
            raise failure

        def __getattr__(self, name):
            return getattr(self.stream, name)

    def named(*args, **kwargs):
        assert kwargs.get("delete") is False and "dir" not in kwargs
        handle = Handle(tempfile.NamedTemporaryFile(*args, dir=tmp_path, **kwargs))
        files.append(handle)
        return handle

    def unlink(name):
        assert len(files) == 1 and name == files[0].name
        assert files[0].stream.closed, "pathname removed before stream close"
        unlinks.append(name)
        os.unlink(name)

    def tripwire(*args, **kwargs):
        denied.append(True)
        raise AssertionError("unreviewed API behavior reached")

    namespace = {
        "Path": Path,
        "tempfile": SimpleNamespace(NamedTemporaryFile=named),
        "json": json,
        "os": SimpleNamespace(unlink=unlink),
        "ExitStack": ExitStack,
        "load_exploit_context": tripwire,
        "print_exploit_context": tripwire,
    }
    exec(
        compile(ast.Module(body=[method], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    try:
        with pytest.raises(type(failure)) as caught:
            namespace[method.name](object())
        assert caught.value is failure and refusals == [stage]
        assert writes and len(files) == 1 and not denied
        handle = files[0]
        assert handle.stream.closed
        with pytest.raises(OSError) as closed:
            os.fstat(handle.fd)
        assert closed.value.errno == errno.EBADF
        assert unlinks == [handle.name]
        assert not Path(handle.name).exists(), (
            "API fixture pathname survived IO refusal"
        )
        observation = {
            "case": case["class"] + "." + case["method"],
            "stage": stage,
            "exception_identity": True,
            "io_refused": True,
            "stream_closed": True,
            "descriptor_consumed": True,
            "pathname_removed": True,
            "stream_closed_before_unlink": True,
            "mode": mode,
            "unlink_calls": len(unlinks),
            "forbidden": denied,
            "scope": "injected write/flush refusal, not actual ENOSPC or API behavior",
        }
        (tmp_path / "OBSERVATION.json").write_text(
            json.dumps(observation, indent=2) + "\n"
        )
    finally:
        for handle in files:
            handle.stream.close()
            Path(handle.name).unlink(missing_ok=True)
