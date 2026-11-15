"""Exact stamp fixture helper owns streams and paths before setup IO."""

import ast
import builtins
import errno
import hashlib
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
import weakref

import pytest


@pytest.mark.parametrize("refuse_write", [False, True], ids=["normal", "write-refusal"])
def test_stamp_fixture_owns_setup_file(refuse_write, tmp_path):
    source = (
        Path(__file__).resolve().parents[3] / "core/sage/tests/test_sage_mcp_guard.py"
    )
    text = source.read_text()
    cls = next(
        n
        for n in ast.parse(text).body
        if isinstance(n, ast.ClassDef) and n.name == "TestStampSectionInjection"
    )
    node = next(
        n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name == "_write"
    )
    assert (
        hashlib.sha256(ast.get_source_segment(text, node).encode()).hexdigest()
        == "83dd210a7154f30578bb0bb4076a057cf9c4e3089794dc3de3e03b733b9f02aa"
    )
    assert not node.decorator_list
    meta = {}

    def refuse(*args, **kwargs):
        raise OSError(errno.ENOSPC, "owned stamp first write refusal")

    def factory(*args, **kwargs):
        assert "dir" not in kwargs
        handle = tempfile.NamedTemporaryFile(*args, dir=tmp_path, **kwargs)
        meta.update(ref=weakref.ref(handle), name=handle.name, fd=handle.fileno())
        if refuse_write:
            handle.write = refuse
        return handle

    importing = builtins.__import__

    def private_import(name, *args, **kwargs):
        if name == "tempfile":
            return SimpleNamespace(NamedTemporaryFile=factory)
        return importing(name, *args, **kwargs)

    namespace = {
        "__builtins__": dict(vars(builtins), __import__=private_import),
        "Path": Path,
    }
    exec(
        compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    case = unittest.TestCase()
    body = "### initialize.instructions\nowned fixture body\n"
    fired = False
    returned = None
    try:
        try:
            returned = namespace["_write"](case, body)
        except OSError as exc:
            assert exc.errno == errno.ENOSPC
            assert str(exc) == "[Errno 28] owned stamp first write refusal"
            fired = True
        assert fired is refuse_write
        assert meta["ref"]() is None
        with pytest.raises(OSError) as consumed:
            os.fstat(meta["fd"])
        assert consumed.value.errno == errno.EBADF
        assert Path(meta["name"]).is_file()
        if not refuse_write:
            assert returned == meta["name"]
            assert (
                Path(returned).read_text()
                == "# SAGE boot payload\n# SHA256: 0\n# ---\n" + body
            )
        assert case.doCleanups()
        assert not Path(meta["name"]).exists()
        assert not list(tmp_path.iterdir())
    finally:
        if meta.get("ref") and meta["ref"]() is not None:
            meta["ref"]().close()
        if "name" in meta:
            Path(meta["name"]).unlink(missing_ok=True)
