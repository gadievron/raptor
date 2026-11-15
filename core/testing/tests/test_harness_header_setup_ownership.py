"""The exact hostile-header test owns files across setup and body refusals.

These source-bound checks stop at generator construction. They qualify file
ownership, not harness generation, compilation or actual disk exhaustion.
"""

import ast
import errno
import hashlib
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
import unittest

import pytest


_METHOD_SHA256 = "0fb4469f1b26e80ff852c27d4c85d9b905865a7e91beb20e1326ee102a244645"


@pytest.mark.parametrize("mode", ["first-error", "second-error", "body-error", "body-interrupt"])
def test_header_scope_retires_setup_files(mode, tmp_path):
    source = Path(__file__).resolve().parents[3] / "packages/fuzzing/tests/test_harness_generator.py"
    text = source.read_text()
    owner = next(node for node in ast.parse(text).body
                 if isinstance(node, ast.ClassDef) and node.name == "TestHarnessGenerator")
    method = next(node for node in owner.body if isinstance(node, ast.FunctionDef)
                  and node.name == "test_fallback_gates_hostile_header_filename")
    assert hashlib.sha256(ast.get_source_segment(text, method).encode()).hexdigest() == _METHOD_SHA256
    assert not method.decorator_list
    roots, writes, boundaries = [], [], []
    failure = (KeyboardInterrupt("owned header body interruption") if mode == "body-interrupt"
               else OSError(errno.ENOSPC, "owned header setup refusal") if mode.endswith("error") and mode != "body-error"
               else RuntimeError("owned header body refusal"))

    class HeaderPath(type(Path())):
        def write_text(self, data, *args, **kwargs):
            writes.append(self.name)
            selected = ((mode == "first-error" and len(writes) == 1)
                        or (mode == "second-error" and len(writes) == 2))
            if selected:
                boundaries.append("write")
                raise failure
            return super().write_text(data, *args, **kwargs)

    def directory():
        owned = tempfile.TemporaryDirectory(prefix="headers-", dir=tmp_path)
        roots.append(Path(owned.name))
        return owned

    def generator(*args, **kwargs):
        assert mode.startswith("body-")
        boundaries.append("body")
        assert len(writes) == 2 and len(list(roots[0].iterdir())) == 2
        raise failure

    def forbidden(*args, **kwargs):
        pytest.fail("unreviewed harness behavior reached")

    namespace = {"Path": HeaderPath, "tempfile": SimpleNamespace(TemporaryDirectory=directory),
                 "HarnessGenerator": generator, "HarnessSpec": forbidden}
    exec(compile(ast.Module(body=[method], type_ignores=[]), str(source), "exec"), namespace)
    try:
        with pytest.raises(type(failure)) as caught:
            namespace[method.name](unittest.TestCase())
        assert caught.value is failure
        assert boundaries == (["body"] if mode.startswith("body-") else ["write"])
        assert len(writes) == (1 if mode == "first-error" else 2)
        assert len(roots) == 1 and not roots[0].exists(), "header owner leaked setup files"
    finally:
        # Observe owner cleanup above, before this independent rescue.
        for root in roots:
            shutil.rmtree(root, ignore_errors=True)
