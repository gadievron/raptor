"""Exact named-header methods own setup pathnames after write refusals."""

import ast
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import pytest

CASES = [
    {
        "class": "TestHarnessGenerator",
        "method": "test_no_llm_returns_fallback",
        "method_sha256": "01b253ea92c7d5ee67d159bf865ebbb020d6cb02d70eccd8083e885d4a981b35",
    },
    {
        "class": "TestHarnessGenerator",
        "method": "test_fallback_emits_safe_extra_includes_and_drops_unsafe",
        "method_sha256": "102742e2db2e622ca0a729f46c236a8326e80fcc3780624d2c553edb29399045",
    },
    {
        "class": "TestHarnessGenerator",
        "method": "test_llm_success_path",
        "method_sha256": "f3b5e2682a34dee2c17d73f58f79581093a67398df47b23ed3a2e02cd78d857e",
    },
    {
        "class": "TestHarnessGenerator",
        "method": "test_llm_returns_no_source_falls_back",
        "method_sha256": "99eb1c9a9c2e1d64ce4f84dc3bd37c36d9378e73a71d2252e12e232ee4591b61",
    },
    {
        "class": "TestHarnessGenerator",
        "method": "test_compile_command_includes_sanitisers",
        "method_sha256": "2c7dc594622219a7f9a18570059d34fdc51b7fd085e0daa495df2fffb8fb1cab",
    },
    {
        "class": "TestHarnessGenerator",
        "method": "test_write_creates_source_and_build_script",
        "method_sha256": "94badf9be47fa2e4875c0baab824eb7fe4f21eeef3f27c77d3219718829017b8",
    },
    {
        "class": "TestCompileCommandShellSafety",
        "method": "_make_header",
        "method_sha256": "2011bc543069c3c575d52d1dfdf3df9c185fbf8370ecfec6f06b847171b66d0e",
    },
    {
        "class": "TestTargetSymbolGrammar",
        "method": "_make_header",
        "method_sha256": "55d38dd20b5a27168457c36ac3b22cc37fe10250a8458c6653ea66baed67edd7",
    },
    {
        "class": "TestPromptEnvelope",
        "method": "_generate_and_capture",
        "method_sha256": "5bf8c649ee9c54b28c3e907f78e0b7f6ffe77a0a3ca3901e5e97a7d3c18b8d72",
    },
]


@pytest.mark.parametrize("mode", ["error", "interrupt"])
@pytest.mark.parametrize(
    "case", CASES, ids=lambda row: row["class"] + "." + row["method"]
)
def test_write_refusal_retires_named_header(case, mode, tmp_path):
    source = (
        Path(__file__).resolve().parents[3]
        / "packages/fuzzing/tests/test_harness_generator.py"
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
    assert not method.decorator_list
    files, writes, denied = [], [], []
    failure = (
        KeyboardInterrupt("owned named-header write interruption")
        if mode == "interrupt"
        else OSError(errno.ENOSPC, "owned named-header write refusal")
    )

    class Handle:
        def __init__(self, stream):
            self.stream = stream
            self.fd = stream.fileno()
            self.name = stream.name

        def __enter__(self):
            self.stream.__enter__()
            return self

        def __exit__(self, *exc):
            return self.stream.__exit__(*exc)

        def write(self, value):
            writes.append(True)
            raise failure

        def __getattr__(self, name):
            return getattr(self.stream, name)

    def named(*args, **kwargs):
        assert kwargs.get("delete") is False and "dir" not in kwargs
        stream = tempfile.NamedTemporaryFile(*args, dir=tmp_path, **kwargs)
        handle = Handle(stream)
        files.append(handle)
        return handle

    def tripwire(*args, **kwargs):
        denied.append(True)
        raise AssertionError("unreviewed mock/harness construction")

    namespace = {
        "Path": Path,
        "tempfile": SimpleNamespace(NamedTemporaryFile=named),
        "HarnessSpec": tripwire,
        "HarnessGenerator": tripwire,
        "MagicMock": tripwire,
        "GeneratedHarness": object,
    }
    exec(
        compile(ast.Module(body=[method], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    owner = unittest.TestCase()
    try:
        with pytest.raises(type(failure)) as caught:
            args = (
                ("int parse_buf(void);\n",)
                if case["method"] == "_generate_and_capture"
                else ()
            )
            namespace[method.name](owner, *args)
        assert caught.value is failure
        assert owner.doCleanups()
        assert writes == [True] and len(files) == 1 and not denied
        handle = files[0]
        assert handle.stream.closed
        with pytest.raises(OSError) as closed:
            os.fstat(handle.fd)
        assert closed.value.errno == errno.EBADF
        assert not Path(handle.name).exists(), (
            "named header survived its unittest cleanup"
        )
        observation = {
            "case": case["class"] + "." + case["method"],
            "exception_identity": True,
            "write_refused": True,
            "stream_closed": True,
            "descriptor_consumed": True,
            "pathname_removed_after_unittest_cleanup": True,
            "mode": mode,
            "forbidden": denied,
            "scope": "injected write refusal/interrupt only; not actual ENOSPC or harness behavior",
        }
        (tmp_path / "OBSERVATION.json").write_text(
            json.dumps(observation, indent=2) + "\n"
        )
    finally:
        owner.doCleanups()
        for handle in files:
            handle.stream.close()
            Path(handle.name).unlink(missing_ok=True)
