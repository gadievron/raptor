"""Exact orchestration file setups retire paths after write refusals.

Only setup ownership is exercised; planning and probes remain tripwired.
"""

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
        "class": "TestOrchestratorPlanning",
        "method": "test_plan_for_pe_sys_blocks_with_helpful_message",
        "method_sha256": "68eed264661e1833a64746178b0291b30953192627627bda8948b5884675dfda",
        "decorators": [],
    },
    {
        "class": "TestOrchestratorPlanning",
        "method": "test_plan_for_linux_elf_on_linux_picks_afl",
        "method_sha256": "4808848759ebc97383cd85fe3dc571a0f2ea37aef8696cf3d4e95461b71715bd",
        "decorators": [],
    },
    {
        "class": "TestOrchestratorPlanning",
        "method": "test_plan_for_source_file_needs_harness",
        "method_sha256": "09040b09d570cb51ec4254571c16906f5e1f3fa52099cb48235d55f2a3e82e8f",
        "decorators": [],
    },
    {
        "class": "TestOrchestratorPlanning",
        "method": "test_plan_with_no_fuzzers_blocks",
        "method_sha256": "bbdfbf4efd1acbc0693214f6ddd547c9caf0723b9c4be00eaba85221ecb70b3f",
        "decorators": [],
    },
    {
        "class": "TestOrchestratorPlanning",
        "method": "test_macos_with_broken_afl_does_not_run_plain_macho_as_libfuzzer",
        "method_sha256": "dc957e9d9b8e75eb31300408d0dd5747b84d1948f906bdcc46911c09fce457d4",
        "decorators": ["pytest.mark.slow"],
    },
    {
        "class": "TestOrchestratorPlanning",
        "method": "test_instrumented_unix_binary_can_use_libfuzzer",
        "method_sha256": "666297a73e34f9f68efb21d454da35e0316850ce270e04497035d4f0958f3812",
        "decorators": [],
    },
    {
        "class": "TestOrchestratorPlanning",
        "method": "test_plan_summary_has_required_fields",
        "method_sha256": "161433f5581a7a72816c93af5fc6aad547d236d6fababb1ab4524102d7f9514c",
        "decorators": [],
    },
    {
        "class": "TestEnvRootfsLifetime",
        "method": "test_env_build_flag_on_file_target_hints_no_op",
        "method_sha256": "bb2bf3d45ae10595f67662636ca571c726f72e973d0922159960ab0619e100ad",
        "decorators": [],
    },
]


@pytest.mark.parametrize("mode", ["error", "interrupt"])
@pytest.mark.parametrize(
    "case", CASES, ids=lambda row: row["class"] + "." + row["method"]
)
def test_first_write_refusal_retires_orchestration_file(case, mode, tmp_path):
    source = (
        Path(__file__).resolve().parents[3]
        / "packages/fuzzing/tests/test_orchestrator.py"
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
    decorators = [ast.unparse(n) for n in method.decorator_list]
    assert decorators == case["decorators"]
    assert decorators in ([], ["pytest.mark.slow"])
    method.decorator_list = []
    files, writes, denied = [], [], []
    failure = (
        KeyboardInterrupt("owned orchestration file setup interruption")
        if mode == "interrupt"
        else OSError(errno.ENOSPC, "owned orchestration file write refusal")
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

    import platform

    tripwire.object = tripwire
    namespace = {
        "Path": Path,
        "tempfile": SimpleNamespace(NamedTemporaryFile=named),
        "platform": platform,
        "FuzzingOrchestrator": tripwire,
        "patch": tripwire,
        "mock_module_attribute": tripwire,
        "_full_caps_linux": tripwire,
        "_full_caps_macos": tripwire,
        "_no_fuzzers_caps": tripwire,
        "InspectResult": tripwire,
        "_mock_consumer_platform": object(),
    }
    exec(
        compile(ast.Module(body=[method], type_ignores=[]), str(source), "exec"),
        namespace,
    )
    owner = unittest.TestCase()
    try:
        with pytest.raises(type(failure)) as caught:
            namespace[method.name](owner)
        assert caught.value is failure
        assert owner.doCleanups()
        assert writes == [True] and len(files) == 1 and not denied
        handle = files[0]
        assert handle.stream.closed
        with pytest.raises(OSError) as closed:
            os.fstat(handle.fd)
        assert closed.value.errno == errno.EBADF
        assert not Path(handle.name).exists(), (
            "orchestration fixture file survived unittest cleanup"
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
            "scope": "injected firstwrite refusal only; actual Linux guard, slow metadata excluded only for file phase; no orchestration/probe/native/ENOSPC claim",
        }
        (tmp_path / "OBSERVATION.json").write_text(
            json.dumps(observation, indent=2) + "\n"
        )
    finally:
        owner.doCleanups()
        for handle in files:
            handle.stream.close()
            Path(handle.name).unlink(missing_ok=True)
