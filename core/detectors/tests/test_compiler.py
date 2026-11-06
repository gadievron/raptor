"""Resource, error-authority and concurrency contracts for compiler stages."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from core.detectors.compiler import (
    CompilerInvocationError, CompilerRequest, run_compiler_analysis,
)


def request(tmp_path, **kwargs):
    return CompilerRequest(
        command=("/trusted/compiler", "-c", "input.c"), target=tmp_path,
        timeout=17, caller_label="compiler-test", scratch_prefix="compiler_test_",
        scratch_root=str(tmp_path), parse=lambda workdir, stderr: [], **kwargs,
    )


def test_parser_and_analysis_share_live_scratch_then_cleanup(tmp_path):
    calls = []

    def run(cmd, **kw):
        calls.append(kw)
        assert cmd == ["/trusted/compiler", "-c", "input.c"]
        assert kw["block_network"] is True
        assert kw["target"] == str(tmp_path)
        assert kw["cwd"] == kw["output"]
        assert kw["timeout"] == 17
        assert kw["caller_label"] == "compiler-test"
        assert kw["capture_output"] and kw["text"]
        Path(kw["output"], "diagnostic").write_text("warning")
        return SimpleNamespace(returncode=0, stderr="abcdef", stdout="unused")

    def parse(workdir, stderr):
        assert workdir.is_dir() and stderr == "abcdef"
        return [{"message": (workdir / "diagnostic").read_text()}]

    def analyze(record, workdir):
        assert workdir.is_dir()
        assert record == {"returncode": 0, "diags": [{"message": "warning"}], "raw": "abc"}
        return "candidate"

    execution = run_compiler_analysis(
        replace(request(tmp_path, raw_limit=3, analyze=analyze), parse=parse), run,
    )
    assert execution.status == "complete"
    assert execution.value.result == "candidate"
    assert execution.value._stderr == ""
    assert len(calls) == 1
    assert not Path(calls[0]["output"]).exists()


@pytest.mark.parametrize("returncode", [1, -9, 139])
def test_failed_compile_is_parsed_but_never_analyzed(tmp_path, returncode):
    analyses = []
    parsed = []

    def parse(workdir, stderr):
        parsed.append(workdir)
        assert workdir.is_dir()
        return [{"kind": "error", "message": "bad compile"}]

    execution = run_compiler_analysis(
        replace(request(tmp_path, analyze=lambda *args: analyses.append(args)), parse=parse),
        lambda *a, **kw: SimpleNamespace(returncode=returncode, stderr="bad compile"),
    )
    assert execution.status == "error"
    assert execution.value.record["returncode"] == returncode
    assert execution.value.record["diags"] == [{"kind": "error", "message": "bad compile"}]
    assert not analyses
    assert len(parsed) == 1 and not parsed[0].exists()
    assert [s.name for s in execution.stages] == ["prepare", "invoke", "parse"]


@pytest.mark.parametrize("error", [subprocess.TimeoutExpired("cc", 17), OSError("spawn"), TypeError("args")])
def test_invocation_failure_has_distinct_type_and_closes_scratch(tmp_path, error):
    directories = []

    def run(*a, **kw):
        directories.append(Path(kw["output"]))
        raise error

    with pytest.raises(CompilerInvocationError) as raised:
        run_compiler_analysis(request(tmp_path), run)
    assert raised.value.error is error
    assert not directories[0].exists()


@pytest.mark.parametrize("phase", ["parse", "analyze"])
def test_python_failure_propagates_without_becoming_an_invocation_error(tmp_path, phase):
    directories = []

    def fail(*args):
        raise TypeError("Python analysis bug")

    def run(*a, **kw):
        directories.append(Path(kw["output"]))
        return SimpleNamespace(returncode=0, stderr="")

    req = request(tmp_path)
    req = replace(req, **{phase: fail})
    with pytest.raises(TypeError, match="Python analysis bug"):
        run_compiler_analysis(req, run)
    assert not directories[0].exists()


def test_parallel_runs_do_not_share_records_or_scratch(tmp_path):
    def one(number):
        directories = []

        def run(*a, **kw):
            directories.append(kw["output"])
            return SimpleNamespace(returncode=0, stderr=str(number))

        result = run_compiler_analysis(
            replace(request(tmp_path), parse=lambda workdir, stderr: [{"number": stderr}]), run,
        )
        return result.value.record, directories[0]

    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(one, range(8)))
    assert [r[0]["diags"] for r in results] == [[{"number": str(i)}] for i in range(8)]
    assert len({r[1] for r in results}) == 8
    assert all(not Path(r[1]).exists() for r in results)


@pytest.mark.parametrize("returncode", [-9, 0, 1])
def test_malformed_diagnostics_preserve_signal_death(tmp_path, returncode):
    from core.detectors.compiler import CompilerDiagnosticError

    def malformed(workdir, stderr):
        raise CompilerDiagnosticError("truncated diagnostics")

    req = replace(request(tmp_path), parse=malformed)
    run = lambda *a, **kw: SimpleNamespace(returncode=returncode, stderr="[")
    if returncode < 0:
        execution = run_compiler_analysis(req, run)
        assert execution.status == "error"
        assert execution.value.record["returncode"] == returncode
        assert execution.value.record["diags"] == []
    else:
        with pytest.raises(CompilerDiagnosticError, match="truncated diagnostics"):
            run_compiler_analysis(req, run)


@pytest.mark.parametrize("returncode", [-9, 0, 1, 2])
def test_unsuccessful_execution_preserves_owned_nonzero_exit(tmp_path, returncode):
    from core.detectors.compiler import CompilerExecutionError

    def unsuccessful(workdir, stderr):
        raise CompilerExecutionError("compiler reported unsuccessful execution")

    req = replace(request(tmp_path), parse=unsuccessful,
                  analyze=lambda *args: pytest.fail("failed execution reached analysis"))
    directories = []

    def run(*args, **kwargs):
        directories.append(kwargs["output"])
        return SimpleNamespace(returncode=returncode, stderr="compile failure")

    if returncode == 0:
        with pytest.raises(CompilerExecutionError):
            run_compiler_analysis(req, run)
    else:
        execution = run_compiler_analysis(req, run)
        assert execution.status == "error"
        assert execution.value.record == {"returncode": returncode, "diags": [], "raw": ""}
    assert directories and all(not Path(path).exists() for path in directories)


@pytest.mark.parametrize('phase', ['complete', 'failed-compile', 'invoke', 'parse', 'analyze'])
def test_finished_compiler_state_releases_callbacks_but_keeps_results(tmp_path, monkeypatch, phase):
    import gc
    import weakref
    from core.detectors import compiler

    states = []
    references = []
    original = compiler.run_detector

    def capture(definition, state):
        states.append(state)
        return original(definition, state)
    monkeypatch.setattr(compiler, 'run_detector', capture)

    class Payload:
        pass

    def run_owned():
        payload = Payload()
        references.append(weakref.ref(payload))

        def run(*args, **kwargs):
            assert payload is not None
            if phase == 'invoke':
                raise TypeError('owned invocation failure')
            return SimpleNamespace(returncode=1 if phase == 'failed-compile' else 0, stderr='raw')

        def parse(workdir, stderr):
            assert payload is not None and workdir.is_dir()
            if phase == 'parse':
                raise TypeError('owned parser failure')
            return [{'message': 'retained'}]

        def analyze(record, workdir):
            assert payload is not None and workdir.is_dir()
            if phase == 'analyze':
                raise TypeError('owned analysis failure')
            return {'derived': True}

        owned = replace(request(tmp_path, analyze=analyze), parse=parse)
        try:
            result = run_compiler_analysis(owned, run)
        except (TypeError, CompilerInvocationError):
            assert phase in ('invoke', 'parse', 'analyze')
            result = None
        assert owned.parse is parse and owned.analyze is analyze
        return result

    result = run_owned()
    state = states[0]
    assert state.request is None and state.sandbox_run is None and state._stderr == ''
    assert not state._workdir.exists()
    if phase in ('complete', 'failed-compile'):
        assert state.record == {'returncode': 1 if phase == 'failed-compile' else 0,
                                'diags': [{'message': 'retained'}], 'raw': ''}
        assert result.status == ('error' if phase == 'failed-compile' else 'complete')
        assert state.result == ({'derived': True} if phase == 'complete' else None)
    gc.collect(0)
    assert references[0]() is None
