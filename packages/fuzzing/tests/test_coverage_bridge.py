"""Fuzz → audit per-function coverage producer.

The audit side has three consumers of ``coverage-fuzz.json`` and had
zero producers — these tests pin the producer end-to-end with stubbed
execution (no target runs, no gcov binary) and prove the emitted
document satisfies BOTH existing consumer schemas.
"""

from __future__ import annotations

import json

import pytest

from packages.fuzzing.coverage_bridge import (
    COVERAGE_FUZZ_FILE,
    MAX_REPLAY_INPUTS,
    build_fuzz_coverage,
    collect_gcov_function_coverage,
    emit_fuzz_coverage,
    find_corpus_inputs,
    has_gcov_instrumentation,
    parse_gcov_function_report,
    replay_corpus,
    write_fuzz_coverage,
)

_GCOV_OUTPUT = """\
Function 'parse_header'
Lines executed:92.31% of 13

Function 'parse_body'
Lines executed:0.00% of 24

File 'src/parse.c'
Lines executed:44.00% of 37
Creating 'parse.c.gcov'

Function 'main'
Lines executed:100.00% of 5

File 'src/main.c'
Lines executed:100.00% of 5
"""


class TestGcovParser:
    def test_functions_attributed_to_files(self):
        parsed = parse_gcov_function_report(_GCOV_OUTPUT)
        assert parsed == {
            "src/parse.c": {"parse_header": True, "parse_body": False},
            "src/main.c": {"main": True},
        }

    def test_empty_and_garbage_input(self):
        assert parse_gcov_function_report("") == {}
        assert parse_gcov_function_report("random\nnoise\n") == {}

    def test_reached_merges_or_wise(self):
        text = (
            "Function 'f'\nLines executed:0.00% of 3\n"
            "File 'a.c'\nLines executed:0.00% of 3\n"
            "Function 'f'\nLines executed:50.00% of 3\n"
            "File 'a.c'\nLines executed:50.00% of 3\n"
        )
        assert parse_gcov_function_report(text) == {"a.c": {"f": True}}


class TestCollectGcov:
    def test_merges_across_gcda_files(self, tmp_path):
        build = tmp_path / "build"
        (build / "sub").mkdir(parents=True)
        (build / "a.gcda").write_bytes(b"")
        (build / "sub" / "b.gcda").write_bytes(b"")

        calls = []

        class _Proc:
            stdout = _GCOV_OUTPUT

        def runner(cmd, *, cwd=None, stdin_bytes=None, timeout=0):
            calls.append(cmd)
            return _Proc()

        cov = collect_gcov_function_coverage(build, runner=runner)
        assert len(calls) == 2
        assert all(c[0] == "gcov" and "-f" in c for c in calls)
        assert cov["src/parse.c"]["parse_header"] is True
        assert cov["src/parse.c"]["parse_body"] is False

    def test_source_root_relativises_paths(self, tmp_path):
        build = tmp_path / "src"
        build.mkdir()
        (build / "a.gcda").write_bytes(b"")

        abs_path = str(tmp_path / "src" / "parse.c")

        class _Proc:
            stdout = (
                f"Function 'f'\nLines executed:10.00% of 3\n"
                f"File '{abs_path}'\nLines executed:10.00% of 3\n"
            )

        def runner(cmd, *, cwd=None, stdin_bytes=None, timeout=0):
            return _Proc()

        cov = collect_gcov_function_coverage(
            build, source_root=tmp_path, runner=runner,
        )
        assert list(cov) == ["src/parse.c"]

    def test_no_gcda_returns_empty(self, tmp_path):
        assert collect_gcov_function_coverage(tmp_path) == {}

    def test_runner_failure_survivable(self, tmp_path):
        (tmp_path / "a.gcda").write_bytes(b"")

        def runner(cmd, **kw):
            raise OSError("gcov missing")

        assert collect_gcov_function_coverage(tmp_path, runner=runner) == {}


class TestBuildFuzzCoverage:
    def test_satisfies_both_consumer_schemas(self):
        cov = build_fuzz_coverage(
            {
                "src/parse.c": {"parse_header": True, "parse_body": False},
                "src/dead.c": {"never": False},
            },
            iterations=50_000,
            crashes=2,
            crash_functions={"parse_header"},
        )
        # Consumer A: priority.load_fuzz_coverage file-level set.
        assert cov["files_examined"] == ["src/parse.c"]
        # Consumer B: loaders.fuzz_coverage_for nested per-function map.
        from core.audit.loaders import fuzz_coverage_for

        entry = fuzz_coverage_for(cov, "src/parse.c", "parse_header")
        assert entry["reached"] is True
        assert entry["iterations"] == 50_000
        assert entry["crashes"] == 2
        unreached = fuzz_coverage_for(cov, "src/parse.c", "parse_body")
        assert unreached["reached"] is False
        assert unreached["iterations"] == 0
        assert unreached["crashes"] == 0

    def test_gaps_fuzz_info_consumes_producer_output(self):
        from core.audit.gaps import _fuzz_info_for

        cov = build_fuzz_coverage(
            {"src/parse.c": {"parse_header": True}},
            iterations=20_000,
        )
        iters, crashes = _fuzz_info_for(cov, "src/parse.c", "parse_header")
        assert iters == 20_000
        assert crashes == 0

    def test_priority_loader_reads_written_file(self, tmp_path):
        from core.audit.priority import load_fuzz_coverage

        cov = build_fuzz_coverage(
            {"src/parse.c": {"parse_header": True}}, iterations=10,
        )
        write_fuzz_coverage(tmp_path, cov)
        fuzzed = load_fuzz_coverage([tmp_path])
        assert fuzzed == {"src/parse.c"}

    def test_meta_records_provenance(self):
        cov = build_fuzz_coverage({}, iterations=5, crashes=1)
        assert cov["meta"]["producer"] == "raptor-fuzz"
        assert cov["meta"]["total_execs"] == 5
        assert cov["meta"]["campaign_crashes"] == 1


class TestCorpusDiscovery:
    def test_crashes_before_queue_and_bounded(self, tmp_path):
        afl = tmp_path / "afl" / "main"
        (afl / "queue").mkdir(parents=True)
        (afl / "crashes").mkdir(parents=True)
        for i in range(5):
            (afl / "queue" / f"id:{i:06d}").write_bytes(b"q")
        (afl / "crashes" / "id:000000").write_bytes(b"c")
        (afl / "crashes" / "README.txt").write_text("not an input")

        inputs = find_corpus_inputs(tmp_path, max_inputs=3)
        assert len(inputs) == 3
        assert inputs[0].parent.name == "crashes"
        assert all(f.name != "README.txt" for f in inputs)

    def test_default_bound(self, tmp_path):
        afl = tmp_path / "afl" / "main" / "queue"
        afl.mkdir(parents=True)
        for i in range(MAX_REPLAY_INPUTS + 50):
            (afl / f"id:{i:06d}").write_bytes(b"q")
        assert len(find_corpus_inputs(tmp_path)) == MAX_REPLAY_INPUTS

    def test_empty_dir(self, tmp_path):
        assert find_corpus_inputs(tmp_path) == []


class TestReplay:
    def test_file_mode_passes_input_as_argv(self, tmp_path):
        inp = tmp_path / "id:000000"
        inp.write_bytes(b"data")
        calls = []

        def runner(cmd, *, cwd=None, stdin_bytes=None, timeout=0):
            calls.append((cmd, stdin_bytes))

        n = replay_corpus(
            tmp_path / "bin", [inp], input_mode="file", runner=runner,
        )
        assert n == 1
        assert calls[0][0] == [str(tmp_path / "bin"), str(inp)]
        assert calls[0][1] is None

    def test_stdin_mode_feeds_bytes(self, tmp_path):
        inp = tmp_path / "id:000000"
        inp.write_bytes(b"data")
        calls = []

        def runner(cmd, *, cwd=None, stdin_bytes=None, timeout=0):
            calls.append((cmd, stdin_bytes))

        n = replay_corpus(
            tmp_path / "bin", [inp], input_mode="stdin", runner=runner,
        )
        assert n == 1
        assert calls[0][0] == [str(tmp_path / "bin")]
        assert calls[0][1] == b"data"

    def test_failures_survivable(self, tmp_path):
        inp1 = tmp_path / "a"
        inp2 = tmp_path / "b"
        inp1.write_bytes(b"1")
        inp2.write_bytes(b"2")

        def runner(cmd, **kw):
            if cmd[-1].endswith("a"):
                raise OSError("crashed hard")

        n = replay_corpus(
            tmp_path / "bin", [inp1, inp2],
            input_mode="file", runner=runner,
        )
        assert n == 1


class TestEmit:
    def test_no_instrumentation_degrades_silently(self, tmp_path):
        binary = tmp_path / "build" / "target"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"\x7fELF")
        assert (
            emit_fuzz_coverage(tmp_path / "out", binary=binary) is None
        )
        assert not (tmp_path / "out" / COVERAGE_FUZZ_FILE).exists()

    def test_end_to_end_with_stubbed_execution(self, tmp_path):
        build = tmp_path / "build"
        build.mkdir()
        binary = build / "target"
        binary.write_bytes(b"\x7fELF")
        (build / "parse.gcno").write_bytes(b"")
        out_dir = tmp_path / "out"
        afl = out_dir / "afl" / "main" / "queue"
        afl.mkdir(parents=True)
        (afl / "id:000000").write_bytes(b"seed")

        gcda_written = {"done": False}

        class _Proc:
            stdout = _GCOV_OUTPUT

        def runner(cmd, *, cwd=None, stdin_bytes=None, timeout=0):
            if cmd[0] == str(binary):
                # Target replay drops a .gcda like gcov builds do.
                (build / "parse.gcda").write_bytes(b"")
                gcda_written["done"] = True
                return None
            assert cmd[0] == "gcov"
            return _Proc()

        path = emit_fuzz_coverage(
            out_dir,
            binary=binary,
            iterations=12_345,
            crashes=0,
            runner=runner,
        )
        assert gcda_written["done"]
        assert path == out_dir / COVERAGE_FUZZ_FILE
        data = json.loads(path.read_text())
        assert data["files_examined"] == ["src/main.c", "src/parse.c"]
        rec = data["files"]["src/parse.c"]["functions"]["parse_body"]
        assert rec["reached"] is False
        rec = data["files"]["src/parse.c"]["functions"]["parse_header"]
        assert rec["iterations"] == 12_345

    def test_gcov_yields_nothing_no_file(self, tmp_path):
        build = tmp_path / "build"
        build.mkdir()
        binary = build / "target"
        binary.write_bytes(b"\x7fELF")
        (build / "parse.gcno").write_bytes(b"")

        def runner(cmd, **kw):
            class _Proc:
                stdout = ""

            return _Proc()

        assert (
            emit_fuzz_coverage(
                tmp_path / "out", binary=binary, runner=runner,
            )
            is None
        )


class TestInstrumentationDetection:
    def test_detects_gcno(self, tmp_path):
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "x.gcno").write_bytes(b"")
        assert has_gcov_instrumentation(tmp_path) is True

    def test_absent(self, tmp_path):
        assert has_gcov_instrumentation(tmp_path) is False
        assert has_gcov_instrumentation(tmp_path / "missing") is False


class TestOrchestratorWiring:
    def test_execute_calls_bridge(self):
        import inspect

        from packages.fuzzing import orchestrator as orch_mod

        src = inspect.getsource(orch_mod.FuzzingOrchestrator.execute)
        assert "emit_fuzz_coverage" in src
        assert "fuzz_coverage" in src


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))


class TestDefaultRunnerSandboxed:
    """Corpus replay executes the untrusted fuzz target on attacker-
    derived inputs — the default runner must go through core.sandbox.run
    with the network denied (mirroring the afl-showmap sibling), discard
    replay output, and cap gcov capture."""

    @staticmethod
    def _capture(monkeypatch, *, stdout=b"", returncode=0):
        import subprocess as sp

        import core.sandbox

        calls = []

        def fake_run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            return sp.CompletedProcess(
                cmd, returncode, stdout=stdout, stderr=b"",
            )

        monkeypatch.setattr(core.sandbox, "run", fake_run)
        return calls

    def test_replay_sandboxed_network_denied_output_discarded(
        self, tmp_path, monkeypatch,
    ):
        import subprocess as sp

        from packages.fuzzing.coverage_bridge import _default_runner

        calls = self._capture(monkeypatch)
        binary = tmp_path / "target"
        binary.write_bytes(b"\x7fELF")
        inp = tmp_path / "corpus" / "id_0"
        inp.parent.mkdir()
        inp.write_bytes(b"AAAA")
        build = tmp_path / "build"
        build.mkdir()

        _default_runner([str(binary), str(inp)], cwd=build)

        cmd, kwargs = calls[0]
        assert kwargs["block_network"] is True
        assert kwargs["stdout"] == sp.DEVNULL
        assert kwargs["stderr"] == sp.DEVNULL
        assert kwargs["target"] == str(build)
        assert kwargs["output"] == str(build)
        readable = set(kwargs["readable_paths"])
        assert str(binary.resolve().parent) in readable
        assert str(inp.resolve().parent) in readable

    def test_gcov_capture_is_capped(self, tmp_path, monkeypatch):
        import subprocess as sp

        from packages.fuzzing.coverage_bridge import (
            _MAX_CAPTURE_BYTES,
            _default_runner,
        )

        calls = self._capture(
            monkeypatch, stdout=b"y" * (_MAX_CAPTURE_BYTES + 4096),
        )
        build = tmp_path / "build"
        build.mkdir()
        gcda = build / "a.gcda"
        gcda.write_bytes(b"z")

        proc = _default_runner(
            ["gcov", "-f", "-t", str(gcda)], cwd=build, timeout=60,
        )
        cmd, kwargs = calls[0]
        assert kwargs["stdout"] == sp.PIPE
        assert kwargs["block_network"] is True
        assert len(proc.stdout) == _MAX_CAPTURE_BYTES

    def test_sandbox_setup_error_fails_loud(self, tmp_path):
        from core.sandbox import SandboxSetupError

        def runner(cmd, **kw):
            raise SandboxSetupError("isolation unavailable")

        inp = tmp_path / "in0"
        inp.write_bytes(b"A")
        with pytest.raises(SandboxSetupError):
            replay_corpus(tmp_path / "bin", [inp], runner=runner)

        gcda = tmp_path / "b" / "x.gcda"
        gcda.parent.mkdir()
        gcda.write_bytes(b"z")
        with pytest.raises(SandboxSetupError):
            collect_gcov_function_coverage(tmp_path / "b", runner=runner)
