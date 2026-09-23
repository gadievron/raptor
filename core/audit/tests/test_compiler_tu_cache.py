"""Tests for the per-TU analysis cache in run_compiler_analyzer_sweep.

One full-TU analyzer run emits every diagnostic for the translation
unit; per-hypothesis dispatch only differs in the post-run filtering.
These tests stub the sandbox boundary (no real compiler needed) and
assert the cache contract: identical (invocation, TU content) pairs
compile once, any input change compiles again, and the per-hypothesis
family/range/attribution filtering is untouched by cache hits.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.audit import compiler_sweep
from core.audit.compiler_sweep import run_compiler_analyzer_sweep

FAKE_GCC = "/nonexistent/fake-gcc"


@pytest.fixture(autouse=True)
def _fresh_caches():
    compiler_sweep._reset_probe_cache()
    compiler_sweep._reset_tu_cache()
    yield
    compiler_sweep._reset_probe_cache()
    compiler_sweep._reset_tu_cache()


@pytest.fixture(autouse=True)
def _fake_gcc(monkeypatch):
    """Pretend a gcc with JSON diagnostics is installed; no clang."""
    monkeypatch.setattr(
        compiler_sweep, "_gcc_analyzer", lambda: (FAKE_GCC, "json"),
    )
    monkeypatch.setattr(compiler_sweep, "_clang_path", lambda: None)


def _gcc_json_diag(option: str, line: int, file: str, message: str,
                   kind: str = "warning") -> dict:
    return {
        "option": option,
        "kind": kind,
        "message": message,
        "locations": [{"caret": {"line": line, "file": file}}],
    }


@pytest.fixture
def sandbox_stub(monkeypatch):
    """Replace the sandbox with a canned-diagnostics recorder."""
    state = {
        "calls": [],
        "returncode": 0,
        "diags": [],
        "raises": None,
    }

    def fake_sandbox_run(cmd, **kwargs):
        state["calls"].append(list(cmd))
        if state["raises"] is not None:
            raise state["raises"]
        return SimpleNamespace(
            returncode=state["returncode"],
            stdout="",
            stderr=json.dumps(state["diags"]),
        )

    monkeypatch.setattr("core.sandbox.context.run", fake_sandbox_run)
    return state


def _analysis_calls(state: dict) -> list[list[str]]:
    """Analyzer compiles only: the reliable-refutation path adds a
    preprocessor (``-E``) closure-vet invocation with its own cache
    row — the compile-cache contract is asserted over the compiles."""
    return [c for c in state["calls"] if "-E" not in c]


def _pp_calls(state: dict) -> list[list[str]]:
    return [c for c in state["calls"] if "-E" in c]


def _target(tmp_path: Path, source: str) -> Path:
    target = tmp_path / "repo"
    target.mkdir(exist_ok=True)
    (target / "tu.c").write_text(source, encoding="utf-8")
    return target


_UAF_SOURCE = (
    "#include <stdlib.h>\n"
    "void f(void) {\n"
    "    char *p = malloc(4);\n"
    "    free(p);\n"
    "    p[0] = 1;\n"
    "}\n"
    "void g(char *q) {\n"
    "    *q = 2;\n"
    "}\n"
)


def _sweep(target: Path, *, cwe: str = "CWE-416", function: str = "f",
           hypothesis: str = "use of `p` after free",
           line_start: int = 2, line_end: int = 6):
    return run_compiler_analyzer_sweep(
        target_path=target,
        file_path="tu.c",
        function_name=function,
        hypothesis=hypothesis,
        cwe=cwe,
        line_start=line_start,
        line_end=line_end,
    )


class TestCacheHit:
    def test_second_hypothesis_same_tu_skips_compile(
        self, tmp_path: Path, sandbox_stub,
    ):
        target = _target(tmp_path, _UAF_SOURCE)
        sandbox_stub["diags"] = [
            _gcc_json_diag("-Wanalyzer-use-after-free", 5, "tu.c",
                           "use after 'free' of 'p'"),
        ]

        first = _sweep(target)
        second = _sweep(
            target, function="g", hypothesis="write through `q`",
            line_start=7, line_end=9,
        )
        assert len(_analysis_calls(sandbox_stub)) == 1
        assert first.outcome == "confirmed"
        # Same cached diagnostics, different window: no in-range
        # family diagnostic for g → not a confirmation.
        assert second.outcome != "confirmed"

    def test_families_sharing_a_flag_set_share_the_compile(
        self, tmp_path: Path, sandbox_stub,
    ):
        # CWE-416 and CWE-476 both add no extra gcc flags — identical
        # invocation, one compile; filtering stays per-family.
        target = _target(tmp_path, _UAF_SOURCE)
        sandbox_stub["diags"] = [
            _gcc_json_diag("-Wanalyzer-use-after-free", 5, "tu.c",
                           "use after 'free' of 'p'"),
        ]

        uaf = _sweep(target, cwe="CWE-416")
        null = _sweep(
            target, cwe="CWE-476",
            hypothesis="null dereference of `p`",
        )
        assert len(_analysis_calls(sandbox_stub)) == 1
        assert uaf.outcome == "confirmed"
        assert null.outcome != "confirmed"  # no CWE-476-family diagnostic

    def test_failed_compile_is_cached(self, tmp_path: Path, sandbox_stub):
        target = _target(tmp_path, _UAF_SOURCE)
        sandbox_stub["returncode"] = 1
        sandbox_stub["diags"] = [
            _gcc_json_diag("", 1, "tu.c", "missing_header.h: not found",
                           kind="error"),
        ]

        first = _sweep(target)
        second = _sweep(target, function="g", line_start=7, line_end=9)
        assert len(sandbox_stub["calls"]) == 1
        assert first.outcome == "inconclusive"
        assert second.outcome == "inconclusive"


class TestCacheMiss:
    def test_tu_content_change_recompiles(self, tmp_path: Path, sandbox_stub):
        target = _target(tmp_path, _UAF_SOURCE)
        _sweep(target)
        (target / "tu.c").write_text(
            _UAF_SOURCE + "\nvoid h(void) {}\n", encoding="utf-8",
        )
        _sweep(target)
        assert len(_analysis_calls(sandbox_stub)) == 2

    def test_flag_family_change_recompiles(self, tmp_path: Path, sandbox_stub):
        # CWE-134 adds -Wformat flags → different invocation.
        target = _target(tmp_path, _UAF_SOURCE)
        _sweep(target, cwe="CWE-416")
        _sweep(
            target, cwe="CWE-134",
            hypothesis="format string via `p`",
        )
        calls = _analysis_calls(sandbox_stub)
        assert len(calls) == 2
        assert calls[0] != calls[1]


class TestErrorSemantics:
    def test_timeout_is_not_cached(self, tmp_path: Path, sandbox_stub):
        target = _target(tmp_path, _UAF_SOURCE)
        sandbox_stub["raises"] = subprocess.TimeoutExpired("gcc", 120)

        first = _sweep(target)
        assert first.outcome == "error"

        sandbox_stub["raises"] = None
        sandbox_stub["diags"] = [
            _gcc_json_diag("-Wanalyzer-use-after-free", 5, "tu.c",
                           "use after 'free' of 'p'"),
        ]
        second = _sweep(target)
        assert second.outcome == "confirmed"
        assert len(sandbox_stub["calls"]) == 2

    def test_invocation_failure_is_not_cached(
        self, tmp_path: Path, sandbox_stub,
    ):
        target = _target(tmp_path, _UAF_SOURCE)
        sandbox_stub["raises"] = OSError("exec failed")
        assert _sweep(target).outcome == "error"

        sandbox_stub["raises"] = None
        sandbox_stub["diags"] = []
        assert _sweep(target).outcome in ("refuted", "inconclusive")
        assert len(_analysis_calls(sandbox_stub)) == 2

    def test_signal_killed_compile_is_not_cached(
        self, tmp_path: Path, sandbox_stub,
    ):
        """A signal-killed compile (negative returncode — e.g. the
        OOM killer taking gcc during parallel passes) completes
        sandbox_run WITHOUT an exception. It must behave like a
        timeout: error result, nothing cached — a healthy retry
        compiles again and yields its diagnostics instead of being
        served the dead run for the cache's lifetime."""
        target = _target(tmp_path, _UAF_SOURCE)
        sandbox_stub["returncode"] = -9

        first = _sweep(target)
        assert first.outcome == "error"
        assert "signal" in " ".join(first.errors)
        assert len(sandbox_stub["calls"]) == 1

        sandbox_stub["returncode"] = 0
        sandbox_stub["diags"] = [
            _gcc_json_diag("-Wanalyzer-use-after-free", 5, "tu.c",
                           "use after 'free' of 'p'"),
        ]
        second = _sweep(target)
        assert len(sandbox_stub["calls"]) == 2  # recompiled, not stale
        assert second.outcome == "confirmed"


class TestCacheLifetime:
    def test_caller_supplied_caches_are_used(
        self, tmp_path: Path, sandbox_stub,
    ):
        """The orchestrator hands per-RUN caches through the kwargs;
        entries must land there, hit there, and never leak into the
        module-level default instances."""
        from core.audit.run_memo import BoundedMemo

        target = _target(tmp_path, _UAF_SOURCE)
        tu = BoundedMemo(4)
        inc = BoundedMemo(4)

        def sweep():
            return run_compiler_analyzer_sweep(
                target_path=target,
                file_path="tu.c",
                function_name="f",
                hypothesis="use of `p` after free",
                cwe="CWE-416",
                line_start=2,
                line_end=6,
                tu_cache=tu,
                include_dirs_memo=inc,
            )

        sweep()
        sweep()
        # No diagnostics stubbed → the reliable family refutes, so a
        # closure-vet preprocessor run joins the compile; each caches
        # once in the CALLER's memo (one compile row + one -E row).
        assert len(_analysis_calls(sandbox_stub)) == 1
        assert len(_pp_calls(sandbox_stub)) == 1
        assert len(tu) == 2
        assert len(inc) == 1
        assert len(compiler_sweep._tu_cache) == 0
        assert len(compiler_sweep._include_dirs_memo) == 0

    def test_documented_cap_value_is_pinned(self):
        """Value pin (churn-prone-limits doctrine): the binding
        assertions below follow the constant, so mutating it would
        move both sides and stay green — the pin makes a cap change a
        deliberate, test-visible act. Both directions of the trade:
        raising it holds more retained diagnostic lists plus capped
        stderr blobs (~20 KB each) for the cache's lifetime; lowering
        it re-pays full analyzer compiles (10-120s each) as soon as a
        hypothesis batch spans more (TU, flag-family) combinations
        than fit.
        """
        assert compiler_sweep._TU_CACHE_MAX_ENTRIES == 64

    def test_module_caches_bind_to_the_documented_cap(self):
        assert (
            compiler_sweep._tu_cache._max_entries
            == compiler_sweep._TU_CACHE_MAX_ENTRIES
        )
        assert (
            compiler_sweep._include_dirs_memo._max_entries
            == compiler_sweep._TU_CACHE_MAX_ENTRIES
        )

    def test_run_config_caches_bind_to_the_same_cap_per_run(self):
        """OrchestratorConfig default_factory: fresh instances per
        run, sized by the sweep layer's cap constants."""
        from core.audit.orchestrator import OrchestratorConfig

        a = OrchestratorConfig(target_path=Path("/x"), out_dir=Path("/x"))
        b = OrchestratorConfig(target_path=Path("/x"), out_dir=Path("/x"))
        assert (
            a.tu_cache._max_entries
            == compiler_sweep._TU_CACHE_MAX_ENTRIES
        )
        assert (
            a.include_dirs_memo._max_entries
            == compiler_sweep._TU_CACHE_MAX_ENTRIES
        )
        assert a.tu_cache is not b.tu_cache
        assert a.include_dirs_memo is not b.include_dirs_memo
        assert a.tu_cache is not a.include_dirs_memo


class TestIncludeDirDerivation:
    def test_walk_runs_once_per_target_and_tu_dir(
        self, tmp_path: Path, sandbox_stub, monkeypatch,
    ):
        target = _target(tmp_path, _UAF_SOURCE)
        (target / "include").mkdir()
        walks: list[tuple] = []
        real_derive = compiler_sweep._derive_include_dirs

        def counting_derive(target_path: Path, file_dir: Path) -> list[str]:
            walks.append((str(target_path), str(file_dir)))
            return real_derive(target_path, file_dir)

        monkeypatch.setattr(
            compiler_sweep, "_derive_include_dirs", counting_derive,
        )

        _sweep(target)
        _sweep(target, function="g", line_start=7, line_end=9)
        assert len(walks) == 1

    def test_include_dirs_still_reach_the_command_line(
        self, tmp_path: Path, sandbox_stub,
    ):
        target = _target(tmp_path, _UAF_SOURCE)
        (target / "include").mkdir()
        _sweep(target)
        cmd = sandbox_stub["calls"][0]
        assert f"-I{target / 'include'}" in cmd
