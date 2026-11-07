"""Preparation, real runner seam, Python analysis and resource lifetime."""
from contextlib import contextmanager
from functools import partial
from types import SimpleNamespace

import pytest

from core.detectors.semgrep import (
    PreparedInput,
    PreparationUnavailable,
    define_semgrep_detector,
    run_semgrep_analysis,
)

run_analysis = partial(
    run_semgrep_analysis, detector=define_semgrep_detector("fixture-analysis", "1"),
)


@pytest.mark.parametrize("errors", [[], ["another file failed"]])
def test_run_once_then_analyze_live_artifact_and_preserve_partial(tmp_path, monkeypatch, errors):
    target = tmp_path / "expanded.c"
    events = []

    def analyze(findings):
        assert target.exists()
        events.append("analyze")
        return [{"line": findings[0]["line"] - 2}], 3

    @contextmanager
    def prepare():
        events.append("prepare")
        target.write_text("void f(void) {}")
        try:
            yield PreparedInput(target, analyze)
        finally:
            events.append("cleanup")
            target.unlink()

    def run(path, config, **kwargs):
        assert path == target and target.exists()
        assert config == "rules.yml"
        assert kwargs == {"timeout": 17, "name": "pack", "env": {"FIXTURE": "1"}}
        events.append("match")
        return SimpleNamespace(findings=[{"line": 9}], errors=errors)

    monkeypatch.setattr("packages.semgrep.runner.run_rule", run)
    result = run_analysis(
        prepare=prepare, rule_config="rules.yml", timeout=17,
        name="pack", env_factory=lambda: {"FIXTURE": "1"},
    )
    assert events == ["prepare", "match", "analyze", "cleanup"]
    assert result.value.matches == [{"line": 7}]
    assert result.value.dropped == 3
    assert result.status == ("partial" if errors else "complete")
    assert result.value.errors == errors
    assert not target.exists()


@pytest.mark.parametrize("failure", ["exception", "errors"])
def test_engine_failure_skips_analyzer_and_cleans_up(tmp_path, monkeypatch, failure):
    target = tmp_path / "expanded.c"

    def analyze(findings):
        pytest.fail("analyzer saw a failed engine result")

    @contextmanager
    def prepare():
        target.touch()
        try:
            yield PreparedInput(target, analyze)
        finally:
            target.unlink()

    def run(path, config, **kwargs):
        assert kwargs == {"timeout": 5}
        if failure == "exception":
            raise RuntimeError("tool crashed")
        return SimpleNamespace(findings=[], errors=["tool crashed"])

    monkeypatch.setattr("packages.semgrep.runner.run_rule", run)
    result = run_analysis(prepare=prepare, rule_config="x", timeout=5)
    assert result.status == "error"
    assert [record.name for record in result.stages] == ["prepare", "match"]
    assert not target.exists()


def test_preparation_refusal_does_not_invoke_engine(monkeypatch):
    @contextmanager
    def prepare():
        raise PreparationUnavailable("expansion budget exhausted")
        yield  # pragma: no cover — generator contextmanager

    def forbidden(*args, **kwargs):
        pytest.fail("engine ran after preparation refusal")

    monkeypatch.setattr("packages.semgrep.runner.run_rule", forbidden)
    result = run_analysis(prepare=prepare, rule_config="x", timeout=5)
    assert result.status == "skipped"
    assert result.reason == "expansion budget exhausted"
    assert len(result.stages) == 1


def test_empty_match_set_still_reaches_python_analysis(tmp_path, monkeypatch):
    observed = []

    @contextmanager
    def prepare():
        yield PreparedInput(tmp_path, lambda findings: (observed.append(findings) or [], 0))

    monkeypatch.setattr("packages.semgrep.runner.run_rule", lambda *a, **k: SimpleNamespace(findings=[], errors=[]))
    result = run_analysis(prepare=prepare, rule_config="x", timeout=5)
    assert result.status == "complete"
    assert observed == [[]]


def test_analysis_exception_propagates_after_cleanup(tmp_path, monkeypatch):
    target = tmp_path / "expanded.c"

    def analyze(findings):
        raise ValueError("broken line map")

    @contextmanager
    def prepare():
        target.touch()
        try:
            yield PreparedInput(target, analyze)
        finally:
            target.unlink()

    monkeypatch.setattr("packages.semgrep.runner.run_rule", lambda *a, **k: SimpleNamespace(findings=[], errors=[]))
    with pytest.raises(ValueError, match="line map"):
        run_analysis(prepare=prepare, rule_config="x", timeout=5)
    assert not target.exists()


def test_engine_failure_result_does_not_keep_traceback_artifacts_alive(tmp_path, monkeypatch):
    import gc
    import weakref

    class Payload:
        pass

    references = []

    @contextmanager
    def prepare():
        yield PreparedInput(tmp_path, lambda findings: ([], 0))

    def fail(*args, **kwargs):
        payload = Payload()
        references.append(weakref.ref(payload))
        raise RuntimeError("tool crashed")

    monkeypatch.setattr("packages.semgrep.runner.run_rule", fail)
    result = run_analysis(prepare=prepare, rule_config="x", timeout=5)
    assert result.status == "error"
    assert result.value.invocation_error == "tool crashed"
    # Released sentinels are acyclic; do not scan unrelated old worker objects.
    gc.collect(0)
    assert references[0]() is None


def test_explicit_targets_and_project_scope_are_forwarded(tmp_path, monkeypatch):
    calls = []
    first, second = tmp_path / "a.c", tmp_path / "sub/b.c"

    @contextmanager
    def prepare():
        yield PreparedInput(first, lambda findings: ([], 0), extra_targets=(second,), target_root=tmp_path)

    def run(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(findings=[], errors=[])

    monkeypatch.setattr("packages.semgrep.runner.run_rule", run)
    result = run_analysis(prepare=prepare, rule_config="x", timeout=7)
    assert result.status == "complete"
    assert calls == [((first, "x"), {"timeout": 7, "extra_targets": (second,), "target_root": tmp_path})]


@pytest.mark.parametrize("coverage", [
    {"files_failed": [{"path": "bad.c", "reason": "parse error"}]},
    {"skipped_summary": {"total": 1}},
    {"skipped_rules": ["requires a newer Semgrep"]},
])
@pytest.mark.parametrize("findings", [[], [{"line": 9}]])
def test_incomplete_coverage_preserves_analysis_without_claiming_complete(tmp_path, monkeypatch, coverage, findings):
    observed = []

    @contextmanager
    def prepare():
        yield PreparedInput(tmp_path, lambda rows: (observed.extend(rows) or rows, 0))

    monkeypatch.setattr("packages.semgrep.runner.run_rule", lambda *a, **k: SimpleNamespace(
        findings=findings, errors=[], **coverage,
    ))
    result = run_analysis(prepare=prepare, rule_config="x", timeout=5)
    assert result.status == "partial"
    assert result.value.coverage_incomplete
    assert result.value.matches == observed == findings
    assert [stage.name for stage in result.stages] == ["prepare", "match", "analyze"]
