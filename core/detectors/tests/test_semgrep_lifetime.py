"""Returned detector outcomes do not retain execution reports or input owners."""

import gc
import weakref
from contextlib import contextmanager, nullcontext

import pytest

from core.detectors import semgrep
from packages.semgrep.models import SemgrepFinding, SemgrepResult


class Owner:
    """Weak-reference sentinel for an expanded-view or callback owner."""


@pytest.mark.parametrize("mode", ["complete", "partial", "error", "skipped", "invocation-error"])
def test_returned_outcome_releases_report_and_callback_owners(tmp_path, monkeypatch, mode):
    references = []
    events = []
    source = tmp_path / "expanded.c"
    source.write_text("void f(void) {}\n")

    def owner():
        value = Owner()
        references.append(weakref.ref(value))
        return value

    def preparation_factory():
        preparation_owner = owner()

        @contextmanager
        def prepare():
            assert preparation_owner is not None
            if mode == "skipped":
                raise semgrep.PreparationUnavailable("no expanded view")
            analysis_owner = owner()

            def analyze(findings):
                assert analysis_owner is not None
                events.append("analyze")
                return [{"line": finding.line} for finding in findings], 2

            try:
                yield semgrep.PreparedInput(source, analyze)
            finally:
                events.append("cleanup")
        return prepare

    def environment_factory():
        environment_owner = owner()

        def environment():
            assert environment_owner is not None
            return {"FIXTURE": "1"}
        return environment

    def match(*args, **kwargs):
        if mode == "invocation-error":
            raise OSError("tool unavailable")
        result = SemgrepResult(
            findings=[] if mode == "error" else [SemgrepFinding(str(source), 7)],
            errors=["tool diagnostic"] if mode in ("error", "partial") else [],
            sarif="raw report", json_output="raw metadata",
        )
        references.append(weakref.ref(result))
        return result

    monkeypatch.setattr("packages.semgrep.runner.run_rule", match)
    result = semgrep.run_semgrep_analysis(
        detector=semgrep.define_semgrep_detector("lifetime", "1"),
        prepare=preparation_factory(), env_factory=environment_factory(),
        rule_config="rules.yml", timeout=5,
    )
    assert result.status == ("error" if mode == "invocation-error" else mode)
    assert result.value.matches == ([{"line": 7}] if mode in ("complete", "partial") else [])
    assert result.value.errors == (["tool diagnostic"] if mode in ("partial", "error") else [])
    assert result.value.dropped == (2 if mode in ("complete", "partial") else 0)
    if mode == "invocation-error":
        assert result.value.invocation_error == "tool unavailable"
    assert events == (["analyze", "cleanup"] if mode in ("complete", "partial")
                      else [] if mode == "skipped" else ["cleanup"])
    gc.collect()
    assert references and all(reference() is None for reference in references)
    assert result.value._raw is result.value._input is None
    assert result.value.prepare is result.value.env_factory is None


@pytest.mark.parametrize("failure", ["analysis", "cleanup"])
def test_execution_references_are_released_when_exceptions_propagate(tmp_path, monkeypatch, failure):
    states = []
    original = semgrep.run_detector

    def record(definition, state):
        states.append(state)
        return original(definition, state)

    def analyze(findings):
        if failure == "analysis":
            raise ValueError("analysis failed")
        return [], 0

    @contextmanager
    def prepare():
        try:
            yield semgrep.PreparedInput(tmp_path, analyze)
        finally:
            if failure == "cleanup":
                raise ValueError("cleanup failed")

    monkeypatch.setattr(semgrep, "run_detector", record)
    monkeypatch.setattr("packages.semgrep.runner.run_rule", lambda *a, **k: SemgrepResult())
    with pytest.raises(ValueError, match=f"{failure} failed"):
        semgrep.run_semgrep_analysis(
            detector=semgrep.define_semgrep_detector("lifetime", "1"),
            prepare=prepare, rule_config="rules.yml", timeout=5,
        )
    assert len(states) == 1
    assert states[0]._raw is states[0]._input is None
    assert states[0].prepare is states[0].env_factory is None


def test_releasing_one_execution_does_not_close_borrowed_input(tmp_path, monkeypatch):
    source = tmp_path / "shared.c"
    source.write_text("void f(void) {}\n")
    calls = []

    def analyze(findings):
        assert source.exists()
        calls.append(findings)
        return [{"line": findings[0].line}], 0

    prepared = semgrep.PreparedInput(source, analyze)
    monkeypatch.setattr("packages.semgrep.runner.run_rule", lambda *a, **k:
                        SemgrepResult(findings=[SemgrepFinding(str(source), 3)]))
    results = [semgrep.run_semgrep_analysis(
        detector=semgrep.define_semgrep_detector("borrowed", "1"),
        prepare=lambda: nullcontext(prepared), rule_config="rules.yml", timeout=5,
    ) for _ in range(2)]
    assert len(calls) == 2 and source.exists()
    assert all(result.status == "complete" and result.value.matches == [{"line": 3}]
               for result in results)
    assert prepared.analyze is analyze
