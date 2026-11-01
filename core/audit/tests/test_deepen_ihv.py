"""Tests for IHV wiring in _deepen_suspicious (Phase 5d).

When ``immediate_verify=True``, the deepen path must route through
``_verify_hypotheses_immediate`` instead of the legacy ``_sweep_validate``.
"""

from __future__ import annotations

import time
from pathlib import Path

import core.audit.orchestrator as _orch
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _deepen_suspicious,
)


def _config(tmp_path: Path, *, immediate_verify: bool = True) -> OrchestratorConfig:
    d = tmp_path / "out"
    d.mkdir(exist_ok=True)
    return OrchestratorConfig(
        out_dir=str(d),
        target_path=str(tmp_path),
        deepen_suspicious=True,
        immediate_verify=immediate_verify,
        sweep_validate_findings=True,
    )


def _checklist():
    return {
        "files": [{
            "path": "a.c",
            "items": [{"name": "foo", "line_start": 1, "line_end": 50}],
        }],
    }


def _suspicious_outcome(*, body="risky", hypothesis="buffer overflow"):
    return ReviewOutcome(
        file="a.c", function="foo", status="suspicious",
        body=body, hypothesis=hypothesis,
        review_result={"status": "suspicious", "body": body},
    )


class TestDeepenIHVWiring:
    def test_ihv_called_on_finding(self, tmp_path, monkeypatch):
        """When deepen produces a finding and immediate_verify=True,
        _verify_hypotheses_immediate is called instead of _sweep_validate."""
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {
                "file": "a.c", "function": "foo",
                "source": "int foo() { return 0; }",
            },
        )

        ihv_calls = []

        def fake_ihv(outcome, config, result, **kw):
            ihv_calls.append(kw)
            return outcome

        monkeypatch.setattr(_orch, "_verify_hypotheses_immediate", fake_ihv)

        sweep_calls = []
        orig_sweep = _orch._sweep_validate

        def spy_sweep(*a, **kw):
            sweep_calls.append(1)
            return orig_sweep(*a, **kw)

        monkeypatch.setattr(_orch, "_sweep_validate", spy_sweep)

        prior = _suspicious_outcome()
        result = OrchestratorResult(outcomes=[prior], suspicious=1)

        def review_fn(ctx, cfg):
            return ReviewOutcome(
                file="a.c", function="foo", status="finding",
                body="confirmed overflow",
                review_result={"status": "finding", "body": "confirmed"},
            )

        _deepen_suspicious(
            result, _config(tmp_path), review_fn, _checklist(),
            None, None, [], None, set(), time.time(), None,
            mechanical_findings={"a.c:foo": [{"rule": "test"}]},
            synthesis_counter=None,
        )

        assert len(ihv_calls) == 1
        assert ihv_calls[0]["mechanical_findings"] == {"a.c:foo": [{"rule": "test"}]}
        assert sweep_calls == [], "sweep_validate must not be called under IHV"

    def test_ihv_called_on_suspicious(self, tmp_path, monkeypatch):
        """IHV also fires for suspicious deepen outcomes (not just findings),
        unlike sweep_validate which only handles findings."""
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {
                "file": "a.c", "function": "foo",
                "source": "int foo() { return 0; }",
            },
        )

        ihv_calls = []

        def fake_ihv(outcome, config, result, **kw):
            ihv_calls.append(outcome.status)
            return outcome

        monkeypatch.setattr(_orch, "_verify_hypotheses_immediate", fake_ihv)

        prior = _suspicious_outcome()
        result = OrchestratorResult(outcomes=[prior], suspicious=1)

        def review_fn(ctx, cfg):
            return ReviewOutcome(
                file="a.c", function="foo", status="suspicious",
                body="still suspicious",
                review_result={"status": "suspicious", "body": "still"},
            )

        _deepen_suspicious(
            result, _config(tmp_path), review_fn, _checklist(),
            None, None, [], None, set(), time.time(), None,
        )

        assert ihv_calls == ["suspicious"]

    def test_legacy_path_when_ihv_off(self, tmp_path, monkeypatch):
        """When immediate_verify=False, deepen uses _sweep_validate as before."""
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {
                "file": "a.c", "function": "foo",
                "source": "int foo() { return 0; }",
            },
        )

        ihv_calls = []

        def fake_ihv(outcome, config, result, **kw):
            ihv_calls.append(1)
            return outcome

        monkeypatch.setattr(_orch, "_verify_hypotheses_immediate", fake_ihv)

        sweep_calls = []

        def fake_sweep(outcome, config, sarif_cache, **kw):
            sweep_calls.append(1)
            return outcome

        monkeypatch.setattr(_orch, "_sweep_validate", fake_sweep)

        prior = _suspicious_outcome()
        result = OrchestratorResult(outcomes=[prior], suspicious=1)

        def review_fn(ctx, cfg):
            return ReviewOutcome(
                file="a.c", function="foo", status="finding",
                body="confirmed",
                review_result={"status": "finding", "body": "confirmed"},
            )

        _deepen_suspicious(
            result, _config(tmp_path, immediate_verify=False), review_fn,
            _checklist(), None, None, [], None, set(), time.time(), None,
        )

        assert sweep_calls == [1]
        assert ihv_calls == [], "IHV must not be called when immediate_verify=False"

    def test_ihv_receives_gap_and_source(self, tmp_path, monkeypatch):
        """IHV receives the gap dict and source from context, matching
        the _re_review_study_enriched wiring."""
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {
                "file": "a.c", "function": "foo",
                "source": "int foo() { memcpy(a, b, n); }",
            },
        )

        captured_kw = {}

        def fake_ihv(outcome, config, result, **kw):
            captured_kw.update(kw)
            return outcome

        monkeypatch.setattr(_orch, "_verify_hypotheses_immediate", fake_ihv)

        prior = _suspicious_outcome()
        result = OrchestratorResult(outcomes=[prior], suspicious=1)

        def review_fn(ctx, cfg):
            return ReviewOutcome(
                file="a.c", function="foo", status="finding",
                body="confirmed",
                review_result={"status": "finding", "body": "confirmed"},
            )

        _deepen_suspicious(
            result, _config(tmp_path), review_fn, _checklist(),
            None, None, [], None, set(), time.time(), None,
        )

        assert captured_kw.get("gap") is not None
        assert captured_kw["gap"]["name"] == "foo"
        assert "source" in captured_kw

    def test_dominated_clean_skips_ihv(self, tmp_path, monkeypatch):
        """When deepen returns a bare clean (dominated), IHV is not called
        because the dominated branch runs before the verification path."""
        monkeypatch.setattr(
            _orch, "_build_context",
            lambda cfg, gap, *a, **kw: {
                "file": "a.c", "function": "foo",
                "source": "int foo() { return 0; }",
            },
        )

        ihv_calls = []

        def fake_ihv(outcome, config, result, **kw):
            ihv_calls.append(1)
            return outcome

        monkeypatch.setattr(_orch, "_verify_hypotheses_immediate", fake_ihv)

        prior = _suspicious_outcome()
        result = OrchestratorResult(outcomes=[prior], suspicious=1)

        def review_fn(ctx, cfg):
            return ReviewOutcome(
                file="a.c", function="foo", status="clean",
                body="actually clean",
                review_result={"status": "clean", "body": "actually clean"},
            )

        _deepen_suspicious(
            result, _config(tmp_path), review_fn, _checklist(),
            None, None, [], None, set(), time.time(), None,
        )

        assert ihv_calls == [], "dominated clean must not reach IHV"
