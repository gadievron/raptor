"""Tests for real cross-model panel dispatch in /audit.

Two stacked defects previously made ``--model A --model B`` inert:

1. The only ``_multi_pass_review`` call site was gated on
   ``config.review_passes > 1``, so a multi-model run with the default
   single review pass never reached the multi-model branch.
2. Inside the branch, ``adapted_review_fn(context, model_name)``
   ignored ``model_name`` and called the single ``review_fn`` closure
   pinned to ``models[0]`` — model B was never invoked at all.

These tests pin the fix: N configured models → N independent reviews
per function, each through its own per-model review_fn, merged by the
existing ensemble merge. All LLM interaction is stubbed.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

import pytest

from core.audit.orchestrator import (
    OrchestratorConfig,
    ReviewOutcome,
    _ClientBudgetGate,
    _multi_pass_review,
    run_orchestrator,
)


def _outcome(status: str, model: str, body: str = "reviewed") -> ReviewOutcome:
    return ReviewOutcome(
        file="a.c", function="f", status=status, body=body,
        hypothesis="h", cost_usd=0.01, model=model, duration_s=1.0,
    )


def _make_recording_fn(model: str, status: str, calls: dict):
    lock = threading.Lock()

    def review_fn(ctx, cfg):
        with lock:
            calls[model] = calls.get(model, 0) + 1
        return ReviewOutcome(
            file=ctx.get("file", "a.c"),
            function=ctx.get("function", "f"),
            status=status,
            body=f"reviewed by {model}",
            hypothesis="h",
            cost_usd=0.01,
            model=model,
            duration_s=1.0,
        )

    return review_fn


class TestPerModelReviewFnDispatch:
    """Each configured model's review_fn must be called exactly once."""

    def test_each_model_review_fn_called_once(self, tmp_path: Path):
        calls: dict = {}
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            models=["model-a", "model-b"], multi_model=True,
            review_fns_by_model={
                "model-a": _make_recording_fn("model-a", "clean", calls),
                "model-b": _make_recording_fn("model-b", "finding", calls),
            },
        )

        def default_fn(ctx, cfg):
            calls["default"] = calls.get("default", 0) + 1
            return _outcome("clean", "default")

        ctx = {"file": "a.c", "function": "f", "line_start": 1}
        outcome = _multi_pass_review(default_fn, ctx, config, passes=1)

        assert calls.get("model-a") == 1
        assert calls.get("model-b") == 1
        assert "default" not in calls, (
            "panel members must dispatch through their own review_fn, "
            "not the models[0]-pinned default"
        )
        # prefer-positive merge keeps the finding
        assert outcome.status == "finding"

    def test_merge_sums_cost_across_models(self, tmp_path: Path):
        calls: dict = {}
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            models=["model-a", "model-b"], multi_model=True,
            review_fns_by_model={
                "model-a": _make_recording_fn("model-a", "clean", calls),
                "model-b": _make_recording_fn("model-b", "clean", calls),
            },
        )

        ctx = {"file": "a.c", "function": "f", "line_start": 1}
        outcome = _multi_pass_review(
            lambda c, cfg: _outcome("clean", "default"), ctx, config, passes=1,
        )
        assert outcome.cost_usd == pytest.approx(0.02)

    def test_missing_map_falls_back_to_single_review_fn(self, tmp_path: Path):
        """Consumers that never built the per-model map keep working."""
        n_calls = [0]

        def review_fn(ctx, cfg):
            n_calls[0] += 1
            return _outcome("clean", "default")

        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            models=["model-a", "model-b"], multi_model=True,
        )
        ctx = {"file": "a.c", "function": "f", "line_start": 1}
        outcome = _multi_pass_review(review_fn, ctx, config, passes=1)
        assert n_calls[0] == 2  # still one review per panel member
        assert outcome.status == "clean"


@pytest.mark.slow
class TestOrchestratorPanelEntry:
    """The review loop must enter the multi-model branch with the
    default single review pass — gating on review_passes > 1 alone
    made ``--model A --model B`` provably inert."""

    def _setup_target(self, tmp_path: Path):
        target = tmp_path / "target"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "auth.c").write_text(
            "int check_pw(char *pw, int len) {\n"
            "  char buf[256];\n"
            "  memcpy(buf, pw, len);\n"
            "  return 0;\n"
            "}\n"
        )
        out = tmp_path / "out"
        out.mkdir()
        checklist = {
            "files": [
                {
                    "path": "src/auth.c",
                    "items": [
                        {"name": "check_pw", "line_start": 1, "line_end": 5},
                    ],
                },
            ],
        }
        (out / "checklist.json").write_text(json.dumps(checklist))
        return target, out

    def test_both_models_reviewed_with_single_pass(self, tmp_path: Path):
        target, out = self._setup_target(tmp_path)
        calls: dict = {}
        config = OrchestratorConfig(
            target_path=target, out_dir=out, resume=False,
            models=["model-a", "model-b"], multi_model=True,
            review_passes=1,
            review_fns_by_model={
                "model-a": _make_recording_fn("model-a", "clean", calls),
                "model-b": _make_recording_fn("model-b", "clean", calls),
            },
        )

        def default_fn(ctx, cfg):
            calls["default"] = calls.get("default", 0) + 1
            return ReviewOutcome(
                file=ctx.get("file", ""), function=ctx.get("function", ""),
                status="clean", body="reviewed", model="default",
            )

        result = run_orchestrator(config, default_fn)
        assert result.reviewed == 1
        assert calls.get("model-a", 0) >= 1, "model A never reviewed"
        assert calls.get("model-b", 0) >= 1, "model B never reviewed"


class TestClientBudgetGate:
    def test_no_cap_returns_zero(self):
        class _Cfg:
            max_cost_per_scan = float("inf")

        class _Client:
            config = _Cfg()
            total_cost = 5.0

        assert _ClientBudgetGate(_Client()).budget_ratio() == 0.0

    def test_ratio_of_spend_to_cap(self):
        class _Cfg:
            max_cost_per_scan = 10.0

        class _Client:
            config = _Cfg()
            total_cost = 2.5

        assert _ClientBudgetGate(_Client()).budget_ratio() == pytest.approx(0.25)

    def test_missing_fields_return_zero(self):
        class _Client:
            pass

        assert _ClientBudgetGate(_Client()).budget_ratio() == 0.0


class TestPipelineBuildsPerModelReviewFns:
    """run_audit_pipeline must build one review_fn per configured model."""

    def test_map_built_for_multi_model(self, tmp_path: Path, monkeypatch):
        from core.audit import pipeline as pl

        captured: dict = {}

        def fake_make_review_fn(client, **kwargs):
            def _fn(ctx, cfg):
                return _outcome("clean", kwargs.get("model_name") or "default")
            _fn._model_name = kwargs.get("model_name")
            return _fn

        def fake_run_orchestrator(config, review_fn, **kwargs):
            captured["config"] = config
            return object()

        monkeypatch.setattr(
            "core.audit.llm_review.make_review_fn", fake_make_review_fn,
        )
        monkeypatch.setattr(
            "core.audit.orchestrator.run_orchestrator", fake_run_orchestrator,
        )

        class _FakeClientCfg:
            max_cost_per_scan = 10.0

        class _FakeClient:
            config = _FakeClientCfg()
            total_cost = 0.0

        monkeypatch.setattr(
            pl, "_make_llm_client",
            lambda opts: (_FakeClient(), ["model-a", "model-b"], "model-a"),
        )

        opts = pl.AuditPipelineOpts(
            target_path=tmp_path, out_dir=tmp_path,
            models=["model-a", "model-b"],
        )
        pl.run_audit_pipeline(opts)

        config = captured["config"]
        assert config.multi_model is True
        assert config.review_fns_by_model is not None
        assert set(config.review_fns_by_model) == {"model-a", "model-b"}
        assert config.review_fns_by_model["model-a"]._model_name == "model-a"
        assert config.review_fns_by_model["model-b"]._model_name == "model-b"
