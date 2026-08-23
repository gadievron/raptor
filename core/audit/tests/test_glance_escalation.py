"""Tests for glance-suspicious escalation to full individual review.

A batch-glance "suspicious" used to commit directly with
evidence_tool="triage:batch"; now it queues a full review. No LLM
calls — the batch review fn and the individual review fn are stubs."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from core.audit.triage import TOKEN_BUDGETS, TriageBucket, TriageResult


def _task(file="a.c", name="f", line=1):
    return SimpleNamespace(
        key=f"{file}:{name}:{line}",
        gap={"file": file, "name": name, "line_start": line},
    )


def _shared(task):
    return SimpleNamespace(
        checklist={},
        context_map={},
        evidence_index={},
        domain_model=None,
        triage_results={
            task.key: TriageResult(
                bucket=TriageBucket.GLANCE,
                reasons=("small helper",),
                token_budget=TOKEN_BUDGETS[TriageBucket.GLANCE],
            ),
        },
    )


def _config(tmp_path):
    from core.audit.orchestrator import OrchestratorConfig
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(target_path=tmp_path, out_dir=out)


def _result():
    from core.audit.orchestrator import OrchestratorResult
    return OrchestratorResult()


def _glance_outcome(status, file="a.c", function="f", cost=0.01):
    from core.audit.orchestrator import ReviewOutcome
    return ReviewOutcome(
        file=file, function=function, status=status,
        body="glance verdict", evidence_tool="triage:batch",
        cost_usd=cost,
    )


@pytest.fixture
def env(monkeypatch):
    """Stub the orchestrator pieces _process_glance_batch imports."""
    commits = []
    monkeypatch.setattr(
        "core.audit.orchestrator._build_context",
        lambda config, gap, checklist, context_map, evidence_index: {
            "file": gap["file"], "function": gap["name"],
        },
    )
    monkeypatch.setattr(
        "core.audit.orchestrator._commit_outcome",
        lambda config, outcome, gap, **kw: commits.append(outcome),
    )
    monkeypatch.setattr(
        "core.audit.refutation.refute_hypothesis",
        lambda *a, **kw: None,
    )
    return commits


def _run_batch(tasks, outcomes, shared, config, result, review_calls):
    from core.audit.executor import _process_glance_batch

    def review_one_fn(gap, shared_, config_, review_fn_, result_, **kw):
        review_calls.append(gap)

    _process_glance_batch(
        tasks,
        lambda contexts, config_: outcomes,
        shared, config, result,
        review_one_fn,
        review_fn=lambda *a, **kw: None,
    )


class TestGlanceEscalation:
    def test_suspicious_escalates_to_full_review(self, tmp_path, env):
        task = _task()
        shared = _shared(task)
        result = _result()
        review_calls: list = []

        _run_batch(
            [task], [_glance_outcome("suspicious")],
            shared, _config(tmp_path), result, review_calls,
        )

        # Full individual review ran; the glance guess did not commit.
        assert review_calls == [task.gap]
        assert env == []
        assert result.glance_escalated == 1
        # The guess is not tallied as a verdict...
        assert result.suspicious == 0
        assert result.reviewed == 0
        # ...but its LLM spend stays on the ledger.
        assert abs(result.total_cost_usd - 0.01) < 1e-9
        # The re-review gets a full context budget and bypasses
        # batching/triage-skip.
        assert task.gap["force_review"] is True
        upgraded = shared.triage_results[task.key]
        assert upgraded.bucket == TriageBucket.INVESTIGATE
        assert upgraded.token_budget == TOKEN_BUDGETS[TriageBucket.INVESTIGATE]
        assert any("escalated" in r for r in upgraded.reasons)

    def test_cap_reached_commits_glance_outcome(self, tmp_path, env):
        from core.audit.executor import _MAX_GLANCE_ESCALATIONS_PER_RUN

        task = _task()
        shared = _shared(task)
        result = _result()
        result.glance_escalated = _MAX_GLANCE_ESCALATIONS_PER_RUN
        review_calls: list = []

        _run_batch(
            [task], [_glance_outcome("suspicious")],
            shared, _config(tmp_path), result, review_calls,
        )

        # Past the cap: the old short-circuit applies — nothing lost.
        assert review_calls == []
        assert len(env) == 1
        assert result.suspicious == 1
        assert result.glance_escalated == _MAX_GLANCE_ESCALATIONS_PER_RUN
        assert shared.triage_results[task.key].bucket == TriageBucket.GLANCE

    def test_clean_glance_commits_without_escalation(self, tmp_path, env):
        task = _task()
        shared = _shared(task)
        result = _result()
        review_calls: list = []

        _run_batch(
            [task], [_glance_outcome("clean")],
            shared, _config(tmp_path), result, review_calls,
        )

        assert review_calls == []
        assert len(env) == 1
        assert result.clean == 1
        assert result.glance_escalated == 0
        assert "force_review" not in task.gap

    def test_budget_error_from_escalated_review_propagates(
        self, tmp_path, env,
    ):
        from core.audit.executor import _process_glance_batch

        task = _task()
        shared = _shared(task)
        result = _result()

        def raising_review_one_fn(gap, *a, **kw):
            raise RuntimeError("LLM budget exceeded — stopping run")

        with pytest.raises(RuntimeError):
            _process_glance_batch(
                [task],
                lambda contexts, config_: [_glance_outcome("suspicious")],
                shared, _config(tmp_path), result,
                raising_review_one_fn,
                review_fn=lambda *a, **kw: None,
            )


class TestEscalateHelper:
    def test_counts_against_shared_cap(self, tmp_path):
        from core.audit.executor import _escalate_glance_suspicious

        t1, t2 = _task(name="f1"), _task(name="f2")
        shared = _shared(t1)
        shared.triage_results[t2.key] = shared.triage_results[t1.key]
        result = _result()

        assert _escalate_glance_suspicious(t1, shared, result) is True
        assert _escalate_glance_suspicious(t2, shared, result) is True
        assert result.glance_escalated == 2

    def test_missing_triage_record_still_escalates(self, tmp_path):
        from core.audit.executor import _escalate_glance_suspicious

        task = _task()
        shared = SimpleNamespace(triage_results={})
        result = _result()

        assert _escalate_glance_suspicious(task, shared, result) is True
        assert task.gap["force_review"] is True
        upgraded = shared.triage_results[task.key]
        assert upgraded.bucket == TriageBucket.INVESTIGATE
