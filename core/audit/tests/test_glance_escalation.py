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
        from core.audit.executor import _GLANCE_ESCALATION_FLOOR

        task = _task()
        shared = _shared(task)
        result = _result()
        result.glance_escalated = _GLANCE_ESCALATION_FLOOR
        review_calls: list = []

        _run_batch(
            [task], [_glance_outcome("suspicious")],
            shared, _config(tmp_path), result, review_calls,
        )

        # Past the cap: the old short-circuit applies — nothing lost.
        assert review_calls == []
        assert len(env) == 1
        assert result.suspicious == 1
        assert result.glance_escalated == _GLANCE_ESCALATION_FLOOR
        assert shared.triage_results[task.key].bucket == TriageBucket.GLANCE
        # ...but never silently: the run counter and the per-function
        # suppressions.jsonl record disclose the depth downgrade.
        assert result.glance_escalation_capped == 1

    def test_cap_exhaustion_discloses_per_function(
        self, tmp_path, env, caplog,
    ):
        import json
        import logging

        from core.audit.executor import _GLANCE_ESCALATION_FLOOR

        t1, t2 = _task(name="f1"), _task(name="f2")
        shared = _shared(t1)
        shared.triage_results[t2.key] = shared.triage_results[t1.key]
        result = _result()
        result.glance_escalated = _GLANCE_ESCALATION_FLOOR
        config = _config(tmp_path)
        review_calls: list = []

        with caplog.at_level(logging.WARNING, logger="core.audit.executor"):
            _run_batch(
                [t1, t2],
                [_glance_outcome("suspicious", function="f1"),
                 _glance_outcome("suspicious", function="f2")],
                shared, config, result, review_calls,
            )

        # Both glance verdicts committed; both denials counted.
        assert result.glance_escalation_capped == 2
        # The exhaustion warning fires ONCE, not per function.
        hits = [r for r in caplog.records
                if "glance escalation cap exhausted" in r.getMessage()]
        assert len(hits) == 1
        # Per-function suppressions.jsonl records (dropped=false).
        recs = [
            json.loads(line) for line in
            (config.out_dir / "suppressions.jsonl")
            .read_text().splitlines() if line.strip()
        ]
        capped = [r for r in recs
                  if r.get("verdict") == "glance_escalation_capped"]
        assert {r["function"] for r in capped} == {"f1", "f2"}
        assert all(r["dropped"] is False for r in capped)
        assert all(
            r["rule_id"] == "audit:glance-escalation-cap" for r in capped
        )

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


class TestGlanceReviewFailureOutcomes:
    """Non-budget failures in the escalation / fallback reviews must
    commit an ``error`` outcome (a still-a-gap status): the caller
    marks the task complete regardless, so a swallowed failure left
    the function counted reviewed with no journal row anywhere."""

    def test_escalation_failure_commits_error_outcome(
        self, tmp_path, env,
    ):
        from core.audit.executor import _process_glance_batch

        task = _task()
        shared = _shared(task)
        result = _result()

        def raising_review_one_fn(gap, *a, **kw):
            raise ValueError("boom in escalated review")

        committed: set = set()
        _process_glance_batch(
            [task],
            lambda contexts, config_: [_glance_outcome("suspicious")],
            shared, _config(tmp_path), result,
            raising_review_one_fn,
            review_fn=lambda *a, **kw: None,
            committed_keys=committed,
        )

        assert [o.status for o in env] == ["error"]
        assert env[0].file == task.gap["file"]
        assert env[0].function == task.gap["name"]
        assert result.errors == 1
        # The error record IS the member's committed outcome — the
        # async caller's mid-batch except path must not add another.
        assert committed == {task.key}

    def test_fallback_failure_commits_error_outcome(
        self, tmp_path, env,
    ):
        from core.audit.executor import _process_glance_batch

        task = _task()
        shared = _shared(task)
        result = _result()

        def failing_batch(contexts, config_):
            raise ValueError("batch parse error")  # forces the fallback

        def raising_review_one_fn(gap, *a, **kw):
            raise ValueError("boom in fallback review")

        committed: set = set()
        _process_glance_batch(
            [task],
            failing_batch,
            shared, _config(tmp_path), result,
            raising_review_one_fn,
            review_fn=lambda *a, **kw: None,
            committed_keys=committed,
        )

        assert [o.status for o in env] == ["error"]
        assert result.errors == 1
        assert committed == {task.key}


class TestGlanceEscalationCapDerivation:
    """Two-direction regression tests for the derived cap: it must
    scale UP with checklist size (a fixed 20 silently committed the
    glance guess for ≥99.8% of kernel-scale suspicious functions) and
    must stop scaling at the absolute ceiling (checklist size is
    target-derived — a hostile tree must not buy unbounded escalation
    spend)."""

    @staticmethod
    def _shared_with_functions(n_functions, n_files=10):
        per_file, rem = divmod(n_functions, n_files)
        files = []
        for i in range(n_files):
            count = per_file + (1 if i < rem else 0)
            files.append({
                "path": f"src/f{i}.c",
                "items": [{"name": f"fn_{i}_{j}"} for j in range(count)],
            })
        return SimpleNamespace(checklist={"files": files})

    def test_floor_without_checklist(self):
        from core.audit.executor import (
            _GLANCE_ESCALATION_FLOOR,
            _glance_escalation_cap,
        )

        assert _glance_escalation_cap(
            SimpleNamespace(checklist={}),
        ) == _GLANCE_ESCALATION_FLOOR
        assert _glance_escalation_cap(
            SimpleNamespace(),
        ) == _GLANCE_ESCALATION_FLOOR

    def test_floor_on_small_checklist(self):
        from core.audit.executor import (
            _GLANCE_ESCALATION_FLOOR,
            _glance_escalation_cap,
        )

        # 300 functions // 50 = 6 < floor — small runs keep the old cap.
        shared = self._shared_with_functions(300)
        assert _glance_escalation_cap(shared) == _GLANCE_ESCALATION_FLOOR

    def test_cap_scales_with_checklist_size(self):
        from core.audit.executor import (
            _GLANCE_ESCALATION_DIVISOR,
            _glance_escalation_cap,
        )

        # httpd-scale: 7,716 functions → 154, not 20.
        shared = self._shared_with_functions(7716)
        assert _glance_escalation_cap(shared) == (
            7716 // _GLANCE_ESCALATION_DIVISOR
        )

    def test_ceiling_binds_on_inflated_checklist(self):
        from core.audit.executor import (
            _GLANCE_ESCALATION_CEILING,
            _glance_escalation_cap,
        )

        # Kernel-scale (and beyond): the absolute ceiling holds even
        # when the target-derived function count would buy more.
        shared = self._shared_with_functions(124_755)
        assert _glance_escalation_cap(shared) == _GLANCE_ESCALATION_CEILING
        inflated = self._shared_with_functions(1_000_000, n_files=50)
        assert _glance_escalation_cap(inflated) == _GLANCE_ESCALATION_CEILING

    def test_cap_memoised_per_checklist_identity(self):
        from core.audit import executor

        shared = self._shared_with_functions(7716)
        before = len(executor._glance_cap_memo)
        first = executor._glance_escalation_cap(shared)
        assert executor._glance_escalation_cap(shared) == first
        after = len(executor._glance_cap_memo)
        # One memo entry for one checklist object, bounded FIFO.
        assert after <= max(before + 1, executor._GLANCE_CAP_MEMO_MAX)


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
