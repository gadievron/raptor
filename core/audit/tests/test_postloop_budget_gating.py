"""Post-loop passes must honour the budget/SIGTERM rails.

The callee-contract requeue and the dark-verification pass both run
AFTER the main review loop. Without polling ``_check_budget`` they
kept dispatching LLM calls on a budget/deadline-stopped run —
overrunning the SIGTERM drain margin (hard kill at the outer wall, no
report, lifecycle stuck ``running``) and, for dark verify, turning
budget exhaustion into an unstoppable failed-call-per-iteration loop.
"""

from __future__ import annotations

import json
import time

import pytest

import core.audit.orchestrator as _orch
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _callee_contract_requeue,
    _run_dark_verification,
)


def _outcome(file, function, status="dark", hypothesis="", review_result=None,
             evidence_tool=""):
    o = ReviewOutcome(
        file=file, function=function, status=status,
        body="suspected bug", hypothesis=hypothesis,
    )
    o.review_result = review_result
    o.evidence_tool = evidence_tool
    return o


def _result(outcomes):
    r = OrchestratorResult()
    r.outcomes = list(outcomes)
    for o in outcomes:
        if o.status == "dark":
            r.dormant += 1
        elif o.status == "finding":
            r.findings += 1
        elif o.status == "clean":
            r.clean += 1
    return r


def _exhausted_config(tmp_path) -> tuple[OrchestratorConfig, float]:
    """A config + start_time pair for which _check_budget is True."""
    config = OrchestratorConfig(
        target_path=tmp_path, out_dir=tmp_path, max_seconds=1,
    )
    return config, time.monotonic() - 100.0


# ---------------------------------------------------------------------------
# Dark verification
# ---------------------------------------------------------------------------


class TestDarkVerificationBudgetPolling:

    def test_exhausted_budget_dispatches_no_witness_calls(self, tmp_path):
        config, start = _exhausted_config(tmp_path)
        outcomes = [_outcome(f"m{i}.py", "f") for i in range(3)]
        result = _result(outcomes)
        calls: list = []

        def llm(prompt, system):
            calls.append(prompt)
            return "{}"

        _run_dark_verification(
            result, config, llm_client=llm, start_time=start,
        )
        assert calls == []
        assert all(o.status == "dark" for o in result.outcomes)

    def test_sigterm_stops_witness_loop(self, tmp_path, monkeypatch):
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        outcomes = [_outcome(f"m{i}.py", "f") for i in range(3)]
        result = _result(outcomes)
        monkeypatch.setattr(_orch, "is_sigterm_requested", lambda: True)
        calls: list = []
        _run_dark_verification(
            result, config,
            llm_client=lambda p, s: calls.append(p) or "{}",
            start_time=time.monotonic(),
        )
        assert calls == []
        assert result.terminated_by == "sigterm"

    def test_healthy_budget_still_verifies(self, tmp_path):
        """Positive control: with budget headroom the pass still runs
        end-to-end (confirmed witness upgrades the outcome)."""
        src = tmp_path / "math_util.py"
        src.write_text("def divide(a, b):\n    return a / b\n",
                       encoding="utf-8")
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        result = _result([_outcome(
            "math_util.py", "divide", hypothesis="division by zero",
        )])
        llm_response = json.dumps({
            "module_path": "math_util",
            "function": "divide",
            "args": [1, 0],
            "expected_exception": "ZeroDivisionError",
            "rationale": "dividing by zero",
        })
        _run_dark_verification(
            result, config,
            llm_client=lambda p, s: llm_response,
            start_time=time.monotonic(),
        )
        assert result.outcomes[0].status == "finding"

    def test_no_start_time_keeps_legacy_behaviour(self, tmp_path):
        """Callers that pass no start_time (tests, library use) get the
        unpolled behaviour rather than a spurious deadline trip."""
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path, max_seconds=1,
        )
        result = _result([_outcome("README.md", "check")])
        _run_dark_verification(result, config, llm_client=lambda p, s: "{}")
        assert result.outcomes[0].status == "dark"


# ---------------------------------------------------------------------------
# Callee-contract requeue
# ---------------------------------------------------------------------------


def _contract_fixture():
    caller = _outcome(
        "caller.py", "handle", status="clean",
        review_result={"relies_on": [
            {"callee": "parse_input", "assumption": "validates length"},
        ]},
    )
    callee = _outcome(
        "parser.py", "parse_input", status="finding",
        hypothesis="missing bounds check",
        evidence_tool="semgrep:rule-1",
    )
    return _result([caller, callee])


@pytest.fixture()
def _light_context(monkeypatch):
    monkeypatch.setattr(_orch, "_build_context",
                        lambda *a, **k: {})
    monkeypatch.setattr(_orch, "_commit_outcome",
                        lambda *a, **k: None)


class TestCalleeContractBudgetPolling:

    def test_exhausted_budget_skips_all_re_reviews(
        self, tmp_path, _light_context,
    ):
        config, start = _exhausted_config(tmp_path)
        result = _contract_fixture()
        calls: list = []

        def review_fn(ctx, cfg):
            calls.append(ctx)
            return _outcome("caller.py", "handle", status="suspicious")

        n = _callee_contract_requeue(
            result, config, review_fn,
            checklist={}, context_map=None, fuzz_coverage=None,
            evidence_index={}, start_time=start,
        )
        assert n == 0
        assert calls == []

    def test_sigterm_skips_all_re_reviews(
        self, tmp_path, _light_context, monkeypatch,
    ):
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        result = _contract_fixture()
        monkeypatch.setattr(_orch, "is_sigterm_requested", lambda: True)
        calls: list = []

        def review_fn(ctx, cfg):
            calls.append(ctx)
            return _outcome("caller.py", "handle", status="suspicious")

        n = _callee_contract_requeue(
            result, config, review_fn,
            checklist={}, context_map=None, fuzz_coverage=None,
            evidence_index={}, start_time=time.monotonic(),
        )
        assert n == 0
        assert calls == []

    def test_healthy_budget_re_reviews(self, tmp_path, _light_context):
        """Positive control: with headroom the requeue dispatches and
        counts the flipped caller."""
        config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
        result = _contract_fixture()
        calls: list = []

        def review_fn(ctx, cfg):
            calls.append(ctx)
            return _outcome("caller.py", "handle", status="suspicious")

        n = _callee_contract_requeue(
            result, config, review_fn,
            checklist={}, context_map=None, fuzz_coverage=None,
            evidence_index={}, start_time=time.monotonic(),
        )
        assert len(calls) == 1
        assert n == 1

    def test_parallel_path_polls_budget(self, tmp_path, _light_context):
        """The thread-pool path checks the rails per item too."""
        config, start = _exhausted_config(tmp_path)
        result = _contract_fixture()
        calls: list = []

        def review_fn(ctx, cfg):
            calls.append(ctx)
            return _outcome("caller.py", "handle", status="suspicious")

        n = _callee_contract_requeue(
            result, config, review_fn,
            checklist={}, context_map=None, fuzz_coverage=None,
            evidence_index={}, start_time=start, max_workers=4,
        )
        assert n == 0
        assert calls == []
