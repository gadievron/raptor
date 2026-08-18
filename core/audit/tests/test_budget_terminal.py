"""Budget exhaustion is TERMINAL for the /audit review loop.

Covers the observed field failure: the LLM client's cap was exhausted
mid-run (spend from timed-out attempts lives only in the client's
ledger), but the loop kept running — full block-level prep per
remaining function, a doomed LLM call, an "error" journal verdict,
repeat. These tests pin the fixed behaviour:

* a budget-exceeded error from review_fn stops the loop immediately;
* budget-killed functions are NOT journaled — they stay gap-eligible;
* per-function prep is not paid after exhaustion;
* the post-loop passes (deepen dispatch via _check_budget, error
  retry) stop dispatching too;
* error-verdict journal entries never suppress future gaps.

Hermetic: no network, no real LLM calls — review_fn is stubbed and the
budget client is a fake.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.gaps import compute_gaps
from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _check_budget,
    _retry_error_outcomes,
    run_orchestrator,
)
from core.coverage.journal import (
    ReviewJournalEntry,
    append_entry,
    load_entries,
    now_iso,
)
from core.llm.client import (
    LLMBudgetExceededError,
    is_budget_exceeded_error,
)


class _FakeBudgetClient:
    """Stands in for LLMClient — only the budget probe is consulted."""

    def __init__(self, exhausted: bool = False) -> None:
        self.exhausted = exhausted

    def is_budget_exhausted(self, estimated_cost: float = 0.1) -> bool:
        return self.exhausted


def _make_fn_body(name: str, start: int) -> str:
    lines = [f"int {name}(char *input, int len) {{"]
    lines += [f"  int v{i} = len + {i};" for i in range(20)]
    lines += ["  char buf[64];", "  memcpy(buf, input, len);",
              "  return buf[0];", "}"]
    return "\n".join(lines)


def _setup_target(tmp_path: Path, n_functions: int = 3):
    """Target with *n_functions* non-trivial functions (no batching)."""
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    names = [f"handler_{i}" for i in range(n_functions)]
    src_lines: list[str] = []
    items = []
    line = 1
    for name in names:
        body = _make_fn_body(name, line)
        n = body.count("\n") + 1
        items.append(
            {"name": name, "line_start": line, "line_end": line + n - 1},
        )
        src_lines.append(body)
        line += n
    (target / "src" / "big.c").write_text("\n".join(src_lines) + "\n")

    out = tmp_path / "out"
    out.mkdir()
    checklist = {"files": [{"path": "src/big.c", "items": items}]}
    (out / "checklist.json").write_text(json.dumps(checklist))
    return target, out, names


def _config(target: Path, out: Path, **kw) -> OrchestratorConfig:
    defaults: dict = {
        "target_path": target,
        "out_dir": out,
        "resume": False,
        "max_workers": 1,
        "batch_sloc_threshold": 0,  # force the executor path, no batching
        "prefilter": False,         # every function reaches review_fn
        "validate": False,
    }
    defaults.update(kw)
    return OrchestratorConfig(**defaults)


def _journal_functions(out: Path) -> set[str]:
    return {e.function for e in load_entries(out)}


class TestBudgetExceededError:
    def test_typed_and_string_detection(self):
        assert is_budget_exceeded_error(LLMBudgetExceededError("nope"))
        assert is_budget_exceeded_error(
            RuntimeError("LLM budget exceeded: $8.08 spent > $8.00 limit"),
        )
        assert not is_budget_exceeded_error(RuntimeError("api timeout"))
        assert not is_budget_exceeded_error(ValueError("budget exceeded"))

    def test_subclasses_runtime_error(self):
        # Legacy string-matching handlers catch RuntimeError — the typed
        # class must stay inside that net.
        assert issubclass(LLMBudgetExceededError, RuntimeError)


@pytest.mark.slow
class TestBudgetStopsReviewLoop:
    def test_loop_stops_and_unreviewed_stay_gaps(self, tmp_path: Path):
        target, out, names = _setup_target(tmp_path, n_functions=3)

        calls = []

        def review_fn(ctx, config):
            calls.append(ctx["function"])
            if len(calls) >= 2:
                raise LLMBudgetExceededError(
                    "LLM budget exceeded: $8.08 spent > $8.00 limit",
                )
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="ok", cost_usd=0.5,
            )

        result = run_orchestrator(_config(target, out), review_fn)

        # Loop stopped at the budget error: one success, no error
        # verdicts, and the budget-killed function was not retried.
        assert result.reviewed == 1
        assert result.errors == 0
        assert result.terminated_by == "llm_budget_exceeded"
        assert len(calls) == 2

        # Only the successful review reached the journal — the killed
        # and never-attempted functions were NOT journaled.
        journaled = _journal_functions(out)
        assert len(journaled) == 1

        # Gap recomputation still surfaces the two unreviewed functions.
        checklist = json.loads((out / "checklist.json").read_text())
        gaps = compute_gaps(checklist, [], out_dir=out)
        gap_names = {g["name"] for g in gaps}
        assert gap_names == set(names) - journaled
        assert len(gap_names) == 2

    def test_prep_not_run_when_exhausted_from_start(
        self, tmp_path: Path, monkeypatch,
    ):
        target, out, names = _setup_target(tmp_path, n_functions=2)

        prep_calls = []
        import core.audit.orchestrator as orch
        real_prep = orch._try_block_level_context

        def spy_prep(*a, **kw):
            prep_calls.append(a)
            return real_prep(*a, **kw)

        monkeypatch.setattr(orch, "_try_block_level_context", spy_prep)

        review_calls = []

        def review_fn(ctx, config):
            review_calls.append(ctx["function"])
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="ok",
            )

        cfg = _config(
            target, out, llm_budget_client=_FakeBudgetClient(exhausted=True),
        )
        result = run_orchestrator(cfg, review_fn)

        assert review_calls == []
        assert prep_calls == []
        assert result.terminated_by == "llm_budget_exceeded"
        assert _journal_functions(out) == set()
        checklist = json.loads((out / "checklist.json").read_text())
        gaps = compute_gaps(checklist, [], out_dir=out)
        assert {g["name"] for g in gaps} == set(names)

    def test_prep_not_run_after_midrun_exhaustion(
        self, tmp_path: Path, monkeypatch,
    ):
        """Once the client ledger crosses the cap, later functions must
        not pay block-level prep (the observed ~40min post-exhaustion
        waste)."""
        target, out, _names = _setup_target(tmp_path, n_functions=3)

        client = _FakeBudgetClient(exhausted=False)
        prep_calls = []
        import core.audit.orchestrator as orch

        monkeypatch.setattr(
            orch, "_try_block_level_context",
            lambda *a, **kw: prep_calls.append(a),
        )

        review_calls = []

        def review_fn(ctx, config):
            review_calls.append(ctx["function"])
            client.exhausted = True  # spend lands on the client ledger
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="ok", cost_usd=8.0,
            )

        cfg = _config(target, out, llm_budget_client=client)
        result = run_orchestrator(cfg, review_fn)

        assert len(review_calls) == 1
        assert len(prep_calls) == 1  # only the pre-exhaustion function
        assert result.reviewed == 1
        assert result.terminated_by == "llm_budget_exceeded"


class TestCheckBudgetConsultsClient:
    def test_client_ledger_trips_gate(self, tmp_path: Path):
        """result.total_cost_usd can sit far below the cap while the
        client ledger (which includes failed/timed-out attempts) is
        exhausted — the gate must trip on the client ledger too. This
        is what stops the deepen phase from dispatching post-exhaustion
        (its dispatch loops poll _check_budget per item)."""
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            max_cost_usd=8.0,
            llm_budget_client=_FakeBudgetClient(exhausted=True),
        )
        result = OrchestratorResult()
        result.total_cost_usd = 2.82  # successful outcomes only
        assert _check_budget(config, 0.0, result) is True
        assert result.terminated_by == "llm_budget_exceeded"

    def test_not_exhausted_gate_stays_open(self, tmp_path: Path):
        config = OrchestratorConfig(
            target_path=tmp_path, out_dir=tmp_path,
            max_cost_usd=8.0,
            llm_budget_client=_FakeBudgetClient(exhausted=False),
        )
        result = OrchestratorResult()
        result.total_cost_usd = 2.82
        assert _check_budget(config, 0.0, result) is False
        assert result.terminated_by == "complete"


class TestErrorRetryStopsOnBudget:
    def test_retry_pass_stops_after_first_budget_error(self, tmp_path: Path):
        target, out, names = _setup_target(tmp_path, n_functions=3)
        checklist = json.loads((out / "checklist.json").read_text())

        config = _config(target, out)
        result = OrchestratorResult()
        for name in names:
            outcome = ReviewOutcome(
                file="src/big.c", function=name,
                status="error", body="api blip",
                error_class="api_error",  # recoverable → retried
            )
            result.outcomes.append(outcome)
            result.errors += 1

        calls = []

        def review_fn(ctx, config):
            calls.append(ctx["function"])
            raise LLMBudgetExceededError(
                "LLM budget exceeded: $8.08 spent > $8.00 limit",
            )

        result = _retry_error_outcomes(
            result, config, review_fn, checklist,
            None, None, 0.0, None,
        )

        # ONE attempt, then the pass stops — not one per error outcome.
        assert len(calls) == 1
        assert result.terminated_by == "llm_budget_exceeded"


class TestErrorVerdictsStayGapEligible:
    def _entry(self, function: str, verdict: str) -> ReviewJournalEntry:
        return ReviewJournalEntry(
            ts=now_iso(), run_id="run1", file="src/big.c",
            function=function, verdict=verdict, source_hash="",
            line_start=1, line_end=10,
        )

    def test_journal_error_verdict_still_a_gap(self, tmp_path: Path):
        _target, out, names = _setup_target(tmp_path, n_functions=2)
        checklist = json.loads((out / "checklist.json").read_text())

        append_entry(out, self._entry(names[0], "error"))
        append_entry(out, self._entry(names[1], "clean"))

        gaps = compute_gaps(checklist, [], out_dir=out)
        gap_names = {g["name"] for g in gaps}
        assert names[0] in gap_names   # error → retry next run
        assert names[1] not in gap_names

    def test_coverage_import_skips_error_verdicts(self, tmp_path: Path):
        """The run-completion journal→coverage-store projection must not
        mark budget/API-error verdicts as reviewed — that would
        misrepresent coverage for anything derived from the store."""
        from core.coverage.importer import import_journal
        from core.coverage.journal import merge_into_index
        from core.coverage.store import CoverageStore

        _target, out, names = _setup_target(tmp_path, n_functions=2)
        checklist = json.loads((out / "checklist.json").read_text())
        project_dir = tmp_path / "project"
        project_dir.mkdir()

        append_entry(out, self._entry(names[0], "error"))
        append_entry(out, self._entry(names[1], "clean"))
        merge_into_index(project_dir, out)

        store = CoverageStore(tmp_path / "coverage.json")
        marks = import_journal(store, project_dir, checklist)
        assert marks == 1  # the clean entry only
