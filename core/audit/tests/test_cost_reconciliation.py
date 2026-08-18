"""Run-cost ledgers must reconcile or explain themselves.

Observed field failure: one run showed $8.08 (LLM client ledger),
$4.52 (cost-breakdown review phase) and $2.82 (final summary) with no
way to relate them. The fix defines the semantics (see
core/audit/cost_tracker.py module docstring) and these tests pin them.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from core.audit.cost_tracker import PhaseCostLedger, format_cost_summary
from core.audit.orchestrator import (
    OrchestratorResult,
    ReviewOutcome,
    _tally_outcome,
    _untally_outcome,
)


class TestFailedAttemptLedger:
    def test_failed_attempts_tracked_per_phase(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=2.82)
        ct.record_failed_attempt("review", cost_usd=5.26)

        pc = ct.phases["review"]
        assert pc.calls == 1
        assert pc.failed_calls == 1
        assert abs(pc.cost_usd - 2.82) < 1e-9
        assert abs(pc.failed_attempts_cost_usd - 5.26) < 1e-9

        d = ct.to_dict()
        assert d["phases"]["review"]["failed_calls"] == 1
        assert d["phases"]["review"]["failed_attempts_cost_usd"] == 5.26

    def test_reconciliation_arithmetic_closes(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=2.82)
        ct.record_failed_attempt("review", cost_usd=4.0)
        ct.set_total_spend(8.08)  # the client ledger

        assert abs(ct.total_cost_usd - 2.82) < 1e-9
        assert abs(ct.total_failed_attempts_cost_usd - 4.0) < 1e-9
        assert abs(ct.total_spend_usd - 8.08) < 1e-9
        # total_spend = completed + failed + unattributed, always.
        assert abs(
            ct.unattributed_cost_usd - (8.08 - 2.82 - 4.0)
        ) < 1e-9

        totals = ct.to_dict()["totals"]
        assert totals["total_spend_usd"] == 8.08
        assert totals["failed_attempts_cost_usd"] == 4.0
        assert abs(
            totals["cost_usd"]
            + totals["failed_attempts_cost_usd"]
            + totals["unattributed_cost_usd"]
            - totals["total_spend_usd"]
        ) < 1e-3

    def test_client_ledger_cannot_hide_tracked_spend(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=3.0)
        ct.set_total_spend(1.0)  # stale / partial snapshot
        assert ct.total_spend_usd == 3.0
        assert ct.unattributed_cost_usd == 0.0

    def test_clean_run_keeps_legacy_shape(self):
        """No failed attempts + no client ledger → no new totals keys
        (consumers of the old cost-breakdown.json shape unaffected)."""
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=0.5)
        totals = ct.to_dict()["totals"]
        assert "failed_attempts_cost_usd" not in totals
        assert "total_spend_usd" not in totals
        assert "failed_calls" not in ct.to_dict()["phases"]["review"]

    def test_summary_line_labels_residual_unattributed(self):
        # Residual spend with NO recorded failed attempts is
        # unattributed successful spend — a real run printed
        # "failed/timed-out=$9.57" for four successful calls while
        # telemetry showed zero failures. The label must not lie.
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=2.82)
        ct.set_total_spend(8.08)
        s = ct.summary()
        assert "$8.08" in s
        assert "failed/timed-out" not in s
        assert "unattributed=$5.26" in s

    def test_summary_line_splits_failed_from_unattributed(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=2.0)
        ct.record_failed_attempt("review", cost_usd=1.0)
        ct.set_total_spend(4.0)
        s = ct.summary()
        assert "failed/timed-out=$1.00" in s
        assert "unattributed=$1.00" in s


class TestClassBooking:
    """Telemetry call classes no phase captured are booked, not lumped
    into a mislabelled residual. Observed: telemetry $38.84 vs summary
    $36.85 — audit+iris class spend missing from the summary ledger."""

    def test_books_unphased_classes(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=27.28)
        booked = ct.book_unbooked_classes({
            "review": (9, 27.28),        # outcome-booked — skipped
            "audit": (3, 1.99),
            "iris": (2, 1.50),
            "glance_batch": (1, 0.40),
        })
        assert booked == {
            "audit": 1.99, "iris": 1.5, "glance_batch": 0.4,
        }
        assert ct.phases["iris"].calls == 2
        assert abs(ct.total_cost_usd - (27.28 + 1.99 + 1.5 + 0.4)) < 1e-9

    def test_skips_classes_matching_existing_phase(self):
        # checker_synthesis / study spend is booked at source into a
        # phase of the same name — booking the class again would
        # double-count.
        ct = PhaseCostLedger()
        ct.record_call("checker_synthesis", cost_usd=0.8)
        ct.record_call("study", cost_usd=2.0)
        booked = ct.book_unbooked_classes({
            "checker_synthesis": (1, 0.8),
            "study": (4, 2.0),
            "summary": (1, 0.3),
        })
        assert booked == {"summary": 0.3}
        assert abs(ct.phases["checker_synthesis"].cost_usd - 0.8) < 1e-9

    def test_skips_empty_classes(self):
        ct = PhaseCostLedger()
        assert ct.book_unbooked_classes({"idle": (0, 0.0)}) == {}
        assert "idle" not in ct.phases

    def test_booked_class_reaches_summary_line_and_total(self):
        # The observed run: successful support-class spend printed as
        # "failed/timed-out=$9.57". Booked classes print under their
        # own names and the residual is zero.
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=27.28)
        ct.book_unbooked_classes({"iris": (4, 9.57)})
        ct.set_total_spend(36.85)
        s = ct.summary()
        assert "iris=4calls/$9.57" in s
        assert "failed/timed-out" not in s
        assert "unattributed" not in s
        assert abs(ct.total_spend_usd - 36.85) < 1e-9
        assert ct.unattributed_cost_usd < 0.005

    def test_standalone_client_spend_raises_total(self):
        # Classes outside the budget-client ledger (standalone
        # LLMClient instances) still count: tracked > injected ledger
        # → total_spend follows the tracked sum.
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=27.28)
        ct.book_unbooked_classes({
            "iris": (4, 9.57),
            "audit": (3, 1.99),
        })
        ct.set_total_spend(36.85)   # client ledger missed audit's 1.99
        assert abs(ct.total_spend_usd - 38.84) < 1e-9


class TestReconcileLedgers:
    """End-of-run wiring: telemetry classes are booked, the client
    ledger is injected, and >1% telemetry-vs-ledger divergence warns."""

    def _reconcile(self, monkeypatch, *, records, client_total):
        from core.audit import orchestrator as orch
        from core.llm import telemetry

        sink = telemetry.TelemetrySink(
            # Path never written — records go through record() which
            # tolerates unwritable parents anyway.
            __import__("pathlib").Path("/nonexistent-dir/t.jsonl"),
        )
        for rec in records:
            sink.record(dict(rec))

        warnings: list[str] = []
        real_warning = orch.logger.warning

        def _capture(msg, *args, **kw):
            warnings.append(msg % args if args else str(msg))
            real_warning(msg, *args, **kw)

        monkeypatch.setattr(orch.logger, "warning", _capture)
        monkeypatch.setattr(telemetry, "_sink", sink)

        result = OrchestratorResult()
        result.cost_tracker.record_call("review", cost_usd=27.28)
        client = SimpleNamespace(total_cost=client_total)
        config = SimpleNamespace(llm_budget_client=client, out_dir=None)
        orch._reconcile_cost_ledgers(config, result)
        return result, warnings

    @staticmethod
    def _rec(call_class, cost):
        return {
            "event": "call", "disposition": "ok",
            "call_class": call_class, "cost_usd": cost,
        }

    def test_books_classes_and_closes_ledgers(self, monkeypatch):
        result, warnings = self._reconcile(
            monkeypatch,
            records=[
                self._rec("review", 27.28),
                self._rec("iris", 9.57),
                self._rec("audit", 1.99),
            ],
            client_total=36.85,   # iris on the ledger, audit outside it
        )
        # Every class reached the summary ledger: total follows the
        # tracked sum (38.84), not the smaller client ledger.
        assert abs(result.llm_spend_usd - 38.84) < 1e-6
        assert abs(result.cost_tracker.phases["iris"].cost_usd - 9.57) < 1e-9
        assert abs(result.cost_tracker.phases["audit"].cost_usd - 1.99) < 1e-9
        assert result.cost_tracker.unattributed_cost_usd < 0.005
        assert not [w for w in warnings if "cost reconciliation" in w]

    def test_divergence_over_one_percent_warns(self, monkeypatch):
        # Telemetry saw $10 of review spend the phases never booked
        # (phases hold $27.28 review but telemetry says $37.28 —
        # review is class-skipped, so booking can't close it).
        result, warnings = self._reconcile(
            monkeypatch,
            records=[self._rec("review", 37.28)],
            client_total=27.28,
        )
        del result
        assert [w for w in warnings if "cost reconciliation" in w]

    def test_divergence_under_one_percent_quiet(self, monkeypatch):
        result, warnings = self._reconcile(
            monkeypatch,
            records=[self._rec("review", 27.30)],  # 0.07% off
            client_total=27.28,
        )
        del result
        assert not [w for w in warnings if "cost reconciliation" in w]


class TestFormatCostSummary:
    def _result(self, **kw) -> SimpleNamespace:
        base = {
            "total_cost_usd": 0.0,
            "failed_attempts_cost_usd": 0.0,
            "llm_spend_usd": 0.0,
            "reviewed": 0,
            "errors": 0,
        }
        base.update(kw)
        return SimpleNamespace(**base)

    def test_observed_scenario(self):
        """The real run: $8.08 spent, $2.82 across 3 completed
        reviews (15 reviewed, 12 errors), rest on failed attempts."""
        line = format_cost_summary(self._result(
            total_cost_usd=2.82, llm_spend_usd=8.08,
            failed_attempts_cost_usd=5.26, reviewed=15, errors=12,
        ))
        assert line == (
            "Cost: $8.08 ($2.82 across 3 completed reviews; "
            "$5.26 on failed/timed-out attempts)"
        )

    def test_no_failed_spend_stays_simple(self):
        line = format_cost_summary(self._result(
            total_cost_usd=2.82, llm_spend_usd=2.82, reviewed=3,
        ))
        assert line == "Cost: $2.82"

    def test_no_client_ledger_uses_tracked_split(self):
        line = format_cost_summary(self._result(
            total_cost_usd=1.0, failed_attempts_cost_usd=0.5,
            reviewed=2, errors=0,
        ))
        assert line == (
            "Cost: $1.50 ($1.00 across 2 completed reviews; "
            "$0.50 on failed/timed-out attempts)"
        )

    def test_singular_review(self):
        line = format_cost_summary(self._result(
            total_cost_usd=1.0, llm_spend_usd=2.0, reviewed=1,
        ))
        assert "1 completed review;" in line

    def test_zero_spend_prints_nothing(self):
        assert format_cost_summary(self._result()) is None

    def test_legacy_result_without_new_fields(self):
        line = format_cost_summary(
            SimpleNamespace(total_cost_usd=0.75, reviewed=2, errors=0),
        )
        assert line == "Cost: $0.75"


class TestUntallyKeepsSpend:
    def test_untally_reverses_verdict_not_cost(self):
        """Deepen/re-review replace outcomes, but the replaced call's
        money was still spent — reversing it made the summary drift
        below every other ledger and under-enforced --max-cost."""
        result = OrchestratorResult()
        outcome = ReviewOutcome(
            file="a.c", function="f", status="suspicious",
            body="hmm", cost_usd=1.7,
        )
        _tally_outcome(result, outcome)
        assert result.suspicious == 1
        assert abs(result.total_cost_usd - 1.7) < 1e-9

        _untally_outcome(result, outcome)
        assert result.suspicious == 0
        assert result.reviewed == 0
        assert abs(result.total_cost_usd - 1.7) < 1e-9  # spend survives

        replacement = ReviewOutcome(
            file="a.c", function="f", status="clean",
            body="ok", cost_usd=0.3,
        )
        _tally_outcome(result, replacement)
        assert abs(result.total_cost_usd - 2.0) < 1e-9


@pytest.mark.slow
class TestEndToEndReconciliation:
    def test_failed_attempt_spend_reaches_breakdown_and_summary(
        self, tmp_path,
    ):
        """A review call that raises after the client billed the
        attempt: the attempt is COUNTED (failed_calls) but books no
        per-call cost figure — the before/after client-ledger delta
        multiply-booked every concurrent worker's successful spend as
        "failed-attempt cost" (~9x real spend on parallel runs). The
        money still reaches the operator exactly once: the client
        ledger lands in totals.total_spend_usd and the billed-but-
        failed spend surfaces as the unattributed residual, labelled
        as such (not as a phantom "failed/timed-out" figure)."""
        from core.audit.orchestrator import run_orchestrator
        from core.audit.tests.test_budget_terminal import (
            _config,
            _setup_target,
        )

        target, out, names = _setup_target(tmp_path, n_functions=2)

        client = SimpleNamespace(total_cost=0.0)
        client.is_budget_exhausted = lambda estimated_cost=0.1: False

        def review_fn(ctx, config):
            if ctx["function"] == names[0]:
                client.total_cost += 1.7   # billed attempt...
                raise RuntimeError("timeout after 600s")  # ...that died
            client.total_cost += 0.5
            return ReviewOutcome(
                file=ctx["file"], function=ctx["function"],
                status="clean", body="ok", cost_usd=0.5,
            )

        cfg = _config(target, out, llm_budget_client=client)
        result = run_orchestrator(cfg, review_fn)

        # The failed main-pass attempt is counted, but carries NO
        # per-call cost figure (concurrent-spend multiply-booking
        # fix); its billed money must surface as unattributed instead
        # of vanishing.
        assert result.errors == 1
        assert result.failed_attempts_cost_usd == 0.0
        assert abs(result.llm_spend_usd - client.total_cost) < 1e-6

        breakdown = json.loads((out / "cost-breakdown.json").read_text())
        review_phase = breakdown["phases"]["review"]
        assert review_phase["failed_calls"] == 1
        assert review_phase["failed_attempts_cost_usd"] == 0.0
        totals = breakdown["totals"]
        assert abs(totals["total_spend_usd"] - client.total_cost) < 1e-3
        # Nothing vanishes: every billed-but-failed dollar is in the
        # unattributed residual, and the three buckets reconcile to
        # the client ledger.
        assert totals["unattributed_cost_usd"] == pytest.approx(
            client.total_cost - 0.5, abs=1e-3,
        )
        assert abs(
            totals["cost_usd"]
            + totals["failed_attempts_cost_usd"]
            + totals["unattributed_cost_usd"]
            - totals["total_spend_usd"]
        ) < 1e-3

        line = format_cost_summary(result)
        assert line is not None
        total_s = f"${client.total_cost:.2f}"
        assert line.startswith(
            f"Cost: {total_s} ($0.50 across 1 completed review;",
        )
        # No phantom "failed/timed-out" figure: with per-call failed
        # cost no longer fabricated from ledger deltas, the billed
        # spend of failed attempts is reported under the honest
        # unattributed label.
        assert "failed/timed-out" not in line
        other_s = f"${client.total_cost - 0.5:.2f}"
        assert f"{other_s} on unattributed calls" in line
