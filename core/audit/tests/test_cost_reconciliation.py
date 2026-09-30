"""Run-cost ledgers must reconcile or explain themselves.

Observed field failure: one run showed three different totals (LLM
client ledger, cost-breakdown review phase, final summary) with no
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
        ct.record_call("review", cost_usd=3.75)
        ct.record_failed_attempt("review", cost_usd=2.50)

        pc = ct.phases["review"]
        assert pc.calls == 1
        assert pc.failed_calls == 1
        assert abs(pc.cost_usd - 3.75) < 1e-9
        assert abs(pc.failed_attempts_cost_usd - 2.50) < 1e-9

        d = ct.to_dict()
        assert d["phases"]["review"]["failed_calls"] == 1
        assert d["phases"]["review"]["failed_attempts_cost_usd"] == 2.50

    def test_reconciliation_arithmetic_closes(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=3.75)
        ct.record_failed_attempt("review", cost_usd=1.5)
        ct.set_total_spend(6.25)  # the client ledger

        assert abs(ct.total_cost_usd - 3.75) < 1e-9
        assert abs(ct.total_failed_attempts_cost_usd - 1.5) < 1e-9
        assert abs(ct.total_spend_usd - 6.25) < 1e-9
        # total_spend = completed + failed + unattributed, always.
        assert abs(
            ct.unattributed_cost_usd - (6.25 - 3.75 - 1.5)
        ) < 1e-9

        totals = ct.to_dict()["totals"]
        assert totals["total_spend_usd"] == 6.25
        assert totals["failed_attempts_cost_usd"] == 1.5
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
        # unattributed successful spend — the pre-fix label lumped
        # exactly this residual under "failed/timed-out" even when
        # telemetry showed zero failures. The label must not lie.
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=3.75)
        ct.set_total_spend(6.25)
        s = ct.summary()
        assert "$6.25" in s
        assert "failed/timed-out" not in s
        assert "unattributed=$2.50" in s

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
    into a mislabelled residual. Observed live: telemetry above summary
    — audit+iris class spend missing from the summary ledger."""

    def test_books_unphased_classes(self):
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=24.00)
        booked = ct.book_unbooked_classes({
            "review": (9, 24.00),        # outcome-booked — skipped
            "audit": (3, 2.10),
            "iris": (2, 1.50),
            # Registered first-class — booked, but not disclosed
            # (see test_class_phase_registration.py).
            "glance_batch": (1, 0.40),
        })
        assert booked == {"audit": 2.10, "iris": 1.5}
        assert ct.phases["iris"].calls == 2
        assert ct.phases["glance_batch"].calls == 1
        assert abs(ct.total_cost_usd - (24.00 + 2.10 + 1.5 + 0.4)) < 1e-9

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
        # Pre-fix, successful support-class spend printed under the
        # "failed/timed-out" label. Booked classes print under their
        # own names and the residual is zero.
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=24.00)
        ct.book_unbooked_classes({"iris": (4, 6.40)})
        ct.set_total_spend(30.40)
        s = ct.summary()
        assert "iris=4calls/$6.40" in s
        assert "failed/timed-out" not in s
        assert "unattributed" not in s
        assert abs(ct.total_spend_usd - 30.40) < 1e-9
        assert ct.unattributed_cost_usd < 0.005

    def test_standalone_client_spend_raises_total(self):
        # Classes outside the budget-client ledger (standalone
        # LLMClient instances) still count: tracked > injected ledger
        # → total_spend follows the tracked sum.
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=24.00)
        ct.book_unbooked_classes({
            "iris": (4, 6.40),
            "audit": (3, 2.10),
        })
        ct.set_total_spend(30.40)   # client ledger missed audit's 2.10
        assert abs(ct.total_spend_usd - 32.50) < 1e-9


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
        result.cost_tracker.record_call("review", cost_usd=24.00)
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
                self._rec("review", 24.00),
                self._rec("iris", 6.40),
                self._rec("audit", 2.10),
            ],
            client_total=30.40,   # iris on the ledger, audit outside it
        )
        # Every class reached the summary ledger: total follows the
        # tracked sum (32.50), not the smaller client ledger.
        assert abs(result.llm_spend_usd - 32.50) < 1e-6
        assert abs(result.cost_tracker.phases["iris"].cost_usd - 6.40) < 1e-9
        assert abs(result.cost_tracker.phases["audit"].cost_usd - 2.10) < 1e-9
        assert result.cost_tracker.unattributed_cost_usd < 0.005
        assert not [w for w in warnings if "cost reconciliation" in w]

    def test_divergence_over_one_percent_warns(self, monkeypatch):
        # Telemetry saw $10 of review spend the phases never booked
        # (phases hold $24.00 review but telemetry says $34.00 —
        # review is class-skipped, so booking can't close it).
        result, warnings = self._reconcile(
            monkeypatch,
            records=[self._rec("review", 34.00)],
            client_total=24.00,
        )
        del result
        assert [w for w in warnings if "cost reconciliation" in w]

    def test_failed_attempt_covered_gap_does_not_warn(self, monkeypatch):
        """Ledger > telemetry with the gap covered by recorded
        failed-attempt spend is the DOCUMENTED design (telemetry never
        books per-call spend of attempts that raised) — it must read
        as information, not as an unbooked/double-booked alarm."""
        from core.audit import orchestrator as orch
        from core.llm import telemetry

        sink = telemetry.TelemetrySink(
            __import__("pathlib").Path("/nonexistent-dir/t.jsonl"),
        )
        sink.record(self._rec("review", 24.00))

        warnings: list[str] = []
        real_warning = orch.logger.warning

        def _capture(msg, *args, **kw):
            warnings.append(msg % args if args else str(msg))
            real_warning(msg, *args, **kw)

        monkeypatch.setattr(orch.logger, "warning", _capture)
        monkeypatch.setattr(telemetry, "_sink", sink)

        result = OrchestratorResult()
        result.cost_tracker.record_call("review", cost_usd=24.00)
        result.cost_tracker.record_failed_attempt(
            "review", cost_usd=10.0)
        client = SimpleNamespace(total_cost=34.00)
        config = SimpleNamespace(llm_budget_client=client, out_dir=None)
        orch._reconcile_cost_ledgers(config, result)
        assert not [w for w in warnings if "cost reconciliation" in w]

    def test_divergence_under_one_percent_quiet(self, monkeypatch):
        result, warnings = self._reconcile(
            monkeypatch,
            records=[self._rec("review", 24.02)],  # ~0.08% off
            client_total=24.00,
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

    def test_split_spend_scenario(self) -> None:
        """A representative shape: total spend split across completed
        reviews (15 reviewed, 12 errors) and failed attempts."""
        line = format_cost_summary(self._result(
            total_cost_usd=3.75, llm_spend_usd=6.25,
            failed_attempts_cost_usd=2.50, reviewed=15, errors=12,
        ))
        assert line == (
            "Cost: $6.25 ($3.75 across 3 completed reviews; "
            "$2.50 on failed/timed-out attempts)"
        )

    def test_no_failed_spend_stays_simple(self):
        line = format_cost_summary(self._result(
            total_cost_usd=3.75, llm_spend_usd=3.75, reviewed=3,
        ))
        assert line == "Cost: $3.75"

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
        assert f"{other_s} unattributed (see cost-breakdown.json)" in line


class TestCostSummaryAttribution:
    """Incident regression: on a resumed segment the operator-facing
    Cost: line lumped the correctly-booked prior-segment spend and the
    support phases into "$X on unattributed calls" — a healthy run
    reported most of its spend as unexplained while its own
    cost-breakdown.json attributed all but a sliver."""

    def _result(self):
        from types import SimpleNamespace
        from core.audit.cost_tracker import PhaseCostLedger
        tracker = PhaseCostLedger()
        tracker.record_call("prior_segments", cost_usd=12.0)
        tracker.record_call("review", cost_usd=5.0)
        tracker.record_call("summary", cost_usd=2.0)
        tracker.record_call("spec_inference", cost_usd=1.0)
        return SimpleNamespace(
            total_cost_usd=5.0,
            failed_attempts_cost_usd=0.0,
            llm_spend_usd=20.0,
            reviewed=10,
            errors=0,
            cost_tracker=tracker,
        )

    def test_prior_and_support_phases_named(self):
        from core.audit.cost_tracker import format_cost_summary
        line = format_cost_summary(self._result())
        assert "booked from prior segments" in line
        assert "non-review phases" in line
        assert "unattributed" not in line, (
            "ledger-attributed spend must not print as unattributed"
        )

    def test_true_residual_still_reported(self):
        from types import SimpleNamespace
        from core.audit.cost_tracker import PhaseCostLedger
        tracker = PhaseCostLedger()
        tracker.record_call("review", cost_usd=5.0)
        result = SimpleNamespace(
            total_cost_usd=5.0,
            failed_attempts_cost_usd=0.0,
            llm_spend_usd=6.5,
            reviewed=10,
            errors=0,
            cost_tracker=tracker,
        )
        from core.audit.cost_tracker import format_cost_summary
        line = format_cost_summary(result)
        assert "unattributed" in line
