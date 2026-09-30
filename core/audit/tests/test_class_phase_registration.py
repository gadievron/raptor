"""Registered first-class call classes: booked, never disclosed as unknown.

``glance_batch`` and ``concept_discovery`` calls dispatch outside the
review-outcome loop, so no ``record_call`` site books them at source —
the end-of-run reconciliation books them from the telemetry per-class
snapshot. They are designed, expected spend classes (the dominant ones
on binary-target runs), yet the reconciliation reported each as booked
"outside the phase ledger" — an unknown-class anomaly line repeated on
every audit segment of a chained engagement. Registration
(``PhaseCostLedger._REGISTERED_CLASS_PHASES``) changes DISCLOSURE
only: the booking arithmetic is untouched, and the catch-all
disclosure stays fail-open for classes nobody declared.

Failing-first taxonomy (this file run verbatim on pristine BASE):

* RED on BASE (mechanism — BASE has no registered-class set, so the
  two classes come back in the disclosure dict and the reconciliation
  logs them as unknown):
  - test_registered_classes_route_to_named_phases_without_disclosure
  - test_unknown_class_still_disclosed_alongside_registered
  - test_reconcile_logs_no_unknown_class_line_for_registered_classes
  - test_reconcile_discloses_only_the_unknown_class
* GREEN-BY-DESIGN PINS (deliberately green on BASE too — they pin the
  invariant that registration never changes the money: grand totals
  identical, nothing dropped, nothing double-booked):
  - test_grand_totals_identical_with_registered_classes
  - test_rebooking_is_idempotent_no_double_booking
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from core.audit.cost_tracker import PhaseCostLedger


class TestRegisteredClassPhases:
    def test_registered_classes_route_to_named_phases_without_disclosure(
        self,
    ) -> None:
        ct = PhaseCostLedger()
        disclosed = ct.book_unbooked_classes({
            "glance_batch": (21, 96.6),
            "concept_discovery": (3, 2.4),
        })
        # Routing pin: each registered class lands on a ledger phase
        # named after the class, calls and cost intact ...
        assert ct.phases["glance_batch"].calls == 21
        assert abs(ct.phases["glance_batch"].cost_usd - 96.6) < 1e-9
        assert ct.phases["concept_discovery"].calls == 3
        assert abs(ct.phases["concept_discovery"].cost_usd - 2.4) < 1e-9
        # ... and neither is reported as an unknown class.
        assert disclosed == {}

    def test_unknown_class_still_disclosed_alongside_registered(self) -> None:
        ct = PhaseCostLedger()
        disclosed = ct.book_unbooked_classes({
            "glance_batch": (2, 9.2),
            "mystery_class": (1, 0.7),
        })
        # Fail-open preserved: the genuinely unknown class is still
        # booked AND still disclosed; the registered one is not.
        assert disclosed == {"mystery_class": 0.7}
        assert abs(ct.phases["mystery_class"].cost_usd - 0.7) < 1e-9
        assert abs(ct.phases["glance_batch"].cost_usd - 9.2) < 1e-9

    def test_grand_totals_identical_with_registered_classes(self) -> None:
        # GREEN-BY-DESIGN PIN: registration must not move a cent —
        # the grand totals equal the arithmetic sum of every input
        # (the exact numbers the pre-registration catch-all produced),
        # so nothing is dropped from the ledger by declassifying the
        # two classes as expected.
        ct = PhaseCostLedger()
        ct.record_call("review", cost_usd=27.28)
        ct.book_unbooked_classes({
            "audit": (3, 1.99),
            "glance_batch": (21, 96.6),
            "concept_discovery": (3, 2.4),
        })
        expected_total = 27.28 + 1.99 + 96.6 + 2.4
        assert abs(ct.total_cost_usd - expected_total) < 1e-9
        totals = ct.to_dict()["totals"]
        assert totals["cost_usd"] == round(expected_total, 4)
        assert totals["calls"] == 1 + 3 + 21 + 3
        assert ct.unattributed_cost_usd < 0.005

    def test_rebooking_is_idempotent_no_double_booking(self) -> None:
        # GREEN-BY-DESIGN PIN: a second booking pass over the same
        # telemetry snapshot books nothing and discloses nothing —
        # the serialised ledger is byte-identical, so registered
        # classes can never be double-booked.
        snapshot = {
            "glance_batch": (21, 96.6),
            "concept_discovery": (3, 2.4),
        }
        ct = PhaseCostLedger()
        ct.book_unbooked_classes(dict(snapshot))
        before = json.dumps(ct.to_dict(), sort_keys=True)
        assert ct.book_unbooked_classes(dict(snapshot)) == {}
        assert json.dumps(ct.to_dict(), sort_keys=True) == before


class TestReconcileDisclosure:
    """End-of-run reconciliation wiring: the "outside the phase
    ledger" INFO line fires only for genuinely unknown classes, and
    at most once per run — registered classes are booked silently."""

    @staticmethod
    def _rec(call_class: str, cost: float) -> dict[str, object]:
        return {
            "event": "call", "disposition": "ok",
            "call_class": call_class, "cost_usd": cost,
        }

    def _reconcile(
        self,
        monkeypatch,
        *,
        records: list[dict[str, object]],
        client_total: float,
    ):
        from core.audit import orchestrator as orch
        from core.llm import telemetry

        sink = telemetry.TelemetrySink(
            # Path never written — records go through record() which
            # tolerates unwritable parents anyway (same harness as
            # test_cost_reconciliation.py).
            Path("/nonexistent-dir/t.jsonl"),
        )
        for rec in records:
            sink.record(dict(rec))

        infos: list[str] = []
        real_info = orch.logger.info

        def _capture(msg, *args, **kw):
            infos.append(msg % args if args else str(msg))
            real_info(msg, *args, **kw)

        monkeypatch.setattr(orch.logger, "info", _capture)
        monkeypatch.setattr(telemetry, "_sink", sink)

        result = orch.OrchestratorResult()
        result.cost_tracker.record_call("review", cost_usd=27.28)
        client = SimpleNamespace(total_cost=client_total)
        config = SimpleNamespace(llm_budget_client=client, out_dir=None)
        orch._reconcile_cost_ledgers(config, result)
        return result, infos

    def test_reconcile_logs_no_unknown_class_line_for_registered_classes(
        self, monkeypatch,
    ) -> None:
        result, infos = self._reconcile(
            monkeypatch,
            records=[
                self._rec("review", 27.28),
                self._rec("glance_batch", 4.6),
                self._rec("concept_discovery", 1.2),
            ],
            client_total=33.08,
        )
        assert [m for m in infos if "outside the phase ledger" in m] == []
        # The spend still lands on its named phases and the ledger
        # closes with no unattributed residual.
        tracker = result.cost_tracker
        assert abs(tracker.phases["glance_batch"].cost_usd - 4.6) < 1e-9
        assert abs(
            tracker.phases["concept_discovery"].cost_usd - 1.2
        ) < 1e-9
        assert tracker.unattributed_cost_usd < 0.005

    def test_reconcile_discloses_only_the_unknown_class(
        self, monkeypatch,
    ) -> None:
        result, infos = self._reconcile(
            monkeypatch,
            records=[
                self._rec("review", 27.28),
                self._rec("glance_batch", 4.6),
                self._rec("mystery_class", 0.7),
            ],
            client_total=32.58,
        )
        ledger_lines = [m for m in infos if "outside the phase ledger" in m]
        assert len(ledger_lines) == 1
        assert "mystery_class" in ledger_lines[0]
        assert "glance_batch" not in ledger_lines[0]
        assert "1 call class(es)" in ledger_lines[0]
        # The unknown class is booked (fail-open), not just named.
        assert abs(
            result.cost_tracker.phases["mystery_class"].cost_usd - 0.7
        ) < 1e-9
