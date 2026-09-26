"""no_trigger engagement telemetry for taxonomy-gated tiers.

An all-zero tier stanza cannot distinguish "the tier never saw an
eligible item" from "the tier examined every claim and none matched
its trigger vocabulary" — binary audits shipped indistinguishable
all-zero disasm_xcheck stanzas either way. Taxonomy declines are now
counted (``TierCounters.no_trigger``), rendered by the diagnostics
table, written to tier-diagnostics.json only when nonzero (the
extra-keys contract), and the glance-batch refutation call site
passes the run's tier counters so its outcomes land in the same
telemetry as the main review loop's.
"""

from __future__ import annotations

import json
import threading
import types

from core.audit.diagnostics import (
    format_tier_diagnostics,
    increment_tier_dict,
    write_tier_diagnostics,
)
from core.audit.orchestrator import _make_tier_counters


class TestNoTriggerField:
    def test_increment_tier_dict_books_no_trigger(self):
        # The dataclass must carry the field itself — without it,
        # increment_tier_dict's setattr would mint an instance
        # attribute and the assertion below would pass vacuously
        # against a counters shape the rest of the pipeline never
        # serialises.
        from core.audit.orchestrator import TierCounters

        assert "no_trigger" in TierCounters.__dataclass_fields__
        tiers = _make_tier_counters()
        increment_tier_dict(tiers, "disasm_xcheck", "no_trigger")
        increment_tier_dict(tiers, "disasm_xcheck", "no_trigger")
        assert tiers["disasm_xcheck"].no_trigger == 2

    def test_field_defaults_to_zero_on_every_tier(self):
        tiers = _make_tier_counters()
        assert all(tc.no_trigger == 0 for tc in tiers.values())


class TestRendering:
    def test_no_trigger_only_tier_renders(self):
        # Pre-fix the renderer's suppression guard skipped a tier
        # whose only activity was taxonomy declines — the engaged-
        # but-not-matching signal never printed.
        tiers = _make_tier_counters()
        tiers["disasm_xcheck"].no_trigger = 38
        table = format_tier_diagnostics(tiers)
        line = next(
            ln for ln in table.splitlines() if "disasm_xcheck" in ln
        )
        assert "38 no-trigger" in line

    def test_all_zero_tier_stays_suppressed(self):
        # The other direction: the guard still suppresses genuinely
        # untouched tiers, so source-only runs print no dead stanza.
        table = format_tier_diagnostics(_make_tier_counters())
        assert "disasm_xcheck" not in table

    def test_no_trigger_renders_alongside_outcomes(self):
        tiers = _make_tier_counters()
        tiers["disasm_xcheck"].refuted = 2
        tiers["disasm_xcheck"].no_trigger = 5
        table = format_tier_diagnostics(tiers)
        line = next(
            ln for ln in table.splitlines() if "disasm_xcheck" in ln
        )
        assert "2 refuted" in line
        assert "5 no-trigger" in line


class TestWriter:
    def test_written_only_when_nonzero(self, tmp_path):
        tiers = _make_tier_counters()
        tiers["disasm_xcheck"].no_trigger = 5
        write_tier_diagnostics(tiers, tmp_path)
        data = json.loads(
            (tmp_path / "tier-diagnostics.json").read_text(),
        )
        assert data["disasm_xcheck"]["no_trigger"] == 5
        # Extra-keys contract: zero-decline tiers keep their exact
        # pre-existing shape.
        assert "no_trigger" not in data["semgrep"]


class TestGlanceBatchWiring:
    def test_glance_batch_passes_run_tier_counters(
        self, monkeypatch, tmp_path,
    ):
        # The glance-batch refutation call site must tally into the
        # SAME run-level counters as the main loop — pre-fix it
        # omitted tier_counters and every glance-batch adjudication
        # vanished from tier-diagnostics.json.
        import core.audit.executor as ex
        import core.audit.orchestrator as orch
        import core.audit.refutation as refutation

        recorded: dict = {}

        def fake_refute(outcome, **kwargs):
            recorded.update(kwargs)
            return None

        monkeypatch.setattr(
            refutation, "refute_hypothesis", fake_refute,
        )
        monkeypatch.setattr(
            orch, "_build_context", lambda *a, **k: {},
        )
        monkeypatch.setattr(
            orch, "_tally_outcome", lambda *a, **k: None,
        )

        outcome = types.SimpleNamespace(
            status="finding", file="binary:fixture", function="f",
            cost_usd=0.0, line=0,
        )
        task = types.SimpleNamespace(
            gap={"file": "binary:fixture", "name": "f",
                 "line_start": 3},
            key="binary:fixture:f:3",
        )
        shared = types.SimpleNamespace(
            checklist={}, context_map={}, evidence_index={},
            domain_model=None, triage_results=None,
        )
        result = types.SimpleNamespace(
            tier_counters=_make_tier_counters(),
            _lock=threading.Lock(), total_cost_usd=0.0,
        )

        class _Collector:
            def submit(self, outcome, gap) -> None:
                pass

        ex._process_glance_batch(
            [task],
            lambda contexts, config: [outcome],
            shared,
            types.SimpleNamespace(out_dir=tmp_path),
            result,
            review_one_fn=lambda *a, **k: None,
            review_fn=None,
            collector=_Collector(),
        )
        assert recorded, "refutation gate never dispatched"
        assert recorded.get("tier_counters") is result.tier_counters
