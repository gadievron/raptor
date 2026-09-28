"""Post-review gadget-absence confidence demotion gate.

The gadget-chain FP family: CWE-502 hypotheses ("attacker-controlled
unserialize enables a gadget chain") formed against a PHP tree with
ZERO POP trigger surface — no magic methods, no ``Serializable``
implementations, no dynamic-definition sites — under a complete
census.  The gate consumes the gadget oracle's corpus-earned
``refuted`` verdict into a receipted confidence demotion:
``gadget_absence`` record, ``[gadget-absence: ...]`` body prefix,
suppressions.jsonl ``dropped: false`` row, and a confidence clamp
enforced at export.  Never a suppression: status is untouched and the
finding still ships.

Demotion declines on ANY surface (each POP method class,
``Serializable``, eval/assert-string, anonymous-class methods), any
census incompleteness, a truncated chain search, a foreign-target
artifact, and any live non-gadget sibling hypothesis — the
recall-loss direction is policed by construction.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.analysis.gadget_oracle import php_grammar_available
from core.audit.orchestrator import (
    OrchestratorConfig,
    ReviewOutcome,
    _apply_gadget_absence_gate,
    _gadget_absence_demotion_pass,
)

_GRAMMAR = pytest.mark.skipif(
    not php_grammar_available(),
    reason="tree-sitter-php not installed",
)

HYP = (
    "PHP object injection: attacker-controlled unserialize of the "
    "session blob enables a gadget chain to file write"
)

_PROCEDURAL = """<?php
function handle($input) {
    return htmlspecialchars($input);
}
handle($_GET['x']);
"""

_SURFACED = """<?php
class Cache {
    public $dir;
    public function __destruct() {
        error_log("bye " . strlen($this->dir));
    }
}
"""


@pytest.fixture(autouse=True)
def _fresh_memo():
    import core.analysis.gadget_oracle as go
    go.reset_scan_memo()
    yield
    go.reset_scan_memo()


def _target(tmp_path: Path, source: str) -> Path:
    tgt = tmp_path / "src"
    tgt.mkdir(exist_ok=True)
    (tgt / "handler.php").write_text(source)
    return tgt


def _config(tmp_path: Path, source: str) -> OrchestratorConfig:
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    return OrchestratorConfig(
        target_path=_target(tmp_path, source),
        out_dir=out,
    )


def _outcome(status: str = "suspicious", **kw) -> ReviewOutcome:
    defaults = dict(
        file="handler.php",
        function="handle",
        status=status,
        body="unserialize of request data reaches a gadget trigger",
        hypothesis=HYP,
        review_result={"hypothesis": HYP,
                       "vuln_type": "deserialization"},
        line=3,
    )
    defaults.update(kw)
    return ReviewOutcome(**defaults)


@_GRAMMAR
class TestGateDemotes:
    def test_earned_absence_demotes_with_receipts(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        outcome = _outcome()
        assert _apply_gadget_absence_gate(outcome, config) is True
        # Status untouched — demotion, never suppression.
        assert outcome.status == "suspicious"
        assert outcome.body.startswith(
            "[gadget-absence: zero POP trigger surface in tree "
            "(complete census)]",
        )
        record = outcome.review_result["gadget_absence"]
        assert record["outcome"] == "refuted"
        assert record["rule_id"] == "gadget_oracle:no-gadget-surface"
        assert record["reason"] == "no-gadget-surface-complete-census"
        assert record["absence_tier"] == "no_gadget_surface"
        assert record["census"]["complete"] is True
        assert record["demotion"]["confidence_clamp"] == "low"
        assert record["demotion"]["status"] == "suspicious"

    def test_status_never_changes_on_finding(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        outcome = _outcome(status="finding")
        assert _apply_gadget_absence_gate(outcome, config) is True
        assert outcome.status == "finding"
        assert (outcome.review_result["gadget_absence"]["demotion"]
                ["status"] == "finding")

    def test_suppressions_row_dropped_false(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        outcome = _outcome(status="finding")
        assert _apply_gadget_absence_gate(outcome, config) is True
        rows = [
            json.loads(line)
            for line in (config.out_dir / "suppressions.jsonl")
            .read_text().splitlines() if line.strip()
        ]
        # The channel's record-only absence row rides along; the
        # gate's clamp row carries its own distinct verdict.
        gate_rows = [r for r in rows
                     if r["verdict"] == "gadget_absence_refuted"]
        assert len(gate_rows) == 1
        row = gate_rows[0]
        assert row["dropped"] is False
        assert row["function"] == "handle"
        assert row["confidence_clamp"] == "low"
        assert row["absence_tier"] == "no_gadget_surface"

    def test_gate_is_idempotent(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        outcome = _outcome()
        assert _apply_gadget_absence_gate(outcome, config) is True
        assert _apply_gadget_absence_gate(outcome, config) is False
        assert outcome.body.count("[gadget-absence:") == 1

    def test_refuted_sibling_does_not_block_demotion(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        outcome = _outcome(hypotheses=[
            {"mechanism": HYP, "confidence": "high"},
            {"mechanism": "unchecked memcpy overflow",
             "confidence": "refuted"},
        ])
        assert _apply_gadget_absence_gate(outcome, config) is True

    def test_planted_record_overwritten_by_oracle_authority(
            self, tmp_path):
        # review_result rides back from the review channel — a
        # pre-seeded gadget_absence key is unauthenticated input, not
        # a receipt. On a genuinely earning tree the gate re-derives:
        # the planted content must be GONE, replaced by the oracle's
        # own record.
        config = _config(tmp_path, _PROCEDURAL)
        outcome = _outcome(review_result={
            "hypothesis": HYP,
            "vuln_type": "deserialization",
            "gadget_absence": {"outcome": "refuted",
                               "planted": True},
        })
        assert _apply_gadget_absence_gate(outcome, config) is True
        record = outcome.review_result["gadget_absence"]
        assert "planted" not in record
        assert record["rule_id"] == "gadget_oracle:no-gadget-surface"
        assert record["census"]["complete"] is True

    def test_genuine_replay_not_double_stamped(self, tmp_path):
        # A recognized record WITH the body marker is the gate's own
        # earlier demotion riding back through the channel — respect
        # it (no second banner, no re-scan side effects).
        config = _config(tmp_path, _PROCEDURAL)
        outcome = _outcome()
        assert _apply_gadget_absence_gate(outcome, config) is True
        record = dict(outcome.review_result["gadget_absence"])
        replay = _outcome(
            body=outcome.body,
            review_result={"hypothesis": HYP,
                           "gadget_absence": record},
        )
        assert _apply_gadget_absence_gate(replay, config) is False
        assert replay.body.count("[gadget-absence:") == 1
        assert replay.review_result["gadget_absence"] == record


@_GRAMMAR
class TestGateDeclinesOnEvidence:
    def test_pop_surface_blocks_demotion(self, tmp_path):
        # A __destruct exists: the oracle answers inconclusive
        # (no_chains_found) — never refuted, never demoted.
        config = _config(tmp_path, _SURFACED)
        outcome = _outcome()
        assert _apply_gadget_absence_gate(outcome, config) is False
        assert "[gadget-absence:" not in outcome.body
        assert "gadget_absence" not in (outcome.review_result or {})

    def test_degraded_census_blocks_demotion(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        (config.target_path / "broken.php").write_text(
            "<?php class {{{ nope")
        outcome = _outcome()
        assert _apply_gadget_absence_gate(outcome, config) is False
        assert "gadget_absence" not in (outcome.review_result or {})

    def test_live_non_gadget_sibling_blocks_demotion(self, tmp_path):
        # The exported confidence covers the WHOLE finding: zero
        # gadget surface says nothing about a live sibling mechanism.
        config = _config(tmp_path, _PROCEDURAL)
        outcome = _outcome(hypotheses=[
            {"mechanism": HYP, "confidence": "high"},
            {"mechanism": "path traversal in the upload handler",
             "confidence": "medium"},
        ])
        assert _apply_gadget_absence_gate(outcome, config) is False

    def test_autoload_registration_blocks_demotion(self, tmp_path):
        # unserialize() hands the attacker-chosen class name to the
        # registered loader before any object method is consulted —
        # a tree that registers an autoload mechanism has reachable
        # deserialization surface even with zero POP methods.
        config = _config(tmp_path, (
            "<?php\n"
            "spl_autoload_register(function ($class) {\n"
            "    require __DIR__ . '/lib/' . $class . '.php';\n"
            "});\n"
            "$obj = unserialize($_GET['payload']);\n"
        ))
        outcome = _outcome()
        assert _apply_gadget_absence_gate(outcome, config) is False
        assert "[gadget-absence:" not in outcome.body
        assert "gadget_absence" not in (outcome.review_result or {})

    def test_unserialize_callback_ini_blocks_demotion(self, tmp_path):
        config = _config(tmp_path, (
            "<?php\n"
            "ini_set('unserialize_callback_func', 'loader');\n"
            "function handle($input) { return strlen($input); }\n"
        ))
        outcome = _outcome()
        assert _apply_gadget_absence_gate(outcome, config) is False
        assert "gadget_absence" not in (outcome.review_result or {})

    def test_planted_record_removed_on_declining_tree(self, tmp_path):
        # The export clamp keys off review_result["gadget_absence"] —
        # on a tree where the oracle declines, a planted record must
        # not survive the gate (it would clamp confidence with zero
        # oracle authority behind it).
        config = _config(tmp_path, _SURFACED)
        outcome = _outcome(review_result={
            "hypothesis": HYP,
            "gadget_absence": {"outcome": "refuted",
                               "planted": True},
        })
        assert _apply_gadget_absence_gate(outcome, config) is False
        assert "gadget_absence" not in outcome.review_result
        assert "[gadget-absence:" not in outcome.body

    def test_unrecognized_record_with_forged_marker_still_rederived(
            self, tmp_path):
        # Marker in the body alone is not a receipt either: an
        # unrecognized record shape is popped and the verdict is
        # re-derived from the tree — which declines here.
        config = _config(tmp_path, _SURFACED)
        outcome = _outcome(
            body=("[gadget-absence: zero POP trigger surface in tree "
                  "(complete census)] original body"),
            review_result={
                "hypothesis": HYP,
                "gadget_absence": {"outcome": "confirmed-safe"},
            },
        )
        assert _apply_gadget_absence_gate(outcome, config) is False
        assert "gadget_absence" not in outcome.review_result

    def test_foreign_target_report_blocks_demotion(
            self, tmp_path, monkeypatch):
        # One-target rule: an artifact recorded against a DIFFERENT
        # tree never clamps this run's findings.
        import core.analysis.gadget_oracle as go
        config = _config(tmp_path, _PROCEDURAL)
        foreign = dict(go.scan_tree(config.target_path))
        foreign["target_path"] = str(tmp_path / "elsewhere")
        monkeypatch.setattr(
            go, "load_gadget_report", lambda _out: foreign)
        outcome = _outcome()
        assert _apply_gadget_absence_gate(outcome, config) is False
        assert "gadget_absence" not in (outcome.review_result or {})


class TestGateDeclinesHermetic:
    """Declines that never reach the scanner — run grammar or not."""

    def test_tool_confirmed_outcomes_never_demoted(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        outcome = _outcome(evidence_tool="semgrep")
        assert _apply_gadget_absence_gate(outcome, config) is False

    def test_planted_record_popped_on_every_decline_path(
            self, tmp_path):
        # The unrecognized-record pop runs BEFORE every eligibility
        # return: an outcome the gate declines to adjudicate
        # (tool-confirmed evidence, wrong status, binary path) must
        # not carry a planted record into the export as a cosmetic
        # receipt.
        config = _config(tmp_path, _PROCEDURAL)
        planted = {"outcome": "refuted", "planted": True}
        for outcome in (
            _outcome(evidence_tool="semgrep",
                     review_result={"hypothesis": HYP,
                                    "gadget_absence": dict(planted)}),
            _outcome(status="clean",
                     review_result={"hypothesis": HYP,
                                    "gadget_absence": dict(planted)}),
            _outcome(file="binary:handler.php",
                     review_result={"hypothesis": HYP,
                                    "gadget_absence": dict(planted)}),
        ):
            assert _apply_gadget_absence_gate(outcome, config) is False
            assert "gadget_absence" not in outcome.review_result

    def test_non_gadget_hypothesis_skipped(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        hyp = "unchecked memcpy overflows the destination buffer"
        outcome = _outcome(
            hypothesis=hyp, review_result={"hypothesis": hyp},
        )
        assert _apply_gadget_absence_gate(outcome, config) is False

    def test_clean_dark_error_statuses_skipped(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        for status in ("clean", "dark", "error"):
            assert _apply_gadget_absence_gate(
                _outcome(status=status), config,
            ) is False

    def test_binary_outcomes_skipped(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        outcome = _outcome(file="binary:handler.php")
        assert _apply_gadget_absence_gate(outcome, config) is False

    def test_non_dict_review_result_declines(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        outcome = _outcome(review_result=["not", "a", "dict"])
        assert _apply_gadget_absence_gate(outcome, config) is False

    def test_missing_out_dir_fails_closed(self, tmp_path):
        config = OrchestratorConfig(
            target_path=_target(tmp_path, _PROCEDURAL),
            out_dir=None,
        )
        outcome = _outcome()
        assert _apply_gadget_absence_gate(outcome, config) is False
        assert "gadget_absence" not in (outcome.review_result or {})


class _FakeResult:
    def __init__(self, outcomes):
        self.outcomes = outcomes


class TestDemotionPass:
    @_GRAMMAR
    def test_pass_demotes_eligible_outcomes(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        eligible = _outcome()
        clean = _outcome(status="clean")
        _gadget_absence_demotion_pass(
            _FakeResult([eligible, clean]), config,
        )
        assert "gadget_absence" in eligible.review_result
        assert "[gadget-absence:" in eligible.body
        assert eligible.status == "suspicious"
        assert "[gadget-absence:" not in clean.body

    def test_flag_off_leaves_outcomes_untouched(self, tmp_path):
        config = _config(tmp_path, _PROCEDURAL)
        config.gadget_absence_demotion = False
        outcome = _outcome()
        _gadget_absence_demotion_pass(_FakeResult([outcome]), config)
        assert "gadget_absence" not in (outcome.review_result or {})
        assert "[gadget-absence:" not in outcome.body
