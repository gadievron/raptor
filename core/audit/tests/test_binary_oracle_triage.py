"""Binary-oracle absent-suppression at audit hypothesis-triage.

The oracle chokepoint already serves /agentic, /codeql, /validate and
/understand; these tests pin its consumption at audit triage: absent
functions (full-DWARF tier only) are skipped or hard-deprioritised
before hypothesis/synthesis budget is spent, promotions inside absent
functions are demoted with the verdict as mechanical evidence, and
every suppression leaves a suppressions.jsonl record.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.audit.orchestrator import (
    OrchestratorConfig,
    OrchestratorResult,
    ReviewOutcome,
    _binary_absent_gap_keys,
    _demote_absent_promotions,
    _record_triage_suppressions,
)
from core.audit.priority import SCORE_BINARY_ABSENT, score_functions
from core.audit.triage import TriageBucket, classify_all, classify_function


def _config(tmp_path, **kw):
    out_dir = tmp_path / "out"
    out_dir.mkdir(exist_ok=True)
    return OrchestratorConfig(
        target_path=tmp_path / "target",
        out_dir=out_dir,
        **kw,
    )


def _gap(file="a.c", name="foo", line_start=10, sloc=40):
    return {
        "file": file,
        "name": name,
        "line_start": line_start,
        "line_end": line_start + sloc,
        "priority": 0,
        "strategies": [],
        "is_stale": False,
        "sloc": sloc,
        "metadata": None,
    }


def _enriched_inventory(*, tier="full", classification="absent"):
    return {
        "binary_oracle": {"binaries": [{"tier": tier}]},
        "files": [
            {
                "path": "a.c",
                "language": "c",
                "items": [
                    {
                        "name": "foo",
                        "kind": "function",
                        "line_start": 10,
                        "metadata": {
                            "binary_oracle": {
                                "classification": classification,
                                "binaries": [
                                    {"tier": tier, "verdict": classification},
                                ],
                            },
                        },
                    },
                ],
            },
        ],
    }


class TestTriageClassifier:
    def test_binary_absent_alone_skips(self):
        tr = classify_function(
            file="a.c", function="foo", sloc=40, binary_absent=True,
        )
        assert tr.bucket == TriageBucket.SKIP
        assert any("binary_oracle_absent" in r for r in tr.reasons)

    def test_entry_point_exempt(self):
        tr = classify_function(
            file="a.c", function="foo", sloc=40,
            binary_absent=True, is_entry_point=True,
        )
        assert tr.bucket != TriageBucket.SKIP

    def test_sink_exempt(self):
        tr = classify_function(
            file="a.c", function="foo", sloc=40,
            binary_absent=True, is_sink=True,
        )
        assert tr.bucket != TriageBucket.SKIP

    def test_trust_boundary_exempt(self):
        tr = classify_function(
            file="a.c", function="foo", sloc=40,
            binary_absent=True, is_trust_boundary=True,
        )
        assert tr.bucket != TriageBucket.SKIP

    def test_classify_all_threads_keys(self):
        gaps = [_gap(name="foo"), _gap(name="bar", line_start=100)]
        results = classify_all(
            gaps, binary_absent_keys=frozenset({"a.c:foo"}),
        )
        assert results["a.c:foo:10"].bucket == TriageBucket.SKIP
        assert results["a.c:bar:100"].bucket != TriageBucket.SKIP


class TestPriorityDemotion:
    def test_absent_hard_deprioritised(self):
        gaps = [_gap(name="foo"), _gap(name="bar")]
        result = score_functions(
            gaps, binary_absent_keys={"a.c:foo"},
        )
        by_name = {g["name"]: g for g in result}
        assert (
            by_name["foo"]["priority_score"]
            == by_name["bar"]["priority_score"] + SCORE_BINARY_ABSENT
        )
        assert SCORE_BINARY_ABSENT < 0
        # Absent function sorts after the live one.
        assert result[0]["name"] == "bar"


class TestBinaryAbsentGapKeys:
    def test_full_tier_absent_earns_key(self, tmp_path):
        config = _config(tmp_path, inventory=_enriched_inventory())
        keys = _binary_absent_gap_keys([_gap()], None, config, None)
        assert keys == {"a.c:foo"}

    def test_symbol_only_tier_never_earns(self, tmp_path):
        """Chokepoint tier gating: symbol-only absent never suppresses."""
        config = _config(
            tmp_path, inventory=_enriched_inventory(tier="symbol_only"),
        )
        keys = _binary_absent_gap_keys([_gap()], None, config, None)
        assert keys == set()

    def test_alive_verdicts_not_flagged(self, tmp_path):
        config = _config(
            tmp_path,
            inventory=_enriched_inventory(classification="symbol_present"),
        )
        keys = _binary_absent_gap_keys([_gap()], None, config, None)
        assert keys == set()

    def test_header_files_exempt(self, tmp_path):
        config = _config(tmp_path, binary_verdicts={"foo": "absent"})
        keys = _binary_absent_gap_keys(
            [_gap(file="inc/a.h")], None, config, None,
        )
        assert keys == set()

    def test_entry_points_exempt(self, tmp_path):
        config = _config(tmp_path, binary_verdicts={"foo": "absent"})
        context_map = {"entry_points": [{"file": "a.c", "name": "foo"}]}
        keys = _binary_absent_gap_keys([_gap()], None, config, context_map)
        assert keys == set()

    def test_verdict_map_fallback(self, tmp_path):
        config = _config(tmp_path, binary_verdicts={"foo": "absent"})
        keys = _binary_absent_gap_keys([_gap()], None, config, None)
        assert keys == {"a.c:foo"}

    def test_no_oracle_data_no_keys(self, tmp_path):
        config = _config(tmp_path)
        keys = _binary_absent_gap_keys([_gap()], None, config, None)
        assert keys == set()


def _read_suppressions(out_dir: Path):
    path = out_dir / "suppressions.jsonl"
    if not path.exists():
        return []
    return [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]


class TestSuppressionRecords:
    def test_triage_skip_writes_record(self, tmp_path):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        gaps = [_gap()]
        triage = classify_all(
            gaps, binary_absent_keys=frozenset({"a.c:foo"}),
        )
        n = _record_triage_suppressions(
            gaps, triage, {"a.c:foo"}, out_dir,
        )
        assert n == 1
        records = _read_suppressions(out_dir)
        assert len(records) == 1
        rec = records[0]
        assert rec["verdict"] == "binary_oracle_absent"
        assert rec["file_path"] == "a.c"
        assert rec["function"] == "foo"
        assert rec["line"] == 10
        assert rec["rule_id"] == "audit:hypothesis-triage"
        assert rec["dropped"] is False
        assert rec["stage"] == "hypothesis-triage"

    def test_no_record_for_non_oracle_skip(self, tmp_path):
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        gaps = [_gap()]
        # SKIP for a different reason: no oracle key passed to triage.
        triage = classify_all(gaps)
        n = _record_triage_suppressions(gaps, triage, {"a.c:foo"}, out_dir)
        assert n == 0
        assert _read_suppressions(out_dir) == []


def _promoted_outcome(file="a.c", function="foo", evidence_tool="semgrep:x"):
    o = ReviewOutcome(
        file=file,
        function=function,
        status="finding",
        body="[sweep promoted via semgrep:x]\n\noverflow",
        evidence_tool=evidence_tool,
        review_result={},
    )
    o.line = 10
    return o


class TestDemoteAbsentPromotions:
    def test_promotion_demoted_with_receipt(self, tmp_path):
        config = _config(tmp_path, binary_verdicts={"foo": "absent"})
        result = OrchestratorResult()
        result.outcomes.append(_promoted_outcome())
        result.findings = 1

        n = _demote_absent_promotions(result, config)
        assert n == 1
        demoted = result.outcomes[0]
        assert demoted.status == "dormant"
        assert "binary-oracle demotion" in demoted.body
        assert result.findings == 0
        assert result.dormant == 1
        # Mechanical evidence attached to the review result.
        chain = demoted.review_result["evidence_chain"]
        assert chain[0]["source"] == "mechanical:binary_oracle"
        # Audit trail written.
        records = _read_suppressions(config.out_dir)
        assert len(records) == 1
        assert records[0]["verdict"] == "binary_oracle_absent"
        assert records[0]["stage"] == "promotion-demotion"

    def test_runtime_evidence_vetoes_demotion(self, tmp_path):
        """Chokepoint precedence: runtime evidence beats a stale absent."""
        config = _config(tmp_path, binary_verdicts={"foo": "absent"})
        result = OrchestratorResult()
        result.outcomes.append(
            _promoted_outcome(evidence_tool="dynamic:crash")
        )
        result.findings = 1

        n = _demote_absent_promotions(result, config)
        assert n == 0
        assert result.outcomes[0].status == "finding"
        assert _read_suppressions(config.out_dir) == []

    def test_alive_function_untouched(self, tmp_path):
        config = _config(
            tmp_path, binary_verdicts={"foo": "symbol_present"},
        )
        result = OrchestratorResult()
        result.outcomes.append(_promoted_outcome())
        result.findings = 1

        assert _demote_absent_promotions(result, config) == 0
        assert result.outcomes[0].status == "finding"

    def test_unpromoted_findings_untouched(self, tmp_path):
        config = _config(tmp_path, binary_verdicts={"foo": "absent"})
        result = OrchestratorResult()
        o = ReviewOutcome(
            file="a.c", function="foo", status="finding",
            body="direct LLM finding", evidence_tool="",
        )
        result.outcomes.append(o)
        result.findings = 1

        assert _demote_absent_promotions(result, config) == 0
        assert result.outcomes[0].status == "finding"

    def test_no_oracle_data_noop(self, tmp_path):
        config = _config(tmp_path)
        result = OrchestratorResult()
        result.outcomes.append(_promoted_outcome())
        result.findings = 1
        assert _demote_absent_promotions(result, config) == 0
