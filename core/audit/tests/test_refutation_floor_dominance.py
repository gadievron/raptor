"""Receipt-floor dominance — the floor weighs the refuter, not just
the dismissal.

A detection-grade receipt outranks an UNVERIFIED dismissal (the
existing floor), but a proof-grade refuter of the same claim family
outranks the receipt: the full demote stands and the overridden
receipt is persisted through the suppressions.jsonl chokepoint with
``dropped: false``. Heuristic refuters never dominate; findings with
confirming tool evidence are never refuted at all.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from core.audit.refutation import (
    RefutationVerdict,
    _refute_by_architecture,
    _refute_by_contract,
    _refute_by_callee_inheritance,
    _refute_by_known_return_type,
    _refute_by_lifecycle,
    diagnose_rescue,
    rescue_self_refuted,
)


@dataclass
class _Outcome:
    file: str = "src/net.c"
    function: str = "handle_packet"
    status: str = "clean"
    body: str = ""
    hypothesis: str = ""
    hypotheses: Optional[list] = None
    evidence_tool: str = ""
    review_result: Optional[Dict[str, Any]] = None
    line: int = 42


@dataclass
class _Config:
    target_path: Path = field(default_factory=lambda: Path("/nonexistent"))
    out_dir: Optional[Path] = None


def _read_suppressions(out_dir: Path) -> list:
    p = out_dir / "suppressions.jsonl"
    if not p.exists():
        return []
    return [
        json.loads(line)
        for line in p.read_text().splitlines() if line.strip()
    ]


# ---------------------------------------------------------------------------
# Per-gate refuter grades
# ---------------------------------------------------------------------------


class TestRefuterGrades:
    """Each gate's verdict declares the evidence class of its refuting
    fact; only the return-range table is interpretation-free."""

    def test_default_grade_is_heuristic(self):
        v = RefutationVerdict(gate="g", reason="r", demote_to="clean")
        assert v.refuter_grade == "heuristic"

    def test_known_return_type_is_proof(self):
        o = _Outcome(
            status="finding",
            hypothesis=(
                "integer overflow: the ntohs() length wraps the "
                "accumulator"
            ),
            review_result={"cwe": "CWE-190"},
        )
        v = _refute_by_known_return_type(o, None)
        assert v is not None
        assert v.demote_to == "clean"
        assert v.refuter_grade == "proof"

    def test_architecture_is_heuristic(self):
        o = _Outcome(
            status="finding",
            hypothesis="race between reader and writer",
            review_result={"cwe": "CWE-362"},
        )
        dm = {"architecture": {"threading_model": "single_threaded"}}
        v = _refute_by_architecture(o, dm, None, _Config())
        assert v is not None
        assert v.refuter_grade == "heuristic"

    def test_lifecycle_is_heuristic(self):
        checklist = {
            "files": [{
                "path": "src/main.c",
                "items": [],
                "call_graph": {"calls": [
                    {"caller": "main", "chain": ["setup_config"],
                     "line": 5},
                    {"caller": "main", "chain": ["epoll_wait"],
                     "line": 20},
                ]},
            }],
        }
        o = _Outcome(
            status="finding",
            function="setup_config",
            hypothesis="the config fd is leaked, never closed",
            review_result={"cwe": "CWE-772"},
        )
        v = _refute_by_lifecycle(o, checklist)
        assert v is not None
        assert v.refuter_grade == "heuristic"

    def test_contract_is_heuristic(self):
        o = _Outcome(
            status="finding",
            hypothesis="attacker-controlled input reaches the parser",
        )
        dm = {"contracts": [{
            "function": "handle_packet",
            "input_semantics": "locally generated cache copy",
        }]}
        v = _refute_by_contract(o, dm)
        assert v is not None
        assert v.demote_to == "suspicious"
        assert v.refuter_grade == "heuristic"

    def test_callee_inheritance_is_heuristic(self):
        o = _Outcome(
            status="finding",
            hypothesis=(
                "the function parse_inner has a buffer overflow in "
                "its length handling"
            ),
        )
        source = (
            "int handle_packet(struct pkt *p)\n"
            "{\n"
            "\treturn parse_inner(p);\n"
            "}\n"
        )
        v = _refute_by_callee_inheritance(o, source, ["parse_inner"])
        assert v is not None
        assert v.refuter_grade == "heuristic"


# ---------------------------------------------------------------------------
# Dominance over the detector-receipt floor
# ---------------------------------------------------------------------------


_PROOF_REFUTABLE_MECH = (
    "CWE-190: integer overflow — the ntohs() length wraps the "
    "32-bit accumulator downstream"
)


class TestProofRefuterDominatesDetectorFloor:
    """A proof-grade refuter of the dismissed hypothesis beats the
    integer-contract screen receipt: full demote, demote-with-record."""

    def _outcome(self, mechanism=_PROOF_REFUTABLE_MECH, conf="low"):
        return _Outcome(
            hypotheses=[{
                "mechanism": mechanism,
                "confidence": conf,
                "counter": "the value is bounded by its return type",
            }],
        )

    def test_proof_refuted_dismissal_fully_demotes(self, tmp_path: Path):
        r = rescue_self_refuted(
            self._outcome(),
            config=_Config(out_dir=tmp_path),
            pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is None

    def test_dominance_writes_suppressions_record(self, tmp_path: Path):
        cfg = _Config(out_dir=tmp_path)
        r = rescue_self_refuted(
            self._outcome(),
            config=cfg,
            pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is None
        recs = _read_suppressions(tmp_path)
        assert len(recs) == 1
        rec = recs[0]
        assert rec["dropped"] is False
        assert rec["verdict"] == "refuter_dominates_receipt"
        assert rec["file_path"] == "src/net.c"
        assert rec["function"] == "handle_packet"
        assert rec["line"] == 42
        assert rec["rule_id"] == "audit:receipt-floor-dominance"
        assert "smt:check-parsed-int-contract" in rec["reason"]
        assert rec["refuter_gate"] == "input_bound_t0"
        assert rec["refuter_grade"] == "proof"
        assert rec["floor_gate"] == "anti_self_refutation"

    def test_heuristic_only_dismissal_still_floored(self, tmp_path: Path):
        """No proof-grade refuting fact — the receipt keeps outranking
        the unverified dismissal (today's behaviour)."""
        cfg = _Config(out_dir=tmp_path)
        r = rescue_self_refuted(
            self._outcome(
                "huge parsed values overflow int32 storage downstream",
            ),
            config=cfg,
            pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is not None
        assert r.demote_to == "suspicious"
        assert _read_suppressions(tmp_path) == []

    def test_uncovered_receipt_family_not_dominated(self):
        """Family alignment: the return-range fact refutes the
        overflow aspect only — it may not dominate an uninitialised-
        return receipt even when the mechanism mentions both."""
        o = self._outcome(
            "the return value is left unset when the switch falls "
            "through; separately the ntohs() port triggers an "
            "integer overflow wraparound",
        )
        r = rescue_self_refuted(
            o,
            detector_findings=[{"detector": "cocci:uninitialized_return"}],
        )
        assert r is not None
        assert r.demote_to == "suspicious"

    def test_embedded_bounded_name_not_dominated(self, tmp_path: Path):
        """A custom identifier embedding a bounded libc name
        (utf8_tolower) is not that libc function — its range guarantee
        proves nothing about the custom function, so the receipt floor
        stands instead of a proof-grade override demoting to clean."""
        r = rescue_self_refuted(
            self._outcome(
                "CWE-190: integer overflow — the utf8_tolower() result "
                "wraps the 32-bit accumulator downstream",
            ),
            config=_Config(out_dir=tmp_path),
            pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is not None
        assert r.demote_to == "suspicious"
        assert _read_suppressions(tmp_path) == []

    def test_incidental_bounded_name_far_from_claim_not_dominated(self):
        """Hostile/weird phrasing: a bounded function mentioned three
        sentences away from an unrelated overflow claim is not a range
        proof for that claim — the floor stands."""
        far = (
            "the header parser calls ntohs on the port. "
            + "padding words. " * 20
            + "an unrelated integer overflow occurs in the checksum "
              "accumulator"
        )
        r = rescue_self_refuted(
            self._outcome(far),
            pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is not None
        assert r.demote_to == "suspicious"

    def test_confirming_receipt_untouched(self, tmp_path: Path):
        """Tool-confirmed outcomes are never refuted — and no
        dominance record is written for them."""
        cfg = _Config(out_dir=tmp_path)
        o = self._outcome()
        o.evidence_tool = "semgrep"
        r = rescue_self_refuted(
            o,
            config=cfg,
            pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is None
        assert _read_suppressions(tmp_path) == []

    def test_unrecordable_dominance_refused(self):
        """Record-or-refuse: a config without a record sink cannot
        write the demote-with-record row, so the dominance is refused
        and the floor stands — an unrecorded override would be
        silent."""
        r = rescue_self_refuted(
            self._outcome(),
            config=_Config(out_dir=None),
            pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is not None
        assert r.demote_to == "suspicious"

    def test_record_write_failure_refuses_dominance(
        self, tmp_path: Path, monkeypatch,
    ):
        """A chokepoint failure mid-write also refuses: the floor
        stands and no partial dominance survives as the verdict."""
        import core.analysis.reach_chokepoint as chokepoint

        def failing(*_a, **_k):
            raise OSError("record sink failed")

        monkeypatch.setattr(chokepoint, "record_suppression", failing)
        cfg = _Config(out_dir=tmp_path)
        r = rescue_self_refuted(
            self._outcome(),
            config=cfg,
            pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is not None
        assert r.demote_to == "suspicious"
        assert _read_suppressions(tmp_path) == []

    def test_other_hypothesis_still_floors_after_dominance(
        self, tmp_path: Path,
    ):
        """Dominance is per hypothesis: a second dismissed hypothesis
        without a proof refuter keeps the floor."""
        cfg = _Config(out_dir=tmp_path)
        o = _Outcome(
            hypotheses=[
                {
                    "mechanism": _PROOF_REFUTABLE_MECH,
                    "confidence": "low",
                    "counter": "bounded by return type",
                },
                {
                    "mechanism": (
                        "parsed int64 narrows into the int32 field "
                        "without a range check"
                    ),
                    "confidence": "low",
                    "counter": "values are small in practice",
                },
            ],
        )
        r = rescue_self_refuted(
            o, config=cfg, pre_evidence="smt:check-parsed-int-contract",
        )
        assert r is not None
        assert r.demote_to == "suspicious"
        # The dominated first hypothesis is still recorded.
        recs = _read_suppressions(tmp_path)
        assert len(recs) == 1


# ---------------------------------------------------------------------------
# Dominance over the structural-receipt floor
# ---------------------------------------------------------------------------


class TestProofRefuterDominatesStructuralFloor:
    _RECEIPT = {
        "check_type": "integer_overflow_bound",
        "function": "handle_packet",
        "file": "src/net.c",
    }

    def _outcome(self, mechanism):
        return _Outcome(
            hypotheses=[{
                "mechanism": mechanism,
                "confidence": "refuted",
                "counter": "the value is bounded by its return type",
            }],
        )

    def test_proof_refuted_self_refutation_fully_demotes(
        self, tmp_path: Path,
    ):
        cfg = _Config(out_dir=tmp_path)
        o = self._outcome(
            "integer overflow when the bound from ntohs() wraps the "
            "allocation size",
        )
        r = rescue_self_refuted(
            o, config=cfg, negative_space=[self._RECEIPT],
        )
        assert r is None
        recs = _read_suppressions(tmp_path)
        assert len(recs) == 1
        assert recs[0]["receipt"] == "integer_overflow_bound"
        assert recs[0]["dropped"] is False

    def test_without_proof_refuter_structural_floor_stands(self):
        o = self._outcome(
            "integer overflow when the bound computation wraps the "
            "allocation size",
        )
        r = rescue_self_refuted(o, negative_space=[self._RECEIPT])
        assert r is not None
        assert r.demote_to == "suspicious"

    def test_mixed_receipts_floor_in_both_orderings(
        self, tmp_path: Path,
    ):
        """Dominance is over the WHOLE matching receipt set: when a
        hypothesis matches two structural receipts and the proof gate
        covers only one family, the floor stands whatever the receipt
        order — dominance over one family must not silence the other —
        and no dominance row is written for a floor that fired."""
        mech = (
            "integer overflow when the bound from ntohs() wraps the "
            "allocation size check"
        )
        covered = {
            "check_type": "integer_overflow_bound",
            "function": "handle_packet",
            "file": "src/net.c",
        }
        uncovered = {
            "check_type": "allocation_size_check",
            "function": "handle_packet",
            "file": "src/net.c",
        }
        for ordering in ([covered, uncovered], [uncovered, covered]):
            out = tmp_path / f"o{ordering[0]['check_type'][:5]}"
            out.mkdir()
            r = rescue_self_refuted(
                self._outcome(mech),
                config=_Config(out_dir=out),
                negative_space=list(ordering),
            )
            assert r is not None, ordering[0]["check_type"]
            assert r.demote_to == "suspicious"
            assert _read_suppressions(out) == []

    def test_diagnose_reports_dominance_instead_of_would_fire(self):
        o = self._outcome(
            "integer overflow when the bound from ntohs() wraps the "
            "allocation size",
        )
        d = diagnose_rescue(o, negative_space=[self._RECEIPT])
        assert d is not None
        assert d["blocked_on"] == "proof_refuter_dominance"
        assert d["receipt"] == "integer_overflow_bound"


# ---------------------------------------------------------------------------
# Dominance in the post-loop receipt-corroboration gate
# ---------------------------------------------------------------------------


_PROTECTED_C_SRC = (
    "void upd(struct shared *s) {\n"
    "    spin_lock(&s->lock);\n"
    "    s->count++;\n"
    "    spin_unlock(&s->lock);\n"
    "}\n"
)

_UNPROTECTED_C_SRC = (
    "void upd(struct shared *s) {\n"
    "    s->count++;\n"
    "}\n"
)


class TestReceiptCorroborationGateDominance:
    """The post-loop receipt-corroboration floor weighs the refuter:
    a proof-grade refuter of the receipt's family, or the
    race-protection witness corroborating a shared-writer dismissal,
    overrides the floor with a durable record."""

    def _int_receipt(self):
        return {
            "check_type": "integer_overflow_bound",
            "file": "src/net.c",
            "function": "handle_packet",
            "evidence": "2 ntohs() call(s) feed the allocation size",
        }

    def _race_receipt(self):
        return {
            "check_type": "shared_writer_race",
            "file": "src/net.c",
            "function": "handle_packet",
            "evidence": "2 upd() call(s) write the shared counter",
        }

    def _outcome(self, mechanism, conf="low"):
        return _Outcome(
            hypotheses=[{
                "mechanism": mechanism,
                "confidence": conf,
                "counter": "",
            }],
        )

    def test_proof_refuter_overrides_corroboration_floor(
        self, tmp_path: Path,
    ):
        from core.audit.receipt_resolution import (
            _receipt_corroborated_hypothesis,
        )
        cfg = _Config(out_dir=tmp_path)
        o = self._outcome(
            "integer overflow when the bound from ntohs() wraps the "
            "allocation size",
        )
        rv = _receipt_corroborated_hypothesis(
            o, [self._int_receipt()], config=cfg, source=None,
        )
        assert rv is None
        recs = _read_suppressions(tmp_path)
        assert len(recs) == 1
        assert recs[0]["verdict"] == "refuter_dominates_receipt"
        assert recs[0]["floor_gate"] == "receipt_corroborated_hypothesis"
        assert recs[0]["dropped"] is False

    def test_race_witness_corroborates_dismissal(self, tmp_path: Path):
        from core.audit.receipt_resolution import (
            _receipt_corroborated_hypothesis,
        )
        cfg = _Config(out_dir=tmp_path)
        o = self._outcome(
            "concurrent upd() writers could interleave on the shared "
            "counter without holding the lock",
        )
        rv = _receipt_corroborated_hypothesis(
            o, [self._race_receipt()],
            config=cfg, source=_PROTECTED_C_SRC,
        )
        assert rv is None
        recs = _read_suppressions(tmp_path)
        assert len(recs) == 1
        assert recs[0]["verdict"] == "witness_corroborates_dismissal"
        assert recs[0]["receipt"] == "shared_writer_race"
        assert recs[0]["dropped"] is False

    def test_unprotected_source_keeps_floor(self):
        from core.audit.receipt_resolution import (
            _receipt_corroborated_hypothesis,
        )
        o = self._outcome(
            "concurrent upd() writers could interleave on the shared "
            "counter without holding the lock",
        )
        rv = _receipt_corroborated_hypothesis(
            o, [self._race_receipt()],
            config=None, source=_UNPROTECTED_C_SRC,
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"

    def test_no_source_keeps_floor(self):
        from core.audit.receipt_resolution import (
            _receipt_corroborated_hypothesis,
        )
        o = self._outcome(
            "concurrent upd() writers could interleave on the shared "
            "counter without holding the lock",
        )
        rv = _receipt_corroborated_hypothesis(
            o, [self._race_receipt()], config=None, source=None,
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"


class TestPostLoopDominanceWiring:
    """The post-loop backstop threads config to the gate so a
    dominated floor leaves its record in the run's suppressions."""

    def test_dominated_dismissal_not_refloored(self, tmp_path: Path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            OrchestratorResult,
            ReviewOutcome,
            _post_loop_receipt_rescue,
        )
        target = tmp_path / "target"
        target.mkdir()
        (target / "n.go").write_text("package p\n")
        out = tmp_path / "out"
        out.mkdir()
        config = OrchestratorConfig(target_path=target, out_dir=out)
        outcome = ReviewOutcome(
            file="n.go", function="parsePort", status="clean",
            body="reviewed clean", line=1,
            hypotheses=[{
                "mechanism": _PROOF_REFUTABLE_MECH,
                "confidence": "low",
                "counter": "bounded by the uint16 return range",
            }],
        )
        result = OrchestratorResult()
        result.outcomes = [outcome]
        gaps = [{
            "file": "n.go", "name": "parsePort",
            "line_start": 1, "line_end": 2,
            "_smt_pre_evidence": "smt:check-parsed-int-contract",
        }]
        flipped = _post_loop_receipt_rescue(
            result, [], config, gaps=gaps,
        )
        assert flipped == 0
        assert outcome.status == "clean"
        recs = _read_suppressions(out)
        assert len(recs) == 1
        assert recs[0]["verdict"] == "refuter_dominates_receipt"
        assert recs[0]["function"] == "parsePort"
