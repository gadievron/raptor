"""Gate tests: definite-assignment dominance at the receipt floors.

The detector-receipt floor re-raises a dismissed uninitialised-return
hypothesis to suspicious whenever an active mechanical detector
receipt matches it.  A proof-grade definite-assignment refutation of
the same claim now dominates that receipt: the clean verdict stands
and the overridden receipt is persisted through the suppressions
chokepoint (``dropped: false``, ``verdict:
refuter_dominates_receipt``).  These tests pin the dominance, its
record, the trust gate, and — most importantly — every shape that must
keep flooring: unprovable sources, untrusted targets, cross-family
receipts, non-C sources, and claims whose variable cannot be pinned.

Module-level imports here deliberately avoid ``core.audit.defassign``
so the floor-stands regressions also run against trees that predate
the prover.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

import pytest

from core.audit.refutation import rescue_self_refuted


@dataclass
class _Outcome:
    file: str = "src/lookup.c"
    function: str = "find_slot"
    status: str = "clean"
    line: int = 11
    body: str = ""
    hypothesis: str = ""
    hypotheses: Optional[list] = None
    evidence_tool: str = ""
    review_result: Optional[Dict[str, Any]] = None


@dataclass
class _Config:
    target_path: Optional[Path] = None
    out_dir: Optional[Path] = None
    repo_trusted: bool = True
    integer_abi: Any = None


_PROVABLE_SRC = (
    "static int find_slot(int n)\n"
    "{\n"
    "\tint slot;\n"
    "\n"
    "\tslot = -1;\n"
    "\tif (n > 0)\n"
    "\t\tslot = n;\n"
    "\treturn slot;\n"
    "}\n"
)

# Genuinely uninitialisable on the n <= 0 path.
_UNPROVABLE_SRC = (
    "static int find_slot(int n)\n"
    "{\n"
    "\tint slot;\n"
    "\n"
    "\tif (n > 0)\n"
    "\t\tslot = n;\n"
    "\treturn slot;\n"
    "}\n"
)

_UNINIT_MECH = (
    "Mechanical finding [cocci:uninitialized_return] claims slot may "
    "be returned uninitialized when no branch assigns it"
)
_COUNTER = (
    "slot is assigned -1 before the branch; every return sees a value"
)


def _hyp(mechanism: str = _UNINIT_MECH, conf: str = "refuted") -> dict:
    return {
        "mechanism": mechanism, "confidence": conf, "counter": _COUNTER,
    }


def _receipt(desc: str = (
    "Variable 'slot' (declared line 3) may be returned uninitialized"
)) -> dict:
    return {
        "detector": "cocci:uninitialized_return",
        "file": "src/lookup.c", "function": "find_slot",
        "line": 8, "description": desc,
    }


def _records(out_dir: Path) -> list:
    p = out_dir / "suppressions.jsonl"
    if not p.exists():
        return []
    return [
        json.loads(line)
        for line in p.read_text().splitlines() if line.strip()
    ]


def _write_target(tmp_path: Path, source: str = _PROVABLE_SRC) -> Path:
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "lookup.c").write_text(source)
    return target


def _has_ts_c() -> bool:
    try:
        import tree_sitter
        import tree_sitter_c

        tree_sitter.Parser(tree_sitter.Language(tree_sitter_c.language()))
        return True
    except Exception:
        return False


needs_prover = pytest.mark.skipif(
    not _has_ts_c(),
    reason="definite-assignment prover needs the tree-sitter C grammar",
)


# ---------------------------------------------------------------------------
# Dominance (red on trees without the prover)
# ---------------------------------------------------------------------------


@needs_prover
class TestDominance:
    def test_proven_claim_dominates_detector_receipt(self, tmp_path):
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp()])
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC, detector_findings=[_receipt()],
            target_path=target, out_dir=out, repo_trusted=True,
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is None

    def test_dominance_writes_record(self, tmp_path):
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp()])
        rescue_self_refuted(
            o, source=_PROVABLE_SRC, detector_findings=[_receipt()],
            config=_Config(target_path=target, out_dir=out),
        )
        recs = _records(out)
        assert len(recs) == 1
        rec = recs[0]
        assert rec["verdict"] == "refuter_dominates_receipt"
        assert rec["dropped"] is False
        assert rec["rule_id"] == "audit:receipt-floor-dominance"
        assert rec["refuter_gate"] == "definite_assignment"
        assert rec["refuter_grade"] == "proof"
        assert rec["receipt"] == "cocci:uninitialized_return"
        assert rec["floor_gate"] == "anti_self_refutation"
        assert rec["file_path"] == "src/lookup.c"
        assert rec["function"] == "find_slot"
        assert "slot" in rec["reason"]

    def test_low_confidence_dismissal_also_dominates(self, tmp_path):
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(conf="low")])
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC, detector_findings=[_receipt()],
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is None
        assert len(_records(out)) == 1

    def test_unrecordable_dominance_refused(self, tmp_path):
        # Record-or-refuse (the resealed dominance contract): a
        # config without a record sink cannot write the
        # demote-with-record row, so the dominance is refused and the
        # floor stands.
        target = _write_target(tmp_path)
        o = _Outcome(hypotheses=[_hyp()])
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC, detector_findings=[_receipt()],
            config=_Config(target_path=target, out_dir=None),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"


# ---------------------------------------------------------------------------
# Floor stands (must pass on every tree, before and after the prover)
# ---------------------------------------------------------------------------


class TestFloorStands:
    def test_unprovable_source_floors(self, tmp_path):
        target = _write_target(tmp_path, _UNPROVABLE_SRC)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp()])
        rv = rescue_self_refuted(
            o, source=_UNPROVABLE_SRC, detector_findings=[_receipt()],
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert rv.gate == "anti_self_refutation"
        assert rv.demote_to == "suspicious"
        assert _records(out) == []

    def test_untrusted_repo_floors_without_probe(self, tmp_path):
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp()])
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC, detector_findings=[_receipt()],
            config=_Config(
                target_path=target, out_dir=out, repo_trusted=False,
            ),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"
        assert _records(out) == []

    def test_explicit_untrusted_overrides_config_trust(self, tmp_path):
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp()])
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC, detector_findings=[_receipt()],
            config=_Config(target_path=target, out_dir=out),
            repo_trusted=False,
        )
        assert rv is not None
        assert _records(out) == []

    def test_non_c_source_floors(self, tmp_path):
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(
            file="src/lookup.go", hypotheses=[_hyp()],
        )
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC, detector_findings=[_receipt()],
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_missing_source_floors(self, tmp_path):
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp()])
        rv = rescue_self_refuted(
            o, source=None, detector_findings=[_receipt()],
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_missing_target_path_floors(self, tmp_path):
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp()])
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC, detector_findings=[_receipt()],
            config=_Config(target_path=None, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_receipt_naming_unknown_variable_floors(self, tmp_path):
        # The receipt pins a variable the parsed function does not
        # declare: proving a DIFFERENT variable would not cover the
        # receipt's claim, so the extraction refuses wholesale.
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "Mechanical finding [cocci:uninitialized_return] claims "
            "the result may be returned uninitialized",
        )])
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC,
            detector_findings=[_receipt(
                "Variable 'retcode' (declared line 3) may be returned "
                "uninitialized",
            )],
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_claim_without_any_variable_floors(self, tmp_path):
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "Mechanical finding claims the return value may be "
            "garbage on some path",
        )])
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC,
            detector_findings=[_receipt("may return uninitialized")],
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_receipt_without_named_variable_floors(self, tmp_path):
        # A detector receipt that does not name its variable cannot be
        # covered by proving a variable GUESSED from prose — even when
        # the prose names a provable local.
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp()])  # prose names 'slot' (local)
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC,
            detector_findings=[_receipt("may be returned uninitialized")],
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"
        assert _records(out) == []

    def test_parameter_only_candidates_never_dominate(self, tmp_path):
        # Prose-only PARAMETER laundering: the receipt names no
        # variable and the dismissal prose names only the parameter
        # `n` — the trivial "assigned by the caller" proof must not
        # dominate a receipt on a function whose actual local is NOT
        # provable (an uninitialised-value detector cannot flag a
        # parameter).
        target = _write_target(tmp_path, _UNPROVABLE_SRC)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "Mechanical finding claims the return may be garbage / "
            "left unset when n is negative",
        )])
        rv = rescue_self_refuted(
            o, source=_UNPROVABLE_SRC,
            detector_findings=[_receipt("may be returned uninitialized")],
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"
        assert _records(out) == []

    def test_receipt_naming_parameter_never_dominates(self, tmp_path):
        # Same laundering shape with the parameter named IN the
        # receipt: a candidate set consisting solely of parameters
        # refuses.
        target = _write_target(tmp_path, _UNPROVABLE_SRC)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "Mechanical finding claims n may be used uninitialized",
        )])
        rv = rescue_self_refuted(
            o, source=_UNPROVABLE_SRC,
            detector_findings=[_receipt(
                "Variable 'n' (declared line 1) may be returned "
                "uninitialized",
            )],
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert _records(out) == []

    def test_mixed_receipts_floor_in_both_orderings(self, tmp_path):
        # Dominance is over the WHOLE matching receipt set: a
        # mechanism matching both the uninit receipt (dominable) and
        # a return_domain receipt (out of the prover's family) must
        # floor whatever the receipt order, with no dominance rows.
        target = _write_target(tmp_path)
        mech = (
            "slot is left unset on the failure path — a failure "
            "return value other than the tested -1 escapes the check"
        )
        retdom = {
            "detector": "return_domain",
            "file": "src/lookup.c", "function": "find_slot",
            "line": 8, "description": "wide error domain",
        }
        for i, ordering in enumerate(
            ([_receipt(), dict(retdom)], [dict(retdom), _receipt()]),
        ):
            out = tmp_path / f"out{i}"
            o = _Outcome(hypotheses=[_hyp(mech)])
            rv = rescue_self_refuted(
                o, source=_PROVABLE_SRC,
                detector_findings=list(ordering),
                config=_Config(target_path=target, out_dir=out),
            )
            assert rv is not None, i
            assert rv.demote_to == "suspicious"
            assert _records(out) == []

    def test_mixed_uninit_and_lifetime_claim_keeps_cwe_floor(
        self, tmp_path,
    ):
        # Dominance never touches the receipt-free CWE-allowlist
        # floor: a dismissal that ALSO claims a lifetime defect
        # (CWE-416) floors regardless of the definite-assignment
        # proof for its uninit half.
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "CWE-416: slot may be returned uninitialized after the "
            "backing object is freed",
        )])
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC, detector_findings=[_receipt()],
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"


# ---------------------------------------------------------------------------
# Cross-family controls
# ---------------------------------------------------------------------------


class TestFamilyAlignment:
    def test_covers_uninit_receipts_only(self):
        from core.audit.refutation import (
            RefutationVerdict,
            _refuter_covers_receipt,
        )
        v = RefutationVerdict(
            gate="definite_assignment", reason="r",
            demote_to="clean", refuter_grade="proof",
        )
        assert _refuter_covers_receipt(v, "cocci:uninitialized_return")
        assert _refuter_covers_receipt(v, "typestate-uninit")
        for receipt in (
            "shared_writer_race", "auth_mode_registration",
            "integer_overflow_bound", "return_domain",
            "cocci:use_after_free", "smt:check-parsed-int-contract",
        ):
            assert not _refuter_covers_receipt(v, receipt), receipt

    def test_uncovered_receipt_family_keeps_floor(self, tmp_path):
        # The mechanism reads as BOTH a return-domain claim and an
        # uninit claim; the active receipt is return_domain.  The
        # definite-assignment fact says nothing about return-domain
        # corroboration, so the floor stands.
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "the failure return value slot is left unset — a return "
            "other than the tested -1 escapes the check",
        )])
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC,
            detector_findings=[{
                "detector": "return_domain",
                "file": "src/lookup.c", "function": "find_slot",
                "line": 8, "description": "wide error domain",
            }],
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"
        assert _records(out) == []

    def test_integer_receipt_not_dominated_by_defassign(self, tmp_path):
        # Uninit phrasing against the pre-loop integer screen receipt:
        # out of the prover's family — the floor stands even though
        # the variable itself proves.
        target = _write_target(tmp_path)
        out = tmp_path / "out"
        o = _Outcome(hypotheses=[_hyp(
            "slot is left unset and then wraps the int32 width "
            "computation downstream",
        )])
        rv = rescue_self_refuted(
            o, source=_PROVABLE_SRC,
            pre_evidence="smt:check-parsed-int-contract",
            config=_Config(target_path=target, out_dir=out),
        )
        assert rv is not None
        assert rv.demote_to == "suspicious"
        assert _records(out) == []
