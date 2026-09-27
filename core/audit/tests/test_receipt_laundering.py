"""A receipt the run earned must reach the outcome as a tool stamp.

The pre-loop SMT screen runs real solver checks before the review loop
and, on a confirming hit, injects the receipt into the review prompt as
context. The model then restates the tool in its ``evidence_tool``
answer, and sanitisation (correctly) namespaces that restatement to
``llm-claimed:*`` — LLM-supplied values never pass as tool evidence.
But nothing wrote the run's OWN receipt back onto the reviewed outcome,
so the row travelled with ``llm-claimed:`` provenance: the
verification-evidence exemptions downstream (conservative ensemble
merge, quality suppression) never fired for a function a solver had
actually confirmed.

The discriminating direction stays intact: a model that merely NAMES a
tool, without a confirming receipt from the run's own records, must
keep the ``llm-claimed:`` prefix and earn no exemption.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.audit.evidence_grade import sanitize_llm_evidence_tool
from core.audit.orchestrator import (
    OrchestratorConfig,
    ReviewOutcome,
    run_orchestrator,
)
from core.audit.pipeline import _is_verification_evidence, _merge_outcomes


def _restore(outcome: ReviewOutcome, receipt: str) -> ReviewOutcome:
    """Call the restoration helper via a lazy import.

    The E2E class above the unit pins is the discriminating signal on a
    tree without the fix — a module-level import of the helper turns
    that red test into a collection error and masks it. With the lazy
    import, ``pytest core/audit/tests/test_receipt_laundering.py -k
    TestScreenReceiptSurvives`` runs on such a tree as-is (1 failed,
    1 passed); only the unit pins error, individually, at call time.
    """
    from core.audit.orchestrator import _restore_screen_receipt
    return _restore_screen_receipt(outcome, receipt)


# Narrowing shape: a parsed integer cast to a fixed-width unsigned type
# without a range check. The pre-loop screen's check-integer-narrowing
# verb (verification role) confirms on this mechanically.
_NARROWING_GO = (
    "package cfg\n"
    "\n"
    'import "strconv"\n'
    "\n"
    "// SetUser parses an operator-supplied uid string.\n"
    "func SetUser(userstr string) (uint32, error) {\n"
    "\tv, err := strconv.Atoi(userstr)\n"
    "\tif err != nil {\n"
    "\t\treturn 0, err\n"
    "\t}\n"
    "\tuid := uint32(v)\n"
    "\treturn uid, nil\n"
    "}\n"
)

# No parse, no cast, no lock, no resource: none of the screen's checks
# fire here, so no receipt is ever earned for this function.
_SAFE_GO = (
    "package cfg\n"
    "\n"
    "// Describe renders a label for the config entry.\n"
    "func Describe(name string, value string) string {\n"
    '\tif name == "" {\n'
    '\t\treturn "unnamed=" + value\n'
    "\t}\n"
    '\treturn name + "=" + value\n'
    "}\n"
)


def _setup_go_target(tmp_path: Path, source: str, func: str,
                     line_start: int, line_end: int) -> tuple[Path, Path]:
    """One-function Go target with checklist + context map."""
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "user.go").write_text(source)

    out = tmp_path / "out"
    out.mkdir()
    checklist = {
        "files": [
            {
                "path": "src/user.go",
                "items": [
                    {"name": func,
                     "line_start": line_start, "line_end": line_end},
                ],
            },
        ],
    }
    (out / "checklist.json").write_text(json.dumps(checklist))
    (out / "context-map.json").write_text(json.dumps({
        "entry_points": [{"file": "src/user.go", "name": func}],
        "sinks": [],
        "trust_boundaries": [],
        "unchecked_flows": [],
    }))
    return target, out


def _restating_review_fn(hypothesis: str):
    """Stub reviewer that restates "smt" as its evidence, like a model
    that read the SMT pre-pass section of its prompt.

    ``evidence_tool`` lands sanitised, exactly as llm_review's
    normalisation stores raw model answers.
    """

    calls: list[dict] = []

    def review_fn(ctx: dict, config: OrchestratorConfig) -> ReviewOutcome:
        calls.append(ctx)
        review_result = {
            "status": "suspicious",
            "body": "Parsed integer narrowed without a range check.",
            "hypothesis": hypothesis,
            "cwe": "CWE-190",
            # Raw model answer: names the tool it was shown.
            "evidence_tool": "smt",
        }
        return ReviewOutcome(
            file=ctx["file"],
            function=ctx["function"],
            status="suspicious",
            body=review_result["body"],
            hypothesis=hypothesis,
            evidence_tool=sanitize_llm_evidence_tool("smt"),
            review_result=review_result,
        )

    return review_fn, calls


def _hermetic_config(target: Path, out: Path) -> OrchestratorConfig:
    return OrchestratorConfig(
        target_path=target,
        out_dir=out,
        resume=False,
        # hermetic: config.validate dispatches the real validation
        # pipeline on hosts with a live CLI.
        validate=False,
        # hermetic: a live Joern server settles unverifiable suspicious
        # verdicts with a real LLM call.
        joern_overrides={"enabled": False},
        # The scenario under test is a REVIEWED row: prefilter skip_llm
        # shortcuts (sink_unreachable scope-narrowing on this tiny
        # fixture) must not resolve the function without review.
        prefilter_skip=False,
    )


def _clean_bug_first_row(row: ReviewOutcome) -> ReviewOutcome:
    return ReviewOutcome(
        file=row.file,
        function=row.function,
        status="clean",
        body="bug_first pass saw no mechanism",
    )


@pytest.mark.slow
class TestScreenReceiptSurvives:
    def test_receipt_not_laundered_by_model_restatement(
        self, tmp_path: Path,
    ) -> None:
        """The run's own confirming receipt must be the stamp, not the
        model's ``llm-claimed:`` restatement of the same tool."""
        target, out = _setup_go_target(
            tmp_path, _NARROWING_GO, "SetUser", 6, 13,
        )
        review_fn, calls = _restating_review_fn(
            "strconv.Atoi result is cast to uint32 without a range check",
        )
        result = run_orchestrator(_hermetic_config(target, out), review_fn)
        assert calls, "the review stub never ran — scenario is vacuous"

        row = next(
            o for o in result.outcomes if o.function == "SetUser"
        )
        assert row.status == "suspicious"

        # The merged row's provenance is the pipeline's receipt.
        first_stamp = (row.evidence_tool or "").split("+")[0]
        assert first_stamp.startswith("smt:check-integer-narrowing"), (
            f"expected the screen's confirming receipt, got "
            f"{row.evidence_tool!r}"
        )

        # The exemption that protects tool-verified rows fires.
        assert any(
            _is_verification_evidence(part.strip())
            for part in (row.evidence_tool or "").split("+")
        ), f"no verification-grade part in {row.evidence_tool!r}"

        # Dispatch record names the tool family that earned the stamp.
        assert "smt" in {
            str(t).strip().lower()
            for t in (row.tools_dispatched or set())
        }

        # The conservative ensemble merge must not suppress the
        # receipted row against a clean sibling lane.
        merged = _merge_outcomes([row], [_clean_bug_first_row(row)])
        assert merged[0].status == "suspicious", (
            f"receipted row conservatively suppressed to "
            f"{merged[0].status!r} with evidence "
            f"{merged[0].evidence_tool!r}"
        )

    def test_claim_without_receipt_stays_llm_claimed(
        self, tmp_path: Path,
    ) -> None:
        """No confirming receipt in the run's records: the model naming
        a tool keeps the ``llm-claimed:`` prefix and no exemption."""
        target, out = _setup_go_target(
            tmp_path, _SAFE_GO, "Describe", 4, 9,
        )
        review_fn, calls = _restating_review_fn(
            "integer overflow in label length arithmetic",
        )
        result = run_orchestrator(_hermetic_config(target, out), review_fn)
        assert calls, "the review stub never ran — scenario is vacuous"

        rows = [o for o in result.outcomes if o.function == "Describe"]
        assert rows, "Describe row missing from outcomes"
        row = rows[0]

        ev = row.evidence_tool or ""
        assert ev, "review-supplied evidence missing from the final row"
        assert all(
            part.strip().startswith("llm-claimed:")
            for part in ev.split("+") if part.strip()
        ), f"unreceipted claim escaped the llm-claimed namespace: {ev!r}"
        assert not any(
            _is_verification_evidence(part.strip())
            for part in ev.split("+") if part.strip()
        )

        if row.status == "suspicious":
            merged = _merge_outcomes([row], [_clean_bug_first_row(row)])
            assert merged[0].status != "suspicious", (
                "unreceipted suspicious survived the conservative merge"
            )


def _suspicious(evidence: str, status: str = "suspicious") -> ReviewOutcome:
    return ReviewOutcome(
        file="src/user.go",
        function="SetUser",
        status=status,
        body="review prose",
        evidence_tool=evidence,
        review_result={"evidence_tool": evidence},
    )


_RECEIPT = "smt:check-integer-narrowing"


class TestRestoreScreenReceipt:
    """Unit directions for the restoration helper."""

    def test_family_match_restores_receipt(self) -> None:
        o = _restore(_suspicious("llm-claimed:smt"), _RECEIPT)
        assert o.evidence_tool == _RECEIPT
        assert o.review_result["evidence_tool"] == _RECEIPT
        assert "smt" in o.tools_dispatched

    def test_verb_level_restatement_restores_receipt(self) -> None:
        o = _restore(
            _suspicious("llm-claimed:smt:check-integer-narrowing (pre-pass)"),
            _RECEIPT + ":witness",
        )
        assert o.evidence_tool == _RECEIPT + ":witness"

    def test_family_mismatch_stays_llm_claimed(self) -> None:
        o = _restore(
            _suspicious("llm-claimed:codeql"), _RECEIPT,
        )
        assert o.evidence_tool == "llm-claimed:codeql"

    def test_free_form_claim_stays_llm_claimed(self) -> None:
        o = _restore(
            _suspicious("llm-claimed:careful reading of the loop"), _RECEIPT,
        )
        assert o.evidence_tool.startswith("llm-claimed:")

    def test_no_receipt_is_a_noop(self) -> None:
        o = _restore(_suspicious("llm-claimed:smt"), "")
        assert o.evidence_tool == "llm-claimed:smt"
        assert not o.tools_dispatched

    def test_dead_path_observation_never_restored(self) -> None:
        o = _restore(
            _suspicious("llm-claimed:smt"), "smt:dead-path",
        )
        assert o.evidence_tool == "llm-claimed:smt"

    def test_genuine_stamp_untouched(self) -> None:
        o = _restore(
            _suspicious("smt:path-feasible"), _RECEIPT,
        )
        assert o.evidence_tool == "smt:path-feasible"

    def test_clean_outcome_untouched(self) -> None:
        # Clean rows have their own pre_evidence consumer (the
        # anti-self-refutation rescue) — this helper must not race it.
        o = _restore(
            _suspicious("llm-claimed:smt", status="clean"), _RECEIPT,
        )
        assert o.evidence_tool == "llm-claimed:smt"

    def test_composite_with_matching_part_restores(self) -> None:
        o = _restore(
            _suspicious("llm-claimed:code review+llm-claimed:smt"),
            _RECEIPT,
        )
        assert o.evidence_tool == _RECEIPT

    def test_unknown_future_verb_never_restored(self) -> None:
        # Allowlist direction: a receipt verb the confirming table does
        # not name — e.g. a future non-confirming screen observation —
        # fails closed, even against a family-matching restatement.
        o = _restore(
            _suspicious("llm-claimed:smt"), "smt:race-protected",
        )
        assert o.evidence_tool == "llm-claimed:smt"
        assert not o.tools_dispatched

    def test_unknown_future_verb_with_witness_never_restored(self) -> None:
        # The ":witness" suffix strips before the allowlist check —
        # it must not smuggle an unknown verb past the table.
        o = _restore(
            _suspicious("llm-claimed:smt"), "smt:race-protected:witness",
        )
        assert o.evidence_tool == "llm-claimed:smt"

    def test_non_smt_receipt_never_restored(self) -> None:
        o = _restore(
            _suspicious("llm-claimed:cocci"),
            "cocci:missing_bounds_check",
        )
        assert o.evidence_tool == "llm-claimed:cocci"

    def test_every_confirming_verb_restores(self) -> None:
        # Companion pin to the fail-closed direction: each allowlisted
        # verb the screen mints still restores over its restatement.
        from core.audit.orchestrator import _SCREEN_CONFIRMING_VERBS
        for verb in sorted(_SCREEN_CONFIRMING_VERBS):
            receipt = f"smt:{verb}:witness"
            o = _restore(_suspicious("llm-claimed:smt"), receipt)
            assert o.evidence_tool == receipt, verb
