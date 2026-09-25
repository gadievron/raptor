"""Structured findings export with evidence chains.

Converts raw audit outcomes into the output contract: each finding
carries a graded evidence chain, impact assessment, and downstream
consumer metadata. The export feeds /validate, /exploit, and
report generation.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from core.json import save_json

from .evidence_grade import (
    Confidence,
    GradedEvidence,
    finding_confidence,
    grade_evidence_record,
    grade_review_result,
    is_tool_evidence,
)
from .tree_class import classify_tree_class, is_test_tree_path

logger = logging.getLogger(__name__)

# Confirming receipts that are not tool namespaces: the /validate
# runtime bridge stamps (ReviewOutcome._CONFIRMED_EVIDENCE members).
# Kept in sync with core.audit.orchestrator.ReviewOutcome.
_RUNTIME_CONFIRMING_STAMPS = frozenset({
    "validate:observed_runtime", "validate:replayed_crash",
})

# Receipt stamped when the reviewed outcome matches a fresh CONFIRMED
# entry in the function's /validate verdict history.
_HISTORY_RECEIPT = "validate:confirmed-history"

# Line slack when matching an outcome to a confirmed history entry —
# reviews anchor on the hypothesis line, /validate on the sink line;
# the same mechanism routinely lands a few lines apart.
_HISTORY_LINE_SLACK = 10


def _coerce_line(value: Any) -> int:
    """Tolerant coercion — history records are built from LLM-written
    findings files; '~242'-style values degrade to 0, never raise."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _mechanism_tokens(text: str) -> set[str]:
    tokens = set(re.findall(r"[a-z0-9_]{3,}", str(text).lower()))
    return tokens - _MECHANISM_STOPWORDS


_MECHANISM_STOPWORDS = frozenset({
    "the", "and", "for", "with", "that", "this", "from", "are", "can",
    "not", "has", "was", "when", "into", "which", "here", "its",
    "function", "code", "line", "bug", "finding", "vulnerability",
})


def _validate_history_receipt(
    history: Any,
    *,
    line: int,
    cwe: str,
    hypothesis: str = "",
) -> str:
    """Confirming receipt from prior /validate history, or ''.

    A fresh (source-unchanged) CONFIRMED verdict for the same function
    counts as a confirming receipt only when it plausibly names the
    SAME mechanism as this outcome. The history record must itself
    carry evidence (strong receipts or runtime tiers) — a bare
    status-flip ruling never mints a receipt. Matching: when both
    sides carry line numbers they must agree within
    ``_HISTORY_LINE_SLACK`` (disagreeing lines veto — a same-CWE
    defect hundreds of lines away is a different mechanism); with line
    agreement, an equal CWE class (or a missing one) convicts, while a
    conflicting CWE additionally needs mechanism-text overlap with the
    outcome hypothesis (CWE labels are noisy across pipelines — the
    same dead-branch defect classifies as CWE-570 in one and CWE-697
    in the other). Without line numbers, CWE equality alone is too
    weak and also needs mechanism overlap. Stale confirms and
    function-level-only overlap never convict — the prompt hint covers
    those.
    """
    if not isinstance(history, dict):
        return ""
    hyp_tokens = _mechanism_tokens(hypothesis)
    for rec in history.get("confirmed") or []:
        if not isinstance(rec, dict) or not rec.get("fresh"):
            continue
        if not (rec.get("strong_receipts") or rec.get("runtime_tiers")):
            continue
        rec_line = _coerce_line(rec.get("line"))
        out_line = _coerce_line(line)
        rec_cwe = str(rec.get("cwe") or "").strip().lower()
        out_cwe = str(cwe or "").strip().lower()
        both_lines = bool(rec_line and out_line)
        both_cwes = bool(rec_cwe and out_cwe)
        line_match = (
            both_lines and abs(rec_line - out_line) <= _HISTORY_LINE_SLACK
        )
        if both_lines and not line_match:
            continue
        cwe_match = both_cwes and rec_cwe == out_cwe
        mech_overlap = (
            len(hyp_tokens & _mechanism_tokens(rec.get("mechanism", ""))) >= 2
        )
        if line_match and (cwe_match or not both_cwes or mech_overlap):
            return _HISTORY_RECEIPT
        if not both_lines and cwe_match and mech_overlap:
            return _HISTORY_RECEIPT
    return ""


def classify_file_class(
    file_path: str,
    vendor_verdicts: dict[str, Any] | None = None,
) -> str:
    """File-class context for an exported finding.

    Returns ``"vendored"`` / ``"generated"`` from the prep-time
    vendored/generated detector verdicts (threaded in, not re-detected
    per finding), ``"test"`` for test-tree / fixture paths, or ``""``
    for first-party code (the field is then omitted from the export).
    """
    if not file_path:
        return ""
    if vendor_verdicts:
        verdict = vendor_verdicts.get(file_path)
        if verdict is not None:
            kind = getattr(verdict, "kind", "")
            if not kind and isinstance(verdict, dict):
                kind = verdict.get("kind", "")
            if kind:
                return str(kind)
    if is_test_tree_path(file_path):
        return "test"
    return ""


def build_graded_finding(
    outcome: Any,
    evidence_record: Any | None = None,
    *,
    file_class: str = "",
    tree_class: str = "",
) -> dict[str, Any]:
    """Build a finding dict with graded evidence chain.

    Combines mechanical evidence (from EvidenceRecord) with LLM review
    evidence (from ReviewOutcome.review_result) into a single ordered
    chain with source tags and confidence levels.

    The exported ``confidence`` is computed only from
    hypothesis-correlated evidence: the review-derived items plus tool
    receipts (which pass correlation gates before they are stamped).
    Ambient mechanical signals from the evidence record — e.g. a Joern
    flow that exists somewhere in the function but was never matched
    to THIS hypothesis — stay in the exported chain as context but no
    longer export an LLM-only guess as ``confidence=high``.
    """
    chain: list[GradedEvidence] = []

    if evidence_record is not None:
        chain.extend(grade_evidence_record(evidence_record))

    review_result = getattr(outcome, "review_result", None) or {}
    evidence_tool = getattr(outcome, "evidence_tool", "")
    # Pipeline-recorded typestate context for this function — the
    # corroboration gate for the model's typestate_violation claim
    # (absent record / absent field → the claim grades LLM-only).
    ts_context = (
        getattr(evidence_record, "typestate_violations", None)
        if evidence_record is not None else None
    )
    review_items = grade_review_result(
        review_result, evidence_tool, typestate_context=ts_context,
    )
    chain.extend(review_items)

    if is_tool_evidence(evidence_tool):
        confidence = finding_confidence(chain)
    else:
        confidence = finding_confidence(review_items)

    file_val = getattr(outcome, "file", "")
    func_val = getattr(outcome, "function", "")
    line_val = getattr(outcome, "line", 0)
    status_val = getattr(outcome, "status", "")
    hypothesis_val = getattr(outcome, "hypothesis", "")

    finding_id = getattr(outcome, "finding_id", "")
    if not finding_id:
        finding_id = f"{file_val}:{func_val}:{line_val}"

    # Verification tier: prefer a live recompute (post-resolution
    # dispatch state), fall back to the journaled attribute.
    tier = ""
    compute = getattr(outcome, "compute_tier", None)
    if callable(compute):
        try:
            tier = compute() or ""
        except Exception:  # noqa: BLE001 — export must not fail the run
            tier = ""
    if not tier:
        tier = getattr(outcome, "verification_tier", "") or "speculative"

    # ``discovery.confirmed_by`` used to read a never-set outcome
    # attribute and exported ``[]`` on every finding (185/185 on the
    # instrumented corpus) while the tier claimed tool_backed. Derive
    # it from the receipts that actually confirm: the confirming-role
    # parts of the evidence stamp (detection-role variants stay out —
    # they corroborate, they do not convict) plus secondary-hypothesis
    # dispatch confirmations.
    _confirmed_by = getattr(outcome, "confirmed_by", None)
    _confirmed_by = _confirmed_by if isinstance(_confirmed_by, list) else []
    if not _confirmed_by:
        for part in (evidence_tool or "").split("+"):
            part = part.strip()
            if not part or part in _confirmed_by:
                continue
            # The validate-bridge runtime stamps and witness stamps are
            # confirming receipts in compute_tier's vocabulary but not
            # tool namespaces — count them here so the receipt gate
            # below (which now covers the confirmed tier too) never
            # demotes a genuinely runtime-confirmed finding.
            if (
                is_tool_evidence(part)
                or part in _RUNTIME_CONFIRMING_STAMPS
                or part.endswith(":witness")
            ):
                _confirmed_by.append(part)
        for sec in review_result.get("secondary_confirmations") or []:
            sec_tool = sec.get("evidence_tool") if isinstance(sec, dict) else ""
            if sec_tool and not sec.get("premise_blocked") \
                    and sec_tool not in _confirmed_by:
                _confirmed_by.append(sec_tool)

    # A fresh CONFIRMED /validate history entry matching this outcome
    # is a real confirming receipt — the mechanism was already
    # tool/runtime-confirmed by the validation pipeline. Without it, a
    # re-found validate-confirmed defect exported with
    # confirmed_by=[] and was demoted to llm_only by the gate below.
    if (
        evidence_record is not None
        and _HISTORY_RECEIPT not in _confirmed_by
        and status_val in ("finding", "suspicious", "dark")
    ):
        history_receipt = _validate_history_receipt(
            getattr(evidence_record, "validate_history", None),
            line=_coerce_line(line_val),
            cwe=str(review_result.get("cwe_class") or ""),
            hypothesis=str(hypothesis_val or ""),
        )
        if history_receipt:
            _confirmed_by.append(history_receipt)

    # Discrimination gate (measured, not theoretical): tool_backed
    # with no confirming receipt means the tier came from a journaled
    # attribute or a grading path that bypassed the evidence firewall.
    # On the instrumented corpus 136 of 137 tool_backed findings were
    # disproven in validation — the stamps confirmed lexical shape,
    # not vulnerability. Cap confidence at medium and tier at llm_only
    # until a confirming receipt exists. The CONFIRMED tier is no
    # longer exempt: a live compute_tier() 'confirmed' always carries
    # its confirming stamp in evidence_tool (counted above, including
    # the validate-bridge runtime stamps), so the only 'confirmed'
    # values without a receipt are journaled attributes / bypass
    # paths — exactly what this gate exists to catch.
    if not _confirmed_by and tier in ("tool_backed", "confirmed"):
        tier = "llm_only"
        if confidence is Confidence.HIGH:
            confidence = Confidence.MEDIUM

    finding: dict[str, Any] = {
        "id": finding_id,
        "file": file_val,
        "function": func_val,
        "line": line_val,
        "status": status_val,
        "hypothesis": hypothesis_val,
        "title": hypothesis_val[:120] if hypothesis_val else f"{status_val} in {func_val}",
        "vuln_type": review_result.get("vuln_type", ""),
        "depth": getattr(outcome, "depth", "L1"),
        "confidence": confidence.value,
        "verification_tier": tier,
        "evidence_chain": [e.to_dict() for e in chain],
    }
    if status_val == "dark":
        # Tool-blind bucket: no mechanical channel can decide this
        # class — exactly the findings /validate exists to judge.
        finding["needs_validation"] = True
    if getattr(outcome, "provisional", False):
        # Cadence-tick promotion not yet finalized — only interrupted
        # runs export it (finalization clears the mark first).
        finding["provisional"] = True
    if file_class:
        # File-class context: a finding in vendored / generated / test
        # code is not an unqualified first-party finding — a fuzz-
        # harness overflow must not export indistinguishable from a
        # production one. Absent for first-party code.
        finding["file_class"] = file_class
    # Tree class (core.audit.tree_class vocabulary) — always present,
    # so report ordering and /validate selection read one field
    # instead of re-deriving it. A tag for ordering/weighting only.
    finding["tree_class"] = (
        tree_class or classify_tree_class(file_val)
    )

    # Hypothesis multiplicity: the review's full hypotheses array.
    # A multi-bug function used to export as one finding with one
    # hypothesis string — the sibling mechanisms (and their
    # confidences) were invisible to the operator and to /validate.
    hyp_entries = getattr(outcome, "hypotheses", None) or []
    if not hyp_entries and review_result:
        hyp_entries = review_result.get("hypotheses") or []
    hyp_entries = [
        h for h in hyp_entries
        if isinstance(h, dict) and h.get("mechanism")
    ]
    if hyp_entries:
        finding["hypothesis_multiplicity"] = {
            "count": len(hyp_entries),
            "mechanisms": [
                {
                    "mechanism": (h.get("mechanism") or "")[:200],
                    "confidence": (h.get("confidence") or "").lower(),
                }
                for h in hyp_entries[:8]
            ],
        }

    # Secondary-hypothesis tool confirmations (dispatch lane receipts).
    secondary = review_result.get("secondary_confirmations")
    if secondary:
        finding["secondary_confirmations"] = secondary

    if review_result.get("cwe_class"):
        finding["cwe_class"] = review_result["cwe_class"]

    impact = review_result.get("impact")
    if impact:
        finding["impact"] = impact

    spec_dev = review_result.get("spec_deviation")
    if spec_dev and spec_dev.get("deviation"):
        finding["spec_deviation"] = spec_dev

    ts_viol = review_result.get("typestate_violation")
    if ts_viol and ts_viol.get("violation_kind"):
        finding["typestate_violation"] = ts_viol

    # File pile-up dampening audit trail (see pipeline.dampen_file_pileup):
    # the demotion/collapse record travels with the exported finding so
    # the operator can see WHY a status was softened.
    dampening = review_result.get("file_dampening")
    if dampening:
        finding["file_dampening"] = dampening

    # Caller-contract demotion receipt (see orchestrator
    # _apply_caller_contract_gate): the per-site receipts travel with
    # the finding, and the confidence clamp is ENFORCED here — a
    # caller obligation mechanically refuted at every enumerated call
    # site may not export above low unless a confirming receipt
    # exists (tool-confirmed findings are never demoted).
    caller_ev = review_result.get("caller_evidence")
    if caller_ev:
        finding["caller_evidence"] = caller_ev
        clamp = (caller_ev.get("demotion") or {}).get("confidence_clamp")
        if clamp == "low" and not _confirmed_by:
            confidence = Confidence.LOW
            finding["confidence"] = confidence.value

    discovery_sources = []
    if evidence_record is not None:
        if getattr(evidence_record, "joern_flows", None):
            discovery_sources.append("joern")
        if getattr(evidence_record, "codeql_alerts", None):
            discovery_sources.append("codeql")
        if getattr(evidence_record, "taint_approx", None):
            discovery_sources.append("taint_approx")
        if getattr(evidence_record, "binary_layer0_findings", None):
            discovery_sources.append("layer0")
        if getattr(evidence_record, "semgrep_results", None):
            discovery_sources.append("semgrep")
    if review_result:
        discovery_sources.append("llm_review")
    review_depth = getattr(outcome, "review_depth", "")
    tokens_spent = getattr(outcome, "tokens_spent", 0)
    confirmed_by = _confirmed_by
    discovered_by_attr = getattr(outcome, "discovered_by", "")

    finding["discovery"] = {
        "sources": discovery_sources or ["llm_review"],
        "evidence_tool": evidence_tool or "none",
        "discovered_by": discovered_by_attr or (discovery_sources[0] if discovery_sources else "llm_review"),
        "confirmed_by": confirmed_by if isinstance(confirmed_by, list) else [],
        "review_depth": review_depth or "investigate",
        "tokens_spent": tokens_spent or 0,
    }

    run_id = getattr(outcome, "run_id", "")
    checker_id = getattr(outcome, "checker_id", "")
    summary_source = getattr(outcome, "summary_source", "")
    finding["provenance"] = {
        "model": getattr(outcome, "model", ""),
        "cost_usd": getattr(outcome, "cost_usd", 0.0),
        "duration_s": getattr(outcome, "duration_s", 0.0),
        "run_id": run_id,
        "checker_id": checker_id,
        "summary_source": summary_source or ("joern" if discovery_sources and "joern" in discovery_sources else "llm"),
    }
    finding["model"] = getattr(outcome, "model", "")
    finding["cost_usd"] = getattr(outcome, "cost_usd", 0.0)

    callers = review_result.get("callers", [])
    callees = review_result.get("callees", [])
    entry_point = review_result.get("entry_point", "")
    if callers or callees or entry_point:
        finding["context"] = {}
        if callers:
            finding["context"]["callers"] = callers[:10]
        if callees:
            finding["context"]["callees"] = callees[:10]
        if entry_point:
            finding["context"]["entry_point"] = entry_point

    return finding


def export_findings(
    outcomes: list[Any],
    evidence_index: dict[str, Any] | None = None,
    attack_chains: list[Any] | None = None,
    *,
    out_dir: Path | None = None,
    run_id: str = "",
    vendor_verdicts: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Export all findings with evidence chains and attack chains.

    Returns a structured dict suitable for writing to findings-graded.json.

    ``vendor_verdicts`` is the orchestrator's prep-time per-file
    vendored/generated map (``core.audit.vendored_detector``) — threaded
    in so each finding exports its ``file_class`` without re-detecting.

    When ``out_dir`` is given, the promotion-without-tool-evidence
    alarm sweeps the FINAL outcome statuses here (post-loop promotions
    run after the per-review journal writes, so the export is the
    second chokepoint that sees them).  Enforcing: a violating finding
    is demoted to suspicious before it is graded, so the export ships
    the gated status.
    """
    if out_dir is not None:
        try:
            from .promotion_alarm import check_outcomes
            check_outcomes(
                Path(out_dir), outcomes, stage="findings-export",
                run_id=run_id, enforce=True,
            )
        except Exception:
            logger.debug("promotion alarm export sweep failed", exc_info=True)

    findings: list[dict[str, Any]] = []
    for outcome in outcomes:
        status = getattr(outcome, "status", "clean")
        # "dark" is exported alongside finding/suspicious: it is the
        # "tool-blind, needs concrete verification" bucket — excluding
        # it made every hypothesis the gates routed to dark invisible
        # to the operator and to /validate, the one pipeline built to
        # judge tool-blind findings.
        if status not in ("finding", "suspicious", "dark"):
            continue

        file_path = getattr(outcome, "file", "")
        key = f"{file_path}:{getattr(outcome, 'function', '')}"
        ev_record = evidence_index.get(key) if evidence_index else None
        finding = build_graded_finding(
            outcome, ev_record,
            file_class=classify_file_class(file_path, vendor_verdicts),
            tree_class=classify_tree_class(file_path, vendor_verdicts),
        )
        findings.append(finding)

    result: dict[str, Any] = {
        "findings": findings,
        "stats": {
            "total": len(findings),
            "high_confidence": sum(
                1 for f in findings if f["confidence"] == "high"
            ),
            "medium_confidence": sum(
                1 for f in findings if f["confidence"] == "medium"
            ),
            "low_confidence": sum(
                1 for f in findings if f["confidence"] == "low"
            ),
            "dark": sum(
                1 for f in findings if f["status"] == "dark"
            ),
        },
    }

    if attack_chains:
        result["attack_chains"] = [
            c.to_dict() if hasattr(c, "to_dict") else c
            for c in attack_chains
        ]

    return result


def write_graded_findings(
    export: dict[str, Any],
    out_dir: Path,
) -> Path:
    """Write findings-graded.json to the run directory."""
    path = out_dir / "findings-graded.json"
    save_json(path, export)
    return path


def format_findings_summary(export: dict[str, Any]) -> str:
    """Render a human-readable summary of graded findings."""
    stats = export.get("stats", {})
    total = stats.get("total", 0)
    if total == 0:
        return "No findings."

    lines = [f"**{total} findings**"]

    high = stats.get("high_confidence", 0)
    med = stats.get("medium_confidence", 0)
    low = stats.get("low_confidence", 0)

    parts = []
    if high:
        parts.append(f"{high} high-confidence")
    if med:
        parts.append(f"{med} medium-confidence")
    if low:
        parts.append(f"{low} low-confidence")
    if parts:
        lines.append(f"Confidence: {', '.join(parts)}")

    dark = stats.get("dark", 0)
    if dark:
        lines.append(
            f"Dark (tool-blind, needs concrete verification): {dark} "
            f"— route to /validate"
        )

    chains = export.get("attack_chains", [])
    if chains:
        confirmed = sum(
            1 for c in chains
            if (c.get("chain_status") or "") == "confirmed"
        )
        lines.append(f"Attack chains: {len(chains)} ({confirmed} confirmed)")

    return "\n".join(lines)


def export_graded_from_journal(out_dir: Path) -> dict[str, Any] | None:
    """Emit findings-graded.json from the review journal when the
    orchestrator's richer export is absent (in-session runs).

    findings-graded.json is the finding-level escrow hand-off: the
    /validate import and cross-run dedup read it, and suspicious/dark
    records ride it into downstream adjudication. The orchestrator
    writes it unconditionally, but in-session runs (reviews recorded
    via ``raptor-audit record``) never produced one at all — a
    tool-confirmed suspicious result from such a run was invisible to
    every later dedup/validation set and got re-discovered as novel.
    A pass with suspicious/dark items and ZERO findings must still
    emit the artifact.

    Returns the graded container, or ``None`` when nothing was
    written (an existing export is never overwritten — the
    orchestrator's outcome-based export carries evidence chains this
    journal reconstruction cannot; and a run with no journal has
    nothing to grade).
    """
    out_dir = Path(out_dir)
    if (out_dir / "findings-graded.json").exists():
        return None
    if not (out_dir / "review-journal.jsonl").exists():
        return None
    from types import SimpleNamespace

    from core.coverage import journal_mac
    from core.coverage.journal import RUN_ID_UNATTRIBUTED, latest_entries

    outcomes = []
    unverified_rows = 0
    foreign_run_rows = 0
    unscoped_run_rows = 0
    # The exporting run's identity for the receipt run-scope check:
    # journal writers stamp ``run_id`` with the run dir's NAME, and
    # the row MAC covers it (an edited run_id demotes the row to
    # tampered). Derived from the consumer's own directory, never
    # from a run-dir artifact. RESOLVED first: a relative spelling
    # ("." from --out .) has name == "" — comparing against that
    # inverted both fail directions (same-run rows read foreign;
    # run_id="" rows read run-scoped WITH receipts and no marker).
    # A still-empty resolved name (filesystem root) disables the
    # run-scope tier entirely: nothing grades run-scoped, attributed
    # rows fail toward foreign, unattributed rows keep the marked
    # grandfather.
    # Scope bound (documented, adjudicated): the identity is the
    # directory BASENAME, so a same-basename dir in another project
    # replays with receipts. Stamping a stronger identity into rows
    # is not available — an additive row field demotes at older
    # readers (their dataclass round-trip drops it before the MAC
    # recompute; measured) — and basenames are operator-conventional
    # (timestamped run names), not attacker-chosen from outside the
    # same-user trust tier that could forge rows outright anyway.
    try:
        run_identity = Path(out_dir).resolve().name
    except OSError:
        run_identity = out_dir.name
    for entry in latest_entries(out_dir).values():
        if entry.verdict not in ("finding", "suspicious", "dark"):
            continue
        hypothesis = ""
        for hyp in entry.hypotheses or []:
            if isinstance(hyp, dict):
                hypothesis = str(
                    hyp.get("mechanism") or hyp.get("text") or "",
                )
                if hypothesis:
                    break
        if not hypothesis:
            hypothesis = (entry.body or "")[:500]
        review_result: dict[str, Any] = {}
        if entry.cwe:
            review_result["vuln_type"] = entry.cwe
        # Receipt authority is tiered on row provenance AND run
        # scope: the journal lives in the target-writable run dir,
        # and the journaled ``evidence_tools`` stamp is what mints
        # ``confirmed_by`` receipts and confidence=high downstream.
        # The row MAC is install-scoped (journal rows travel across
        # runs by design — see core.coverage.journal_mac), so a MAC
        # alone proves "this install's writer recorded it in SOME
        # run" — a writer-minted row byte-copied from a sibling run
        # dir verifies here too. Receipts therefore additionally
        # require the MAC-covered ``run_id`` to name THIS run: only
        # then is the row this run's own record (whose in-session
        # record gate enforced tool grounding at record time).
        # Unstamped/tampered rows, and verified rows attributed to
        # another run, export receipt-less — the grading caps their
        # confidence at the LLM-only tier instead of shipping a
        # replayed or forged receipt. Verified rows with NO run
        # attribution are grandfathered WITH a marker: stripping
        # every legacy receipt would regress honest old exports, and
        # the grandfather is visible per record
        # (``provenance.receipt_scope: install``) and per container
        # (``derivation.unscoped_run_rows``). No-attribution has two
        # equivalent spellings: ``run_id=""`` (legacy writers that
        # never stamped one) and the record CLI's documented
        # ``RUN_ID_UNATTRIBUTED`` sentinel (stamped whenever no dir
        # basename was available — including every relative ``--out``
        # spelling before the CLI resolved it). Both say "this row
        # names no run", never "this row names another run", so both
        # take the marked install tier — grading the sentinel foreign
        # stripped honest rows with an accusatory replay warning. The
        # tier's exposure is unchanged by admitting the sentinel: a
        # sibling-run copy of a sentinel row verifies here exactly
        # like a sibling-run copy of a ``run_id=""`` row always did,
        # and both stay visibly install-scoped, never run-scoped.
        # Exact match only: any other value is a run attribution and
        # fails toward the foreign arm.
        verified = (
            journal_mac.entry_provenance(entry)
            == journal_mac.ROW_VERIFIED
        )
        receipt_scope = None
        if not verified:
            unverified_rows += 1
        elif run_identity and entry.run_id == run_identity:
            receipt_scope = "run"
        elif not entry.run_id or entry.run_id == RUN_ID_UNATTRIBUTED:
            receipt_scope = "install"
            unscoped_run_rows += 1
        else:
            foreign_run_rows += 1
        outcomes.append(SimpleNamespace(
            file=entry.file,
            function=entry.function,
            line=entry.line_start or 0,
            status=entry.verdict,
            hypothesis=hypothesis,
            review_result=review_result,
            evidence_tool=(
                "+".join(entry.evidence_tools or [])
                if receipt_scope else ""
            ),
            model=entry.model or "",
            receipt_scope=receipt_scope,
        ))
    # out_dir deliberately NOT passed to export_findings: the
    # promotion-alarm sweep correlates orchestrator outcome objects
    # with dispatch receipts; journal reconstructions carry only the
    # journaled evidence stamp, and the in-session ``record`` gate
    # (G2: executed confirmed sweep receipt) already enforced tool
    # grounding at record time. Re-demoting here on a correlation the
    # reconstruction cannot express would strip gated statuses.
    graded = export_findings(outcomes)
    # Provenance marker, container AND per-record: this export is a
    # journal reconstruction, not the orchestrator's outcome-based
    # export — downstream consumers (and cross-run merges that lift
    # records out of the container) can weigh its evidence chains
    # accordingly. Consumers tolerate extra keys by contract.
    graded["derivation"] = {
        "source": "review-journal",
        "unverified_rows": unverified_rows,
        "foreign_run_rows": foreign_run_rows,
        "unscoped_run_rows": unscoped_run_rows,
    }
    # Statuses are pre-filtered above, so export_findings emits exactly
    # one record per outcome, in order — the zip is total.
    for rec, oc in zip(graded["findings"], outcomes):
        prov = rec.setdefault("provenance", {})
        prov["derivation"] = "journal"
        if getattr(oc, "receipt_scope", None) == "install":
            # Grandfathered receipt: the row MAC verifies but carries
            # no run attribution (legacy writer) — receipts kept, the
            # scope RECORDED per record. No consumer weighs the
            # marker today; it exists so one can, and so an operator
            # reading the export sees which receipts are install-
            # scoped rather than run-attributed.
            prov["receipt_scope"] = "install"
    if unverified_rows:
        logger.warning(
            "graded findings (journal-derived): %d row(s) without a "
            "verifying integrity token — exported without tool "
            "receipts (confidence capped at the LLM-only tier)",
            unverified_rows,
        )
    if foreign_run_rows:
        logger.warning(
            "graded findings (journal-derived): %d verified row(s) "
            "attributed to another run (authenticated run_id does not "
            "name this run dir — replayed or relocated) — exported "
            "without tool receipts",
            foreign_run_rows,
        )
    write_graded_findings(graded, out_dir)
    logger.info(
        "graded findings (journal-derived): %d record(s) exported",
        graded["stats"]["total"],
    )
    return graded
