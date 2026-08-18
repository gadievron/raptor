"""Post-audit validation handoff.

After the audit loop completes, findings (including sweep-promoted
suspicious items) are emitted as findings.json and /validate is
dispatched automatically to filter false positives via the full
Stage A-F pipeline.

Controlled by OrchestratorConfig.validate (default False).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.orchestration.skill_dispatch import (
    MAX_VALIDATE_FINDINGS,
    run_skill_dispatch,
    truncate_findings_by_signal,
)
from core.schema_constants import CWE_TO_VULN_TYPE, normalise_vuln_type

from .orchestrator import OrchestratorResult, ReviewOutcome
from .record import append_audit_log

logger = logging.getLogger(__name__)

_RAPTOR_DIR = Path(os.environ["RAPTOR_DIR"])
# Re-exported from the shared skill-dispatch substrate (kept as a module
# attribute so tests/monkeypatchers can dial the cap per-module).
_MAX_VALIDATE_FINDINGS = MAX_VALIDATE_FINDINGS
_VALIDATE_TOOLS = "Read,Grep,Glob,Write,Bash"
_VALIDATE_BUDGET_USD = "10.00"
_VALIDATE_TIMEOUT_S = 1800


@dataclass
class ValidatePostpassResult:
    ran: bool
    selected_count: int = 0
    validate_dir: str | None = None
    skipped_reason: str = ""
    duration_s: float = 0.0


def validate_findings(
    result: OrchestratorResult,
    *,
    target_path: Path,
    out_dir: Path,
    review_fn: Any = None,
    config: Any = None,
) -> OrchestratorResult:
    """Emit audit findings and dispatch /validate.

    Writes findings.json, then launches /validate as a Claude Code
    subprocess to run the full Stage A-F pipeline. The sweep is a
    cheap wide net; /validate is the expensive filter that kills
    false promotions by tracing reachability.
    """
    findings_outcomes = [
        (i, o) for i, o in enumerate(result.outcomes)
        if o.status == "finding"
    ]
    if not findings_outcomes:
        logger.info("validate_findings: no findings to emit")
        return result

    logger.info(
        "validate_findings: emitting %d finding(s) for /validate",
        len(findings_outcomes),
    )

    path = _emit_findings_json(findings_outcomes, out_dir, target_path)

    append_audit_log(out_dir, {
        "action": "findings_emitted",
        "count": len(findings_outcomes),
        "path": str(path),
    })

    postpass = _dispatch_validate(
        target_path=target_path,
        audit_out_dir=out_dir,
        findings_path=path,
        findings_count=len(findings_outcomes),
    )

    append_audit_log(out_dir, {
        "action": "validate_postpass",
        "ran": postpass.ran,
        "selected_count": postpass.selected_count,
        "validate_dir": postpass.validate_dir,
        "skipped_reason": postpass.skipped_reason,
        "duration_s": postpass.duration_s,
    })

    if postpass.ran and postpass.validate_dir:
        logger.info(
            "validate post-pass completed in %.1fs → %s",
            postpass.duration_s, postpass.validate_dir,
        )
        _auto_feedback(
            validate_dir=Path(postpass.validate_dir),
            annotations_dir=_resolve_annotations_dir(out_dir),
            audit_out_dir=out_dir,
        )
    elif postpass.skipped_reason:
        logger.info(
            "validate post-pass skipped: %s", postpass.skipped_reason,
        )

    return result


def _dispatch_validate(
    *,
    target_path: Path,
    audit_out_dir: Path,
    findings_path: Path,
    findings_count: int,
) -> ValidatePostpassResult:
    """Launch /validate as a Claude Code subprocess.

    Mirrors the /agentic post-pass pattern: create a validate run
    directory, copy the findings file, build a prompt, and dispatch
    via the cc_adapter. Never raises — enrichment failure must not
    break the base audit pipeline.
    """
    try:
        return _dispatch_validate_unsafe(
            target_path=target_path,
            audit_out_dir=audit_out_dir,
            findings_path=findings_path,
            findings_count=findings_count,
        )
    except Exception as e:
        logger.exception("validate post-pass crashed unexpectedly")
        return ValidatePostpassResult(
            ran=False,
            skipped_reason=f"unexpected {type(e).__name__}: {e}",
        )


def _dispatch_validate_unsafe(
    *,
    target_path: Path,
    audit_out_dir: Path,
    findings_path: Path,
    findings_count: int,
) -> ValidatePostpassResult:
    target_path = Path(target_path).resolve()
    audit_out_dir = Path(audit_out_dir).resolve()

    if findings_count > _MAX_VALIDATE_FINDINGS:
        logger.warning(
            "validate post-pass: %d findings; truncating to %d",
            findings_count, _MAX_VALIDATE_FINDINGS,
        )
        findings_count = _MAX_VALIDATE_FINDINGS

    def _stage(validate_dir: Path) -> None:
        selection_file = validate_dir / "selected-findings.json"
        _copy_findings_for_validate(findings_path, selection_file)

        audit_checklist = audit_out_dir / "checklist.json"
        if audit_checklist.is_file():
            from core.json import save_json
            save_json(
                validate_dir / "parent-checklist-pointer.json",
                {
                    "checklist_path": str(audit_checklist.resolve()),
                    "expected_target_path": str(target_path),
                    "expected_root_dir": str(audit_out_dir),
                },
            )

    def _prompt(validate_dir: Path) -> str:
        return _build_audit_validate_prompt(
            target_path, audit_out_dir, validate_dir,
            validate_dir / "selected-findings.json", findings_count,
        )

    # cc-trust gate: refuse to dispatch a Claude Code child against a
    # repo whose .claude/settings / .mcp.json the operator has not
    # trusted for cc dispatch. Same gate the /agentic launcher applies
    # (check_repo_claude_trust honours the operator's --trust-repo via
    # set_trust_override). Pre-consolidation the audit handoff had no
    # such gate — an untrusted repo's config reached the CC child.
    from core.security.cc_trust import check_repo_claude_trust

    dispatch = run_skill_dispatch(
        command="validate",
        target=target_path,
        tools=_VALIDATE_TOOLS,
        budget_usd=_VALIDATE_BUDGET_USD,
        timeout_s=_VALIDATE_TIMEOUT_S,
        caller_label="audit-validate",
        log_label="validate post-pass",
        build_prompt=_prompt,
        block_cc_dispatch=check_repo_claude_trust(str(target_path)),
        context_dirs=(audit_out_dir,),
        stage=_stage,
    )
    return ValidatePostpassResult(
        ran=dispatch.ran,
        selected_count=findings_count,
        validate_dir=str(dispatch.run_dir) if dispatch.run_dir else None,
        skipped_reason=dispatch.skipped_reason or "",
        duration_s=dispatch.duration_s,
    )


def _copy_findings_for_validate(
    findings_path: Path,
    dest: Path,
) -> None:
    """Copy audit findings.json into the validate dir.

    Over-cap selections are truncated SIGNAL-SORTED (shared policy from
    core.orchestration.skill_dispatch): is_exploitable first, then
    exploitability_score, ties stable in emission order. Pre-
    consolidation this head-truncated — silently dropping the
    strongest findings whenever more than the cap qualified.
    """
    try:
        with open(findings_path, encoding="utf-8") as f:
            container = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return
    entries = container.get("findings", [])
    if isinstance(entries, list) and len(entries) > _MAX_VALIDATE_FINDINGS:
        if all(isinstance(e, dict) for e in entries):
            entries = truncate_findings_by_signal(
                entries, _MAX_VALIDATE_FINDINGS,
                log_label="validate post-pass",
            )
        else:
            # Corrupt container (non-dict entries) — fall back to the
            # positional cap rather than crash the best-effort copy.
            entries = entries[:_MAX_VALIDATE_FINDINGS]
        container["findings"] = entries
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(container, f, indent=2)


def _build_audit_validate_prompt(
    target: Path,
    audit_out_dir: Path,
    validate_dir: Path,
    selection_file: Path,
    findings_count: int,
) -> str:
    from core.security.log_sanitisation import escape_nonprintable
    safe_target = escape_nonprintable(str(target))
    safe_audit = escape_nonprintable(str(audit_out_dir))
    safe_validate = escape_nonprintable(str(validate_dir))
    safe_selection = escape_nonprintable(str(selection_file))
    safe_raptor = escape_nonprintable(str(_RAPTOR_DIR))
    threat_model = _threat_model_prompt_block(target)
    return f"""You are running the /validate post-pass for the /audit security
review. The audit loop has finished and produced {findings_count} findings
(including sweep-promoted suspicious items confirmed by mechanical tools).
Your job is to run the full validation pipeline to filter false positives.

Target repository:    {safe_target}
Audit out_dir:        {safe_audit}
Selection file:       {safe_selection}
Validate output dir:  {safe_validate}
{threat_model}
Read the findings from {safe_selection}. They are in /validate's
FindingsContainer shape (id, file, line, description, status, etc.) —
no field-mapping needed. Use it as-if it were a findings.json.

Steps:

1. Load .claude/skills/exploitability-validation/SKILL.md from {safe_raptor}
   and follow the full pipeline (Stage 0 mechanical inventory, then Stages
   A through F LLM analysis, then Stage 1 mechanical report) for the
   findings only.

2. Use {safe_validate} as the validate output directory. The launcher has
   already created it via the run lifecycle — do not call
   libexec/raptor-run-lifecycle start.

3. If /understand ran beforehand, its run directory is a sibling of the
   audit out_dir. The /validate bridge finds it automatically.

4. Write the final validation-report.md into {safe_validate}.

Many audit findings are false positives from mechanical tools (SMT proves
arithmetic feasibility but not reachability; Coccinelle matches structure
but not value flow). Stage B and C should catch these — trace the actual
call paths and check for guards at the syscall boundary.

Keep narration brief. Report the per-finding outcomes and exit.
"""


def _threat_model_prompt_block(target: Path) -> str:
    """Load threat-model data from *target* and format it for prompt inclusion.

    # SECURITY: threat model data from target repo is included in prompt.
    # This is by design — the operator chose to scan this repo, so its
    # threat-model file is treated as operator-provided context.  When
    # scanning untrusted repositories the threat model could contain
    # prompt-injection payloads; however, the operator's decision to
    # scan a repo implies acceptance of its content influencing analysis.
    # Reviewers: do NOT remove this without providing an alternative
    # channel for threat-model context.
    """
    try:
        from core.threat_model import threat_model_prompt_block
        return threat_model_prompt_block(target)
    except Exception:  # noqa: BLE001 — best-effort context block, never load-bearing
        return ""


def _emit_findings_json(
    findings_outcomes: list[tuple],
    out_dir: Path,
    target_path: Path,
) -> Path:
    """Write audit findings in /validate container format.

    Built on the canonical /validate dataclasses
    (``FindingsContainer.create_empty`` + ``Finding.from_dict``) so
    the emission carries the same schema /validate Stage A reads —
    including the ``timestamp`` this hand-rolled emitter had silently
    drifted away from — and inherits the canonical value coercion.
    Only the INPUT-side mapping (ReviewOutcome → field names) lives
    here, plus two audit-owned extras the canonical dataclass doesn't
    model (``title``, ``hypothesis``).
    """
    from packages.exploitability_validation.models import (
        Finding,
        FindingsContainer,
    )

    findings: list[dict[str, Any]] = []
    for seq, (_, outcome) in enumerate(findings_outcomes, start=1):
        cwe = _extract_cwe(outcome)
        vuln_type = _resolve_vuln_type(outcome, cwe)
        raw: dict[str, Any] = {
            "id": f"FIND-{seq:03d}",
            "file": outcome.file,
            "function": outcome.function,
            "line": outcome.line or 1,
            "vuln_type": vuln_type,
            "status": "pending",
            "description": outcome.body,
            "severity": "medium",
            "origin": "pre_existing",
        }
        if cwe:
            raw["cwe_id"] = cwe
        finding = Finding.from_dict(raw).to_dict()
        # Audit-owned extras (not modelled by the canonical Finding).
        finding["title"] = (outcome.hypothesis
                            or f"Finding in {outcome.function}")
        if outcome.hypothesis:
            finding["hypothesis"] = outcome.hypothesis
        findings.append(finding)

    container = FindingsContainer.create_empty("audit", str(target_path))
    container.source = "audit"
    payload = container.to_dict()
    payload["findings"] = findings

    path = out_dir / "findings.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    logger.info("emitted %d findings to %s", len(findings), path)
    return path


def _resolve_vuln_type(outcome: ReviewOutcome, cwe: str) -> str:
    """Derive vuln_type from the review result or CWE mapping.

    Priority: review_result.vuln_type (normalised) > CWE mapping > "other".
    """
    if outcome.review_result:
        raw = outcome.review_result.get("vuln_type", "")
        if raw:
            return normalise_vuln_type(raw)
    if cwe:
        return CWE_TO_VULN_TYPE.get(cwe.upper(), "other")
    return "other"


def _extract_cwe(outcome: ReviewOutcome) -> str:
    """Extract CWE from the review result."""
    if outcome.review_result:
        return outcome.review_result.get("cwe") or outcome.review_result.get("cwe_class", "")
    return ""


def _resolve_annotations_dir(out_dir: Path) -> Path:
    """Resolve the annotations directory for this run."""
    ann_dir = out_dir / "annotations"
    if ann_dir.is_dir():
        return ann_dir
    return out_dir.parent / "annotations"


def _auto_feedback(
    *,
    validate_dir: Path,
    annotations_dir: Path,
    audit_out_dir: Path,
) -> None:
    """Import /validate results back into audit annotations.

    Searches for findings.json in the validate output directory and
    feeds verdicts back to update annotation statuses (Reflexion).
    """
    validate_findings_path = validate_dir / "findings.json"
    if not validate_findings_path.is_file():
        logger.debug(
            "auto-feedback: no findings.json in %s", validate_dir,
        )
        return

    if not annotations_dir.is_dir():
        logger.debug(
            "auto-feedback: annotations dir %s not found", annotations_dir,
        )
        return

    try:
        from .feedback import import_validation_results
        counts = import_validation_results(
            validation_report=validate_findings_path,
            annotations_dir=annotations_dir,
            audit_out_dir=audit_out_dir,
        )
        logger.info(
            "auto-feedback: %d updated (%d downgraded, %d upgraded, "
            "%d corroborated, %d skipped)",
            counts.get("updated", 0),
            counts.get("downgraded", 0),
            counts.get("upgraded", 0),
            counts.get("corroborated", 0),
            counts.get("skipped", 0),
        )
    except Exception:
        logger.warning("auto-feedback failed", exc_info=True)
