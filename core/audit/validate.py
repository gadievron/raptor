"""Post-audit validation handoff.

After the audit loop completes, findings (including sweep-promoted
suspicious items) are emitted as findings.json and /validate is
dispatched automatically to filter false positives via the full
Stage A-F pipeline.

Controlled by OrchestratorConfig.validate (default False).
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.json import load_json, save_json
from core.orchestration.skill_dispatch import (
    MAX_VALIDATE_FINDINGS,
    SkillDispatchResult,
    is_sandbox_setup_skip,
    missing_validation_report,
    run_skill_dispatch,
    truncate_findings_by_signal,
)
from core.schema_constants import CWE_TO_VULN_TYPE, normalise_vuln_type

from .record import _resolve_annotations_dir, append_audit_log
from .tree_class import NON_PRODUCTION_TREE_CLASSES, classify_tree_class

if TYPE_CHECKING:
    from .orchestrator import OrchestratorResult, ReviewOutcome

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
    #: Parent-observed child exit (numeric status or timeout label) —
    #: the out-of-band authority for the tail artifact's line-1 label;
    #: None when no child produced one (launch failure / crash).
    child_exit: str | None = None


# Review-confidence rank for dark-outcome selection ordering: dark
# rows carry no exploitability signal (no tool ever confirmed them),
# so the LLM review's own confidence is the only priority available.
_DARK_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}


def _dark_priority(outcome: Any) -> tuple[int, int]:
    """Dark-slot ordering: review confidence first, then tree class —
    production rows win a tied confidence over vendored-compat /
    test-harness rows (preference only; non-production rows still
    fill remaining slots)."""
    review_result = getattr(outcome, "review_result", None) or {}
    conf = str(review_result.get("confidence", "")).lower()
    tree_class = classify_tree_class(str(getattr(outcome, "file", "") or ""))
    return (
        _DARK_CONFIDENCE_RANK.get(conf, 3),
        1 if tree_class in NON_PRODUCTION_TREE_CLASSES else 0,
    )


def validate_findings(
    result: OrchestratorResult,
    *,
    target_path: Path,
    out_dir: Path,
    _review_fn: Any = None,
    _config: Any = None,
) -> OrchestratorResult:
    """Emit audit findings and dispatch /validate.

    Writes findings.json, then launches /validate as a Claude Code
    subprocess to run the full Stage A-F pipeline. The sweep is a
    cheap wide net; /validate is the expensive filter that kills
    false promotions by tracing reachability.

    Dark outcomes ("tool-blind, needs concrete verification") ride the
    same selection: finding-status rows fill the cap first (they are
    signal-sorted at copy time), dark rows take the remaining slots
    ordered by review confidence. Dark rows that do not fit — or that
    never dispatch because the post-pass is skipped — are recorded in
    ``validate-postpass.json`` so the report's completeness block can
    state exactly how many are awaiting validation and how to run it.
    """
    findings_outcomes = [
        (i, o) for i, o in enumerate(result.outcomes)
        if o.status == "finding"
    ]
    dark_outcomes = [
        (i, o) for i, o in enumerate(result.outcomes)
        if o.status == "dark"
    ]
    if not findings_outcomes and not dark_outcomes:
        logger.info("validate_findings: no findings to emit")
        return result

    dark_slots = max(0, _MAX_VALIDATE_FINDINGS - len(findings_outcomes))
    ordered_dark = sorted(dark_outcomes, key=lambda io: _dark_priority(io[1]))
    selected_dark = ordered_dark[:dark_slots]
    dark_deferred = len(dark_outcomes) - len(selected_dark)

    selected = findings_outcomes + selected_dark

    logger.info(
        "validate_findings: emitting %d finding(s) + %d dark for "
        "/validate (%d dark deferred by cap)",
        len(findings_outcomes), len(selected_dark), dark_deferred,
    )

    # findings.json keeps its established contract — finding-status
    # rows only (the /project merged views read it with no status
    # filter, so dark rows there would render as ordinary findings).
    # When dark rows are selected, the post-pass dispatches on a
    # separate validate-selection.json carrying findings + dark.
    path = None
    if findings_outcomes:
        path = _emit_findings_json(findings_outcomes, out_dir, target_path)
    if selected_dark:
        path = _emit_findings_json(
            selected, out_dir, target_path,
            filename="validate-selection.json",
        )

    append_audit_log(out_dir, {
        "action": "findings_emitted",
        "count": len(selected),
        "dark_selected": len(selected_dark),
        "dark_deferred": dark_deferred,
        # Empty selection emits no file — record that as "", not the
        # string "None".
        "path": str(path) if path is not None else "",
    })

    if path is None:
        # Degenerate cap (nothing selectable) — no dispatch, but the
        # remainder is still recorded so the report states it.
        postpass = ValidatePostpassResult(
            ran=False, skipped_reason="empty selection (cap exhausted)",
        )
    else:
        postpass = _dispatch_validate(
            target_path=target_path,
            audit_out_dir=out_dir,
            findings_path=path,
            findings_count=len(selected),
            dark_count=len(selected_dark),
        )

    append_audit_log(out_dir, {
        "action": "validate_postpass",
        "ran": postpass.ran,
        "selected_count": postpass.selected_count,
        "dark_selected": len(selected_dark),
        "dark_deferred": dark_deferred,
        "validate_dir": postpass.validate_dir,
        "skipped_reason": postpass.skipped_reason,
        "duration_s": postpass.duration_s,
    })

    _write_postpass_record(
        out_dir=out_dir,
        target_path=target_path,
        postpass=postpass,
        findings_selected=len(findings_outcomes),
        dark_total=len(dark_outcomes),
        dark_selected=len(selected_dark),
        dark_deferred=dark_deferred,
    )

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


def _followup_command(target_path: Path, out_dir: Path) -> str:
    """The exact operator command that adjudicates deferred dark rows.

    ``/validate`` accepts ``--findings <file>`` imports (see
    ``.claude/commands/validate.md``; ``libexec/raptor-validation-helper``
    stage 0 parses the flag), and findings-graded.json carries every
    dark row with ``needs_validation: true``. ``--include-dark`` is
    required: the import chokepoint routes dark rows to the witness
    backlog by default, and THIS command's whole purpose is the
    explicit opt-in — running it IS the operator's decision to spend
    validation budget on tool-blind rows.
    """
    return (
        f"/validate {target_path} "
        f"--findings {Path(out_dir) / 'findings-graded.json'} "
        f"--include-dark"
    )


#: Bytes read from the end of the tail artifact before escaping.
_CHILD_TAIL_READ_BYTES = 4096

#: Bytes read from the start of the artifact for the head line.
_CHILD_TAIL_HEAD_BYTES = 256

#: Escaped-character window applied to the artifact tail.
_CHILD_TAIL_WINDOW_CHARS = 2000


def _read_child_tail_untrusted(path: Path) -> str | None:
    """Bounded, symlink-refusing read of the dispatch tail artifact.

    The artifact lives in a directory the CC child writes by design,
    and on the launch-failure path the PARENT never wrote it (the
    timeout arm persists the kill's partial capture, but the child
    may still have replaced the name) — whatever sits here can be
    child-controlled. Refuse
    symlinks and specials (O_NOFOLLOW + fstat, the inventory probe's
    discipline), read only the file's head line and last 4 KiB (a
    planted sparse giant must not buffer), and escape control bytes
    AT READ TIME — the writer's escape only covers the paths where
    the parent wrote.

    Label-preserving window (see the excerpting contract in
    :mod:`core.security.log_sanitisation`): the excerpt re-attaches
    the artifact's line 1 with an explicit elision marker whenever
    the tail window cut anything. A bare tail slice dropped the
    parent-authored ``exit=<label>`` authority line as soon as the
    child padded its stdout past the window — the operator-facing
    excerpt then LED with whatever narrative the child chose to end
    its stream with. Exit AUTHORITY still never comes from these
    bytes (``child_exit`` carries it out-of-band); the head line is
    re-attached so the artifact's own account cannot be silently
    beheaded.
    """
    import stat as _stat

    from core.security.log_sanitisation import (
        escape_nonprintable,
        sanitise_for_terminal,
    )

    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            return None
        head = os.read(fd, _CHILD_TAIL_HEAD_BYTES)
        if st.st_size > _CHILD_TAIL_READ_BYTES:
            os.lseek(fd, st.st_size - _CHILD_TAIL_READ_BYTES, os.SEEK_SET)
        else:
            os.lseek(fd, 0, os.SEEK_SET)
        data = os.read(fd, _CHILD_TAIL_READ_BYTES)
    except OSError:
        return None
    finally:
        os.close(fd)
    text = data.decode("utf-8", errors="replace")
    escaped = escape_nonprintable(text, preserve_newlines=True)
    window = escaped[-_CHILD_TAIL_WINDOW_CHARS:]
    skipped_bytes = max(0, st.st_size - len(data))
    if skipped_bytes == 0 and len(window) == len(escaped):
        return window
    # The cut landed mid-document: resume at a true line boundary so
    # a boundary-truncated quoted body line (``| XXexit=0`` cut right
    # before the ``e``) cannot masquerade as a column-0 writer line.
    # A window with no newline at all is kept whole — the writer's
    # artifact format always carries newlines, so that case is a
    # wholesale child-replaced artifact where quoting carries no
    # authority anyway (``child_exit`` does).
    nl = window.find("\n")
    if nl >= 0:
        window = window[nl + 1:]
    cut_chars = len(escaped) - len(window)
    head_line = sanitise_for_terminal(
        head.split(b"\n", 1)[0].decode("utf-8", errors="replace"),
        max_len=300,
    )
    return (
        f"{head_line}\n"
        f"[… ~{skipped_bytes + cut_chars} bytes elided …]\n"
        f"{window}"
    )


def _write_postpass_record(
    *,
    out_dir: Path,
    target_path: Path,
    postpass: ValidatePostpassResult,
    findings_selected: int,
    dark_total: int,
    dark_selected: int,
    dark_deferred: int,
) -> None:
    """Persist the post-pass selection record (validate-postpass.json).

    The report's completeness block reads this to state honestly how
    many dark findings never reached the post-pass — cap-deferred rows
    when the dispatch ran, ALL dark rows when it did not — together
    with the exact follow-up command. Best-effort: a write failure
    must not break the audit pipeline (the report then conservatively
    treats every dark row as awaiting).
    """
    dark_awaiting = dark_total if not postpass.ran else dark_deferred
    record: dict[str, object] = {
        "ran": postpass.ran,
        "skipped_reason": postpass.skipped_reason,
        # Out-of-band exit authority: computed from the dispatch
        # result the parent holds, never recovered from artifact
        # bytes (the tail artifact is child-controllable).
        "child_exit": postpass.child_exit,
        "validate_dir": postpass.validate_dir,
        "findings_selected": findings_selected,
        "dark_total": dark_total,
        "dark_selected": dark_selected,
        "dark_awaiting": dark_awaiting,
        "followup_command": _followup_command(target_path, out_dir),
    }
    if not postpass.ran and postpass.validate_dir:
        # A failed dispatch usually leaves the child's narrative
        # beside the pass (dispatch-child-tail.log); an excerpt in the
        # record saves the operator a dig for the most common question
        # — what did the child say.
        tail = Path(postpass.validate_dir) / "dispatch-child-tail.log"
        excerpt = _read_child_tail_untrusted(tail)
        if excerpt is not None:
            record["child_tail_path"] = str(tail)
            record["child_tail_excerpt"] = excerpt
    try:
        save_json(Path(out_dir) / "validate-postpass.json", record)
    except Exception:
        logger.debug("validate-postpass.json write failed", exc_info=True)


def _dispatch_validate(
    *,
    target_path: Path,
    audit_out_dir: Path,
    findings_path: Path,
    findings_count: int,
    dark_count: int = 0,
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
            dark_count=dark_count,
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
    dark_count: int = 0,
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

        from core.inventory import checklist_exists
        audit_checklist = audit_out_dir / "checklist.json"
        # Either on-disk form qualifies (the pointer names the SLOT
        # path; the /validate reader resolves the form itself).
        if checklist_exists(audit_out_dir):
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
            dark_count=dark_count,
        )

    # cc-trust gate: refuse to dispatch a Claude Code child against a
    # repo whose .claude/settings / .mcp.json the operator has not
    # trusted for cc dispatch. Same gate the /agentic launcher applies
    # (check_repo_claude_trust honours the operator's --trust-repo via
    # set_trust_override). Pre-consolidation the audit handoff had no
    # such gate — an untrusted repo's config reached the CC child.
    from core.security.cc_trust import check_repo_claude_trust

    def _run_dispatch() -> SkillDispatchResult:
        return run_skill_dispatch(
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
            # Success = the pipeline's actual outcome, never the CC
            # child's exit status alone: a child whose in-run pipeline
            # crashed can still exit 0 (it narrates the failure and
            # exits cleanly), which used to record the pass as
            # ran/completed while every selected finding stayed
            # pending. The probe requires the terminal artifact
            # (validation-report.md, non-empty) before the pass may
            # count as ran; otherwise the lifecycle is failed and the
            # reason reaches validate-postpass.json + the run report.
            validate_outputs=missing_validation_report,
        )

    dispatch = _run_dispatch()
    if not dispatch.ran and is_sandbox_setup_skip(dispatch.skipped_reason):
        # One bounded retry, sandbox-setup failures only: the child
        # never launched (no billed work to double-run) and the
        # refusal can be transient host state rather than a property
        # of this pass. A second identical refusal is treated as real
        # and surfaces through the postpass record and run report.
        #
        # A zero-verdict outcome (missing_validation_report) is
        # deliberately NOT retried: the child ran to completion, so
        # the pass's LLM budget is already spent (a retry doubles it),
        # and an in-child pipeline crash is a property of the run's
        # inputs or host configuration rather than transient launch
        # state — the retry would spend the same budget to hit the
        # same wall. It surfaces as a failed pass with the reason and
        # the exact operator follow-up command instead.
        logger.warning(
            "validate post-pass: %s — retrying once",
            dispatch.skipped_reason,
        )
        dispatch = _run_dispatch()
    return ValidatePostpassResult(
        ran=dispatch.ran,
        selected_count=findings_count,
        validate_dir=str(dispatch.run_dir) if dispatch.run_dir else None,
        skipped_reason=dispatch.skipped_reason or "",
        duration_s=dispatch.duration_s,
        child_exit=dispatch.child_exit,
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
    container = load_json(findings_path, max_bytes=256 * 1024 * 1024)
    if container is None:
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
    save_json(dest, container)


def _build_audit_validate_prompt(
    target: Path,
    audit_out_dir: Path,
    validate_dir: Path,
    selection_file: Path,
    findings_count: int,
    *,
    dark_count: int = 0,
) -> str:
    from core.security.log_sanitisation import escape_nonprintable
    safe_target = escape_nonprintable(str(target))
    safe_audit = escape_nonprintable(str(audit_out_dir))
    safe_validate = escape_nonprintable(str(validate_dir))
    safe_selection = escape_nonprintable(str(selection_file))
    safe_raptor = escape_nonprintable(str(_RAPTOR_DIR))
    threat_model = _threat_model_prompt_block(target)
    dark_block = ""
    if dark_count:
        # The selection deliberately carries these dark rows (they won
        # cap slots at selection time) — if the child stages them via
        # a `--findings` import it must opt in with --include-dark,
        # because the import chokepoint otherwise routes dark rows to
        # the witness backlog by default.
        dark_block = f"""
{dark_count} of the findings carry audit_status "dark": the audit's
mechanical tools had NO channel to confirm or refute them (tool-blind
class). Treat them as unverified hypotheses — they need concrete
reachability and impact verification from first principles, not tool
corroboration. If you import the selection file with
`raptor-validation-helper 0 --findings ...`, pass `--include-dark` —
these dark rows were deliberately selected for validation and must not
be routed to the witness backlog.
"""
    return f"""You are running the /validate post-pass for the /audit security
review. The audit loop has finished and produced {findings_count} findings
(including sweep-promoted suspicious items confirmed by mechanical tools).
Your job is to run the full validation pipeline to filter false positives.
{dark_block}
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
    *,
    filename: str = "findings.json",
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
        # tree_class rides along so the budget-capped selection
        # (truncate_findings_by_signal) can prefer production findings
        # on signal ties — a tag, never a filter.
        finding["tree_class"] = classify_tree_class(str(outcome.file or ""))
        finding["title"] = (outcome.hypothesis
                            or f"Finding in {outcome.function}")
        if outcome.hypothesis:
            finding["hypothesis"] = outcome.hypothesis
        if outcome.status == "dark":
            # Tool-blind bucket routed into the post-pass: keep the
            # audit-side status visible so /validate (and readers of
            # selected-findings.json) know this row was never
            # tool-confirmed — it needs concrete verification.
            finding["audit_status"] = "dark"
            finding["needs_validation"] = True
        findings.append(finding)

    container = FindingsContainer.create_empty("audit", str(target_path))
    container.source = "audit"
    payload = container.to_dict()
    payload["findings"] = findings

    path = out_dir / filename
    save_json(path, payload)

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


# Annotations resolve through record._resolve_annotations_dir (run-pin
# aware) — a local pre-pin twin here resolved --out and standalone
# runs to a shared bare out_dir.parent pseudo-project dir, so the
# Reflexion auto-feedback read/wrote annotations at a different level
# than the orchestrator's writer.


def _auto_feedback(
    *,
    validate_dir: Path,
    annotations_dir: Path,
    audit_out_dir: Path,
) -> None:
    """Import /validate results as review-journal corrections.

    Searches for findings.json in the validate output directory and
    appends correction entries to the review journal (Reflexion);
    annotations are consulted read-only, never written back.
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
            "auto-feedback: %d updated (%d downgraded to clean, "
            "%d demoted to suspicious, %d upgraded, "
            "%d corroborated, %d skipped)",
            counts.get("updated", 0),
            counts.get("downgraded_clean", 0),
            counts.get("downgraded_suspicious", 0),
            counts.get("upgraded", 0),
            counts.get("corroborated", 0),
            counts.get("skipped", 0),
        )
    except Exception:
        logger.warning("auto-feedback failed", exc_info=True)
