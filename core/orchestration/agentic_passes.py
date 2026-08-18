"""Pre-scan and post-scan enrichment passes for /agentic.

When the user passes ``--understand`` or ``--validate``, these functions
dispatch ``claude -p`` subprocesses with the relevant skill loaded. Both
passes are first-class run dirs created via libexec/raptor-run-lifecycle,
so the resulting artefacts are project-aware and discoverable by the
existing /understand → /validate bridge:

  --understand: creates a proper command_type=understand run dir as a
                sibling of the agentic run dir (project sibling in
                project mode, global out/ otherwise). Builds checklist,
                runs the /understand --map workflow via claude -p, and
                produces context-map.json. The artefact is reusable by
                later /validate runs against the same target via the
                bridge tier-2/3 lookup.

  --validate:   creates a proper command_type=validate run dir as a
                sibling of the agentic run dir. Selects findings with
                is_exploitable == True or confidence == "high",
                persists them to a file (defending against finding_id
                prompt injection), then runs the /validate skill via
                claude -p. The bridge tier-2 lookup finds the
                understand sibling automatically — no copying.

Both passes degrade gracefully:
  - claude not on PATH      -> skipped, base pipeline still runs
  - block_cc_dispatch=True  -> skipped (untrusted target repo)
  - lifecycle start fails   -> skipped, no orphan dir
  - subprocess fails        -> lifecycle marked failed, base pipeline continues

The return value carries a ``skipped`` reason so the main flow can log it.
Functions never raise — a backstop catches unexpected exceptions and turns
them into ran=False.
"""

from __future__ import annotations

import logging
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from core.json import load_json, save_json
from core.orchestration.skill_dispatch import (
    MAX_VALIDATE_FINDINGS,
    StageError,
    run_skill_dispatch,
    truncate_findings_by_signal,
)
from core.orchestration.skill_dispatch import (
    build_checklist as _build_checklist_via_libexec,
)
from core.schema_constants import CONFIDENCE_LEVELS
from core.security.log_sanitisation import escape_nonprintable

logger = logging.getLogger(__name__)

# core/orchestration/agentic_passes.py -> repo root (parents[2])
_RAPTOR_DIR = Path(__file__).resolve().parents[2]

# Canonical "high" confidence value. Asserted against the enum at import so a
# future reorder of CONFIDENCE_LEVELS can't silently break post-pass selection.
_HIGH_CONFIDENCE = "high"
assert _HIGH_CONFIDENCE in CONFIDENCE_LEVELS, \
    f"_HIGH_CONFIDENCE drift: {_HIGH_CONFIDENCE!r} not in {CONFIDENCE_LEVELS!r}"

# Re-exported from the shared skill-dispatch substrate (kept as a module
# attribute so tests/monkeypatchers can dial the cap per-module).
_MAX_VALIDATE_FINDINGS = MAX_VALIDATE_FINDINGS

_UNDERSTAND_TOOLS = "Read,Grep,Glob,Write,Bash"
_VALIDATE_TOOLS = "Read,Grep,Glob,Write,Bash"

_PREPASS_BUDGET_USD = "5.00"
_POSTPASS_BUDGET_USD = "10.00"
_PREPASS_TIMEOUT_S = 900    # 15 min — whole-repo map can take a while
_POSTPASS_TIMEOUT_S = 1800  # 30 min — multi-stage validate over multiple findings
_LIFECYCLE_TIMEOUT_S = 30   # lifecycle helpers are mechanical; should be instant
_CHECKLIST_TIMEOUT_S = 300  # build_checklist parses every source file


@dataclass
class PrepassResult:
    """Outcome of run_understand_prepass()."""
    ran: bool
    skipped_reason: str | None = None
    understand_dir: Path | None = None     # the proper run dir, if created
    context_map_path: Path | None = None
    checklist_enriched: bool = False          # priority markers written to agentic checklist?
    duration_s: float = 0.0


@dataclass
class PostpassResult:
    """Outcome of run_validate_postpass()."""
    ran: bool
    skipped_reason: str | None = None
    selected_count: int = 0
    validate_dir: Path | None = None
    report_path: Path | None = None
    duration_s: float = 0.0


@dataclass
class ReachabilityPrepassResult:
    """Outcome of run_reachability_prepass().

    ``inventory`` is the (possibly cached) inventory dict the
    prepass built. The agentic launcher threads it through to
    downstream consumers (codeql analyzer, /validate Stage B)
    so they don't re-walk the source tree.
    """
    ran: bool
    skipped_reason: str | None = None
    marked_count: int = 0          # functions marked priority=low
    inventory: Any | None = None
    duration_s: float = 0.0


def run_understand_prepass(
    target: Path,
    agentic_out_dir: Path,
    block_cc_dispatch: bool = False,
    claude_bin: str | None = None,
) -> PrepassResult:
    """Run the /understand --map skill before scanning.

    Creates a proper /understand run directory and enriches the agentic
    pipeline's checklist with priority markers from the resulting context map.

    Never raises — enrichment failure must not break the base agentic pipeline.
    """
    try:
        return _run_understand_prepass_unsafe(
            target, agentic_out_dir, block_cc_dispatch, claude_bin)
    except Exception as e:
        logger.exception("understand pre-pass crashed unexpectedly")
        return PrepassResult(ran=False,
                             skipped_reason=f"unexpected {type(e).__name__}: {e}")


def _run_understand_prepass_unsafe(
    target: Path,
    agentic_out_dir: Path,
    block_cc_dispatch: bool,
    claude_bin: str | None,
) -> PrepassResult:
    target = Path(target).resolve()
    agentic_out_dir = Path(agentic_out_dir).resolve()

    def _stage(understand_dir: Path) -> None:
        # Reuse the agentic pipeline's checklist if it's already built. Both
        # are produced from the same target via the same parser, so the
        # contents are equivalent — and it skips parsing the whole repo a
        # second time. Falls back to a fresh build if the agentic checklist
        # isn't present (e.g. when build_inventory failed earlier).
        if not _provision_understand_checklist(target, agentic_out_dir,
                                                understand_dir):
            raise StageError("checklist build failed")

    def _check_outputs(understand_dir: Path) -> str | None:
        context_map = understand_dir / "context-map.json"
        if not context_map.exists():
            return "context-map.json missing after run"
        # claude -p might have crashed mid-write or produced structurally
        # invalid output. Existence isn't enough — the bridge silently returns
        # no context for unparseable files, and crashes mid-iteration if a
        # required-list field is the wrong type. Validate both parseability
        # and basic shape here so a misbehaving claude run fails the
        # lifecycle cleanly instead of being marked complete with garbage.
        parsed = load_json(context_map)
        shape_error = _validate_context_map_shape(parsed)
        if shape_error is not None:
            return f"context-map.json invalid: {shape_error}"
        return None

    # The shared runner adds str(_RAPTOR_DIR) on top of the calibrated
    # readable_paths so the LLM-directed Bash tool can invoke
    # libexec/raptor-normalize-context-map (MAP-5) and
    # libexec/raptor-coverage-summary --mark (MAP-6) — those scripts
    # live under RAPTOR_DIR. target + understand_dir are auto-
    # allowlisted via the target=/output= positional args.
    dispatch = run_skill_dispatch(
        command="understand",
        target=target,
        tools=_UNDERSTAND_TOOLS,
        budget_usd=_PREPASS_BUDGET_USD,
        timeout_s=_PREPASS_TIMEOUT_S,
        caller_label="agentic-understand",
        log_label="understand pre-pass",
        build_prompt=lambda run_dir: _build_understand_prompt(target, run_dir),
        block_cc_dispatch=block_cc_dispatch,
        claude_bin=claude_bin,
        stage=_stage,
        validate_outputs=_check_outputs,
    )
    if not dispatch.ran:
        return PrepassResult(ran=False,
                             skipped_reason=dispatch.skipped_reason,
                             understand_dir=dispatch.run_dir,
                             duration_s=dispatch.duration_s)

    context_map = dispatch.run_dir / "context-map.json"

    # Best-effort: enrich the agentic checklist with priority markers from
    # the context map. The agentic analysis pipeline reads priority/
    # priority_reason from per-function metadata and surfaces it in the
    # analysis prompt — so --understand pays off in this run too, not just
    # any later /validate.
    enriched = _enrich_agentic_checklist(agentic_out_dir, context_map)

    # NOTE: the reachability low-priority marking previously
    # lived here (under the --understand-only branch) but is
    # now hoisted to ``run_reachability_prepass`` so it fires
    # regardless of whether --understand was passed.
    # Operators not using --understand still get the dead-
    # code priority signal in their checklist, which
    # benefits the agentic LLM budget allocation.

    return PrepassResult(
        ran=True,
        understand_dir=dispatch.run_dir,
        context_map_path=context_map,
        checklist_enriched=enriched,
        duration_s=dispatch.duration_s,
    )


def run_validate_postpass(
    target: Path,
    agentic_out_dir: Path,
    analysis_report: Path,
    block_cc_dispatch: bool = False,
    claude_bin: str | None = None,
    *,
    allow_unreachable: bool = False,
) -> PostpassResult:
    """Run /validate against findings flagged exploitable or high-confidence.

    Creates a proper /validate run directory as a sibling of the agentic dir
    so the bridge's tier-2 lookup finds any /understand sibling automatically.

    ``allow_unreachable`` is forwarded into the validate-driver prompt so
    the claude-code sub-agent knows the operator opted into in-isolation
    review. The agent passes it through to the PipelineConfig when
    constructing the validation pipeline (the substrate's
    PipelineConfig.allow_unreachable field threads to the Stage B
    attack-path demoter).

    Never raises — enrichment failure must not break the base agentic pipeline.
    """
    try:
        return _run_validate_postpass_unsafe(
            target, agentic_out_dir, analysis_report, block_cc_dispatch,
            claude_bin, allow_unreachable=allow_unreachable)
    except Exception as e:
        logger.exception("validate post-pass crashed unexpectedly")
        return PostpassResult(ran=False,
                              skipped_reason=f"unexpected {type(e).__name__}: {e}")


def _run_validate_postpass_unsafe(
    target: Path,
    agentic_out_dir: Path,
    analysis_report: Path,
    block_cc_dispatch: bool,
    claude_bin: str | None,
    *,
    allow_unreachable: bool = False,
) -> PostpassResult:
    target = Path(target).resolve()
    agentic_out_dir = Path(agentic_out_dir).resolve()
    analysis_report = Path(analysis_report)

    selected: list = []

    def _preflight() -> str | None:
        if not analysis_report.exists():
            return "analysis report not found — base pipeline produced no results"
        found = _select_findings_for_validate(analysis_report)
        if not found:
            return "no findings matched is_exploitable=true or confidence=high"
        selected.extend(truncate_findings_by_signal(
            found, _MAX_VALIDATE_FINDINGS, log_label="validate post-pass"))
        return None

    def _stage(validate_dir: Path) -> None:
        # Persist the selected records to a file rather than splicing
        # LLM-generated finding_id values into the prompt — defends against
        # any injection attempt riding in on a finding identifier.
        # Convert from /agentic shape to /validate shape so the validate
        # skill can consume the file directly without prompt-driven
        # field translation (was the stopgap; this is the real fix).
        selection_file = validate_dir / "selected-findings.json"
        save_json(selection_file,
                  convert_agentic_to_validate(selected, str(target)))

        # Drop a pointer to the parent /agentic checklist so /validate's
        # Stage 0 can reuse it instead of rebuilding the inventory from
        # scratch. The reachability prepass already built one; pointing
        # at it saves a full source-tree walk + AST parse (~30-60s on
        # typical large repos). /validate's Stage 0 reads
        # ``parent-checklist-pointer.json`` and falls through to a fresh
        # build when the pointer is missing / stale / mistargeted /
        # outside the expected root.
        #
        # ``expected_root_dir`` is the agentic_out_dir; /validate
        # rejects pointers whose ``checklist_path`` resolves outside
        # this root (defense against a buggy or malicious pointer
        # pointing at arbitrary file paths). Same defensive principle
        # as the /understand bridge's path validation. The mtime-based
        # TTL on the validate side rejects checklists older than 1h
        # (stale source drift).
        agentic_checklist = agentic_out_dir / "checklist.json"
        if agentic_checklist.is_file():
            save_json(
                validate_dir / "parent-checklist-pointer.json",
                {
                    "checklist_path": str(agentic_checklist.resolve()),
                    "expected_target_path": str(target),
                    "expected_root_dir": str(agentic_out_dir.resolve()),
                },
            )

        # Operator-flag handoff to the validation orchestrator.
        # Mirrors the parent-checklist-pointer.json pattern: the
        # launcher writes overrides to a known filename in
        # validate_dir; the orchestrator's Stage 0 reads it and
        # merges into self.config. Substrate-enforced — bypasses
        # the claude-code sub-agent's prompt-interpretation path
        # entirely, so the flag works regardless of whether the
        # SKILL.md teaches the agent about it.
        if allow_unreachable:
            save_json(
                validate_dir / "pipeline-config-overrides.json",
                {"allow_unreachable": True},
            )

    def _prompt(validate_dir: Path) -> str:
        return _build_validate_prompt(
            target, agentic_out_dir, validate_dir,
            analysis_report.resolve(),
            validate_dir / "selected-findings.json", len(selected),
            allow_unreachable=allow_unreachable)

    # /validate's tool list is broad (Bash for sandbox prep, SMT,
    # feasibility helpers), all of which run from RAPTOR_DIR/libexec;
    # agentic_out_dir (context_dirs) holds the prior phases' artefacts
    # the LLM reads back. restrict_reads still applies — those paths
    # are in readable_paths; $HOME secrets stay denied.
    dispatch = run_skill_dispatch(
        command="validate",
        target=target,
        tools=_VALIDATE_TOOLS,
        budget_usd=_POSTPASS_BUDGET_USD,
        timeout_s=_POSTPASS_TIMEOUT_S,
        caller_label="agentic-validate",
        log_label="validate post-pass",
        build_prompt=_prompt,
        block_cc_dispatch=block_cc_dispatch,
        claude_bin=claude_bin,
        context_dirs=(agentic_out_dir,),
        preflight=_preflight,
        stage=_stage,
    )
    if not dispatch.ran:
        return PostpassResult(ran=False, selected_count=len(selected),
                              validate_dir=dispatch.run_dir,
                              skipped_reason=dispatch.skipped_reason,
                              duration_s=dispatch.duration_s)

    report_path = dispatch.run_dir / "validation-report.md"
    return PostpassResult(ran=True, selected_count=len(selected),
                          validate_dir=dispatch.run_dir,
                          report_path=report_path if report_path.exists() else None,
                          duration_s=dispatch.duration_s)


def _provision_understand_checklist(target: Path, agentic_out_dir: Path,
                                     understand_dir: Path) -> bool:
    """Make sure understand_dir/checklist.json exists.

    Both the agentic pipeline and an /understand run produce checklists from
    the same target via the same parser, so when the agentic checklist
    already exists we just copy it (saves re-parsing the whole repo).
    Falls back to running raptor-build-checklist when no agentic checklist
    is available (e.g. build_inventory failed earlier).
    """
    agentic_checklist = agentic_out_dir / "checklist.json"
    if agentic_checklist.exists():
        try:
            shutil.copyfile(agentic_checklist, understand_dir / "checklist.json")
            logger.info("reused agentic checklist for understand pre-pass (skipped reparse)")
            return True
        except OSError as e:
            logger.warning("checklist copy failed (%s); falling back to fresh build", e)
    return _build_checklist_via_libexec(target, understand_dir)


def convert_agentic_to_validate(agentic_findings: list, target_path: str) -> dict:
    """Translate /agentic finding shape into /validate FindingsContainer shape.

    The two pipelines deliberately use different field names (see the field
    alignment table in core/schema_constants.py). Without this converter,
    the post-pass would have to ask claude to do the translation in-prompt
    — fragile, since the LLM may forget fields or mis-handle the
    ``ruling`` string→object change.

    The output is built on the canonical /validate dataclasses
    (``FindingsContainer.create_empty`` + ``Finding.from_dict``) so
    coercion fixes on the /validate side (line coercion, None handling)
    apply here automatically instead of being re-implemented. Only the
    INPUT-side field mapping (agentic → validate names) lives here.

    Args:
        agentic_findings: list of finding dicts in /agentic shape (per
            FINDING_RESULT_SCHEMA).
        target_path: the target repo path; written into the container.

    Returns:
        A dict in /validate FindingsContainer shape — ready to drop into a
        findings.json that /validate's Stage 0/A can consume directly.
    """
    from packages.exploitability_validation.models import FindingsContainer

    container = FindingsContainer.create_empty(
        "agentic-postpass", target_path)
    container.source = "agentic-hybrid-orchestration"
    payload = container.to_dict()
    payload["findings"] = [
        _convert_one_finding(f)
        for f in (agentic_findings or [])
        if isinstance(f, dict)
    ]
    return payload


def _convert_one_finding(f: dict) -> dict:
    """Convert a single /agentic finding dict to /validate Finding shape.

    Input-side renames stay here; the value coercion and serialisation
    happen in the canonical ``Finding`` dataclass. Two caller-owned
    exceptions ride on top of the canonical dict:

    - ``ruling``: /agentic's verdict trace passes through verbatim
      (deep-copied) — the canonical ``Ruling`` would drop the
      ``agentic_ruling`` marker and any nested evidence other readers
      still hold references to.
    - ``origin``: set to "agentic-postpass" so /validate knows the
      finding came pre-analysed.
    """
    from packages.exploitability_validation.models import Finding

    # Renames per the schema_constants alignment table.
    raw: dict = {
        "id": str(f.get("finding_id") or f.get("id") or ""),
        "file": f.get("file_path") or f.get("file") or "",
        "line": f.get("start_line") or f.get("line") or 0,
        "description": f.get("reasoning") or f.get("description") or "",
        # Origin marker so /validate knows the finding came pre-analysed
        # and may want to skip Stage A discovery.
        "origin": "agentic-postpass",
    }
    # Pass-through fields — same names on both sides.
    for key in (
        "vuln_type", "cwe_id", "severity_assessment",
        "cvss_vector", "cvss_score_estimate",
        "confidence", "attack_scenario",
        "dataflow_summary", "remediation",
        "false_positive_reason",
        "tool", "rule_id",
    ):
        if f.get(key) is not None:
            raw[key] = f[key]
    # is_exploitable: /agentic uses two key names depending on dispatch
    # mode (the schema says is_exploitable, sequential mode emits the
    # legacy "exploitable"). Normalise to is_exploitable.
    if f.get("is_exploitable") is not None:
        raw["is_exploitable"] = f["is_exploitable"]
    elif f.get("exploitable") is not None:
        raw["is_exploitable"] = f["exploitable"]
    if f.get("is_true_positive") is not None:
        raw["is_true_positive"] = f["is_true_positive"]

    out = Finding.from_dict(raw).to_dict()
    # ruling: /agentic emits a string verdict (e.g. "validated",
    # "false_positive"); /validate expects an object {"status": ...}.
    # Attached AFTER canonical serialisation — see docstring.
    out["ruling"] = _convert_ruling(
        f.get("ruling"), f.get("false_positive_reason"))
    return out


def _convert_ruling(agentic_ruling, fp_reason) -> dict:
    """Wrap /agentic's string ruling into /validate's ruling object shape.

    Returns an object with at least ``status``, plus ``reason`` carrying any
    false_positive_reason. Keeps the agentic ruling string as a separate
    field so the original verdict is preserved verbatim alongside the
    /validate-native status field.

    When the input is already a dict, returns a DEEP COPY rather than
    aliasing the original. Pre-fix the dict-input branch returned the
    caller's reference unchanged. Downstream consumers writing into
    `result.ruling.<field>` (status update, reason augmentation,
    nested evidence push) would mutate the original /agentic
    finding's ruling — which OTHER readers (per-finding telemetry,
    consensus scoring, the finding-id-keyed rolled-up report) might
    still be holding. Symptom: later log/report renderings showed
    "ruling.reason" with content that should only have appeared in
    the /validate post-pass, contaminating /agentic's verdict trace.
    """
    if isinstance(agentic_ruling, dict):
        from copy import deepcopy
        return deepcopy(agentic_ruling)
    ruling = {"status": agentic_ruling or "", "agentic_ruling": agentic_ruling or ""}
    if fp_reason:
        ruling["reason"] = fp_reason
    return ruling


def _validate_context_map_shape(parsed) -> str | None:
    """Return None if parsed context-map is structurally usable, else an
    error message describing the first problem found.

    The bridge iterates entry_points / sink_details / sources / sinks /
    trust_boundaries directly and calls .get() on each entry. If any of
    those is the wrong type (e.g. a string instead of a list), iteration
    explodes with AttributeError. Catch it here so the lifecycle gets
    marked failed, not the backstop after lifecycle was already completed.
    """
    if parsed is None:
        return "unparseable JSON"
    if not isinstance(parsed, dict):
        return "not a JSON object"
    list_keys = (
        "entry_points",
        "sink_details",
        "sources",
        "sinks",
        "trust_boundaries",
        # Pre-fix `unchecked_flows` was missing from this guard
        # despite the bridge iterating it in `_filter_context_map`
        # and `enrich_checklist`. A non-list value (LLM emitting
        # `unchecked_flows: {}` or `unchecked_flows: "n/a"`)
        # crashed the bridge after lifecycle had already started,
        # producing a stack trace that read like a bridge bug
        # rather than a malformed input.
        "unchecked_flows",
        # Same applies to `boundary_details` — _filter_context_map
        # iterates this list under the same shape contract.
        "boundary_details",
    )
    for key in list_keys:
        value = parsed.get(key)
        if value is None:
            continue
        if not isinstance(value, list):
            return f"{key!r} must be a list, got {type(value).__name__}"
    return None


def _enrich_agentic_checklist(agentic_out_dir: Path, context_map_path: Path) -> bool:
    """Mark high-priority functions in the agentic checklist using the context map.

    The bridge's enrich_checklist writes ``priority`` / ``priority_reason``
    onto matching function entries. The agentic analysis pipeline copies
    these into per-finding metadata (see packages/llm_analysis/agent.py)
    and surfaces them in the analysis prompt (see prompts/analysis.py).

    Returns True if enrichment succeeded, False otherwise. Best-effort —
    failure here doesn't block the pipeline.

    Logs a warning if the context map exposed entry-points/sinks but zero
    file-paths matched the checklist — that's almost always a path-convention
    mismatch (LLM produced absolute paths instead of relative-from-target,
    or some other drift) and would otherwise be a silent no-op.
    """
    checklist_path = agentic_out_dir / "checklist.json"
    if not checklist_path.exists():
        logger.info("agentic checklist not found at %s; skipping enrichment", checklist_path)
        return False
    try:
        from core.orchestration.understand_bridge import enrich_checklist
        checklist = load_json(checklist_path)
        context_map = load_json(context_map_path)
        if not isinstance(checklist, dict) or not isinstance(context_map, dict):
            logger.warning("checklist or context_map not a JSON object; skipping enrichment")
            return False

        ep_count = len(context_map.get("entry_points") or [])
        sink_count = len(context_map.get("sink_details") or [])
        if ep_count == 0 and sink_count == 0:
            # Empty/trivial context-map — nothing to enrich. Don't claim
            # success: the caller checks ``checklist_enriched`` to decide
            # whether the analysis prompts will see priority markers.
            logger.info(
                "context-map has no entry_points or sinks; skipping enrichment "
                "(claude -p may have produced an empty/degenerate map)"
            )
            return False
        enrich_checklist(checklist, context_map, str(agentic_out_dir))
        # `or []` falls back only on falsy — a malformed checklist with
        # files / items / functions as a non-list (string, int, dict)
        # would still hit `for x in 42` and raise TypeError. Guard each
        # iteration explicitly so corrupt input degrades to "0 marked"
        # rather than crashing the post-pass.
        def _as_list(v):
            return v if isinstance(v, list) else []
        marked = sum(
            1
            for f in _as_list(checklist.get("files"))
            if isinstance(f, dict)
            for fn in (_as_list(f.get("items")) or _as_list(f.get("functions")))
            if isinstance(fn, dict) and fn.get("priority") == "high"
        )
        if marked == 0:
            # Path-convention mismatch is the most common cause: context-map
            # uses paths the checklist's strict-equality match doesn't see.
            logger.warning(
                "checklist enrichment marked 0 functions despite %d entry-points + "
                "%d sinks in context map — likely a path-convention mismatch "
                "(check context-map.json file paths vs checklist.json file paths)",
                ep_count, sink_count,
            )
            return False
        logger.info("enriched %d functions in agentic checklist", marked)
        return True
    except Exception as e:                          # noqa: BLE001
        logger.warning("checklist enrichment failed: %s", e)
        return False


class _ChecklistWriteSkipped(Exception):
    """Raised inside an ``update_checklist`` transform to abort the
    write while still releasing the accessor's flock — used when the
    current checklist is missing/malformed (never clobber it with an
    empty object) or when the transform made no changes."""


def _mark_unreachable_low_priority(
    agentic_out_dir: Path, target: Path,
    *,
    allow_unreachable: bool = False,
) -> int:
    """Mark dead-code functions as ``priority=low`` in the
    agentic checklist.

    Sibling of :func:`_enrich_agentic_checklist` — that pass
    UPGRADES priority based on /understand context-map data;
    this pass DOWNGRADES priority for functions not called
    anywhere in non-test project source. The two are
    complementary and run consecutively. Functions already
    marked ``priority=high`` by context-map enrichment are
    skipped (entry-point analysis trumps reachability).

    ``allow_unreachable`` (from --allow-unreachable) is threaded
    to ``mark_unreachable_low_priority``: when True, NOT_CALLED
    functions do NOT get the priority=low demotion. Framework-
    callable / registered-via-call annotations still apply.

    Returns the count of functions marked low-priority. Best-
    effort; failures logged at debug.
    """
    checklist_path = agentic_out_dir / "checklist.json"
    if not checklist_path.exists():
        return 0
    counted = {"marked": 0}
    try:
        from core.inventory import update_checklist
        from core.orchestration.reachability_enrichment import (
            mark_unreachable_low_priority,
        )

        # Route the write through the accessor: it resolves the
        # project-mode checklist symlink and holds the flock across
        # the whole read-modify-write, so a concurrent writer's
        # priority markers survive. A direct load+save here lost
        # both properties.
        def _transform(current: dict[str, Any]) -> dict[str, Any]:
            if not isinstance(current, dict) or not current:
                raise _ChecklistWriteSkipped
            counted["marked"] = mark_unreachable_low_priority(
                current, target, allow_unreachable=allow_unreachable,
            )
            if not counted["marked"]:
                raise _ChecklistWriteSkipped
            return current

        update_checklist(agentic_out_dir, _transform)
        return counted["marked"]
    except _ChecklistWriteSkipped:
        return counted["marked"]
    except Exception:
        logger.debug(
            "reachability low-priority enrichment failed",
            exc_info=True,
        )
        return 0


def run_reachability_prepass(
    target: Path,
    agentic_out_dir: Path,
    *,
    allow_unreachable: bool = False,
    joern_server=None,
    inventory: dict[str, Any] | None = None,
) -> ReachabilityPrepassResult:
    """Always-on companion to ``run_understand_prepass``.

    Runs unconditionally (no --understand gating): builds the
    inventory once, marks dead-code functions priority=low in
    the agentic checklist, returns the inventory so downstream
    consumers (codeql analyzer, /validate Stage B) can reuse it
    without rebuilding.

    The /agentic LLM analysis prompt already reads
    ``priority`` / ``priority_reason`` per function and surfaces
    them to the model — so the priority=low marking shifts the
    analysis budget to live code regardless of whether the
    operator passed --understand.

    ``allow_unreachable`` (from --allow-unreachable) is threaded
    to the underlying enrichment pass. When True, NOT_CALLED
    functions are NOT demoted (still get caller-context fields
    + framework_callable / registered_via_call annotations).

    Best-effort: any failure (missing checklist, inventory build
    error, malformed call_graph) is logged at debug; the
    returned ``ReachabilityPrepassResult.ran`` is False with a
    non-None ``skipped_reason``.
    """
    t0 = time.monotonic()
    checklist_path = agentic_out_dir / "checklist.json"
    if not checklist_path.exists():
        return ReachabilityPrepassResult(
            ran=False,
            skipped_reason="agentic checklist not yet built",
            duration_s=time.monotonic() - t0,
        )

    if inventory is None:
        try:
            import tempfile

            from core.inventory.builder import build_inventory
            with tempfile.TemporaryDirectory() as td:
                inventory = build_inventory(str(target), td)
        except Exception as e:                      # noqa: BLE001
            logger.debug(
                "reachability prepass: inventory build failed (%s)", e,
            )
            return ReachabilityPrepassResult(
                ran=False,
                skipped_reason="inventory build failed",
                duration_s=time.monotonic() - t0,
            )

    try:
        from core.inventory import update_checklist
        from core.orchestration.reachability_enrichment import (
            enrich_with_caller_context,
            enrich_with_frida_traces,
            mark_unreachable_low_priority,
        )
        if joern_server is not None:
            from core.analysis.reach_audit import set_joern_server
            set_joern_server(joern_server)

        # All three enrichment passes run inside the accessor's
        # transform so the read-modify-write happens under the flock
        # (concurrent writers can't drop each other's markers) and
        # against the symlink-resolved project checklist.
        state = {"marked": 0, "malformed": False}

        def _transform(current: dict[str, Any]) -> dict[str, Any]:
            if not isinstance(current, dict) or not current:
                state["malformed"] = True
                raise _ChecklistWriteSkipped
            state["marked"] = mark_unreachable_low_priority(
                current, target, inventory=inventory,
                allow_unreachable=allow_unreachable,
            )
            enriched_frida = enrich_with_frida_traces(
                current, target,
                search_dirs=[agentic_out_dir, agentic_out_dir.parent],
                inventory=inventory,
            )
            enriched_caller_ctx = enrich_with_caller_context(
                current, target, inventory=inventory,
            )
            if not (state["marked"] or enriched_caller_ctx or enriched_frida):
                raise _ChecklistWriteSkipped
            return current

        try:
            update_checklist(agentic_out_dir, _transform)
        except _ChecklistWriteSkipped:
            pass
        if state["malformed"]:
            return ReachabilityPrepassResult(
                ran=False,
                skipped_reason="checklist not a JSON object",
                inventory=inventory,
                duration_s=time.monotonic() - t0,
            )
        marked = state["marked"]
    except Exception:
        logger.warning(
            "reachability prepass: enrichment failed",
            exc_info=True,
        )
        marked = 0
    finally:
        if joern_server is not None:
            from core.analysis.reach_audit import set_joern_server
            set_joern_server(None)

    return ReachabilityPrepassResult(
        ran=True,
        marked_count=marked,
        inventory=inventory,
        duration_s=time.monotonic() - t0,
    )


# ---------------------------------------------------------------------------
# Selection + prompt builders.
# ---------------------------------------------------------------------------


def _select_findings_for_validate(analysis_report: Path) -> list:
    """Return findings from the agentic report that warrant a validate post-pass.

    A finding qualifies if either is_exploitable is True (boolean), or confidence
    equals the canonical high value. Schema-enforced enum values mean no
    case-folding or fuzzy matching is needed (see FINDING_RESULT_SCHEMA).
    """
    # `allow_non_finite=True`: scanner outputs (Semgrep + CodeQL +
    # LLM-stage scoring) can legitimately carry NaN / Infinity in
    # `exploitability_score`. The downstream truncation logic
    # (`_truncate_findings_for_validate`) treats NaN as 0 to keep
    # ordering deterministic. Without the opt-in the whole report
    # rejects on the first NaN cell — every finding silently
    # dropped, validate pass becomes a no-op.
    report = load_json(analysis_report, allow_non_finite=True)
    if not isinstance(report, dict):
        logger.warning("could not parse %s as a JSON object", analysis_report)
        return []

    results = report.get("results")
    if not isinstance(results, list):
        return []
    selected = []
    for r in results:
        if not isinstance(r, dict):
            continue
        # The agentic report uses two different keys for the exploitable
        # boolean depending on which dispatch path produced it: orchestrated
        # mode emits both "is_exploitable" (from FINDING_RESULT_SCHEMA) and
        # "exploitable" (legacy key set at orchestrator.py:504); sequential
        # mode (--sequential) and prep-only emit only "exploitable" (from
        # VulnerabilityContext.to_dict()). Accept either so the post-pass
        # works across modes.
        is_exploitable = (r.get("is_exploitable") is True
                          or r.get("exploitable") is True)
        # Confidence comparison was strict equality against the
        # canonical lowercase value. Schema enforces it for the
        # orchestrated path, but several non-orchestrated dispatch
        # routes (sequential mode, prep-only, retry-prompt-injected
        # rewrites) and any future external producer can supply a
        # confidence string with leading/trailing whitespace
        # (`"high "` from a textual splice) or different case
        # (`"High"`, `"HIGH"` from an LLM that wasn't envelope-
        # constrained). Pre-fix any of those produced an exact-
        # match miss and the finding silently failed to qualify.
        # Strip + lower before compare.
        confidence = r.get("confidence")
        if isinstance(confidence, str):
            confidence = confidence.strip().lower()
        if is_exploitable or confidence == _HIGH_CONFIDENCE:
            selected.append(r)
    return selected


def _build_understand_prompt(target: Path, understand_dir: Path) -> str:
    # Escape control / format / ANSI bytes from path interpolation
    # before splicing into the prompt. `target` and `understand_dir`
    # come from caller-supplied input that may have flowed from a
    # repository name, an argv flag, or a config file. A path
    # containing `\x1b[2J` (clear-screen escape), CR/LF (prompt
    # injection — adds "  Now follow these new instructions:"
    # on the next visible line), or bidi-control bytes (visually
    # mask malicious content) hijacks the prompt the LLM sees.
    # `escape_nonprintable` replaces dangerous bytes with `\xHH`
    # escapes that the model still reads as a path string.
    safe_target = escape_nonprintable(str(target))
    safe_dir = escape_nonprintable(str(understand_dir))
    safe_raptor = escape_nonprintable(str(_RAPTOR_DIR))
    threat_model = _threat_model_prompt_block(target)
    return f"""You are running the /understand --map workflow on a target repository
as a pre-pass for the /agentic security workflow.

Target repository: {safe_target}
Output directory:  {safe_dir}
{threat_model}

The launcher has already created the run directory and built checklist.json.
Your job is to produce context-map.json so downstream analysis (the agentic
checklist enrichment, and any later /validate run against the same target)
has architectural context.

Steps:

1. Load .claude/skills/code-understanding/SKILL.md and
   .claude/skills/code-understanding/map.md from {safe_raptor}.

2. Perform the --map analysis (MAP-0 through MAP-5) against the target.

3. Write the resulting context-map.json directly into {safe_dir}.

4. Do not call libexec/raptor-run-lifecycle — the launcher manages the
   lifecycle for you. Just produce context-map.json.

Keep output concise. Report what you mapped and exit.
"""


def _build_validate_prompt(target: Path, agentic_out_dir: Path, validate_dir: Path,
                            analysis_report: Path, selection_file: Path,
                            selected_count: int,
                            *,
                            allow_unreachable: bool = False) -> str:
    safe_target = escape_nonprintable(str(target))
    safe_agentic = escape_nonprintable(str(agentic_out_dir))
    safe_validate = escape_nonprintable(str(validate_dir))
    safe_report = escape_nonprintable(str(analysis_report))
    safe_selection = escape_nonprintable(str(selection_file))
    safe_raptor = escape_nonprintable(str(_RAPTOR_DIR))
    threat_model = _threat_model_prompt_block(target)
    allow_unreachable_note = ""
    if allow_unreachable:
        allow_unreachable_note = """
**OPERATOR FLAG: --allow-unreachable**

The operator passed --allow-unreachable. When constructing the
validation PipelineConfig (or whatever your equivalent invocation
path uses), set ``allow_unreachable=True`` so the Stage B attack-
path demoter does NOT demote paths anchored to NOT_CALLED
functions. The substrate's PipelineConfig.allow_unreachable
threads to packages.exploitability_validation.reachability.
demote_unreachable_paths and turns the demotion into a no-op.
Reachability-related findings still surface; the report ranking
reflects the LLM verdict rather than the static reachability gate.
"""
    return f"""You are running the /validate post-pass for the /agentic security
workflow. The base agentic pipeline has finished and produced an analysis
report; your job is to run the full validation pipeline against the
{selected_count} findings the launcher pre-selected.

Target repository:    {safe_target}
Agentic out_dir:      {safe_agentic}
Analysis report:      {safe_report}
Selection file:       {safe_selection}
Validate output dir:  {safe_validate}
{threat_model}
{allow_unreachable_note}
Read the findings from {safe_selection}. **The launcher has already
translated them into /validate's FindingsContainer shape** (id, file, line,
description, ruling.status, etc.) — no field-mapping needed on your end.
Use it as-if it were a findings.json: feed straight into Stage 0 / A.

Steps:

1. Load .claude/skills/exploitability-validation/SKILL.md from {safe_raptor}
   and follow the full pipeline (Stage 0 mechanical inventory, then Stages
   A through F LLM analysis, then Stage 1 mechanical report) for the
   selected findings only.

2. Use {safe_validate} as the validate output directory. The launcher has
   already created it via the run lifecycle — do not call
   libexec/raptor-run-lifecycle.

3. If a /understand pre-pass ran in this session, its run directory is a
   sibling of the agentic out_dir. The /validate bridge (tier-2 sibling
   search and tier-3 global lookup) finds it automatically — no manual
   wiring needed.

4. Write the final validation-report.md into {safe_validate}.

Keep narration brief. Report the per-finding outcomes and exit.
"""


def _threat_model_prompt_block(target: Path) -> str:
    try:
        from core.threat_model import threat_model_prompt_block
        return threat_model_prompt_block(target)
    except Exception:
        logger.warning("threat model context unavailable for %s", target, exc_info=True)
        return ""
