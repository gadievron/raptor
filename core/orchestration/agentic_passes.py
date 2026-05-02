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
import math
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from core.json import load_json, save_json
from core.sandbox import run as sandbox_run
from core.schema_constants import CONFIDENCE_LEVELS

logger = logging.getLogger(__name__)

# core/orchestration/agentic_passes.py -> repo root (parents[2])
_RAPTOR_DIR = Path(__file__).resolve().parents[2]
_LIFECYCLE = _RAPTOR_DIR / "libexec" / "raptor-run-lifecycle"
_BUILD_CHECKLIST = _RAPTOR_DIR / "libexec" / "raptor-build-checklist"

# Canonical "high" confidence value. Asserted against the enum at import so a
# future reorder of CONFIDENCE_LEVELS can't silently break post-pass selection.
_HIGH_CONFIDENCE = "high"
assert _HIGH_CONFIDENCE in CONFIDENCE_LEVELS, \
    f"_HIGH_CONFIDENCE drift: {_HIGH_CONFIDENCE!r} not in {CONFIDENCE_LEVELS!r}"

# Sanity cap: even a pathological report shouldn't push more than this through
# a single post-pass subprocess. Above the cap we truncate and log a warning.
_MAX_VALIDATE_FINDINGS = 50

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
    skipped_reason: Optional[str] = None
    understand_dir: Optional[Path] = None     # the proper run dir, if created
    context_map_path: Optional[Path] = None
    checklist_enriched: bool = False          # priority markers written to agentic checklist?
    duration_s: float = 0.0


@dataclass
class PostpassResult:
    """Outcome of run_validate_postpass()."""
    ran: bool
    skipped_reason: Optional[str] = None
    selected_count: int = 0
    validate_dir: Optional[Path] = None
    report_path: Optional[Path] = None
    duration_s: float = 0.0


def run_understand_prepass(
    target: Path,
    agentic_out_dir: Path,
    block_cc_dispatch: bool = False,
    claude_bin: Optional[str] = None,
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
    claude_bin: Optional[str],
) -> PrepassResult:
    if block_cc_dispatch:
        return PrepassResult(ran=False, skipped_reason="cc_trust blocked dispatch (untrusted target)")

    from core.security.rule_of_two import (
        NonInteractiveError, require_interactive_for_agentic_pass,
    )
    try:
        require_interactive_for_agentic_pass("understand")
    except NonInteractiveError as e:
        return PrepassResult(ran=False, skipped_reason=str(e))

    claude_bin = claude_bin or shutil.which("claude")
    if not claude_bin:
        return PrepassResult(ran=False, skipped_reason="claude not on PATH")

    target = Path(target).resolve()
    agentic_out_dir = Path(agentic_out_dir).resolve()

    t0 = time.time()

    understand_dir = _start_lifecycle("understand", target)
    if understand_dir is None:
        return PrepassResult(ran=False, skipped_reason="lifecycle start failed",
                             duration_s=time.time() - t0)

    # Track whether the run reached a definitive end-state. If we exit via
    # KeyboardInterrupt or another BaseException (which Exception doesn't
    # catch), the finally clause still marks the lifecycle failed so the
    # run dir doesn't linger in "running" state forever.
    lifecycle_settled = False
    try:
        # Reuse the agentic pipeline's checklist if it's already built. Both
        # are produced from the same target via the same parser, so the
        # contents are equivalent — and it skips parsing the whole repo a
        # second time. Falls back to a fresh build if the agentic checklist
        # isn't present (e.g. when build_inventory failed earlier).
        if not _provision_understand_checklist(target, agentic_out_dir, understand_dir):
            _fail_lifecycle(understand_dir, "checklist build failed")
            lifecycle_settled = True
            return PrepassResult(ran=False, skipped_reason="checklist build failed",
                                 understand_dir=understand_dir,
                                 duration_s=time.time() - t0)

        prompt = _build_understand_prompt(target, understand_dir)
        try:
            from core.llm.cc_adapter import CCDispatchConfig, build_cc_command
            prepass_config = CCDispatchConfig(
                claude_bin=claude_bin,
                tools=_UNDERSTAND_TOOLS,
                add_dirs=(str(_RAPTOR_DIR), str(target), str(understand_dir)),
                budget_usd=_PREPASS_BUDGET_USD,
                timeout_s=_PREPASS_TIMEOUT_S,
                capture_json_envelope=False,
            )
            proc = sandbox_run(
                build_cc_command(prepass_config),
                input=prompt, text=True,
                timeout=_PREPASS_TIMEOUT_S,
                target=str(target), output=str(understand_dir),
                use_egress_proxy=True,
                proxy_hosts=["api.anthropic.com"],
                caller_label="agentic-understand",
            )
        except subprocess.TimeoutExpired:
            _fail_lifecycle(understand_dir, f"timeout after {_PREPASS_TIMEOUT_S}s")
            lifecycle_settled = True
            logger.warning("understand pre-pass timed out after %ds", _PREPASS_TIMEOUT_S)
            return PrepassResult(ran=False, skipped_reason=f"timeout after {_PREPASS_TIMEOUT_S}s",
                                 understand_dir=understand_dir,
                                 duration_s=time.time() - t0)
        except OSError as e:
            _fail_lifecycle(understand_dir, f"launch failed: {e}")
            lifecycle_settled = True
            logger.warning("understand pre-pass failed to launch: %s", e)
            return PrepassResult(ran=False, skipped_reason=f"launch failed: {e}",
                                 understand_dir=understand_dir,
                                 duration_s=time.time() - t0)

        if proc.returncode != 0:
            _fail_lifecycle(understand_dir, f"subprocess returned {proc.returncode}")
            lifecycle_settled = True
            logger.warning("understand pre-pass returned %d", proc.returncode)
            return PrepassResult(ran=False, skipped_reason=f"subprocess returned {proc.returncode}",
                                 understand_dir=understand_dir,
                                 duration_s=time.time() - t0)

        context_map = understand_dir / "context-map.json"
        if not context_map.exists():
            _fail_lifecycle(understand_dir, "context-map.json missing after run")
            lifecycle_settled = True
            logger.warning("understand pre-pass completed but context-map.json was not written")
            return PrepassResult(ran=False, skipped_reason="context-map.json missing after run",
                                 understand_dir=understand_dir,
                                 duration_s=time.time() - t0)

        # claude -p might have crashed mid-write or produced structurally
        # invalid output. Existence isn't enough — the bridge silently returns
        # no context for unparseable files, and crashes mid-iteration if a
        # required-list field is the wrong type. Validate both parseability
        # and basic shape here so a misbehaving claude run fails the
        # lifecycle cleanly instead of being marked complete with garbage.
        parsed = load_json(context_map)
        shape_error = _validate_context_map_shape(parsed)
        if shape_error is not None:
            _fail_lifecycle(understand_dir, f"context-map.json invalid: {shape_error}")
            lifecycle_settled = True
            logger.warning("understand pre-pass: context-map.json failed shape check (%s)",
                           shape_error)
            return PrepassResult(ran=False, skipped_reason=f"context-map.json invalid: {shape_error}",
                                 understand_dir=understand_dir,
                                 duration_s=time.time() - t0)

        _complete_lifecycle(understand_dir)
        lifecycle_settled = True

        # Best-effort: enrich the agentic checklist with priority markers from
        # the context map. The agentic analysis pipeline reads priority/
        # priority_reason from per-function metadata and surfaces it in the
        # analysis prompt — so --understand pays off in this run too, not just
        # any later /validate.
        enriched = _enrich_agentic_checklist(agentic_out_dir, context_map)

        return PrepassResult(
            ran=True,
            understand_dir=understand_dir,
            context_map_path=context_map,
            checklist_enriched=enriched,
            duration_s=time.time() - t0,
        )

    except Exception:
        # Make sure the lifecycle is marked failed before propagating.
        _fail_lifecycle(understand_dir, "unexpected exception")
        lifecycle_settled = True
        raise
    finally:
        # KeyboardInterrupt / SystemExit / any other BaseException bypasses
        # the except-Exception clause above. Make sure the run dir is marked
        # failed so the bridge doesn't keep finding it as "in progress".
        if not lifecycle_settled:
            _fail_lifecycle(understand_dir, "interrupted")


def run_validate_postpass(
    target: Path,
    agentic_out_dir: Path,
    analysis_report: Path,
    block_cc_dispatch: bool = False,
    claude_bin: Optional[str] = None,
) -> PostpassResult:
    """Run /validate against findings flagged exploitable or high-confidence.

    Creates a proper /validate run directory as a sibling of the agentic dir
    so the bridge's tier-2 lookup finds any /understand sibling automatically.

    Never raises — enrichment failure must not break the base agentic pipeline.
    """
    try:
        return _run_validate_postpass_unsafe(
            target, agentic_out_dir, analysis_report, block_cc_dispatch, claude_bin)
    except Exception as e:
        logger.exception("validate post-pass crashed unexpectedly")
        return PostpassResult(ran=False,
                              skipped_reason=f"unexpected {type(e).__name__}: {e}")


def _run_validate_postpass_unsafe(
    target: Path,
    agentic_out_dir: Path,
    analysis_report: Path,
    block_cc_dispatch: bool,
    claude_bin: Optional[str],
) -> PostpassResult:
    if block_cc_dispatch:
        return PostpassResult(ran=False, skipped_reason="cc_trust blocked dispatch (untrusted target)")

    from core.security.rule_of_two import (
        NonInteractiveError, require_interactive_for_agentic_pass,
    )
    try:
        require_interactive_for_agentic_pass("validate")
    except NonInteractiveError as e:
        return PostpassResult(ran=False, skipped_reason=str(e))

    claude_bin = claude_bin or shutil.which("claude")
    if not claude_bin:
        return PostpassResult(ran=False, skipped_reason="claude not on PATH")

    analysis_report = Path(analysis_report)
    if not analysis_report.exists():
        return PostpassResult(ran=False, skipped_reason="analysis report not found — base pipeline produced no results")

    selected = _select_findings_for_validate(analysis_report)
    if not selected:
        return PostpassResult(ran=False,
                              skipped_reason="no findings matched is_exploitable=true or confidence=high")

    if len(selected) > _MAX_VALIDATE_FINDINGS:
        # Sort by signal strength so truncation drops the weakest qualifiers,
        # not whoever happened to be last in report order. Priority:
        # 1. is_exploitable=True wins over confidence-only
        # 2. higher exploitability_score wins (when present)
        # 3. ties broken by report order (Python sort is stable)
        def _safe_score(f):
            # The schema says exploitability_score is a number, but malformed
            # LLM output (e.g. "high" instead of 0.9) shouldn't crash sort
            # mid-truncation. Coerce non-numeric to 0. Also guard against
            # NaN/Inf — Python sort with NaN keys produces undefined order
            # because NaN compares False to everything; we'd get
            # non-deterministic truncation.
            raw = f.get("exploitability_score")
            try:
                v = float(raw) if raw is not None else 0.0
            except (TypeError, ValueError):
                return 0.0
            if math.isnan(v) or math.isinf(v):
                return 0.0
            return v
        def _signal_key(f):
            return (
                0 if f.get("is_exploitable") is True else 1,  # exploitable first
                -_safe_score(f),                                # score descending
            )
        selected.sort(key=_signal_key)
        logger.warning("validate post-pass: %d findings selected; truncating to %d "
                       "(keeping highest-signal: is_exploitable then exploitability_score)",
                       len(selected), _MAX_VALIDATE_FINDINGS)
        selected = selected[:_MAX_VALIDATE_FINDINGS]

    target = Path(target).resolve()
    agentic_out_dir = Path(agentic_out_dir).resolve()
    analysis_report = analysis_report.resolve()

    t0 = time.time()

    validate_dir = _start_lifecycle("validate", target)
    if validate_dir is None:
        return PostpassResult(ran=False, selected_count=len(selected),
                              skipped_reason="lifecycle start failed",
                              duration_s=time.time() - t0)

    # Same KeyboardInterrupt-aware cleanup pattern as the pre-pass — see
    # _run_understand_prepass_unsafe for the rationale.
    lifecycle_settled = False
    try:
        # Persist the selected records to a file rather than splicing
        # LLM-generated finding_id values into the prompt — defends against
        # any injection attempt riding in on a finding identifier.
        # Convert from /agentic shape to /validate shape so the validate
        # skill can consume the file directly without prompt-driven
        # field translation (was the stopgap; this is the real fix).
        selection_file = validate_dir / "selected-findings.json"
        save_json(selection_file,
                  convert_agentic_to_validate(selected, str(target)))

        prompt = _build_validate_prompt(target, agentic_out_dir, validate_dir,
                                        analysis_report, selection_file, len(selected))

        try:
            from core.llm.cc_adapter import CCDispatchConfig, build_cc_command
            postpass_config = CCDispatchConfig(
                claude_bin=claude_bin,
                tools=_VALIDATE_TOOLS,
                add_dirs=(str(_RAPTOR_DIR), str(target), str(agentic_out_dir), str(validate_dir)),
                budget_usd=_POSTPASS_BUDGET_USD,
                timeout_s=_POSTPASS_TIMEOUT_S,
                capture_json_envelope=False,
            )
            proc = sandbox_run(
                build_cc_command(postpass_config),
                input=prompt, text=True,
                timeout=_POSTPASS_TIMEOUT_S,
                target=str(target), output=str(validate_dir),
                use_egress_proxy=True,
                proxy_hosts=["api.anthropic.com"],
                caller_label="agentic-validate",
            )
        except subprocess.TimeoutExpired:
            _fail_lifecycle(validate_dir, f"timeout after {_POSTPASS_TIMEOUT_S}s")
            lifecycle_settled = True
            logger.warning("validate post-pass timed out after %ds", _POSTPASS_TIMEOUT_S)
            return PostpassResult(ran=False, selected_count=len(selected),
                                  validate_dir=validate_dir,
                                  skipped_reason=f"timeout after {_POSTPASS_TIMEOUT_S}s",
                                  duration_s=time.time() - t0)
        except OSError as e:
            _fail_lifecycle(validate_dir, f"launch failed: {e}")
            lifecycle_settled = True
            logger.warning("validate post-pass failed to launch: %s", e)
            return PostpassResult(ran=False, selected_count=len(selected),
                                  validate_dir=validate_dir,
                                  skipped_reason=f"launch failed: {e}",
                                  duration_s=time.time() - t0)

        if proc.returncode != 0:
            _fail_lifecycle(validate_dir, f"subprocess returned {proc.returncode}")
            lifecycle_settled = True
            logger.warning("validate post-pass returned %d", proc.returncode)
            return PostpassResult(ran=False, selected_count=len(selected),
                                  validate_dir=validate_dir,
                                  skipped_reason=f"subprocess returned {proc.returncode}",
                                  duration_s=time.time() - t0)

        _complete_lifecycle(validate_dir)
        lifecycle_settled = True
        report_path = validate_dir / "validation-report.md"

        return PostpassResult(ran=True, selected_count=len(selected),
                              validate_dir=validate_dir,
                              report_path=report_path if report_path.exists() else None,
                              duration_s=time.time() - t0)

    except Exception:
        _fail_lifecycle(validate_dir, "unexpected exception")
        lifecycle_settled = True
        raise
    finally:
        if not lifecycle_settled:
            _fail_lifecycle(validate_dir, "interrupted")


# ---------------------------------------------------------------------------
# Lifecycle helpers — wrap libexec/raptor-run-lifecycle and raptor-build-checklist.
# ---------------------------------------------------------------------------


def _start_lifecycle(command: str, target: Path) -> Optional[Path]:
    """Start a new lifecycle-managed run dir.

    Returns the OUTPUT_DIR path on success, or None if the helper failed
    or its output couldn't be parsed.
    """
    try:
        proc = subprocess.run(
            [str(_LIFECYCLE), "start", command, "--target", str(target)],
            capture_output=True, text=True, timeout=_LIFECYCLE_TIMEOUT_S,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("lifecycle start %s failed: %s", command, e)
        return None
    if proc.returncode != 0:
        logger.warning("lifecycle start %s returned %d: %s",
                       command, proc.returncode, (proc.stderr or "")[:300])
        return None
    for line in reversed(proc.stdout.splitlines()):
        line = line.strip()
        if line.startswith("OUTPUT_DIR="):
            return Path(line[len("OUTPUT_DIR="):])
    logger.warning("lifecycle start %s did not emit OUTPUT_DIR=", command)
    return None


def _complete_lifecycle(output_dir: Path) -> None:
    """Mark a lifecycle run as completed. Best-effort; swallows errors."""
    try:
        proc = subprocess.run(
            [str(_LIFECYCLE), "complete", str(output_dir)],
            capture_output=True, text=True, timeout=_LIFECYCLE_TIMEOUT_S,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("lifecycle complete failed: %s", e)
        return
    if proc.returncode != 0:
        logger.warning("lifecycle complete returned %d: %s",
                       proc.returncode, (proc.stderr or "")[:300])


def _fail_lifecycle(output_dir: Path, message: str) -> None:
    """Mark a lifecycle run as failed. Best-effort; swallows errors."""
    if output_dir is None:
        return
    try:
        proc = subprocess.run(
            [str(_LIFECYCLE), "fail", str(output_dir), message],
            capture_output=True, text=True, timeout=_LIFECYCLE_TIMEOUT_S,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("lifecycle fail failed: %s", e)
        return
    if proc.returncode != 0:
        logger.warning("lifecycle fail returned %d: %s",
                       proc.returncode, (proc.stderr or "")[:300])


def _build_checklist(target: Path, output_dir: Path) -> bool:
    """Run libexec/raptor-build-checklist. Returns True on success."""
    try:
        proc = subprocess.run(
            [str(_BUILD_CHECKLIST), str(target), str(output_dir)],
            capture_output=True, text=True, timeout=_CHECKLIST_TIMEOUT_S,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.warning("build_checklist failed: %s", e)
        return False
    if proc.returncode != 0:
        logger.warning("build_checklist returned %d: %s",
                       proc.returncode, (proc.stderr or "")[:300])
        return False
    return True


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
    return _build_checklist(target, understand_dir)


def convert_agentic_to_validate(agentic_findings: list, target_path: str) -> dict:
    """Translate /agentic finding shape into /validate FindingsContainer shape.

    The two pipelines deliberately use different field names (see the field
    alignment table in core/schema_constants.py). Without this converter,
    the post-pass would have to ask claude to do the translation in-prompt
    — fragile, since the LLM may forget fields or mis-handle the
    ``ruling`` string→object change.

    Args:
        agentic_findings: list of finding dicts in /agentic shape (per
            FINDING_RESULT_SCHEMA).
        target_path: the target repo path; written into the container.

    Returns:
        A dict in /validate FindingsContainer shape — ready to drop into a
        findings.json that /validate's Stage 0/A can consume directly.
    """
    converted = []
    for f in agentic_findings or []:
        if not isinstance(f, dict):
            continue
        converted.append(_convert_one_finding(f))
    return {
        "stage": "agentic-postpass",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "target_path": target_path,
        "source": "agentic-hybrid-orchestration",
        "findings": converted,
    }


def _convert_one_finding(f: dict) -> dict:
    """Convert a single /agentic finding dict to /validate Finding shape."""
    # Renames per the schema_constants alignment table.
    out: dict = {
        "id": str(f.get("finding_id") or f.get("id") or ""),
        "file": f.get("file_path") or f.get("file") or "",
        "line": int(f.get("start_line") or f.get("line") or 0),
        "description": f.get("reasoning") or f.get("description") or "",
        # ruling: /agentic emits a string verdict (e.g. "validated",
        # "false_positive"); /validate expects an object {"status": ...}.
        "ruling": _convert_ruling(f.get("ruling"), f.get("false_positive_reason")),
    }
    # Pass-through fields — same names on both sides. Only include when
    # present so /validate's _clean_dict doesn't have to strip them.
    for key in (
        "vuln_type", "cwe_id", "severity_assessment",
        "cvss_vector", "cvss_score_estimate",
        "confidence", "attack_scenario",
        "dataflow_summary", "remediation",
        "false_positive_reason",
        "tool", "rule_id",
    ):
        if f.get(key) is not None:
            out[key] = f[key]
    # is_exploitable: /agentic uses two key names depending on dispatch
    # mode (the schema says is_exploitable, sequential mode emits the
    # legacy "exploitable"). Normalise to is_exploitable.
    if f.get("is_exploitable") is not None:
        out["is_exploitable"] = f["is_exploitable"]
    elif f.get("exploitable") is not None:
        out["is_exploitable"] = f["exploitable"]
    if f.get("is_true_positive") is not None:
        out["is_true_positive"] = f["is_true_positive"]
    # Origin marker so /validate knows the finding came pre-analysed and
    # may want to skip Stage A discovery.
    out["origin"] = "agentic-postpass"
    return out


def _convert_ruling(agentic_ruling, fp_reason) -> dict:
    """Wrap /agentic's string ruling into /validate's ruling object shape.

    Returns an object with at least ``status``, plus ``reason`` carrying any
    false_positive_reason. Keeps the agentic ruling string as a separate
    field so the original verdict is preserved verbatim alongside the
    /validate-native status field.
    """
    if isinstance(agentic_ruling, dict):
        return agentic_ruling  # already in object shape
    ruling = {"status": agentic_ruling or "", "agentic_ruling": agentic_ruling or ""}
    if fp_reason:
        ruling["reason"] = fp_reason
    return ruling


def _validate_context_map_shape(parsed) -> Optional[str]:
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
    list_keys = ("entry_points", "sink_details", "sources", "sinks", "trust_boundaries")
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
    except Exception as e:
        logger.warning("checklist enrichment failed: %s", e)
        return False


# ---------------------------------------------------------------------------
# Selection + prompt builders.
# ---------------------------------------------------------------------------


def _select_findings_for_validate(analysis_report: Path) -> list:
    """Return findings from the agentic report that warrant a validate post-pass.

    A finding qualifies if either is_exploitable is True (boolean), or confidence
    equals the canonical high value. Schema-enforced enum values mean no
    case-folding or fuzzy matching is needed (see FINDING_RESULT_SCHEMA).
    """
    report = load_json(analysis_report)
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
        if is_exploitable or r.get("confidence") == _HIGH_CONFIDENCE:
            selected.append(r)
    return selected


def _build_understand_prompt(target: Path, understand_dir: Path) -> str:
    return f"""You are running the /understand --map workflow on a target repository
as a pre-pass for the /agentic security workflow.

Target repository: {target}
Output directory:  {understand_dir}

The launcher has already created the run directory and built checklist.json.
Your job is to produce context-map.json so downstream analysis (the agentic
checklist enrichment, and any later /validate run against the same target)
has architectural context.

Steps:

1. Load .claude/skills/code-understanding/SKILL.md and
   .claude/skills/code-understanding/map.md from {_RAPTOR_DIR}.

2. Perform the --map analysis (MAP-0 through MAP-5) against the target.

3. Write the resulting context-map.json directly into {understand_dir}.

4. Do not call libexec/raptor-run-lifecycle — the launcher manages the
   lifecycle for you. Just produce context-map.json.

Keep output concise. Report what you mapped and exit.
"""


def _build_validate_prompt(target: Path, agentic_out_dir: Path, validate_dir: Path,
                            analysis_report: Path, selection_file: Path,
                            selected_count: int) -> str:
    return f"""You are running the /validate post-pass for the /agentic security
workflow. The base agentic pipeline has finished and produced an analysis
report; your job is to run the full validation pipeline against the
{selected_count} findings the launcher pre-selected.

Target repository:    {target}
Agentic out_dir:      {agentic_out_dir}
Analysis report:      {analysis_report}
Selection file:       {selection_file}
Validate output dir:  {validate_dir}

Read the findings from {selection_file}. **The launcher has already
translated them into /validate's FindingsContainer shape** (id, file, line,
description, ruling.status, etc.) — no field-mapping needed on your end.
Use it as-if it were a findings.json: feed straight into Stage 0 / A.

Steps:

1. Load .claude/skills/exploitability-validation/SKILL.md from {_RAPTOR_DIR}
   and follow the full pipeline (Stage 0 mechanical inventory, then Stages
   A through F LLM analysis, then Stage 1 mechanical report) for the
   selected findings only.

2. Use {validate_dir} as the validate output directory. The launcher has
   already created it via the run lifecycle — do not call
   libexec/raptor-run-lifecycle.

3. If a /understand pre-pass ran in this session, its run directory is a
   sibling of the agentic out_dir. The /validate bridge (tier-2 sibling
   search and tier-3 global lookup) finds it automatically — no manual
   wiring needed.

4. Write the final validation-report.md into {validate_dir}.

Keep narration brief. Report the per-finding outcomes and exit.
"""
