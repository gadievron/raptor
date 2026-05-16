"""Annotation synthesis from ``/understand`` JSON outputs.

Reads ``context-map.json`` and any ``flow-trace-*.json`` files in a
``/understand`` run directory, plus the run's ``checklist.json``,
and writes per-function annotations attached to:

  * Entry points (status ``entry_point``)
  * Sinks (status ``sink``)
  * Trust boundaries (status ``trust_boundary``)
  * Flow-trace steps (status ``flow_step``)
  * Unchecked flows (status ``unchecked_flow``, attached to the
    entry-point function)

Calls ``write_annotation(..., overwrite="respect-manual")`` so a
manual operator note (``source=human``) survives subsequent
``/understand`` runs.

Pure post-processor — does not invoke the LLM, doesn't need network,
runs at the end of ``/understand --map`` and ``/understand --trace``
next to ``raptor-render-diagrams``.

Skipped silently when:

  * Output dir doesn't exist or has no relevant JSON.
  * No ``checklist.json`` (function-name lookup unavailable).
  * A specific entry/sink/step has no matching inventory function.
  * A specific same-name annotation has ``source=human``.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from core.annotations import (
    Annotation,
    compute_function_hash,
    write_annotation,
)
from core.inventory.lookup import lookup_function

logger = logging.getLogger(__name__)


@dataclass
class SynthCounts:
    """Telemetry returned to the caller."""

    emitted: int = 0
    skipped_no_function: int = 0
    skipped_manual_blocked: int = 0
    errors: int = 0
    sources: Dict[str, int] = field(default_factory=dict)

    def bump(self, kind: str) -> None:
        self.sources[kind] = self.sources.get(kind, 0) + 1


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    """Load a JSON file or return None on any failure."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _safe_meta(value: Any) -> str:
    """Sanitise an arbitrary value for metadata storage. The
    annotation substrate rejects newlines, nulls, and HTML-comment
    delimiters — strip them rather than raise from inside the synth
    loop and lose the whole batch."""
    s = str(value)
    s = s.replace("\n", " ").replace("\r", " ").replace("\x00", "")
    s = s.replace("-->", "->").replace("<!--", "<!-")
    return s.strip()


def _resolve(
    checklist: Dict[str, Any], file_path: str, line: int,
    repo_root: Path,
) -> Optional[Dict[str, Any]]:
    """Look up the function containing ``file:line`` in the inventory.
    Returns the function dict (with ``name``, ``line_start``,
    optionally ``line_end``) or ``None``."""
    if not file_path or not line:
        return None
    try:
        return lookup_function(
            checklist, file_path, int(line),
            repo_root=str(repo_root),
        )
    except (ValueError, TypeError):
        return None


def _hash_metadata(
    repo_root: Path, file_path: str, func: Dict[str, Any],
) -> Dict[str, str]:
    """Return ``{hash, start_line, end_line}`` if the function has
    line bounds in the inventory. Empty dict otherwise."""
    line_start = func.get("line_start")
    line_end = func.get("line_end")
    if not (line_start and line_end and file_path):
        return {}
    src = repo_root / file_path
    h = compute_function_hash(src, line_start, line_end)
    if not h:
        return {}
    return {
        "hash": h,
        "start_line": str(line_start),
        "end_line": str(line_end),
    }


def _write(
    base_dir: Path, ann: Annotation, counts: SynthCounts, kind: str,
) -> None:
    """Write one annotation through the substrate, accounting the
    outcome in ``counts``. Best-effort — exceptions land in
    ``errors``."""
    try:
        path = write_annotation(base_dir, ann, overwrite="respect-manual")
    except (ValueError, OSError) as e:
        logger.warning(
            f"annotation synth: {kind} write failed for "
            f"{ann.file}:{ann.function}: {e}"
        )
        counts.errors += 1
        return
    if path is None:
        counts.skipped_manual_blocked += 1
    else:
        counts.emitted += 1
        counts.bump(kind)


# ---------------------------------------------------------------------------
# context-map.json: entry points, sinks, trust boundaries, unchecked flows
# ---------------------------------------------------------------------------


def _safe_list_of_dicts(obj: Any, key: str) -> Iterable[Dict[str, Any]]:
    """Read ``obj[key]`` defensively — an LLM-emitted JSON could put
    a string, null, or scalar where we expect a list of dicts. Yield
    only the items that are actually dicts, silently dropping the rest."""
    raw = obj.get(key) if isinstance(obj, dict) else None
    if not isinstance(raw, list):
        return
    for item in raw:
        if isinstance(item, dict):
            yield item


def _emit_entry_points(
    cmap: Dict[str, Any],
    base_dir: Path, checklist: Dict[str, Any], repo_root: Path,
    counts: SynthCounts,
) -> None:
    for ep in _safe_list_of_dicts(cmap, "entry_points"):
        file_path = ep.get("file")
        line = ep.get("line")
        func = _resolve(checklist, file_path, line, repo_root)
        if not func or not func.get("name"):
            counts.skipped_no_function += 1
            continue
        body_lines: List[str] = []
        if ep.get("type"):
            t = ep["type"]
            if ep.get("method") and ep.get("path"):
                body_lines.append(f"Entry point ({t}): "
                                  f"{ep['method']} {ep['path']}")
            else:
                body_lines.append(f"Entry point: {t}")
        if ep.get("accepts"):
            body_lines.append(f"Accepts: {ep['accepts']}")
        if ep.get("auth_required") is not None:
            body_lines.append(f"Auth required: {ep['auth_required']}")
        if ep.get("notes"):
            body_lines.append(f"Notes: {ep['notes']}")
        metadata = {
            "source": "llm",
            "status": "entry_point",
        }
        if ep.get("id"):
            metadata["entry_point_id"] = _safe_meta(ep["id"])
        if ep.get("type"):
            metadata["type"] = _safe_meta(ep["type"])
        metadata.update(_hash_metadata(repo_root, file_path, func))
        ann = Annotation(
            file=file_path, function=func["name"],
            body="\n\n".join(body_lines), metadata=metadata,
        )
        _write(base_dir, ann, counts, "entry_point")


def _emit_sinks(
    cmap: Dict[str, Any],
    base_dir: Path, checklist: Dict[str, Any], repo_root: Path,
    counts: SynthCounts,
) -> None:
    for sink in _safe_list_of_dicts(cmap, "sink_details"):
        file_path = sink.get("file")
        line = sink.get("line")
        func = _resolve(checklist, file_path, line, repo_root)
        if not func or not func.get("name"):
            counts.skipped_no_function += 1
            continue
        body_lines: List[str] = []
        if sink.get("type") and sink.get("operation"):
            body_lines.append(
                f"Sink ({sink['type']}): {sink['operation']}"
            )
        if "parameterized" in sink:
            body_lines.append(f"Parameterized: {sink['parameterized']}")
        reaches = sink.get("reaches_from") or []
        if reaches:
            body_lines.append(f"Reaches from: {', '.join(reaches)}")
        boundaries = sink.get("trust_boundaries_crossed") or []
        if boundaries:
            body_lines.append(
                f"Trust boundaries crossed: {', '.join(boundaries)}"
            )
        if sink.get("notes"):
            body_lines.append(f"Notes: {sink['notes']}")
        metadata = {
            "source": "llm",
            "status": "sink",
        }
        if sink.get("id"):
            metadata["sink_id"] = _safe_meta(sink["id"])
        if sink.get("type"):
            metadata["type"] = _safe_meta(sink["type"])
        metadata.update(_hash_metadata(repo_root, file_path, func))
        ann = Annotation(
            file=file_path, function=func["name"],
            body="\n\n".join(body_lines), metadata=metadata,
        )
        _write(base_dir, ann, counts, "sink")


def _emit_trust_boundaries(
    cmap: Dict[str, Any],
    base_dir: Path, checklist: Dict[str, Any], repo_root: Path,
    counts: SynthCounts,
) -> None:
    for bound in _safe_list_of_dicts(cmap, "boundary_details"):
        file_path = bound.get("file")
        line = bound.get("line")
        func = _resolve(checklist, file_path, line, repo_root)
        if not func or not func.get("name"):
            counts.skipped_no_function += 1
            continue
        body_lines: List[str] = []
        if bound.get("type"):
            body_lines.append(f"Trust boundary ({bound['type']})")
        covers = bound.get("covers") or []
        if covers:
            body_lines.append(f"Covers: {', '.join(covers)}")
        if bound.get("gaps"):
            body_lines.append(f"Gaps: {bound['gaps']}")
        metadata = {
            "source": "llm",
            "status": "trust_boundary",
        }
        if bound.get("id"):
            metadata["boundary_id"] = _safe_meta(bound["id"])
        if bound.get("type"):
            metadata["type"] = _safe_meta(bound["type"])
        metadata.update(_hash_metadata(repo_root, file_path, func))
        ann = Annotation(
            file=file_path, function=func["name"],
            body="\n\n".join(body_lines), metadata=metadata,
        )
        _write(base_dir, ann, counts, "trust_boundary")


def _emit_unchecked_flows(
    cmap: Dict[str, Any],
    base_dir: Path, checklist: Dict[str, Any], repo_root: Path,
    counts: SynthCounts,
) -> None:
    """Attach unchecked-flow notes to the corresponding entry-point's
    function. The flow record itself is just an ID pair, so we have
    to re-resolve the entry-point's file:line."""
    eps_by_id = {
        ep.get("id"): ep
        for ep in _safe_list_of_dicts(cmap, "entry_points")
        if ep.get("id")
    }
    for flow in _safe_list_of_dicts(cmap, "unchecked_flows"):
        ep_id = flow.get("entry_point")
        ep = eps_by_id.get(ep_id)
        if not ep:
            counts.skipped_no_function += 1
            continue
        file_path = ep.get("file")
        func = _resolve(checklist, file_path, ep.get("line"), repo_root)
        if not func or not func.get("name"):
            counts.skipped_no_function += 1
            continue
        body_lines = [
            f"Unchecked flow: {ep_id} → {flow.get('sink', '?')}",
        ]
        if flow.get("missing_boundary"):
            body_lines.append(f"Missing boundary: {flow['missing_boundary']}")
        metadata = {
            "source": "llm",
            "status": "unchecked_flow",
        }
        if ep_id:
            metadata["entry_point_id"] = _safe_meta(ep_id)
        if flow.get("sink"):
            metadata["sink_id"] = _safe_meta(flow["sink"])
        metadata.update(_hash_metadata(repo_root, file_path, func))
        ann = Annotation(
            file=file_path, function=func["name"],
            body="\n\n".join(body_lines), metadata=metadata,
        )
        _write(base_dir, ann, counts, "unchecked_flow")


# ---------------------------------------------------------------------------
# flow-trace-*.json: per-step annotations
# ---------------------------------------------------------------------------


def _parse_definition(definition: str) -> Optional[tuple[str, int]]:
    """Trace ``definition`` strings are either ``file:line`` or a
    library symbol like ``psycopg2.cursor.execute()`` for sinks. Only
    the file:line form is annotatable in our codebase."""
    if not definition or ":" not in definition:
        return None
    # Take the LAST colon so Windows ``C:\foo:42`` parses; no Windows
    # path support today but cheap insurance.
    file_part, _, line_part = definition.rpartition(":")
    try:
        return file_part, int(line_part)
    except ValueError:
        return None


def _emit_trace_steps(
    trace: Dict[str, Any], trace_id: str,
    base_dir: Path, checklist: Dict[str, Any], repo_root: Path,
    counts: SynthCounts,
) -> None:
    for step in _safe_list_of_dicts(trace, "steps"):
        defn = _parse_definition(step.get("definition", ""))
        if not defn:
            # External library or non-resolvable target — skip.
            counts.skipped_no_function += 1
            continue
        file_path, line = defn
        func = _resolve(checklist, file_path, line, repo_root)
        if not func or not func.get("name"):
            counts.skipped_no_function += 1
            continue
        body_lines: List[str] = []
        step_num = step.get("step")
        step_type = step.get("type") or "step"
        if step_num:
            body_lines.append(f"Flow trace step {step_num} ({step_type})")
        if step.get("description"):
            body_lines.append(step["description"])
        if step.get("tainted_var"):
            body_lines.append(f"Tainted variable: {step['tainted_var']}")
        if step.get("transform") and step["transform"] != "none":
            body_lines.append(f"Transform: {step['transform']}")
        if step.get("call_site"):
            body_lines.append(f"Call site: {step['call_site']}")
        metadata = {
            "source": "llm",
            "status": "flow_step",
        }
        if trace_id:
            metadata["trace_id"] = _safe_meta(trace_id)
        if step_num is not None:
            metadata["step"] = _safe_meta(step_num)
        if step_type:
            metadata["type"] = _safe_meta(step_type)
        if step.get("confidence"):
            metadata["confidence"] = _safe_meta(step["confidence"])
        metadata.update(_hash_metadata(repo_root, file_path, func))
        ann = Annotation(
            file=file_path, function=func["name"],
            body="\n\n".join(body_lines), metadata=metadata,
        )
        _write(base_dir, ann, counts, "flow_step")


# ---------------------------------------------------------------------------
# variants.json: per-variant annotations from /understand --hunt
# ---------------------------------------------------------------------------


# Map hunt's taint_status / status fields to our annotation status enum.
# Confirmed-tainted / not_disproven variants are findings worth chasing.
# Unlikely-tainted / false_positive are still flagged so the operator
# sees them — "suspicious" rather than dropped silently.
_TAINT_TO_STATUS = {
    "confirmed_tainted": "finding",
    "likely_tainted": "finding",
    "unlikely_tainted": "suspicious",
    "false_positive": "suspicious",
}
_STATUS_TO_STATUS = {
    "not_disproven": "finding",
    "poc_success": "finding",
    "disproven": "suspicious",
    "false_positive": "suspicious",
}


def _variant_annotation_status(variant: Dict[str, Any]) -> str:
    """Decide the annotation status for a hunt variant.

    Prefers ``taint_status`` (hunt's primary signal) over ``status``
    (the validation-flow lifecycle field, often absent on raw hunt
    output). Defaults to ``suspicious`` so a variant the LLM emitted
    without status fields is still surfaced for operator review.
    """
    taint = variant.get("taint_status")
    if isinstance(taint, str) and taint in _TAINT_TO_STATUS:
        return _TAINT_TO_STATUS[taint]
    status = variant.get("status")
    if isinstance(status, str) and status in _STATUS_TO_STATUS:
        return _STATUS_TO_STATUS[status]
    return "suspicious"


def _emit_variants(
    variants_data: Dict[str, Any],
    base_dir: Path, checklist: Dict[str, Any], repo_root: Path,
    counts: SynthCounts,
) -> None:
    for variant in _safe_list_of_dicts(variants_data, "variants"):
        file_path = variant.get("file")
        line = variant.get("line")
        func = _resolve(checklist, file_path, line, repo_root)
        if not func or not func.get("name"):
            counts.skipped_no_function += 1
            continue
        body_lines: List[str] = []
        if variant.get("vuln_type"):
            body_lines.append(f"Variant ({variant['vuln_type']})")
        if variant.get("matched_code"):
            body_lines.append(
                f"Matched code: `{variant['matched_code']}`"
            )
        proof = variant.get("proof")
        if isinstance(proof, dict):
            if proof.get("vulnerable_code"):
                body_lines.append(
                    f"Vulnerable code: `{proof['vulnerable_code']}`"
                )
            if proof.get("source"):
                body_lines.append(f"Source: {proof['source']}")
            if proof.get("sink"):
                body_lines.append(f"Sink: {proof['sink']}")
        elif variant.get("taint_source"):
            body_lines.append(f"Taint source: {variant['taint_source']}")
        eps = variant.get("entry_points") or []
        if isinstance(eps, list) and eps:
            body_lines.append(
                f"Entry points: {', '.join(str(e) for e in eps)}"
            )
        if variant.get("auth_required") is not None:
            body_lines.append(f"Auth required: {variant['auth_required']}")
        if variant.get("notes"):
            body_lines.append(f"Notes: {variant['notes']}")
        metadata = {
            "source": "llm",
            "status": _variant_annotation_status(variant),
        }
        if variant.get("id"):
            metadata["variant_id"] = _safe_meta(variant["id"])
        if variant.get("vuln_type"):
            metadata["vuln_type"] = _safe_meta(variant["vuln_type"])
        if variant.get("confidence"):
            metadata["confidence"] = _safe_meta(variant["confidence"])
        if variant.get("taint_status"):
            metadata["taint_status"] = _safe_meta(variant["taint_status"])
        if variant.get("root_cause_group"):
            metadata["root_cause_group"] = _safe_meta(
                variant["root_cause_group"],
            )
        if variant.get("priority") is not None:
            metadata["priority"] = _safe_meta(variant["priority"])
        metadata.update(_hash_metadata(repo_root, file_path, func))
        ann = Annotation(
            file=file_path, function=func["name"],
            body="\n\n".join(body_lines), metadata=metadata,
        )
        _write(base_dir, ann, counts, "variant")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def synthesise_from_understand_output(
    output_dir: Path, repo_root: Optional[Path] = None,
) -> SynthCounts:
    """Walk ``output_dir`` for ``/understand`` JSON outputs and emit
    annotations under ``output_dir/annotations/``.

    ``repo_root`` defaults to ``checklist.json``'s ``target_path``
    field. Raises nothing — silently does no work when prerequisites
    are missing.
    """
    counts = SynthCounts()
    if not output_dir.exists():
        return counts

    checklist_path = output_dir / "checklist.json"
    checklist = _load_json(checklist_path)
    if not checklist:
        logger.debug(
            f"annotation synth: no checklist at {checklist_path}; "
            f"skipping (function lookup unavailable)"
        )
        return counts
    if repo_root is None:
        repo_root = Path(checklist.get("target_path", "."))

    base_dir = output_dir / "annotations"

    cmap = _load_json(output_dir / "context-map.json")
    if cmap:
        _emit_entry_points(cmap, base_dir, checklist, repo_root, counts)
        _emit_sinks(cmap, base_dir, checklist, repo_root, counts)
        _emit_trust_boundaries(cmap, base_dir, checklist, repo_root, counts)
        _emit_unchecked_flows(cmap, base_dir, checklist, repo_root, counts)

    variants_data = _load_json(output_dir / "variants.json")
    if variants_data:
        _emit_variants(
            variants_data, base_dir, checklist, repo_root, counts,
        )

    for trace_path in sorted(output_dir.glob("flow-trace-*.json")):
        trace = _load_json(trace_path)
        if not trace:
            continue
        # ID from filename: flow-trace-EP-001.json → EP-001
        stem = trace_path.stem  # "flow-trace-EP-001"
        trace_id = stem.split("flow-trace-", 1)[-1]
        _emit_trace_steps(
            trace, trace_id, base_dir, checklist, repo_root, counts,
        )

    # Emit a coverage record so ``raptor-coverage-summary`` picks
    # up the annotated functions as reviewed. Best-effort.
    if counts.emitted > 0:
        try:
            from core.coverage.record import (
                build_from_annotations, write_record,
            )
            record = build_from_annotations(base_dir)
            if record:
                write_record(output_dir, record, tool_name="annotations")
        except Exception:
            logger.debug(
                "annotation coverage record failed", exc_info=True,
            )

    return counts
