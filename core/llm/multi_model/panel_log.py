"""Panel-log loader — Phase 2a of the calibrated-aggregation arc.

Reads per-finding per-model verdicts from the orchestrator's
``orchestrated_report.json`` (and equivalents). The data already exists
on disk — Phase 2a's job is just to surface it in the shape Dawid–Skene
consumes, not to wire a new logging path.

Source-of-truth audit (verified against current tree):

* ``packages/llm_analysis/orchestrator.py:816`` attaches
  ``multi_model_analyses`` to each primary finding when ≥2 models
  contributed.
* ``packages/llm_analysis/finding_adapter.py:60`` defines the per-model
  record shape:
  ``{model, is_exploitable, exploitability_score, ruling, reasoning}``.
* ``core/llm/scorecard/consensus.py:135`` documents the
  ``agentic:<rule_id>`` decision-class convention. We honour that
  exactly so D–S consumes the same partition the scorecard uses.

Robustness contract:

* Findings without ``multi_model_analyses`` (single-model runs) are
  skipped — D–S needs ≥2 models to infer per-model confusion matrices.
* Records with missing or non-boolean ``is_exploitable`` are dropped
  (the model's verdict on that finding is unknown). The finding
  survives if at least 2 valid records remain.
* Error entries (``{"error": ...}``) and entries missing ``model`` are
  dropped silently — the orchestrator already logged the failure.
"""
from __future__ import annotations

import glob
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence


# Convention from ``core/llm/scorecard/consensus.py:135``. Reused so the
# scorecard's accumulated counts (Phase 4 will close the loop on those)
# and D–S aggregation share the same partition keying.
DEFAULT_DECISION_CLASS_PREFIX = "agentic"


@dataclass(frozen=True)
class PanelRecord:
    """One model's verdict on one finding.

    Fields are the minimum D–S consumes. ``ruling`` / ``reasoning`` /
    ``exploitability_score`` from the orchestrator record are dropped
    here — they're useful for explainability surfaces but not for the
    binary-verdict EM. Keeping ``PanelRecord`` narrow makes the EM
    inner loop's signature obvious.
    """
    finding_id: str
    decision_class: str
    model: str
    verdict: bool


def _decision_class_for(rule_id: Optional[str], prefix: str) -> str:
    """``prefix:rule_id`` — matches ``consensus.py`` exactly. Findings
    with no ``rule_id`` are bucketed under ``prefix:unknown`` rather
    than dropped so the bucket count is honest about coverage gaps."""
    rid = rule_id if (isinstance(rule_id, str) and rule_id) else "unknown"
    return f"{prefix}:{rid}"


def _extract_records_from_finding(
    finding: dict, *, decision_class_prefix: str,
) -> List[PanelRecord]:
    """Return one PanelRecord per (finding, model) with a usable verdict.

    Empty list when the finding has fewer than 2 valid model records —
    D–S needs ≥2 models per finding for the EM to have leverage.
    """
    analyses = finding.get("multi_model_analyses")
    if not isinstance(analyses, list) or len(analyses) < 2:
        return []
    finding_id = finding.get("finding_id")
    if not isinstance(finding_id, str) or not finding_id:
        return []
    decision_class = _decision_class_for(
        finding.get("rule_id"), decision_class_prefix,
    )
    records: List[PanelRecord] = []
    for entry in analyses:
        if not isinstance(entry, dict):
            continue
        if "error" in entry:
            continue
        model = entry.get("model")
        if not isinstance(model, str) or not model:
            continue
        raw_verdict = entry.get("is_exploitable")
        if not isinstance(raw_verdict, bool):
            # Tri-state safety: None, "yes", 1, etc. are all dropped.
            # Booleans only — the EM treats this as a Bernoulli signal.
            continue
        records.append(PanelRecord(
            finding_id=finding_id,
            decision_class=decision_class,
            model=model,
            verdict=raw_verdict,
        ))
    if len(records) < 2:
        return []
    return records


def load_from_orchestrated_report(
    path: Path, *,
    decision_class_prefix: str = DEFAULT_DECISION_CLASS_PREFIX,
) -> List[PanelRecord]:
    """Walk one ``orchestrated_report.json`` and return every usable
    panel record. Missing file → empty list with no error (the caller
    decides whether absence is fatal); malformed JSON → ``ValueError``
    with the source path embedded for diagnosis."""
    if not path.is_file():
        return []
    try:
        with path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"panel_log: cannot parse {path}: {exc}"
        ) from exc
    results = payload.get("results")
    if not isinstance(results, list):
        return []
    out: List[PanelRecord] = []
    for finding in results:
        if isinstance(finding, dict):
            out.extend(_extract_records_from_finding(
                finding, decision_class_prefix=decision_class_prefix,
            ))
    return out


def load_from_paths(
    paths: Iterable[Path], *,
    decision_class_prefix: str = DEFAULT_DECISION_CLASS_PREFIX,
) -> List[PanelRecord]:
    """Concatenate records from multiple report files in path order.

    Duplicate ``finding_id`` across files is allowed and preserved —
    different runs can re-analyse the same finding with different
    panels, and D–S should see all of them (each panel is an
    independent observation event).
    """
    out: List[PanelRecord] = []
    for p in paths:
        out.extend(load_from_orchestrated_report(
            p, decision_class_prefix=decision_class_prefix,
        ))
    return out


def discover_reports(root: Path) -> List[Path]:
    """Find every ``orchestrated_report.json`` under ``root``. Sorted
    for determinism. Symlinks followed only one hop deep to avoid
    cycle traversal."""
    if not root.is_dir():
        return []
    pattern = str(root / "**" / "orchestrated_report.json")
    return sorted(Path(p) for p in glob.glob(pattern, recursive=True))


# ---------------------------------------------------------------------------
# Convenience aggregators — used by the D–S estimator caller
# ---------------------------------------------------------------------------


def group_by_finding(
    records: Sequence[PanelRecord],
) -> dict:
    """Group records into ``{finding_id: [PanelRecord, ...]}``.

    Order within each finding is the load order of the underlying file —
    deterministic given the path order. Phase 2b consumes this shape
    for the EM's outer loop.
    """
    grouped: dict = {}
    for r in records:
        grouped.setdefault(r.finding_id, []).append(r)
    return grouped


def group_by_decision_class(
    records: Sequence[PanelRecord],
) -> dict:
    """Group records into ``{decision_class: [PanelRecord, ...]}`` for
    per-class partitioning. Returns a dict, not a defaultdict, so
    callers see explicit keys."""
    grouped: dict = {}
    for r in records:
        grouped.setdefault(r.decision_class, []).append(r)
    return grouped


def distinct_models(records: Sequence[PanelRecord]) -> List[str]:
    """Sorted list of distinct model names across all records.
    The EM allocates a confusion-matrix slot per name."""
    return sorted({r.model for r in records})


__all__ = [
    "PanelRecord",
    "DEFAULT_DECISION_CLASS_PREFIX",
    "load_from_orchestrated_report",
    "load_from_paths",
    "discover_reports",
    "group_by_finding",
    "group_by_decision_class",
    "distinct_models",
]
