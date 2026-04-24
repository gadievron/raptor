"""Classify raptor runs into command families and navigation lanes.

Raptor has three parallel execution lanes (source analysis, binary fuzzing,
OSS forensics). Each slash command lives in exactly one lane and maps to one
or more sidebar stages. `/agentic` spans both scan and validate stages because
it runs the full source-analysis workflow end-to-end.
"""

from __future__ import annotations

from typing import Iterable

# Canonical command families, ordered by specificity so substring matching
# finds the longest match first (e.g., "crash-analysis" before "analysis").
_KNOWN_KINDS = (
    "crash-analysis",
    "oss-forensics",
    "understand",
    "agentic",
    "validate",
    "analyze",
    "codeql",
    "exploit",
    "patch",
    "fuzz",
    "scan",
    "web",
)

# A run of kind K contributes a completion signal to every stage in this list.
# Multiple stages because /agentic is an end-to-end workflow that covers both
# the scan and validate stages in one go.
_STAGES_BY_KIND: dict[str, tuple[str, ...]] = {
    "understand":     ("understand",),
    "scan":           ("scan",),
    "codeql":         ("scan",),
    "agentic":        ("scan", "validate"),
    "analyze":        ("scan",),
    "web":            ("scan",),
    "validate":       ("validate",),
    "fuzz":           ("fuzz",),
    "crash-analysis": ("crash-analysis",),
    "oss-forensics":  ("oss-forensics",),
    "exploit":        ("exploits",),
    "patch":          ("patches",),
}

_LANE_BY_KIND: dict[str, str] = {
    "understand":     "source",
    "scan":           "source",
    "codeql":         "source",
    "agentic":        "source",
    "analyze":        "source",
    "web":            "source",
    "validate":       "source",
    "fuzz":           "binary",
    "crash-analysis": "binary",
    "oss-forensics":  "forensics",
    "exploit":        "artifacts",
    "patch":          "artifacts",
}

LANE_ORDER = ("source", "binary", "forensics")

SOURCE_STAGES = ("understand", "scan", "validate")
BINARY_STAGES = ("fuzz", "crash-analysis")
FORENSICS_STAGES = ("oss-forensics",)

STAGE_LABELS = {
    "understand":     "Understand",
    "scan":           "Scan",
    "validate":       "Validate",
    "fuzz":           "Fuzz",
    "crash-analysis": "Crash analysis",
    "oss-forensics":  "OSS forensics",
    "exploits":       "Exploits",
    "patches":        "Patches",
}

STAGE_DESCRIPTIONS = {
    "understand":     "Map attack surface, trace data flows, hunt for variants.",
    "scan":           "Semgrep + CodeQL static analysis, optionally with LLM dispatch.",
    "validate":       "Multi-stage exploitability validation (A–F) on existing findings.",
    "fuzz":           "AFL++ campaign with autonomous or goal-directed corpus.",
    "crash-analysis": "rr + GDB + gcov root-cause analysis for a specific crash.",
    "oss-forensics":  "Evidence-backed GitHub investigation via GH Archive + Wayback + git.",
}


def classify(command: str, dirname: str = "") -> str:
    """Return the canonical kind for a raptor run.

    Prefers command string; falls back to dirname. Returns ``"other"`` if
    nothing matches.
    """
    text = f"{command or ''} {dirname or ''}".lower()
    for kind in _KNOWN_KINDS:
        if kind in text:
            return kind
    return "other"


def lane_for(kind: str) -> str:
    return _LANE_BY_KIND.get(kind, "other")


def stages_for(kind: str) -> tuple[str, ...]:
    return _STAGES_BY_KIND.get(kind, ())


def lane_status(runs: Iterable) -> dict[str, dict[str, dict]]:
    """Compute per-stage status across a project's runs.

    Returns ``{lane: {stage: {"status": str, "count": int, "last_run": Run?}}}``
    where status is one of ``pending`` (no runs), ``partial`` (any running),
    ``complete`` (all finished).

    Runs are expected to be ordered newest-first; we preserve that order so
    ``last_run`` is the most recent.
    """
    structure: dict[str, dict[str, list]] = {
        "source":    {s: [] for s in SOURCE_STAGES},
        "binary":    {s: [] for s in BINARY_STAGES},
        "forensics": {s: [] for s in FORENSICS_STAGES},
    }

    for run in runs:
        for stage in stages_for(run.kind):
            for lane_stages in structure.values():
                if stage in lane_stages:
                    lane_stages[stage].append(run)

    out: dict[str, dict[str, dict]] = {}
    for lane, lane_stages in structure.items():
        out[lane] = {}
        for stage, stage_runs in lane_stages.items():
            if not stage_runs:
                status = "pending"
            elif any(r.status == "running" for r in stage_runs):
                status = "partial"
            elif any(r.status == "failed" for r in stage_runs) and not any(
                r.status == "completed" for r in stage_runs
            ):
                status = "failed"
            else:
                status = "complete"
            out[lane][stage] = {
                "status": status,
                "count": len(stage_runs),
                "last_run": stage_runs[0] if stage_runs else None,
                "label": STAGE_LABELS.get(stage, stage),
                "description": STAGE_DESCRIPTIONS.get(stage, ""),
            }
    return out


def next_action(runs: Iterable, project_kind: str | None = None) -> dict | None:
    """Suggest the next stage the user should run.

    Walks the lane matching ``project_kind`` and returns the first pending
    stage. Falls back to the source lane when the project type is unknown.
    Returns None if every stage in the chosen lane has run.
    """
    lane_order: tuple[str, ...]
    if project_kind == "binary":
        lane_order = BINARY_STAGES
        lane_key = "binary"
    elif project_kind == "forensics":
        lane_order = FORENSICS_STAGES
        lane_key = "forensics"
    else:
        lane_order = SOURCE_STAGES
        lane_key = "source"

    status = lane_status(runs)
    for stage in lane_order:
        entry = status[lane_key][stage]
        if entry["status"] == "pending":
            return {
                "stage": stage,
                "label": STAGE_LABELS[stage],
                "description": STAGE_DESCRIPTIONS[stage],
            }
    return None
