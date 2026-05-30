"""Per-finding provenance stamping.

Closes the gap between the L1 provenance layer (which records *what produced
this run* in ``.raptor-run.json``) and individual findings (which historically
carried no back-reference to the run that produced them). After a run
completes, every finding gets a ``provenance_refs`` field — a list (always
plural, one entry at stamp time) of ``{run_id, ts, manifest_path}`` triples.

Why plural from day 1: cross-run merging (``core/project/merge.py``)
collapses N runs that surface the same finding into ONE record. The merged
record's ``provenance_refs`` is the UNION of all source runs' refs — the
plural shape makes that concatenation trivial without a singular/plural
schema awkwardness post-merge.

What's INTENTIONALLY thin in a ProvenanceRef:
  * run_id      = the run-dir basename (stable, file-system grep-able).
  * ts          = the manifest's start-time ISO timestamp.
  * manifest_path = the path to ``.raptor-run.json`` (relative to the run
    dir when possible, absolute otherwise — see ``_relative_manifest_path``).

Engines / models / target / det_repro are NOT duplicated here. Consumers
that need them call ``core.run.load_run_metadata(Path(manifest_path).parent)``.
This keeps the per-finding payload small and forces single-source-of-truth
reads against the manifest.

NOT stamped: SARIF files (the SARIF spec has its own ``tool`` / ``run`` /
``originalUriBaseIds`` provenance; injecting our own field would mangle the
standard). Only files matching the ``findings.json`` convention.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging import get_logger

from .metadata import RUN_METADATA_FILE, load_run_metadata

logger = get_logger()

# Field name on each finding dict. Always a list (plural-from-day-1).
PROVENANCE_REFS_FIELD = "provenance_refs"

# Files we stamp, relative to the run dir. Tested via load_findings_from_dir's
# shape detection (top-level list OR {"findings": [...]} wrapper).
_STAMP_PATHS: tuple = (
    "findings.json",
    "sca/findings.json",
)


def build_provenance_ref(run_dir: Path) -> Optional[Dict[str, Any]]:
    """Build the per-finding ProvenanceRef for ``run_dir``.

    Returns ``None`` if the run dir has no ``.raptor-run.json`` (an
    untracked output dir, or a stale partial run). Callers MUST treat
    ``None`` as "no provenance available" and SKIP stamping — never
    synthesise a partial ref.
    """
    manifest = load_run_metadata(run_dir)
    if not manifest:
        return None
    ref = {
        "run_id": run_dir.name,
        "manifest_path": str(_relative_manifest_path(run_dir)),
    }
    # Manifest top-level uses ``timestamp`` (per core/run/metadata.py
    # generate_run_metadata). Accept legacy/alternate keys defensively.
    ts = manifest.get("timestamp") or manifest.get("started_at") or manifest.get("ts")
    if ts:
        ref["ts"] = ts
    return ref


def _relative_manifest_path(run_dir: Path) -> Path:
    """Manifest path relative to ``run_dir`` (so it survives moves of the
    enclosing project dir). Always returns a relative path within the run."""
    return Path(RUN_METADATA_FILE)


def stamp_findings_in_run(run_dir: Path) -> Dict[str, int]:
    """Walk every ``findings.json`` in ``run_dir`` and inject
    ``provenance_refs`` into each finding that doesn't already have it.

    Idempotent — re-running on an already-stamped run is a no-op. Best-effort
    per file: a malformed ``findings.json`` is logged and skipped, doesn't
    abort the lifecycle. Returns ``{"files_stamped", "findings_stamped",
    "files_skipped"}``.

    No-op when the run dir has no manifest (returns zeros) — callers must
    not assume stamping succeeded; check the counts.
    """
    counts = {"files_stamped": 0, "findings_stamped": 0, "files_skipped": 0}
    run_dir = Path(run_dir)
    ref = build_provenance_ref(run_dir)
    if ref is None:
        logger.debug(f"No manifest in {run_dir}; skipping stamping.")
        return counts

    for rel in _STAMP_PATHS:
        path = run_dir / rel
        if not path.is_file():
            continue
        stamped = _stamp_file(path, ref)
        if stamped < 0:
            counts["files_skipped"] += 1
        elif stamped > 0:
            counts["files_stamped"] += 1
            counts["findings_stamped"] += stamped
    return counts


def _stamp_file(path: Path, ref: Dict[str, Any]) -> int:
    """Stamp findings in one file. Returns count of findings newly stamped,
    or -1 on parse failure (file skipped, not modified)."""
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning(f"stamp_findings: read failed {path}: {e}")
        return -1
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError) as e:
        logger.warning(f"stamp_findings: parse failed {path}: {e}")
        return -1

    findings_list, container_kind = _resolve_findings_list(data)
    if findings_list is None:
        # Shape we don't recognise — skip silently rather than risk mangling.
        return 0

    new_count = 0
    for f in findings_list:
        if not isinstance(f, dict):
            continue
        existing = f.get(PROVENANCE_REFS_FIELD)
        if isinstance(existing, list) and any(
            isinstance(r, dict) and r.get("run_id") == ref["run_id"]
            for r in existing
        ):
            # Idempotent — already stamped for this run.
            continue
        # Plural-from-day-1: always a list. New stamp = single-element.
        if isinstance(existing, list):
            existing.append(ref)
        else:
            f[PROVENANCE_REFS_FIELD] = [ref]
        new_count += 1

    if new_count == 0:
        return 0

    # Re-serialize the SAME container shape we read in.
    if container_kind == "list":
        out = json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
    else:  # dict-wrapped
        out = json.dumps(data, indent=2, sort_keys=False, default=str) + "\n"
    try:
        path.write_text(out, encoding="utf-8")
    except OSError as e:
        logger.warning(f"stamp_findings: write failed {path}: {e}")
        return -1
    return new_count


def _resolve_findings_list(
    data: Any,
) -> tuple[Optional[List[Any]], Optional[str]]:
    """Mirror load_findings_from_dir's shape detection but return the LIST
    by reference so mutations stamp into the original container.

    Returns ``(list_ref, container_kind)`` where container_kind is
    ``"list"`` for a top-level array, ``"dict"`` for a wrapped shape, or
    ``(None, None)`` if neither applies.
    """
    if isinstance(data, list):
        return data, "list"
    if isinstance(data, dict):
        for key in ("findings", "results"):
            v = data.get(key)
            if isinstance(v, list):
                return v, "dict"
    return None, None
