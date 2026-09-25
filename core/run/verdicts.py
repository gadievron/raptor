"""Operator finding-verdict substrate: id resolution + override edits.

Mechanics behind ``raptor-review verdict`` — pure run-directory work,
no SAGE dependency (the SAGE side lives in ``core/sage/hooks.py``):

* resolve an operator-supplied finding id against the findings
  artifacts of one or more run directories (exact match, unique-prefix
  match, did-you-mean suggestions on miss);
* read the pipeline's coordinate binding off a finding record;
* set / clear the ``manual_override`` flag on the stored finding
  records — the exact per-finding key the suppression chokepoints
  consume (``core.analysis.reach_chokepoint.check_suppress``, the
  guard-dominance skip, the SAGE prior-verdict pre-flight, and the
  /validate models' ``manual_override`` / ``manual_override_reason``
  fields), so every future pass that CONSUMES these findings files
  (/validate, /analyze re-passes, project merge views) sees the
  operator's decision.

Findings files are written into the sandbox-writable run dir, so every
read here is byte-budgeted (``MAX_FINDINGS_JSON_BYTES``) and every
value treated as attacker bytes — rendering is the caller's job
(escape-at-render), this module never prints.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from core.json import save_json
from core.logging import get_logger
from core.project.findings_utils import (
    _load_size_gated_json,
    get_finding_id,
)

from .findings import _STAMP_PATHS, _resolve_findings_list

logger = get_logger()

# The findings artifacts a verdict edit touches: the provenance
# stamper's convention (one owner: core/run/findings.py) plus the
# /validate handoff file — its records are the input of /validate
# re-passes and deserialise the manual_override fields directly.
FINDINGS_ARTIFACTS: tuple = (*_STAMP_PATHS, "validation/findings.json")

# Read-only id-resolution sources: per-finding ANALYSIS results. An
# /agentic run has no top-level findings.json — its findings live in
# orchestrated_report.json (finding_id / file_path / function / line /
# rule_id per core/run/orchestrated_report_schema.py). Resolution must
# see them (the SAGE verbs only need coordinates), but a verdict edit
# never rewrites a report.
_REPORT_SOURCES: tuple = ("orchestrated_report.json",)

_MAX_IDS = 100_000  # candidate-id bound: run dirs are attacker-writable
_SUGGESTION_COUNT = 5


@dataclass
class FindingRef:
    """One located finding record inside a run's findings artifact."""

    run_dir: Path
    artifact: Path            # absolute path of the findings file
    finding: dict[str, Any]   # the record itself (by reference)
    finding_id: str
    editable: bool = True     # False for analysis-report sources


def iter_findings(run_dir: Path) -> Iterator[FindingRef]:
    """Yield a :class:`FindingRef` for every finding record in
    ``run_dir``'s findings artifacts (editable) and analysis reports
    (read-only). Best-effort per file: malformed or oversize
    artifacts are skipped (logged at debug)."""
    run_dir = Path(run_dir)
    sources = [(rel, True) for rel in FINDINGS_ARTIFACTS]
    sources += [(rel, False) for rel in _REPORT_SOURCES]
    for rel, editable in sources:
        path = run_dir / rel
        if not path.is_file():
            continue
        data = _load_size_gated_json(path)
        if data is None:
            logger.debug("verdicts: skipping unreadable %s", path)
            continue
        findings_list, _kind = _resolve_findings_list(data)
        if findings_list is None:
            continue
        for f in findings_list:
            if not isinstance(f, dict):
                continue
            fid = get_finding_id(f)
            if not isinstance(fid, str) or not fid:
                continue
            yield FindingRef(run_dir=run_dir, artifact=path,
                            finding=f, finding_id=fid,
                            editable=editable)


def resolve_finding(
    run_dirs: list[Path],
    finding_id: str,
) -> tuple[list[FindingRef], list[str]]:
    """Resolve ``finding_id`` against the findings of ``run_dirs``.

    Returns ``(matches, suggestions)``:

    * exact-id matches when any exist (a finding can legitimately
      appear in several runs / artifacts — the caller applies the verb
      to all of them);
    * else unique-prefix matches (one distinct id only — an ambiguous
      prefix resolves to nothing, with the colliding ids as
      suggestions);
    * on a miss, ``matches`` is empty and ``suggestions`` carries the
      did-you-mean candidates (close matches first, then prefix
      collisions), capped at :data:`_SUGGESTION_COUNT`.
    """
    wanted = str(finding_id).strip()
    exact: list[FindingRef] = []
    prefix: dict[str, list[FindingRef]] = {}
    all_ids: list[str] = []
    seen_ids: set[str] = set()
    for run_dir in run_dirs:
        for ref in iter_findings(run_dir):
            if ref.finding_id == wanted:
                exact.append(ref)
            elif wanted and ref.finding_id.startswith(wanted):
                prefix.setdefault(ref.finding_id, []).append(ref)
            if ref.finding_id not in seen_ids and len(all_ids) < _MAX_IDS:
                seen_ids.add(ref.finding_id)
                all_ids.append(ref.finding_id)
    if exact:
        return exact, []
    if len(prefix) == 1:
        return next(iter(prefix.values())), []
    if len(prefix) > 1:
        return [], sorted(prefix)[:_SUGGESTION_COUNT]
    suggestions = difflib.get_close_matches(
        wanted, all_ids, n=_SUGGESTION_COUNT, cutoff=0.4)
    return [], suggestions


def finding_coords(finding: dict[str, Any]) -> tuple[str, str, int]:
    """``(relative_path, function_name, line)`` for a finding record.

    Mirrors the pipeline's binding order (``_finding_coords`` in
    ``packages/llm_analysis/agent.py`` — kept there because importing
    the analysis agent pulls the whole LLM stack into a read-only
    CLI): ``file_path``/``file``, ``function``/``metadata.function_name``/
    ``metadata.name``, ``line``/``startLine``/``start_line``. Missing
    pieces resolve to ``""`` / ``0`` — callers gate on truthiness.
    """
    meta = finding.get("metadata") or {}
    if not isinstance(meta, dict):
        meta = {}
    rel = str(finding.get("file_path") or finding.get("file") or "")
    fn = (
        finding.get("function")
        or meta.get("function_name")
        or meta.get("name")
        or ""
    )
    line_raw = finding.get("line")
    if line_raw is None:
        line_raw = finding.get("startLine")
    if line_raw is None:
        line_raw = finding.get("start_line")
    try:
        line = int(line_raw or 0)
    except (TypeError, ValueError):
        line = 0
    return rel, str(fn), line


def finding_rule_id(finding: dict[str, Any]) -> str:
    """The scanner rule id, across the key shapes in play (same
    binding order as the pipeline's SAGE verdict loop)."""
    return str(finding.get("rule_id") or finding.get("check_id") or "")


def set_manual_override(
    refs: list[FindingRef],
    value: bool,
    reason: str | None = None,
) -> tuple[list[Path], list[Path]]:
    """Set (``value=True``) or clear (``value=False``) the
    ``manual_override`` flag on the located finding records, in place
    in their artifacts.

    ``manual_override: true`` is the exact key the suppression
    chokepoints read (reachability, guard-dominance, SAGE prior
    verdict) and the /validate finding model deserialises; ``reason``
    lands in ``manual_override_reason`` (the model's companion
    field). Clearing removes both keys — the neutral state, not
    ``false`` (an explicit false is still an operator statement).

    Writes each touched artifact once (atomic ``save_json``).
    Returns ``(changed, failed)`` — artifacts rewritten, and
    artifacts that could NOT be rewritten (became unreadable /
    over-budget / write error between resolution and rewrite).
    Callers must surface ``failed`` — an edit that silently did not
    happen reads as "force-through set" to the operator. Read-only
    refs (analysis reports) are skipped — a verdict edit never
    rewrites a report.
    """
    by_artifact: dict[Path, list[FindingRef]] = {}
    for ref in refs:
        if not ref.editable:
            continue
        by_artifact.setdefault(ref.artifact, []).append(ref)

    changed: list[Path] = []
    failed: list[Path] = []
    for artifact, artifact_refs in by_artifact.items():
        # Re-load so the rewrite starts from current bytes; mutate the
        # records matched BY ID inside the fresh container (the refs'
        # dicts belong to an earlier parse).
        data = _load_size_gated_json(artifact)
        if data is None:
            logger.warning("verdicts: %s became unreadable — skipped",
                           artifact)
            failed.append(artifact)
            continue
        findings_list, _kind = _resolve_findings_list(data)
        if findings_list is None:
            failed.append(artifact)
            continue
        wanted_ids = {r.finding_id for r in artifact_refs}
        mutated = False
        for f in findings_list:
            if not isinstance(f, dict):
                continue
            if get_finding_id(f) not in wanted_ids:
                continue
            if value:
                if f.get("manual_override") is not True:
                    f["manual_override"] = True
                    mutated = True
                if reason and f.get("manual_override_reason") != reason:
                    f["manual_override_reason"] = reason
                    mutated = True
            else:
                for key in ("manual_override", "manual_override_reason"):
                    if key in f:
                        del f[key]
                        mutated = True
        if not mutated:
            continue
        try:
            save_json(artifact, data)
        except OSError as e:
            logger.warning("verdicts: write failed %s: %s", artifact, e)
            failed.append(artifact)
            continue
        changed.append(artifact)
    return changed, failed


__all__ = [
    "FINDINGS_ARTIFACTS",
    "FindingRef",
    "finding_coords",
    "finding_rule_id",
    "iter_findings",
    "resolve_finding",
    "set_manual_override",
]
