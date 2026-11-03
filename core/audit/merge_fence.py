"""Merge-lane receipt fence: standing detection receipts survive Phase 2.

The ensemble pipeline's lane-level floors (anti-self-refutation,
receipt-outranks-dismissal — :mod:`core.audit.refutation`) hold a
function at suspicious when the reviewer raises then dismisses the
exact defect a mechanical detector receipt corroborates, unless a
proof-grade tool refutes the receipt.  The ensemble MERGE lane had no
such contract: after both lanes resolve, the Phase-2 quality
classification (an LLM call) may demote merged findings to clean —
and nothing stopped it from minting a merge-level clean over a
detector receipt that was still standing in both lanes.  An LLM lane
overriding an un-refuted mechanical receipt with prose is the exact
failure mode the lane-level floors exist to prevent, occurring in the
one lane that did not honor receipts.

The fence: when a function carries a standing detection receipt that
no mechanical tool has refuted, the merge lane may not lower the
function's grade below suspicious.  Blocking keeps the lane grade
exactly as merged (a suspicious row stays suspicious, a finding row
stays a finding); the fence never promotes, never touches functions
without receipts, and never overrides a mechanical refutation.  It is
family-agnostic across receipt classes and grade-direction-narrow:
its only action is refusing the clean mint.

Receipt taxonomy — reused, not invented.  The anti-self-refutation
floor consumes two receipt classes:

* **Detector receipts** — mechanical detector hits whose family (the
  last ``:``-segment of the detector name) is in
  :data:`core.audit.refutation.FLOOR_DETECTOR_FAMILIES`.  These are
  durable run artifacts (``mechanical-findings.json`` in each lane's
  output tree) and are what this fence reads; a family added to the
  floor's table is covered here automatically.
* **Structural negative-space receipts** — computed in-memory per
  reviewed gap; their only durable trace is the ``refutation_gate``
  journal row written when the structural floor FIRES, carried on
  lane rows as ``receipt_floored``.  That flag reaches the merge lane
  through the Phase-2 suppression's ``receipt_floored`` exemption AND
  is propagated across the ensemble merge as the OR of both lanes'
  flags (a fired floor is mechanical evidence; it must survive the
  merge regardless of which lane's row wins).  The fence adds no
  parallel notion for them; it covers the remaining gap — receipts
  that STAND without their lane floor having fired.

Mechanical refutation lifts the fence — prose cannot.  A tool CAN
prove a receipt wrong: a proof-grade refuter that dominates a receipt
floor writes a demote-with-record row through the suppressions.jsonl
chokepoint (``verdict ==``
:data:`core.audit.refutation.DOMINANCE_VERDICT`, ``dropped: false``).
The fence subtracts receipts named by such rows; a function whose
every receipt is refuted is fully demotable.  Confirming verification
evidence on the merged row itself already exempts the row from the
Phase-2 suppression upstream of this fence
(``_is_verification_evidence`` — the :func:`~core.audit.evidence_grade.
is_tool_evidence` class), so the fence never needs to weigh it.

Record-or-refuse, inverted.  When the fence blocks a merge-level
clean it writes an audit row via
:func:`core.analysis.reach_chokepoint.record_suppression`
(``dropped: false``, verdict :data:`MERGE_FENCE_VERDICT`).  Unlike
the floors' dominance lane — where the UNSAFE action (overriding a
receipt) is refused without a record — the fence's action is the SAFE
direction: holding the grade at suspicious needs no record to be
safe.  So the record is best-effort but never silent: a record that
cannot be written is logged at warning and the fence still holds.

Trust gating: NOT trust-gated.  This fence consumes only mechanical
receipts (RAPTOR's own detectors wrote them into the lanes' run
output; nothing here is read from the scanned repository's own
content as an instruction) and RESTRICTS an LLM lane — its only
effect is preventing a demotion to clean.  There is no hostile-source
laundering surface: a crafted target cannot use the fence to hide or
promote a finding; at worst a planted detector-visible shape holds a
function at suspicious for operator review, which is the direction
the audit pipeline already fails toward.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

from core.json import load_json, load_jsonl

logger = logging.getLogger(__name__)

# Verdict string of the audit row written when the fence blocks a
# merge-level clean.  ``dropped`` is always False on these rows — the
# finding SURVIVED (that is the point).
MERGE_FENCE_VERDICT = "merge_fence_receipt_stands"

# mechanical-findings.json / suppressions.jsonl are RAPTOR-written run
# output — the audit-artifact budget class (same bound the corpus
# attribution reader uses).
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def _receipt_identity(rec: dict[str, Any]) -> tuple[str, str, str]:
    """(file, function, detector) identity a dominance row refutes."""
    return (
        str(rec.get("file", "") or ""),
        str(rec.get("function", "") or ""),
        str(rec.get("detector", "") or ""),
    )


def _artifact_group(root: Path, artifact: Path) -> str:
    """Repo-group name an artifact belongs to (its dir under *root*).

    A corpus lane writes one ``<repo-group>/`` dir per fixture repo.
    An artifact directly under *root* (no group level) scopes to the
    root's own directory NAME: when a caller hands the per-group
    audit dir itself instead of the lane root, that dirname IS the
    repo key — attributing by it keeps repo-carrying rows matchable,
    and for any other root shape it is no worse than an anonymous
    group (rows of a different repo never match either way).
    """
    try:
        rel = artifact.relative_to(root)
    except ValueError:
        return ""
    return rel.parts[0] if len(rel.parts) > 1 else root.name


def load_standing_receipts(
    run_dirs: Iterable[Path | str],
) -> dict[str, dict[str, list[dict[str, Any]]]]:
    """Index un-refuted floor-class detector receipts, group-scoped.

    Reads every ``mechanical-findings.json`` under *run_dirs* (the
    ensemble lanes' output trees), keeps the detector receipt classes
    the anti-self-refutation floor consumes
    (:data:`core.audit.refutation.FLOOR_DETECTOR_FAMILIES`), and
    subtracts receipts a mechanical proof-grade refuter dominated
    (recorded :data:`~core.audit.refutation.DOMINANCE_VERDICT` rows in
    the same repo group of any lane's ``suppressions.jsonl``).

    Shape: ``{repo_group: {file:function: [receipts]}}`` — the group
    is the artifact's repo dir under the lane root.  Receipt keys are
    repo-relative, so an unscoped index would let a receipt from one
    fixture repo hold a same-keyed function of another repo in the
    same multi-repo run.  Best-effort on unreadable artifacts — a
    lane that wrote nothing contributes nothing.

    Caller contract — *run_dirs* MUST be the lane ROOTS (the dirs
    whose immediate children are the per-repo group dirs, e.g.
    ``<out>-sec``/``<out>-bf``), the one layout both ensemble path
    shapes share:

    * fresh pass — ``_run_audit`` writes
      ``<lane_root>/<repo_key>/mechanical-findings.json`` and stamps
      every row with ``repo=<repo_key>``;
    * checkpoint resume — the same lane roots are what the resume
      branch has on disk.

    Passing the PER-GROUP audit dirs instead (the dirs ``_run_audit``
    happens to append to its ``run_dirs`` return) degrades
    gracefully — a root-level artifact scopes to the root's dirname,
    which is exactly the repo key in that shape — but the lane roots
    are the contract: they are what the resume branch has, and they
    need no dirname inference.  The ensemble caller passes
    ``sec_out``/``bf_out`` directly.
    """
    from core.audit.refutation import (
        DOMINANCE_VERDICT,
        FLOOR_DETECTOR_FAMILIES,
    )

    receipts: dict[str, dict[str, list[dict[str, Any]]]] = {}
    seen: set[tuple[str, str, str, str, int]] = set()
    refuted: set[tuple[str, str, str, str]] = set()

    for run_dir in run_dirs:
        root = Path(run_dir)
        if not root.is_dir():
            continue
        for spath in sorted(root.rglob("suppressions.jsonl")):
            group = _artifact_group(root, spath)
            rows = load_jsonl(spath, max_total_bytes=_MAX_ARTIFACT_BYTES)
            for rec in rows or []:
                if not isinstance(rec, dict):
                    continue
                if rec.get("verdict") != DOMINANCE_VERDICT:
                    continue
                refuted.add((
                    group,
                    str(rec.get("file_path", "") or ""),
                    str(rec.get("function", "") or ""),
                    str(rec.get("receipt", "") or ""),
                ))
        for mpath in sorted(root.rglob("mechanical-findings.json")):
            mf = load_json(mpath, max_bytes=_MAX_ARTIFACT_BYTES)
            if not isinstance(mf, dict):
                continue
            group = _artifact_group(root, mpath)
            for key, hits in mf.items():
                if not isinstance(hits, list):
                    continue
                for hit in hits:
                    if not isinstance(hit, dict):
                        continue
                    det = str(hit.get("detector", "") or "")
                    family = det.rsplit(":", 1)[-1]
                    if family not in FLOOR_DETECTOR_FAMILIES:
                        continue
                    fkey = str(key)
                    file_part, _, func_part = fkey.rpartition(":")
                    file_s = str(hit.get("file", "") or file_part)
                    func_s = str(hit.get("function", "") or func_part)
                    # Best-effort contract: a malformed line value
                    # (unhashable included) must degrade, not abort
                    # the run post-spend.
                    line_raw = hit.get("line")
                    line_v = line_raw if isinstance(line_raw, int) else 0
                    dedup = (
                        group, fkey, det, f"{file_s}:{func_s}", line_v,
                    )
                    if dedup in seen:
                        continue
                    seen.add(dedup)
                    receipts.setdefault(group, {}).setdefault(
                        fkey, [],
                    ).append({
                        "detector": det,
                        "file": file_s,
                        "function": func_s,
                        "line": line_v,
                    })

    if refuted:
        for group in list(receipts):
            for key in list(receipts[group]):
                kept = [
                    rc for rc in receipts[group][key]
                    if (group, *_receipt_identity(rc)) not in refuted
                ]
                if kept:
                    receipts[group][key] = kept
                else:
                    del receipts[group][key]
            if not receipts[group]:
                del receipts[group]
    return receipts


def bare_key(function_id: str) -> str:
    """Reduce a function id to its bare ``file:method`` form.

    Strips a trailing ``:<line>`` suffix and a receiver qualifier
    (``sql.go:Rows.Scan:12`` → ``sql.go:Scan``) — the key form the
    mechanical-findings artifact uses.
    """
    fid = str(function_id or "")
    head, _, tail = fid.rpartition(":")
    if head and tail.isdigit():
        fid = head
    file_part, _, func_part = fid.rpartition(":")
    if file_part and "." in func_part:
        return f"{file_part}:{func_part.rsplit('.', 1)[-1]}"
    return fid


def standing_receipts_for(
    index: dict[str, dict[str, list[dict[str, Any]]]] | None,
    function_id: str,
    *,
    repo: str | None = None,
    ambiguous_bare_keys: frozenset[str] | set[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Standing receipts for a merged row's ``function_id``.

    Tries the id as written, then with a trailing ``:<line>`` suffix
    stripped, then with a receiver-qualified name reduced to the bare
    method name (``sql.go:Rows.Scan`` → ``sql.go:Scan``) — the same
    key forms the corpus outcome parser resolves.

    *repo* scopes the lookup to that repo group's receipts (receipt
    keys are repo-relative; without scoping a receipt from one
    fixture repo could hold a same-keyed function of another repo in
    the same multi-repo run).  A row that carries no repo (legacy
    checkpoint rows) is matched conservatively: only when exactly ONE
    group resolves the key — a cross-group ambiguous key never
    fences.

    *ambiguous_bare_keys* names reduced forms (line-suffix stripped
    or receiver-stripped) shared by more than one function under
    review: the artifact keys receipts by bare method name, so a
    receipt on such a key cannot be attributed to one of the twins —
    both reduced-form fallbacks are skipped for them (the same
    ambiguity guard the outcome parser applies to stripped keys).
    Never touching a function whose receipt attribution is ambiguous
    beats holding a receipt-free twin.  The as-written id is always
    tried exactly.
    """
    if not index:
        return []
    fid = str(function_id or "")
    candidates = [fid]
    head, _, tail = fid.rpartition(":")
    if head and tail.isdigit():
        fid = head
        if head not in ambiguous_bare_keys:
            candidates.append(head)
    file_part, _, func_part = fid.rpartition(":")
    if file_part and "." in func_part:
        bare = f"{file_part}:{func_part.rsplit('.', 1)[-1]}"
        if bare not in ambiguous_bare_keys:
            candidates.append(bare)

    if repo is not None:
        groups: list[dict[str, list[dict[str, Any]]]] = (
            [index[repo]] if repo in index else []
        )
    else:
        groups = list(index.values())
    for key in candidates:
        hits = [g[key] for g in groups if g.get(key)]
        if len(hits) == 1:
            return list(hits[0])
        if len(hits) > 1:
            # Repo-less row, key present in several groups: cannot
            # attribute the receipt — never fence on ambiguity.
            return []
    return []


def hold_clean_mint(
    row: dict[str, Any],
    receipts: list[dict[str, Any]],
    record_dir: Path | str | None,
) -> None:
    """Block a merge-level clean mint over standing receipts.

    Keeps the row's merged grade exactly as-is (the fence never
    lowers, never raises), annotates the engagement on the row, and
    writes the audit row through the suppressions.jsonl chokepoint
    (``dropped: false``).  The hold does not depend on the record —
    holding is the safe direction — but a record that cannot be
    written is logged at warning, never silently dropped.
    """
    detectors = sorted({
        str(rc.get("detector", "") or "")
        for rc in receipts if rc.get("detector")
    })
    row["merge_fence"] = "receipt_stands"
    row["merge_fence_receipts"] = detectors

    fid = str(row.get("function_id", "") or "")
    file_part, _, func_part = fid.rpartition(":")
    line = 0
    for rc in receipts:
        if isinstance(rc.get("line"), int) and rc["line"]:
            line = rc["line"]
            break
    reason = (
        f"merge-lane receipt fence: standing detection receipt(s) "
        f"{', '.join(detectors)} on this function have no mechanical "
        f"refutation; the Phase-2 quality classification may not mint "
        f"clean over them — grade held at "
        f"{row.get('actual', '?')}"
    )

    recorded = False
    try:
        if record_dir:
            import os

            from core.analysis.reach_chokepoint import record_suppression

            # Per-invocation nonce: Phase 2 re-runs on every resume
            # segment and re-appends, so a stale fence row with the
            # same finding_id must not satisfy verification of THIS
            # write.
            nonce = os.urandom(8).hex()
            sink = Path(record_dir)
            record_suppression(
                sink,
                finding={
                    "finding_id": f"audit-merge-fence:{fid}",
                    "rule_id": "audit:merge-fence",
                    "file_path": file_part,
                    "line": line,
                    "function": func_part,
                },
                verdict=MERGE_FENCE_VERDICT,
                reason=reason,
                dropped=False,
                extra={
                    "stage": "ensemble-merge",
                    "receipts": detectors,
                    "held_status": str(row.get("actual", "") or ""),
                    "phase2_classification": str(
                        row.get("phase2_classification", "") or "",
                    ),
                    "record_nonce": nonce,
                },
            )
            recorded = _verify_recorded(sink, fid, nonce)
    except Exception:
        logger.debug("merge fence record attempt failed", exc_info=True)
        recorded = False
    if recorded:
        logger.info(
            "merge fence: Phase-2 clean mint blocked for %s — "
            "standing receipt(s) %s; grade held at %s",
            fid, ", ".join(detectors), row.get("actual", "?"),
        )
    else:
        # record_suppression swallows IO errors by its single-writer
        # contract; verify the row landed so a lost record is never
        # silent.  The fence holds either way — holding needs no
        # record to be safe.
        logger.warning(
            "merge fence: audit row for %s could not be written — "
            "the fence still holds (grade stays %s)",
            fid, row.get("actual", "?"),
        )


def _verify_recorded(
    record_dir: Path, function_id: str, nonce: str,
) -> bool:
    """True when THIS invocation's fence row is present in the sink.

    ``record_suppression`` logs-and-swallows IO errors, so the caller
    cannot see a lost write; parse the tail of the sink (single-writer
    file, appends are ordered) and match the exact ``finding_id`` and
    the per-invocation ``record_nonce``.  Parsing (rather than a
    substring probe) survives non-ASCII ids written as ``\\uXXXX``
    escapes; the nonce rejects stale same-id rows appended by earlier
    resume segments.
    """
    import json as _json

    sink = record_dir / "suppressions.jsonl"
    try:
        if not sink.is_file():
            return False
        with sink.open("rb") as fh:  # raw-open: suppressions ledger written by this run (bounded tail read)
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - 65536))
            tail = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return False
    wanted = f"audit-merge-fence:{function_id}"
    for ln in tail.splitlines():
        try:
            rec = _json.loads(ln)
        except ValueError:
            continue
        if (
            isinstance(rec, dict)
            and rec.get("verdict") == MERGE_FENCE_VERDICT
            and rec.get("finding_id") == wanted
            and rec.get("record_nonce") == nonce
        ):
            return True
    return False


__all__ = [
    "MERGE_FENCE_VERDICT",
    "bare_key",
    "hold_clean_mint",
    "load_standing_receipts",
    "standing_receipts_for",
]
