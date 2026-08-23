"""Append-only corpus run-history store and reporting CLI.

Usage:
    python3 -m core.audit.corpus.history runs
    python3 -m core.audit.corpus.history compare <runA> <runB>
    python3 -m core.audit.corpus.history trend --label <function_id>
    python3 -m core.audit.corpus.history stability
    python3 -m core.audit.corpus.history import <results.json>...

Every corpus run appends one RUN header record plus one LABEL record
per scored label to a JSONL store (default
``~/.local/share/raptor/corpus-history.jsonl``, overridable via
``RAPTOR_CORPUS_HISTORY``).  ``compare`` is the report for measuring
fix impact between two runs: per-label verdict flips grouped by flip
type, attribution-cell changes, and cost deltas.  ``stability``
measures nondeterminism: verdict variance across runs that share the
same pipeline tree and config.

Reporting-only, by design: nothing in the audit/corpus pipeline reads
this store to alter behavior.  The read side is exclusively this
module's CLI.  The write side is a post-finalization hook in
``run_corpus`` (after results.json lands) whose failure warns and
never fails the run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TYPE_CHECKING

from core.json import load_json, loads

if TYPE_CHECKING:
    from collections.abc import Iterable, Iterator

logger = logging.getLogger(__name__)

HISTORY_ENV = "RAPTOR_CORPUS_HISTORY"

# results.json files track corpus size — the checklist budget class.
_MAX_RESULTS_BYTES = 256 * 1024 * 1024

# Output filenames that identify the run only through their directory
# (out/corpus-full-v3/results.json -> run id "corpus-full-v3").
_GENERIC_STEMS = frozenset({"results", "corpus-results"})


def store_path() -> Path:
    """Resolve the history store path (env override > default)."""
    override = os.environ.get(HISTORY_ENV, "").strip()
    if override:
        return Path(override).expanduser()
    return (
        Path.home() / ".local" / "share" / "raptor"
        / "corpus-history.jsonl"
    )


def _warn(msg: str) -> None:
    print(f"WARNING: {msg}", file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Record construction
# ---------------------------------------------------------------------------

def pipeline_tree_sha() -> str:
    """``git rev-parse HEAD^{tree}`` of the repo this runner executes from.

    The pipeline-under-test is the checkout whose code is actually
    running, so the root is resolved from this module's own location,
    not the caller's cwd.  Returns ``""`` when the sha cannot be
    resolved (not a git checkout, git missing) — recording must never
    fail a run over provenance.
    """
    root = Path(__file__).resolve().parents[3]
    try:
        from core.config import RaptorConfig
        from core.git import safe_git_readonly_command

        result = subprocess.run(
            safe_git_readonly_command(
                "-C", str(root), "rev-parse", "HEAD^{tree}",
            ),
            capture_output=True, text=True, timeout=30,
            env=RaptorConfig.get_safe_env(), check=False,
        )
        sha = result.stdout.strip()
        if result.returncode == 0 and sha:
            return sha
    except Exception:  # noqa: BLE001 — provenance is best-effort
        logger.debug("pipeline tree sha resolution failed", exc_info=True)
    return ""


def label_set_hash(labels: Iterable[Any]) -> str:
    """SHA-256 over the sorted ``function_id:span_sha`` entries."""
    entries = sorted(
        f"{lb.function_id}:{getattr(lb.source, 'span_sha', '') or ''}"
        for lb in labels
    )
    return hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()


def _gate_outcomes(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Recompute calibration-gate outcomes for the run header.

    Deterministic re-derivation from the same rows the summary scores;
    failures degrade to ``passed: None`` rather than blocking the
    write.
    """
    try:
        from .corpus_metrics import check_gate, compute_metrics

        aggregate, per_class, _ = compute_metrics(rows)
        failures = check_gate(aggregate, per_class, rows)
        return {"passed": not failures, "failures": failures}
    except Exception:  # noqa: BLE001 — recording must not fail the run
        logger.debug("gate recomputation failed", exc_info=True)
        return {"passed": None, "failures": []}


def run_id_for_output(output: Path) -> str:
    """Derive a run id from the results path.

    A generic filename (``results.json``) identifies the run through
    its directory; anything else uses the file stem.
    """
    resolved = output.resolve()
    if resolved.stem in _GENERIC_STEMS and resolved.parent.name:
        return resolved.parent.name
    return resolved.stem


def _timestamp_for_run(run_tag: str | None, output: Path) -> str:
    """ISO-8601 UTC timestamp from the run's own artifacts.

    Prefers the runner's run tag (the epoch it stamped at run start);
    falls back to the results file's mtime.  No fresh clock reads.
    """
    if run_tag:
        try:
            return datetime.fromtimestamp(
                int(run_tag), tz=timezone.utc,
            ).isoformat()
        except (ValueError, OverflowError, OSError):
            pass
    try:
        return datetime.fromtimestamp(
            output.stat().st_mtime, tz=timezone.utc,
        ).isoformat()
    except OSError:
        return ""


def build_run_record(
    results: list[dict[str, Any]],
    meta: dict[str, Any],
    *,
    run_id: str,
    timestamp: str,
    tree_sha: str,
    config: dict[str, Any],
    labels_hash: str,
    imported: bool = False,
    profile: str = "deployed",
    selection: Any = "full",
) -> dict[str, Any]:
    """Build the RUN header record for one corpus run.

    ``profile`` records which knowledge profile produced the run
    (``cold`` = raw first-time-user capability, ``deployed`` = all
    accumulated-knowledge channels on). Records written before the
    field existed are read as ``deployed`` (see :func:`run_profile`).

    ``selection`` distinguishes a full-corpus run (``"full"``) from a
    selective refire (a dict like ``{"class": ..., "labels": [...]}``
    mirroring the --class/--label filters), so history readers never
    misread a 3-label refire as a full-run regression. The label-set
    hash already reflects the subset; this field records the
    operator's intent. Absent on pre-selection records.
    """
    reviewed = [r for r in results if not r.get("skipped")]
    return {
        "record": "run",
        "run_id": run_id,
        "timestamp": timestamp,
        "pipeline_tree_sha": tree_sha,
        "profile": profile or "deployed",
        "selection": selection if selection is not None else "full",
        "config": dict(config),
        "label_set_hash": labels_hash,
        "gates": _gate_outcomes(results),
        "totals": {
            "labels": len(results),
            "reviewed": len(reviewed),
            "matched": sum(1 for r in reviewed if r.get("match")),
            "errors": sum(
                1 for r in results if r.get("actual") == "error"
            ),
            "skipped": len(results) - len(reviewed),
            "wall_s": meta.get("wall_s", 0.0),
            "llm_s": meta.get("llm_s", 0.0),
        },
        "cost_usd": meta.get(
            "cost_usd",
            round(sum(r.get("cost_usd", 0.0) for r in results), 4),
        ),
        "imported": imported,
    }


def describe_selection(run_rec: dict[str, Any]) -> str:
    """Human-readable selection: 'full', 'class=x', 'N label(s)'.

    Pre-selection records return '' (unknown — full runs and refires
    were recorded identically before the field existed).
    """
    sel = run_rec.get("selection")
    if sel is None:
        return ""
    if sel == "full":
        return "full"
    parts = []
    if isinstance(sel, dict):
        if sel.get("class"):
            parts.append(f"class={sel['class']}")
        if sel.get("labels"):
            parts.append(f"{len(sel['labels'])} label(s)")
    return "refire: " + ", ".join(parts) if parts else "refire"


def run_profile(run_rec: dict[str, Any]) -> str:
    """The run header's profile, tolerant of pre-profile records.

    Every run recorded before the profile field existed ran with all
    accumulated-knowledge channels on — today's ``deployed``.
    """
    return run_rec.get("profile") or "deployed"


def build_label_records(
    results: list[dict[str, Any]],
    *,
    run_id: str,
    span_shas: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Build one LABEL record per result row.

    Tolerates older result shapes: every field beyond ``function_id``
    is optional and defaults (v2 rows lack ``error_reason``, probe
    rows lack ``skipped``, pre-attribution rows lack the attribution
    fields).
    """
    span_shas = span_shas or {}
    records = []
    for row in results:
        fid = row.get("function_id", "")
        if not fid:
            _warn(f"history: result row without function_id skipped "
                  f"(run {run_id})")
            continue
        records.append({
            "record": "label",
            "run_id": run_id,
            "function_id": fid,
            "span_sha": span_shas.get(fid, ""),
            "bug_class": row.get("bug_class", ""),
            "expected": row.get("expected", ""),
            "actual": row.get("actual", ""),
            "match": bool(row.get("match", False)),
            "skipped": bool(row.get("skipped", False)),
            "attribution": row.get("attribution", ""),
            "observed_mechanisms": list(
                row.get("observed_mechanisms", []) or [],
            ),
            "error_reason": row.get("error_reason", ""),
            "model": row.get("model", ""),
            "cost_usd": row.get("cost_usd", 0.0),
            "duration_s": row.get("duration_s", 0.0),
        })
    return records


def append_records(path: Path, records: list[dict[str, Any]]) -> None:
    """Append records to the JSONL store (append-only, one per line)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with Path(path).open("a", encoding="utf-8") as f:
        f.writelines(json.dumps(rec, sort_keys=True) + "\n" for rec in records)


def record_run(
    results: list[dict[str, Any]],
    meta: dict[str, Any],
    *,
    output_path: Path,
    run_tag: str | None = None,
    labels: list[Any] | None = None,
    config: dict[str, Any] | None = None,
    store: Path | None = None,
    profile: str = "deployed",
    selection: Any = "full",
) -> bool:
    """Append one run to the history store.  Never raises.

    The run_corpus writer hook: called once results.json is finalized
    (normal and gate-fail exits alike).  Any failure warns on stderr
    and returns False — history is reporting-only and must never fail
    the run that produced the data.
    """
    try:
        path = Path(store) if store is not None else store_path()
        output = Path(output_path)
        run_id = run_id_for_output(output)
        run_rec = build_run_record(
            results, meta,
            run_id=run_id,
            timestamp=_timestamp_for_run(run_tag, output),
            tree_sha=pipeline_tree_sha(),
            config=config or {},
            labels_hash=label_set_hash(labels) if labels else "",
            profile=profile,
            selection=selection,
        )
        span_shas = {
            lb.function_id: getattr(lb.source, "span_sha", "") or ""
            for lb in (labels or [])
        }
        label_recs = build_label_records(
            results, run_id=run_id, span_shas=span_shas,
        )
        append_records(path, [run_rec] + label_recs)
        print(f"Run history appended to {path} (run {run_id})",
              flush=True)
        return True
    except Exception as exc:  # noqa: BLE001 — history must never fail the run
        logger.debug("history recording failed", exc_info=True)
        _warn(f"corpus run history not recorded: {exc}")
        return False


# ---------------------------------------------------------------------------
# Store reading
# ---------------------------------------------------------------------------

def iter_records(path: Path) -> Iterator[dict[str, Any]]:
    """Yield store records, skipping malformed lines with a warning.

    A corrupt line (interrupted append, manual edit) must not kill
    reads over the rest of an append-only store.
    """
    try:
        f = Path(path).open(encoding="utf-8")
    except OSError:
        return
    with f:
        for lineno, raw in enumerate(f, 1):
            raw = raw.strip()
            if not raw:
                continue
            try:
                rec = loads(raw)
            except ValueError:
                _warn(f"{path}:{lineno}: malformed history line skipped")
                continue
            if (
                not isinstance(rec, dict)
                or rec.get("record") not in ("run", "label")
            ):
                _warn(f"{path}:{lineno}: unrecognized history record "
                      f"skipped")
                continue
            yield rec


def load_store(
    path: Path,
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, Any]]]]:
    """Load (run_headers, label_records_by_run_id) in append order."""
    runs: list[dict[str, Any]] = []
    labels: dict[str, list[dict[str, Any]]] = {}
    for rec in iter_records(path):
        if rec["record"] == "run":
            runs.append(rec)
        else:
            labels.setdefault(rec.get("run_id", ""), []).append(rec)
    return runs, labels


def resolve_run(
    runs: list[dict[str, Any]],
    token: str,
) -> dict[str, Any]:
    """Resolve a run id (or unique substring) to its latest header.

    Raises ``ValueError`` listing candidates on ambiguity, or when
    nothing matches.
    """
    exact = [r for r in runs if r.get("run_id") == token]
    if exact:
        return exact[-1]
    matches = [r for r in runs if token in r.get("run_id", "")]
    ids = sorted({r.get("run_id", "") for r in matches})
    if len(ids) == 1:
        return [r for r in matches if r.get("run_id") == ids[0]][-1]
    if not ids:
        known = ", ".join(
            sorted({r.get("run_id", "") for r in runs}),
        ) or "none recorded"
        msg = f"no run matches {token!r} (runs: {known})"
        raise ValueError(msg)
    msg = f"run token {token!r} is ambiguous: {', '.join(ids)}"
    raise ValueError(msg)


def _latest_labels(
    run: dict[str, Any],
    labels_by_run: dict[str, list[dict[str, Any]]],
) -> dict[str, dict[str, Any]]:
    """Latest label record per function_id for one run."""
    out: dict[str, dict[str, Any]] = {}
    for rec in labels_by_run.get(run.get("run_id", ""), []):
        out[rec["function_id"]] = rec
    return out


# ---------------------------------------------------------------------------
# compare
# ---------------------------------------------------------------------------

def classify_flip(a: dict[str, Any], b: dict[str, Any]) -> str:
    """Classify a verdict flip between two records of the same label.

    ``errored``: the label now errors.  ``recovered``: it errored
    before and now matches (``regressed`` if it errored before and
    still mismatches).  ``improved`` / ``regressed``: the match flag
    flipped.  ``lateral``: verdict changed, match unchanged.
    """
    if b.get("actual") == "error":
        return "errored"
    if a.get("actual") == "error":
        return "recovered" if b.get("match") else "regressed"
    a_match = bool(a.get("match"))
    b_match = bool(b.get("match"))
    if b_match and not a_match:
        return "improved"
    if a_match and not b_match:
        return "regressed"
    return "lateral"


def compare_runs(
    run_a: dict[str, Any],
    run_b: dict[str, Any],
    labels_a: dict[str, dict[str, Any]],
    labels_b: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Compute the fix-impact diff between two runs."""
    common = sorted(set(labels_a) & set(labels_b))
    flips: dict[str, list[dict[str, Any]]] = {}
    attribution_changes: list[dict[str, Any]] = []
    for fid in common:
        a, b = labels_a[fid], labels_b[fid]
        if a.get("actual") != b.get("actual"):
            flips.setdefault(classify_flip(a, b), []).append({
                "function_id": fid,
                "expected": b.get("expected", a.get("expected", "")),
                "from": a.get("actual", ""),
                "from_skipped": bool(a.get("skipped")),
                "to": b.get("actual", ""),
                "to_skipped": bool(b.get("skipped")),
                "error_reason": b.get("error_reason", ""),
            })
        if a.get("attribution", "") != b.get("attribution", ""):
            attribution_changes.append({
                "function_id": fid,
                "from": a.get("attribution", ""),
                "to": b.get("attribution", ""),
                "observed": b.get("observed_mechanisms", []),
            })

    def _matched(recs: dict[str, dict[str, Any]]) -> tuple[int, int]:
        """(matched, reviewed) over non-skipped records — the same
        convention as the run header and the runner summary."""
        reviewed = [r for r in recs.values() if not r.get("skipped")]
        return sum(1 for r in reviewed if r.get("match")), len(reviewed)

    cost_a = float(run_a.get("cost_usd") or 0.0)
    cost_b = float(run_b.get("cost_usd") or 0.0)
    matched_a, reviewed_a = _matched(labels_a)
    matched_b, reviewed_b = _matched(labels_b)
    return {
        "run_a": run_a,
        "run_b": run_b,
        "common": len(common),
        "only_in_a": sorted(set(labels_a) - set(labels_b)),
        "only_in_b": sorted(set(labels_b) - set(labels_a)),
        "matched_a": matched_a,
        "reviewed_a": reviewed_a,
        "matched_b": matched_b,
        "reviewed_b": reviewed_b,
        "flips": flips,
        "attribution_changes": attribution_changes,
        "cost_a": cost_a,
        "cost_b": cost_b,
        "cost_delta": cost_b - cost_a,
    }


# Fixed report order: improvements first, then the bad news.
_FLIP_ORDER = ("improved", "recovered", "lateral", "regressed", "errored")


def format_compare(diff: dict[str, Any]) -> str:
    """Format the compare report."""
    a, b = diff["run_a"], diff["run_b"]
    lines = []
    lines.append(
        f"Compare {a.get('run_id')} ({a.get('timestamp') or '?'}) -> "
        f"{b.get('run_id')} ({b.get('timestamp') or '?'})"
    )
    for run, tag in ((a, "run a"), (b, "run b")):
        desc = describe_selection(run)
        if desc and desc != "full":
            lines.append(
                f"  NOTE: {tag} ({run.get('run_id')}) is a selective "
                f"refire ({desc}) — flips reflect the refired subset, "
                f"not a full-run regression"
            )
    prof_a, prof_b = run_profile(a), run_profile(b)
    if (prof_a, prof_b) != ("deployed", "deployed"):
        note = (
            " — PROFILES DIFFER (cold measures raw first-run "
            "capability; deployed folds accumulated knowledge)"
            if prof_a != prof_b else ""
        )
        lines.append(f"  Profiles: {prof_a} -> {prof_b}{note}")
    lines.append(
        f"  Labels: {diff['common']} common"
        + (f", {len(diff['only_in_a'])} only in {a.get('run_id')}"
           if diff["only_in_a"] else "")
        + (f", {len(diff['only_in_b'])} only in {b.get('run_id')}"
           if diff["only_in_b"] else "")
    )
    delta = diff["matched_b"] - diff["matched_a"]
    lines.append(
        f"  Matched (reviewed): {diff['matched_a']}/{diff['reviewed_a']}"
        f" -> {diff['matched_b']}/{diff['reviewed_b']} ({delta:+d})"
    )
    lines.append(
        f"  Cost: ${diff['cost_a']:.4f} -> ${diff['cost_b']:.4f} "
        f"({diff['cost_delta']:+.4f})"
    )
    for run, tag in ((a, "  Gates"), (b, "      ->")):
        gates = run.get("gates") or {}
        passed = gates.get("passed")
        verdict = (
            "unknown" if passed is None
            else "pass" if passed
            else f"fail ({len(gates.get('failures', []))})"
        )
        lines.append(f"{tag} [{run.get('run_id')}]: {verdict}")

    flips = diff["flips"]
    total_flips = sum(len(v) for v in flips.values())
    if not total_flips:
        lines.append("\nNo verdict flips.")
    else:
        lines.append(f"\nVerdict flips ({total_flips}):")
        for kind in _FLIP_ORDER:
            group = flips.get(kind)
            if not group:
                continue
            lines.append(f"  {kind} ({len(group)}):")
            for flip in group:
                from_tag = " (skipped)" if flip["from_skipped"] else ""
                to_tag = " (skipped)" if flip["to_skipped"] else ""
                lines.append(
                    f"    {flip['function_id']}: {flip['from']}"
                    f"{from_tag} -> {flip['to']}{to_tag} "
                    f"[expected={flip['expected']}]"
                )
                if flip["error_reason"]:
                    lines.append(
                        f"      reason: {flip['error_reason']}"
                    )

    changes = diff["attribution_changes"]
    if changes:
        lines.append(f"\nAttribution changes ({len(changes)}):")
        for ch in changes:
            observed = ", ".join(ch["observed"]) or "none"
            lines.append(
                f"  {ch['function_id']}: {ch['from'] or '(unset)'} -> "
                f"{ch['to'] or '(unset)'} [observed: {observed}]"
            )
    else:
        lines.append("\nNo attribution changes.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# runs / trend / stability
# ---------------------------------------------------------------------------

def format_runs(runs: list[dict[str, Any]]) -> str:
    """Format the run-header listing."""
    if not runs:
        return "No runs recorded."
    lines = [
        f"{'Run':<28} {'Timestamp':<26} {'Tree':<12} {'Profile':<9} "
        f"{'Mode':<10} "
        f"{'Labels':>6} {'Match':>6} {'Cost':>9} {'Gates':<9} Imported",
        "-" * 128,
    ]
    for r in runs:
        totals = r.get("totals") or {}
        gates = r.get("gates") or {}
        passed = gates.get("passed")
        gate_str = (
            "unknown" if passed is None
            else "pass" if passed
            else f"fail({len(gates.get('failures', []))})"
        )
        config = r.get("config") or {}
        lines.append(
            f"{r.get('run_id', '')[:27]:<28} "
            f"{(r.get('timestamp') or '')[:25]:<26} "
            f"{(r.get('pipeline_tree_sha') or '')[:12]:<12} "
            f"{run_profile(r)[:9]:<9} "
            f"{config.get('mode') or ''!s:<10} "
            f"{totals.get('labels', 0):>6} "
            f"{totals.get('matched', 0):>6} "
            f"${float(r.get('cost_usd') or 0.0):>8.4f} "
            f"{gate_str:<9} "
            f"{'yes' if r.get('imported') else 'no'}"
        )
    return "\n".join(lines)


def format_trend(
    function_id: str,
    runs: list[dict[str, Any]],
    labels_by_run: dict[str, list[dict[str, Any]]],
) -> str:
    """Format one label's history across all recorded runs."""
    rows = []
    for run in runs:
        rec = _latest_labels(run, labels_by_run).get(function_id)
        if rec is None:
            continue
        rows.append((run, rec))
    if not rows:
        return f"No history for label {function_id!r}."
    lines = [
        f"History for {function_id}:",
        f"  {'Run':<28} {'Timestamp':<26} {'Expected':<10} "
        f"{'Actual':<12} {'Match':<6} {'Attribution':<14} {'Cost':>9}",
        "  " + "-" * 110,
    ]
    for run, rec in rows:
        lines.append(
            f"  {run.get('run_id', '')[:27]:<28} "
            f"{(run.get('timestamp') or '')[:25]:<26} "
            f"{rec.get('expected', ''):<10} "
            f"{rec.get('actual', ''):<12} "
            f"{'yes' if rec.get('match') else 'NO':<6} "
            f"{rec.get('attribution', '') or '-':<14} "
            f"${float(rec.get('cost_usd') or 0.0):>8.4f}"
        )
        if rec.get("error_reason"):
            lines.append(f"      reason: {rec['error_reason']}")
    return "\n".join(lines)


def stability_groups(
    runs: list[dict[str, Any]],
    labels_by_run: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Group runs by (pipeline tree sha, profile, config), measure variance.

    Runs without a recorded tree sha (imports) cannot assert
    same-tree and are excluded.  Within each group of two or more
    runs, a label is unstable when the same tree and config produced
    different verdicts — the nondeterminism measure.
    """
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for run in runs:
        tree = run.get("pipeline_tree_sha") or ""
        if not tree:
            continue
        key = (
            tree,
            run_profile(run),
            json.dumps(run.get("config") or {}, sort_keys=True),
        )
        grouped.setdefault(key, []).append(run)

    out = []
    for (tree, profile, config_json), group in sorted(grouped.items()):
        if len(group) < 2:
            continue
        verdicts: dict[str, dict[str, str]] = {}
        for run in group:
            for fid, rec in _latest_labels(run, labels_by_run).items():
                verdicts.setdefault(fid, {})[run.get("run_id", "")] = (
                    rec.get("actual", "")
                )
        unstable = {
            fid: by_run for fid, by_run in verdicts.items()
            if len(by_run) >= 2 and len(set(by_run.values())) > 1
        }
        comparable = sum(
            1 for by_run in verdicts.values() if len(by_run) >= 2
        )
        out.append({
            "tree_sha": tree,
            "profile": profile,
            "config": json.loads(config_json),
            "run_ids": [r.get("run_id", "") for r in group],
            "comparable_labels": comparable,
            "unstable": unstable,
        })
    return out


def format_stability(groups: list[dict[str, Any]]) -> str:
    """Format the same-tree same-config variance report."""
    if not groups:
        return (
            "No comparable run groups (need two or more recorded runs "
            "with the same pipeline tree and config)."
        )
    lines = []
    for g in groups:
        config = ", ".join(
            f"{k}={v}" for k, v in sorted(g["config"].items())
            if v is not None
        )
        lines.append(
            f"Tree {g['tree_sha'][:12]} profile {g.get('profile', 'deployed')} "
            f"config [{config}] — runs: {', '.join(g['run_ids'])}"
        )
        n_unstable = len(g["unstable"])
        lines.append(
            f"  Verdict variance: {n_unstable}/"
            f"{g['comparable_labels']} comparable label(s) unstable"
        )
        for fid in sorted(g["unstable"]):
            by_run = g["unstable"][fid]
            detail = ", ".join(
                f"{rid}={verdict}"
                for rid, verdict in sorted(by_run.items())
            )
            lines.append(f"    {fid}: {detail}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# refire deltas
# ---------------------------------------------------------------------------

def refire_deltas(
    store: Path,
    function_ids: list[str],
    *,
    current_run_id: str,
) -> list[str]:
    """Per-label verdict deltas vs each label's latest PRIOR record.

    Post-run operator reporting for the selective-refire loop (fix a
    detector -> refire one label -> read the flip): for every refired
    label, find its most recent record from a run recorded BEFORE the
    current one and phrase the change. Read-only use of the history
    store, consistent with the reporting-only rule — it reports to
    the operator after results are final and never feeds the
    pipeline. Returns [] when the store or the current run is absent.
    """
    try:
        runs, labels_by_run = load_store(store)
    except OSError:
        return []
    order = [r.get("run_id", "") for r in runs]
    if current_run_id not in order:
        return []
    # Last occurrence: a reused --output path re-records under the
    # same id; the newest header is the refire. (Reusing a path also
    # merges the two runs' label records — distinct --output paths
    # per refire keep deltas exact; see the corpus README.)
    cur_idx = max(
        i for i, rid in enumerate(order) if rid == current_run_id
    )
    current = runs[cur_idx]
    cur_labels = _latest_labels(current, labels_by_run)
    prior_runs = [
        r for r in runs[:cur_idx]
        if r.get("run_id") != current_run_id
    ]

    lines: list[str] = []
    for fid in function_ids:
        now = cur_labels.get(fid)
        if now is None:
            continue
        prev = None
        for run in reversed(prior_runs):
            rec = _latest_labels(run, labels_by_run).get(fid)
            if rec is not None:
                prev = (run, rec)
                break
        expected = now.get("expected", "")
        match_tag = "matches" if now.get("match") else "mismatched"
        if prev is None:
            lines.append(
                f"{fid}: {now.get('actual', '')} "
                f"(expected {expected}, {match_tag}) — no prior history"
            )
            continue
        prev_run, prev_rec = prev
        if prev_rec.get("actual") == now.get("actual"):
            lines.append(
                f"{fid}: {now.get('actual', '')} — unchanged since "
                f"{prev_run.get('run_id', '?')} (still {match_tag})"
            )
        else:
            flip = classify_flip(prev_rec, now)
            lines.append(
                f"{fid}: {prev_rec.get('actual', '')} -> "
                f"{now.get('actual', '')} (expected {expected}) — "
                f"{flip.upper()}, now {match_tag} "
                f"[vs {prev_run.get('run_id', '?')}]"
            )
    return lines


def full_run_delta(store: Path, current_run_id: str) -> str | None:
    """Fix-impact delta of THIS run vs the latest prior recorded run.

    Full-run counterpart to :func:`refire_deltas`: a 220-label run
    used to print nothing but "history appended" even when the store
    held a complete prior run — the flip report existed in the data
    and was never shown.  Read-only, reporting-only, best-effort:
    returns None when the store, the current run, a prior run, or any
    common label is absent.
    """
    try:
        runs, labels_by_run = load_store(store)
    except OSError:
        return None
    order = [r.get("run_id", "") for r in runs]
    if current_run_id not in order:
        return None
    # Last occurrence, same convention as refire_deltas: a reused
    # --output path re-records under the same id.
    cur_idx = max(
        i for i, rid in enumerate(order) if rid == current_run_id
    )
    current = runs[cur_idx]
    prior_runs = [
        r for r in runs[:cur_idx]
        if r.get("run_id") != current_run_id
    ]
    if not prior_runs:
        return None
    prior = prior_runs[-1]
    labels_a = _latest_labels(prior, labels_by_run)
    labels_b = _latest_labels(current, labels_by_run)
    if not (set(labels_a) & set(labels_b)):
        return None
    diff = compare_runs(prior, current, labels_a, labels_b)
    return format_compare(diff)


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------

def import_results(results_path: Path, store: Path) -> str:
    """Back-import a results.json into the store.  Returns the run id.

    Tolerates the older result shapes: a bare list (no meta wrapper),
    meta without triage/prefilter, rows without error_reason or
    attribution fields.  The run header is synthesized from whatever
    meta exists plus the file's mtime; ``imported: true`` marks it,
    and the pipeline tree sha and label-set hash are left empty (they
    were not recorded at run time and cannot be reconstructed).
    """
    raw = load_json(results_path, strict=True, max_bytes=_MAX_RESULTS_BYTES)
    if raw is None:
        # Strict load_json still soft-returns None for a missing file.
        raise FileNotFoundError(results_path)
    if isinstance(raw, dict) and "results" in raw:
        meta = raw.get("meta") or {}
        rows = raw["results"]
    elif isinstance(raw, list):
        meta = {}
        rows = raw
    else:
        msg = (
            f"{results_path}: not a corpus results file "
            f"(expected a list or a {{meta, results}} wrapper)"
        )
        raise ValueError(msg)
    if not isinstance(rows, list):
        msg = f"{results_path}: results is not a list"
        raise ValueError(msg)

    modes = sorted({r.get("mode", "") for r in rows if r.get("mode")})
    config = {
        "mode": "+".join(modes) if modes else None,
        "triage": meta.get("triage"),
        "prefilter": meta.get("prefilter"),
        "model": meta.get("model", ""),
        "scope": None,
        "splice": meta.get("spliced_from"),
    }
    run_id = run_id_for_output(results_path)
    run_rec = build_run_record(
        rows, meta,
        run_id=run_id,
        timestamp=_timestamp_for_run(None, results_path),
        tree_sha="",
        config=config,
        labels_hash="",
        imported=True,
        profile=meta.get("profile") or "deployed",
    )
    label_recs = build_label_records(rows, run_id=run_id)
    append_records(store, [run_rec] + label_recs)
    return run_id


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python3 -m core.audit.corpus.history",
        description=(
            "Corpus run-history reporting (reporting-only: the "
            "audit/corpus pipeline never reads this store)"
        ),
    )
    parser.add_argument(
        "--store", type=Path, default=None,
        help=f"History store path (default: {HISTORY_ENV} env var, "
             f"then ~/.local/share/raptor/corpus-history.jsonl)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("runs", help="List recorded run headers")

    p_cmp = sub.add_parser(
        "compare",
        help="Per-label verdict flips, attribution changes, and cost "
             "deltas between two runs (fix-impact report)",
    )
    p_cmp.add_argument("run_a", help="Run id (or unique substring)")
    p_cmp.add_argument("run_b", help="Run id (or unique substring)")

    p_trend = sub.add_parser(
        "trend", help="One label's verdict history across runs",
    )
    p_trend.add_argument(
        "--label", required=True, dest="function_id",
        help="function_id of the label",
    )

    sub.add_parser(
        "stability",
        help="Verdict variance across same-tree same-config runs "
             "(nondeterminism measure)",
    )

    p_imp = sub.add_parser(
        "import", help="Back-import results.json files into the store",
    )
    p_imp.add_argument(
        "results", nargs="+", type=Path,
        help="results.json path(s) from prior corpus runs",
    )

    args = parser.parse_args(argv)
    store = args.store if args.store is not None else store_path()

    if args.cmd == "import":
        rc = 0
        for path in args.results:
            try:
                run_id = import_results(path, store)
            except (OSError, ValueError, json.JSONDecodeError) as exc:
                _warn(f"import failed for {path}: {exc}")
                rc = 1
                continue
            print(f"Imported {path} as run {run_id} into {store}")
        return rc

    runs, labels_by_run = load_store(store)

    if args.cmd == "runs":
        print(format_runs(runs))
        return 0

    if args.cmd == "compare":
        try:
            run_a = resolve_run(runs, args.run_a)
            run_b = resolve_run(runs, args.run_b)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
        print(format_compare(compare_runs(
            run_a, run_b,
            _latest_labels(run_a, labels_by_run),
            _latest_labels(run_b, labels_by_run),
        )))
        return 0

    if args.cmd == "trend":
        report = format_trend(args.function_id, runs, labels_by_run)
        print(report)
        return 0 if not report.startswith("No history") else 1

    if args.cmd == "stability":
        print(format_stability(stability_groups(runs, labels_by_run)))
        return 0

    return 1  # pragma: no cover — argparse enforces the choices


if __name__ == "__main__":
    sys.exit(main())
