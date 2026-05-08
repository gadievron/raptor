"""Annotation diff between two run directories.

Mirrors the findings ``diff.py`` pattern: load annotations from each
run's ``annotations/`` subdir, key by (file, function), classify
into ``added`` / ``removed`` / ``changed`` / ``unchanged``.

A pair is "changed" when the body or metadata.status differs between
the two runs. Other metadata drift (e.g. updated rule_id, refreshed
hash) doesn't count as semantically changed — operators care about
the verdict, not the file checksum.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

from core.annotations import iter_all_annotations


def _load_run(run_dir: Path) -> Dict[tuple, Dict[str, Any]]:
    """Index a run's annotations by (file, function) → record dict."""
    by_pair: Dict[tuple, Dict[str, Any]] = {}
    ann_dir = run_dir / "annotations"
    if not ann_dir.exists():
        return by_pair
    for ann in iter_all_annotations(ann_dir):
        by_pair[(ann.file, ann.function)] = {
            "file": ann.file,
            "function": ann.function,
            "body": ann.body,
            "metadata": dict(ann.metadata),
        }
    return by_pair


def _has_changed(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """Did the verdict-relevant content change between two records?"""
    if a["body"] != b["body"]:
        return True
    if a["metadata"].get("status") != b["metadata"].get("status"):
        return True
    return False


def diff_annotations(run_dir_a: Path, run_dir_b: Path) -> Dict[str, Any]:
    """Compare annotation trees between two run dirs.

    Returns a dict with four lists:
      * ``added``     — present in B, absent in A.
      * ``removed``   — present in A, absent in B.
      * ``changed``   — present in both, body or status differ. Each
                        entry has ``before`` + ``after`` records.
      * ``unchanged`` — present in both, body and status match.
    """
    a_index = _load_run(Path(run_dir_a))
    b_index = _load_run(Path(run_dir_b))

    a_keys = set(a_index)
    b_keys = set(b_index)

    added = [b_index[k] for k in sorted(b_keys - a_keys)]
    removed = [a_index[k] for k in sorted(a_keys - b_keys)]

    changed: List[Dict[str, Any]] = []
    unchanged: List[Dict[str, Any]] = []
    for k in sorted(a_keys & b_keys):
        before = a_index[k]
        after = b_index[k]
        if _has_changed(before, after):
            changed.append({"before": before, "after": after})
        else:
            unchanged.append(after)

    return {
        "run_a": str(run_dir_a),
        "run_b": str(run_dir_b),
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchanged": unchanged,
    }


def format_diff(result: Dict[str, Any]) -> str:
    """Render a diff result as text suitable for stdout."""
    lines: List[str] = []
    a, b = result["run_a"], result["run_b"]
    lines.append(f"Annotations diff: {a} → {b}")
    lines.append("")
    counts = (
        f"added={len(result['added'])} "
        f"removed={len(result['removed'])} "
        f"changed={len(result['changed'])} "
        f"unchanged={len(result['unchanged'])}"
    )
    lines.append(counts)
    if result["added"]:
        lines.append("")
        lines.append("Added:")
        for r in result["added"]:
            status = r["metadata"].get("status", "—")
            source = r["metadata"].get("source", "—")
            lines.append(
                f"  + {r['file']}::{r['function']}  "
                f"status={status}  source={source}"
            )
    if result["removed"]:
        lines.append("")
        lines.append("Removed:")
        for r in result["removed"]:
            status = r["metadata"].get("status", "—")
            lines.append(f"  - {r['file']}::{r['function']}  status={status}")
    if result["changed"]:
        lines.append("")
        lines.append("Changed:")
        for ch in result["changed"]:
            before, after = ch["before"], ch["after"]
            old_status = before["metadata"].get("status", "—")
            new_status = after["metadata"].get("status", "—")
            if old_status != new_status:
                lines.append(
                    f"  ~ {after['file']}::{after['function']}  "
                    f"status: {old_status} → {new_status}"
                )
            else:
                lines.append(
                    f"  ~ {after['file']}::{after['function']}  "
                    f"(body changed; status={new_status})"
                )
    return "\n".join(lines) + "\n"
