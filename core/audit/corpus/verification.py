"""Reporting-only joins from normal audit exports to corpus result rows.

Artifact snapshots are bounded and scoped to one repository group. Their
integrity is not revalidated and they never influence verdicts, mechanism
attribution, metric denominators, or gates. Missing data remains unavailable.
"""

from __future__ import annotations

from collections import defaultdict
import logging
from pathlib import Path

from core.json import loads
from core.source import open_regular_beneath

from ..check_trace import _summarize_observations
from .definitions import source_function_id

_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024
logger = logging.getLogger(__name__)


def unavailable_verification(reason="not_recorded", audit_dir=None) -> dict:
    return {"status": "unavailable", "reason": reason,
            "audit_dir": str(audit_dir) if audit_dir is not None else None,
            "integrity_revalidated": False}


def _read_snapshot(root: Path, name: str):
    try:
        stream = open_regular_beneath(root, name, "rb")
        if stream is None:
            return None, "artifact_unavailable"
        with stream:
            raw = stream.read(_MAX_ARTIFACT_BYTES + 1)
        if len(raw) > _MAX_ARTIFACT_BYTES:
            return None, "artifact_size_limit"
        return loads(raw), ""
    except Exception:
        logger.debug("verification artifact snapshot unreadable: %s", name, exc_info=True)
        return None, "artifact_unreadable"


def _name_matches(label_name, finding, scope):
    qualified = scope.get("function_qualified")
    if "." in label_name and qualified:
        return label_name == qualified
    # Older exports can lack qualified names. A bare-name match still
    # requires the exact pinned file/line and an unambiguous candidate.
    return label_name.rsplit(".", 1)[-1] == finding.get("function")


def annotate_verification(rows: list[dict], labels: list, audit_dir: Path | None) -> None:
    """Attach compact snapshots before checkpointing; never change scoring.

    Each artifact is read at most once per group. Group-wide totals are
    deliberately not credited to individual labels. Checks must be linked
    by the finding's own references and match its source location and claim.
    """
    if audit_dir is None:
        for row in rows:
            row["verification"] = unavailable_verification()
        return
    root = Path(audit_dir).absolute()
    graded, graded_error = _read_snapshot(root, "findings-graded.json")
    if not isinstance(graded, dict) or not isinstance(graded.get("findings"), list):
        for row in rows:
            row["verification"] = unavailable_verification(graded_error or "graded_schema_invalid", root)
        return
    sidecar, check_error = _read_snapshot(root, "verification-checks.json")
    by_id = defaultdict(list)
    if isinstance(sidecar, dict) and sidecar.get("schema_version") == 1 and isinstance(sidecar.get("checks"), list):
        for check in sidecar["checks"]:
            if isinstance(check, dict) and isinstance(check.get("id"), str):
                by_id[check["id"]].append(check)
    else:
        check_error = check_error or "check_schema_invalid"
    by_location = defaultdict(list)
    for finding in graded["findings"]:
        if not isinstance(finding, dict):
            continue
        file, line = finding.get("file"), finding.get("line")
        if isinstance(file, str) and type(line) is int and line > 0:
            by_location[file, line].append(finding)
    labels_by_id = {label.function_id: label for label in labels}
    label_names = defaultdict(set)
    for label in labels:
        label_names[label.source.file, getattr(label.source, "line_start", None)].add(
            source_function_id(label.function_id).partition(":")[2],
        )
    for row in rows:
        label = labels_by_id.get(row.get("function_id"))
        row["verification"] = unavailable_verification("finding_not_exported", root)
        if label is None:
            continue
        line = getattr(label.source, "line_start", None)
        if type(line) is not int or line <= 0:
            row["verification"] = unavailable_verification("label_scope_unavailable", root)
            continue
        name = source_function_id(label.function_id).partition(":")[2]
        candidates = []
        for finding in by_location.get((label.source.file, line), []):
            trace = finding.get("verification_trace")
            scope = trace.get("scope") if isinstance(trace, dict) else None
            if not isinstance(scope, dict):
                continue
            if not scope.get("function_qualified") and len(label_names[label.source.file, line]) > 1:
                row["verification"] = unavailable_verification("ambiguous_label_scope", root)
                continue
            if type(scope.get("line")) is not int or (scope.get("file"), scope.get("function"), scope.get("line")) != (
                finding.get("file"), finding.get("function"), finding.get("line"),
            ):
                continue
            if _name_matches(name, finding, scope):
                candidates.append(finding)
        if len(candidates) != 1:
            if candidates:
                row["verification"] = unavailable_verification("ambiguous_finding", root)
            continue
        finding = candidates[0]
        if (finding.get("status"), finding.get("hypothesis")) != (row.get("actual"), row.get("hypothesis")):
            row["verification"] = unavailable_verification("verdict_or_claim_mismatch", root)
            continue
        trace = finding["verification_trace"]
        links = trace.get("check_results")
        if not isinstance(links, dict):
            row["verification"] = unavailable_verification("trace_unavailable", root)
            continue
        status = links.get("status")
        if status != "recorded":
            row["verification"] = {**unavailable_verification("trace_unavailable", root),
                                   "trace_status": status if isinstance(status, str) else "unavailable"}
            continue
        if check_error or links.get("artifact") != "verification-checks.json":
            row["verification"] = unavailable_verification(check_error or "unexpected_check_artifact", root)
            continue
        refs = links.get("references")
        matching: list[dict] = []
        other: list[dict] = []
        safe_refs = []
        seen = set()
        valid = isinstance(refs, list) and bool(refs)
        for ref in refs if isinstance(refs, list) else []:
            check_id = ref.get("id") if isinstance(ref, dict) else None
            if not isinstance(check_id, str) or check_id in seen or len(by_id.get(check_id, [])) != 1:
                valid = False
                break
            seen.add(check_id)
            check = by_id[check_id][0]
            scope = check.get("scope")
            if not isinstance(scope, dict) or type(scope.get("line_start")) is not int or (scope.get("file"), scope.get("function"), scope.get("line_start")) != (
                finding["file"], finding["function"], finding["line"],
            ):
                valid = False
                break
            matches = scope.get("hypothesis") == finding["hypothesis"]
            if ref.get("matches_final_claim") is not matches:
                valid = False
                break
            safe_refs.append({"id": check_id, "matches_final_claim": matches})
            (matching if matches else other).append(check)
        if not valid:
            row["verification"] = unavailable_verification("check_reference_mismatch", root)
            continue
        row["verification"] = {
            "status": "recorded", "audit_dir": str(root),
            "finding_id": finding.get("id") if isinstance(finding.get("id"), str) else None,
            "integrity_revalidated": False, "history_complete": False,
            "references": safe_refs,
            "observations": {"matching_final_claim": _summarize_observations(matching),
                             "other_claims": _summarize_observations(other)},
        }
