"""Annotation writing + coverage-audit record emission.

Wraps ``core.annotations.storage`` for the audit workflow:
- Writes annotation markdown per reviewed function
- Computes and embeds source hash for staleness detection
- Updates ``coverage-audit.json`` via ``core.coverage.record``
"""

from __future__ import annotations

import json
import logging
import os
import re
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

VALID_STATUSES = frozenset({"clean", "suspicious", "finding", "error", "dormant"})


def _resolve_annotations_dir(out_dir: Path) -> Path:
    """Resolve annotations directory to project level when possible.

    Project runs have out_dir = project_dir/<run_name>/, so
    out_dir.parent is the project directory. Annotations at the project
    level survive /project clean (which deletes run dirs).

    Detection: a run dir contains .raptor-run.json (written by
    raptor-run-lifecycle start). If present, the parent is the
    project directory.
    """
    run_marker = out_dir / ".raptor-run.json"
    if run_marker.exists():
        project_dir = out_dir.parent
        if project_dir and project_dir != out_dir:
            return project_dir / "annotations"
    return out_dir / "annotations"


def record_review(
    *,
    out_dir: Path,
    target_path: Path,
    file_path: str,
    function_name: str,
    status: str,
    body: str,
    line_start: int = 0,
    line_end: Optional[int] = None,
    cwe: Optional[str] = None,
    strategies: Optional[List[str]] = None,
    checked_by: Optional[List[str]] = None,
    annotations_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Record a single function review.

    Writes the annotation markdown and updates the coverage-audit
    tracking data. Returns the record dict.

    Args:
        out_dir: Run output directory.
        target_path: Root of the target codebase.
        file_path: Relative path to the source file.
        function_name: Name of the reviewed function.
        status: One of clean/suspicious/finding/error.
        body: Annotation prose (hypotheses tested, tool evidence).
        line_start: Function start line.
        line_end: Function end line.
        cwe: CWE identifier if applicable.
        strategies: Strategies applied during review.
    """
    if status not in VALID_STATUSES:
        raise ValueError(
            f"Invalid status {status!r}; must be one of {sorted(VALID_STATUSES)}"
        )

    source_hash = _compute_hash(target_path, file_path, line_start, line_end)

    metadata = {"status": status, "source": "llm"}
    if source_hash:
        metadata["hash"] = source_hash
    if cwe:
        metadata["cwe"] = cwe
    if line_start:
        metadata["line_start"] = str(line_start)
    if line_end:
        metadata["line_end"] = str(line_end)

    resolved_ann_dir = annotations_dir or _resolve_annotations_dir(out_dir)
    _write_annotation(
        annotations_dir=resolved_ann_dir,
        file_path=file_path,
        function_name=function_name,
        body=body,
        metadata=metadata,
    )

    record = {
        "file": file_path,
        "function": function_name,
        "status": status,
        "hash": source_hash,
        "strategies": strategies or [],
    }
    if cwe:
        record["cwe"] = cwe
    if checked_by:
        record["checked_by"] = checked_by

    _update_coverage_audit(out_dir, file_path, function_name, record)

    return record


def load_audit_log(out_dir: Path) -> List[Dict[str, Any]]:
    """Load the audit log (one JSON record per line)."""
    log_path = out_dir / ".audit-log.jsonl"
    if not log_path.exists():
        return []
    records = []
    with open(log_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def append_audit_log(out_dir: Path, entry: Dict[str, Any]) -> None:
    """Append an entry to the audit log."""
    log_path = out_dir / ".audit-log.jsonl"
    with open(log_path, "a") as f:
        f.write(json.dumps(entry, separators=(",", ":")) + "\n")


def _compute_hash(
    target_path: Path,
    file_path: str,
    line_start: int,
    line_end: Optional[int],
) -> Optional[str]:
    """Compute source hash for staleness detection."""
    full_path = target_path / file_path
    if not full_path.exists():
        return None

    try:
        from core.annotations.storage import compute_function_hash
        end = line_end if line_end is not None else line_start
        return compute_function_hash(full_path, line_start, end)
    except Exception:
        logger.debug("hash computation failed for %s:%d", file_path, line_start)
        return None


def _write_annotation(
    *,
    annotations_dir: Path,
    file_path: str,
    function_name: str,
    body: str,
    metadata: Dict[str, str],
) -> None:
    """Write an annotation via the annotations storage layer."""
    annotations_dir.mkdir(parents=True, exist_ok=True)

    try:
        from core.annotations.models import Annotation
        from core.annotations.storage import write_annotation

        ann = Annotation(
            file=file_path,
            function=function_name,
            body=body,
            metadata=metadata,
        )
        write_annotation(annotations_dir, ann, overwrite="respect-manual")
    except Exception:
        logger.warning(
            "Failed to write annotation for %s:%s via storage layer, "
            "falling back to direct write",
            file_path, function_name,
        )
        _write_annotation_direct(annotations_dir, file_path, function_name, body, metadata)


def _write_annotation_direct(
    annotations_dir: Path,
    file_path: str,
    function_name: str,
    body: str,
    metadata: Dict[str, str],
) -> None:
    """Direct-write fallback when the storage layer isn't available."""
    if ".." in file_path.split("/"):
        raise ValueError(f"path traversal rejected: {file_path!r}")
    if "\n" in function_name or "<!--" in function_name:
        raise ValueError(f"unsafe function name rejected: {function_name!r}")
    ann_path = annotations_dir / f"{file_path}.md"
    resolved = ann_path.resolve()
    ann_root = annotations_dir.resolve()
    if not (resolved == ann_root or str(resolved).startswith(str(ann_root) + os.sep)):
        raise ValueError(f"path traversal rejected: {file_path!r}")
    ann_path.parent.mkdir(parents=True, exist_ok=True)

    meta_parts = " ".join(f"{k}={v}" for k, v in sorted(metadata.items()))
    section = f"\n## {function_name}\n<!-- meta: {meta_parts} -->\n\n{body}\n"

    if ann_path.exists():
        existing = ann_path.read_text()
        heading_pat = r'^## ' + re.escape(function_name) + r'$'
        if not re.search(heading_pat, existing, re.MULTILINE):
            with open(ann_path, "a") as f:
                f.write(section)
        else:
            match = re.search(heading_pat, existing, re.MULTILINE)
            if match:
                after_heading = existing[match.end():]
                if re.match(r'\s*<!-- meta:.*?source=human', after_heading):
                    logger.debug(
                        "Preserving human annotation for %s:%s",
                        file_path, function_name,
                    )
                    return
            logger.debug("Annotation already exists for %s:%s", file_path, function_name)
    else:
        with open(ann_path, "w") as f:
            f.write(f"# {file_path}\n{section}")


def _update_coverage_audit(
    out_dir: Path,
    file_path: str,
    function_name: str,
    record: Dict[str, Any],
) -> None:
    """Update coverage-audit.json with the new record."""
    audit_path = out_dir / "coverage-audit.json"

    if audit_path.exists():
        try:
            with open(audit_path) as f:
                audit_data = json.load(f)
        except json.JSONDecodeError:
            logger.warning("corrupt coverage-audit.json, reinitialising")
            audit_data = None
        if not isinstance(audit_data, dict):
            audit_data = None
    else:
        audit_data = None
    if audit_data is None:
        audit_data = {
            "tool": "audit",
            "files_examined": [],
            "functions_analysed": [],
        }

    functions = audit_data.setdefault("functions_analysed", [])
    existing = None
    for entry in functions:
        if entry.get("file") == file_path and entry.get("function") == function_name:
            existing = entry
            break
    func_record = {
        "file": file_path,
        "function": function_name,
        "status": record["status"],
        "hash": record.get("hash"),
    }
    if record.get("checked_by"):
        func_record["checked_by"] = record["checked_by"]
    if existing is not None:
        existing.update(func_record)
    else:
        functions.append(func_record)

    if file_path not in audit_data.get("files_examined", []):
        audit_data.setdefault("files_examined", []).append(file_path)

    fd, tmp = tempfile.mkstemp(dir=str(audit_path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(audit_data, f, indent=2)
        os.replace(tmp, str(audit_path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
