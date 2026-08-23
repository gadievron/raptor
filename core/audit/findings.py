"""Findings emission in standard RAPTOR format.

Findings from /audit are emitted in the same JSON format as /scan
and /agentic, so they flow unchanged into /validate.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from typing import Any, TYPE_CHECKING
from pathlib import Path

from core.json import load_json

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# findings.json is RAPTOR-written run output — the findings-class
# budget used across the audit/validate bridges.
_MAX_FINDINGS_BYTES = 64 * 1024 * 1024


def emit_finding(
    *,
    out_dir: Path,
    file_path: str,
    function_name: str,
    line: int,
    title: str,
    description: str,
    cwe: str | None = None,
    severity: str = "medium",
    tool_evidence: list[dict[str, Any]] | None = None,
    hypothesis: str | None = None,
) -> dict[str, Any]:
    """Emit a finding and append to findings.json.

    Args:
        out_dir: Run output directory.
        file_path: Relative path to the source file.
        function_name: Name of the function where the finding is.
        line: Line number of the vulnerable code.
        title: Short title for the finding.
        description: Detailed description with evidence.
        cwe: CWE identifier (e.g. "CWE-78").
        severity: low/medium/high/critical.
        tool_evidence: List of dicts with tool name, rule, output.
        hypothesis: The hypothesis that was confirmed.

    Returns:
        The finding dict.
    """
    existing = load_findings(out_dir)
    next_id = len(existing) + 1
    finding = {
        "id": f"AUDIT-{next_id:03d}",
        "file": file_path,
        "function": function_name,
        "line": line,
        "title": title,
        "description": description,
        "severity": severity,
        "origin": "audit",
    }
    if cwe:
        finding["cwe"] = cwe
        finding["vuln_type"] = cwe
    else:
        finding["vuln_type"] = "novel"

    if tool_evidence:
        finding["tool_evidence"] = tool_evidence
    if hypothesis:
        finding["hypothesis"] = hypothesis

    _append_finding(out_dir, finding)
    return finding


def load_findings(out_dir: Path) -> list[dict[str, Any]]:
    """Load findings.json from the output directory.

    Corrupt/oversize content degrades to ``[]`` with a warning;
    an UNREADABLE file (EACCES, EIO) still raises ``OSError`` —
    findings.json is where "no findings" and "could not read the
    findings" must stay distinguishable.
    """
    path = out_dir / "findings.json"
    try:
        data = load_json(path, strict=True, max_bytes=_MAX_FINDINGS_BYTES)
    except ValueError:
        logger.warning("corrupt findings.json at %s", path)
        return []
    if data is None:
        return []
    return data if isinstance(data, list) else data.get("findings", [])


def write_findings(findings: list[dict[str, Any]], out_dir: Path) -> Path:
    """Write findings.json to the output directory."""
    path = out_dir / "findings.json"
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(findings, f, indent=2)
        os.replace(tmp, str(path))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def _append_findings_batch(
    out_dir: Path, new_findings: list[dict[str, Any]],
) -> None:
    """Append multiple findings to findings.json in one read-modify-write.

    Avoids O(N^2) I/O when appending N findings one at a time.
    """
    if not new_findings:
        return
    findings = load_findings(out_dir)
    findings.extend(new_findings)
    write_findings(findings, out_dir)


def _append_finding(out_dir: Path, finding: dict[str, Any]) -> None:
    """Append a finding to findings.json."""
    _append_findings_batch(out_dir, [finding])
