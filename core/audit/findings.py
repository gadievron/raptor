"""Findings emission in standard RAPTOR format.

Findings from /audit are emitted in the same JSON format as /scan
and /agentic, so they flow unchanged into /validate.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def emit_finding(
    *,
    out_dir: Path,
    file_path: str,
    function_name: str,
    line: int,
    title: str,
    description: str,
    cwe: Optional[str] = None,
    severity: str = "medium",
    tool_evidence: Optional[List[Dict[str, Any]]] = None,
    hypothesis: Optional[str] = None,
) -> Dict[str, Any]:
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


def load_findings(out_dir: Path) -> List[Dict[str, Any]]:
    """Load findings.json from the output directory."""
    path = out_dir / "findings.json"
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        logger.warning("corrupt findings.json at %s", path)
        return []
    return data if isinstance(data, list) else data.get("findings", [])


def write_findings(findings: List[Dict[str, Any]], out_dir: Path) -> Path:
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
    out_dir: Path, new_findings: List[Dict[str, Any]],
) -> None:
    """Append multiple findings to findings.json in one read-modify-write.

    Avoids O(N^2) I/O when appending N findings one at a time.
    """
    if not new_findings:
        return
    findings = load_findings(out_dir)
    findings.extend(new_findings)
    write_findings(findings, out_dir)


def _append_finding(out_dir: Path, finding: Dict[str, Any]) -> None:
    """Append a finding to findings.json."""
    _append_findings_batch(out_dir, [finding])
