"""Findings emission in standard RAPTOR format.

Findings from /audit are emitted in the same JSON format as /scan
and /agentic, so they flow unchanged into /validate.
"""

from __future__ import annotations

import contextlib
import logging
from typing import Any, TYPE_CHECKING
from pathlib import Path

from core.json import load_json, save_json

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

# findings.json is RAPTOR-written run output — the findings-class
# budget used across the audit/validate bridges.
_MAX_FINDINGS_BYTES = 64 * 1024 * 1024


@contextlib.contextmanager
def _findings_lock(out_dir: Path):
    """Advisory cross-process lock for the findings.json
    read-modify-write.

    Parallel emitters (``raptor-audit record`` sub-agents sharing one
    out_dir) both read N findings and both wrote N+1 — one finding was
    lost and the len-derived ids collided. ``save_json``'s atomic
    rename prevents torn files but not lost updates. Best-effort:
    platforms without ``fcntl`` proceed unlocked (the previous
    behaviour), never fail the emit.
    """
    lock_path = out_dir / "findings.json.lock"
    fh = None
    try:
        import fcntl
        fh = open(lock_path, "a+")  # noqa: SIM115 — held across yield
        fcntl.flock(fh.fileno(), fcntl.LOCK_EX)
    except Exception:
        logger.debug("findings lock unavailable", exc_info=True)
        if fh is not None:
            with contextlib.suppress(OSError):
                fh.close()
            fh = None
    try:
        yield
    finally:
        if fh is not None:
            with contextlib.suppress(OSError):
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                fh.close()


def _next_finding_id(existing: list[dict[str, Any]]) -> str:
    """AUDIT-NNN above every existing numeric suffix — ``len()+1``
    collided after any external deletion."""
    top = 0
    for f in existing:
        fid = str(f.get("id", "") or "")
        head, _, tail = fid.rpartition("-")
        if head == "AUDIT" and tail.isdigit():
            top = max(top, int(tail))
    return f"AUDIT-{top + 1:03d}"


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
    # One locked read-modify-write: id derivation and the append must
    # see the same snapshot, or two parallel emitters mint the same id
    # and one finding is lost.
    with _findings_lock(out_dir):
        existing = load_findings(out_dir)
        finding = {
            "id": _next_finding_id(existing),
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

        existing.append(finding)
        write_findings(existing, out_dir)
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
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        found = data.get("findings", [])
        return found if isinstance(found, list) else []
    # Valid-JSON scalar (int/str/bool): wrong shape degrades to []
    # like corrupt content — the docstring's contract.
    logger.warning("wrong-shaped findings.json at %s", path)
    return []


def write_findings(findings: list[dict[str, Any]], out_dir: Path) -> Path:
    """Write findings.json to the output directory."""
    path = out_dir / "findings.json"
    save_json(path, findings)
    return path
