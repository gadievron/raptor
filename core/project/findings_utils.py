"""Shared findings utilities for diff and merge.

Centralises finding ID extraction, loading, and semantic grouping
to avoid duplication across diff.py, merge.py, and coverage.
"""

from collections import defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Tuple

from core.json import load_json
from core.logging import get_logger

logger = get_logger()


def get_finding_id(finding: Dict[str, Any]) -> Optional[str]:
    """Extract finding ID, checking both 'id' and 'finding_id' fields."""
    return finding.get("id") or finding.get("finding_id")


def safe_run_mtime(path: Path) -> float:
    """``st_mtime`` of a run dir, or 0.0 when it has vanished.

    Run dirs can disappear between enumeration and the stat — an
    operator runs ``/project clean``, a parallel pruner unlinks an old
    run, the dir sat on a flaky network mount. Pre-fix callers ran a
    bare ``d.stat()`` inside a sort key and the whole correlate/report
    pass crashed with FileNotFoundError. Treat unstattable dirs as
    mtime 0 (they sort oldest) and log so the operator sees the
    disappearance.
    """
    try:
        return path.stat().st_mtime
    except OSError as exc:
        logger.warning(
            "project: run dir %s vanished during scan (%s) — treating as oldest",
            path.name, exc,
        )
        return 0.0


def finding_file(finding: Dict[str, Any]) -> str:
    """File path for a finding, tolerant of both serialised shapes.

    Scan-shaped findings carry ``file``; orchestrated /agentic results
    carry ``file_path`` (see ``core/run/orchestrated_report_schema.py``).
    Pre-fix ``dedup_key`` read only ``file``, so every agentic finding
    keyed as ``("", fn, line)`` — cross-run-type disagreement detection
    never fired, tool-gap analysis skipped agentic findings entirely,
    and same-named functions in different files collided.

    The path is lightly normalised (``./``-prefixes and redundant
    separators collapsed) so the same relative location keys
    identically regardless of which producer wrote it.
    """
    fp = finding.get("file") or finding.get("file_path") or ""
    if not isinstance(fp, str) or not fp:
        return ""
    return str(PurePosixPath(fp))


def dedup_key(finding: Dict[str, Any]) -> Tuple[str, str, int]:
    """Dedup key for a finding: (file, function, line). More stable than ID.

    Uses :func:`finding_file` so scan-shaped (``file``) and orchestrated
    (``file_path``) findings at the same location share a key.
    """
    return (finding_file(finding), finding.get("function", ""), finding.get("line") or 0)


def group_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    """Semantic group key: (file, function, vuln_type).

    Findings with the same group key are likely the same logical bug
    (e.g. TOCTOU check at line 7 and use at line 10).
    """
    return (
        finding.get("file", ""),
        finding.get("function", ""),
        finding.get("vuln_type", ""),
    )


def group_findings(findings: List[Dict[str, Any]]) -> Dict[Tuple, List[Dict[str, Any]]]:
    """Group findings by (file, function, vuln_type).

    Returns:
        Dict mapping group_key -> list of findings in that group.
        Single-finding groups represent unique vulns.
        Multi-finding groups represent one logical vuln with multiple locations.
    """
    groups: Dict[Tuple, List[Dict[str, Any]]] = defaultdict(list)
    for f in findings:
        groups[group_key(f)].append(f)
    return dict(groups)


def count_vulns(findings: List[Dict[str, Any]]) -> int:
    """Count logical vulns (semantic groups) rather than raw findings."""
    return len(group_findings(findings))


def load_findings_from_dir(run_dir: Path) -> List[Dict[str, Any]]:
    """Load findings list from a run directory's findings.json."""
    data = load_json(run_dir / "findings.json")
    if data is None:
        logger.debug("No findings.json in %s", run_dir)
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings") or data.get("results") or []
    return []


def load_sca_findings_from_dir(run_dir: Path) -> List[Dict[str, Any]]:
    """Load SCA findings from a run's ``sca/findings.json`` subdir.

    ``/sca`` and ``/agentic`` write dependency findings to
    ``<run_dir>/sca/findings.json`` (a bare list of rows) rather than the
    top-level ``findings.json`` that :func:`load_findings_from_dir` reads,
    so the unified project view never saw them. The rows are already
    normalised to the common finding shape (``id`` / ``file`` = manifest
    path / ``function`` = package name / ``line`` / ``severity`` /
    ``vuln_type`` = ``sca:<class>:<kind>``), so they group, dedup, and
    render through the same machinery — they're only *discovered*
    separately. Kept distinct from :func:`load_findings_from_dir` so
    correlate / merge_runs / run-summary keep their code-finding scope;
    the findings view opts in explicitly.
    """
    data = load_json(run_dir / "sca" / "findings.json")
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("findings") or data.get("results") or []
    return []


def merge_sca_findings(run_dirs: List[Path]) -> List[Dict[str, Any]]:
    """Collect + dedup SCA findings across runs.

    Dedup by stable finding id, falling back to ``dedup_key``
    (file, function, line). ``run_dirs`` is ordered (later overrides
    earlier), so the latest run's copy of a recurring finding wins —
    matching :func:`core.project.merge.merge_findings` semantics for
    code findings.
    """
    merged: Dict[Any, Dict[str, Any]] = {}
    for run_dir in run_dirs:
        for finding in load_sca_findings_from_dir(Path(run_dir)):
            # SCA rows always carry a stable finding_id, so the fallback
            # is for malformed/legacy rows only. Use group_key (includes
            # vuln_type), NOT dedup_key (file, function, line) — every SCA
            # row has line=0 and file=manifest, so dedup_key would collide
            # distinct findings on the same package (a slopsquat AND a CVE
            # on `lodash` share ("package.json","lodash",0)). group_key
            # keeps them distinct via the sca:<class>:<kind> vuln_type.
            key = get_finding_id(finding) or group_key(finding)
            merged[key] = finding
    return list(merged.values())
