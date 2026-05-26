"""Cross-tool ``related_findings`` linking.

Scans sibling SARIF files (from Semgrep, CodeQL, etc.) for CVE/GHSA
references that match SCA vulnerability findings, and writes the
matched IDs into each finding's ``related_findings`` list.

The link is additive — existing ``related_findings`` (intra-SCA
sibling links) are preserved.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)
_GHSA_RE = re.compile(r"(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", re.IGNORECASE)


def link_related_findings(
    sca_findings_path: Path,
    sarif_dirs: List[Path],
) -> int:
    """Link SCA findings to sibling SARIF results by CVE/GHSA reference.

    Reads ``sca_findings_path``, scans every ``.sarif`` file under each
    directory in ``sarif_dirs``, and writes the updated findings back.

    Returns the number of new cross-tool links added.
    """
    findings = _load_findings(sca_findings_path)
    if not findings:
        return 0

    cve_to_finding_ids = _build_cve_index(findings)
    if not cve_to_finding_ids:
        return 0

    sarif_refs = _collect_sarif_refs(sarif_dirs)

    added = 0
    for cve_id, sarif_finding_ids in sarif_refs.items():
        sca_ids = cve_to_finding_ids.get(cve_id, [])
        for f in findings:
            if f.get("finding_id") not in sca_ids:
                continue
            existing = set(f.get("related_findings", []))
            for ref in sarif_finding_ids:
                if ref not in existing:
                    f.setdefault("related_findings", []).append(ref)
                    existing.add(ref)
                    added += 1

    if added > 0:
        _write_findings(sca_findings_path, findings)
        logger.info(
            "sca.cross_tool: added %d cross-tool link(s) across %d finding(s)",
            added, len({f["finding_id"] for f in findings
                        if any(r.startswith("sarif:") for r in f.get("related_findings", []))}),
        )

    return added


def _load_findings(path: Path) -> List[Dict[str, Any]]:
    try:
        with open(path) as fh:
            data = json.load(fh)
        return data if isinstance(data, list) else []
    except (OSError, json.JSONDecodeError) as exc:
        logger.debug("sca.cross_tool: cannot read %s: %s", path, exc)
        return []


def _write_findings(path: Path, findings: List[Dict[str, Any]]) -> None:
    with open(path, "w") as fh:
        json.dump(findings, fh, indent=2, default=str)


def _build_cve_index(
    findings: List[Dict[str, Any]],
) -> Dict[str, List[str]]:
    """Map CVE/GHSA ID → list of SCA finding IDs that reference it."""
    out: Dict[str, List[str]] = {}
    for f in findings:
        fid = f.get("finding_id", "")
        if not fid:
            continue
        cves = _extract_cves_from_finding(f)
        for cve in cves:
            out.setdefault(cve.upper(), []).append(fid)
    return out


def _extract_cves_from_finding(f: Dict[str, Any]) -> Set[str]:
    """Extract CVE/GHSA IDs from an SCA finding dict."""
    ids: Set[str] = set()
    for adv in f.get("advisories", []):
        osv_id = adv.get("osv_id", "")
        if osv_id:
            ids.add(osv_id.upper())
        for alias in adv.get("aliases", []):
            ids.add(alias.upper())
    return ids


def _collect_sarif_refs(
    sarif_dirs: List[Path],
) -> Dict[str, List[str]]:
    """Scan SARIF files for CVE/GHSA references in results.

    Returns ``{CVE_ID: [sarif_ref_id, ...]}``.
    """
    out: Dict[str, List[str]] = {}
    for d in sarif_dirs:
        if not d.is_dir():
            continue
        for sarif_file in d.glob("*.sarif"):
            _scan_sarif_file(sarif_file, out)
        for sarif_file in d.glob("**/*.sarif"):
            if sarif_file.parent != d:
                _scan_sarif_file(sarif_file, out)
    return out


def _scan_sarif_file(
    path: Path,
    out: Dict[str, List[str]],
) -> None:
    try:
        with open(path) as fh:
            sarif = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return

    for run in sarif.get("runs", []):
        tool_name = (run.get("tool", {}).get("driver", {})
                     .get("name", "unknown"))
        for result in run.get("results", []):
            result_id = _sarif_result_id(result, tool_name, path.stem)
            cves = _extract_cves_from_sarif_result(result, run)
            for cve in cves:
                out.setdefault(cve.upper(), []).append(result_id)


def _sarif_result_id(
    result: Dict[str, Any],
    tool_name: str,
    file_stem: str,
) -> str:
    """Build a stable reference ID for a SARIF result."""
    rule_id = result.get("ruleId", "unknown")
    fingerprint = ""
    fps = result.get("fingerprints", {})
    if fps:
        fingerprint = next(iter(fps.values()), "")
    if fingerprint:
        return f"sarif:{tool_name}:{rule_id}:{fingerprint[:16]}"
    locs = result.get("locations", [])
    if locs:
        phys = locs[0].get("physicalLocation", {})
        uri = phys.get("artifactLocation", {}).get("uri", "")
        line = phys.get("region", {}).get("startLine", 0)
        return f"sarif:{tool_name}:{rule_id}:{uri}:{line}"
    return f"sarif:{tool_name}:{rule_id}:{file_stem}"


def _extract_cves_from_sarif_result(
    result: Dict[str, Any],
    run: Dict[str, Any],
) -> Set[str]:
    """Extract CVE/GHSA IDs from a SARIF result's message, tags, and properties."""
    ids: Set[str] = set()

    msg = result.get("message", {}).get("text", "")
    ids.update(m.group(1).upper() for m in _CVE_RE.finditer(msg))
    ids.update(m.group(1).upper() for m in _GHSA_RE.finditer(msg))

    props = result.get("properties", {})
    for tag in props.get("tags", []):
        ids.update(m.group(1).upper() for m in _CVE_RE.finditer(tag))
        ids.update(m.group(1).upper() for m in _GHSA_RE.finditer(tag))

    for key in ("cve", "cves", "aliases"):
        val = props.get(key)
        if isinstance(val, str):
            ids.update(m.group(1).upper() for m in _CVE_RE.finditer(val))
        elif isinstance(val, list):
            for v in val:
                if isinstance(v, str):
                    ids.update(m.group(1).upper() for m in _CVE_RE.finditer(v))
                    ids.update(m.group(1).upper() for m in _GHSA_RE.finditer(v))

    rule_id = result.get("ruleId", "")
    rules_by_id = {}
    for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
        rules_by_id[rule.get("id", "")] = rule
    rule = rules_by_id.get(rule_id, {})
    help_uri = rule.get("helpUri", "")
    ids.update(m.group(1).upper() for m in _CVE_RE.finditer(help_uri))
    for tag in rule.get("properties", {}).get("tags", []):
        ids.update(m.group(1).upper() for m in _CVE_RE.finditer(tag))

    return ids
