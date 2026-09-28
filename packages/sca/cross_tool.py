"""Cross-tool ``related_findings`` linking.

Scans sibling SARIF files (from Semgrep, CodeQL, etc.) for CVE/GHSA
references that match SCA vulnerability findings, and writes the
matched IDs into each finding's ``related_findings`` list.

The link is additive — existing ``related_findings`` (intra-SCA
sibling links) are preserved.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from core.json import load_json
from core.sarif.parser import load_sarif

from .kinds import MAX_SELF_FINDINGS_BYTES

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)
_GHSA_RE = re.compile(r"(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})", re.IGNORECASE)


def link_related_findings(
    sca_findings_path: Path,
    sarif_dirs: list[Path],
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
            added, len({f.get("finding_id", "") for f in findings
                        if any(r.startswith("sarif:") for r in f.get("related_findings", []))}),
        )

    return added


def _load_findings(path: Path) -> list[dict[str, Any]]:
    # Self-produced budget, NOT the steered-path one: the only
    # production caller (api.analyse) passes RunResult.findings_path
    # from the in-process run_sca that just wrote the file, so its
    # size is the pipeline's own legitimate output (rationale on both
    # budgets in kinds.py). At the 64 MiB steered budget, big-target
    # runs silently dropped every cross-tool link (oversize -> None
    # -> "no findings"). Missing / corrupt / oversize come back as
    # None and fall into the isinstance guard.
    data = load_json(Path(path), max_bytes=MAX_SELF_FINDINGS_BYTES)
    return data if isinstance(data, list) else []


def _write_findings(path: Path, findings: list[dict[str, Any]]) -> None:
    from core.json import save_json
    save_json(path, findings)


def _build_cve_index(
    findings: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """Map CVE/GHSA ID → list of SCA finding IDs that reference it."""
    out: dict[str, list[str]] = {}
    for f in findings:
        fid = f.get("finding_id", "")
        if not fid:
            continue
        cves = _extract_cves_from_finding(f)
        for cve in cves:
            out.setdefault(cve.upper(), []).append(fid)
    return out


def _extract_cves_from_finding(f: dict[str, Any]) -> set[str]:
    """Extract CVE/GHSA IDs from an SCA finding dict.

    Real findings nest advisory data under ``sca.advisory`` (primary)
    and ``sca.all_advisories`` (full list), each keyed by ``"id"``.
    """
    ids: set[str] = set()
    sca = f.get("sca") or {}
    # Primary advisory.
    primary = sca.get("advisory") or {}
    # isinstance guards: findings.json can be hand-edited; a non-str
    # id/alias must not crash the whole cross-tool pass.
    adv_id = primary.get("id", "")
    if isinstance(adv_id, str) and adv_id:
        ids.add(adv_id.upper())
    for alias in primary.get("aliases", []):
        if isinstance(alias, str):
            ids.add(alias.upper())
    # All advisories (includes primary + siblings).
    for adv in sca.get("all_advisories", []):
        aid = adv.get("id", "")
        if isinstance(aid, str) and aid:
            ids.add(aid.upper())
        for alias in adv.get("aliases", []):
            if isinstance(alias, str):
                ids.add(alias.upper())
    return ids


def _collect_sarif_refs(
    sarif_dirs: list[Path],
) -> dict[str, list[str]]:
    """Scan SARIF files for CVE/GHSA references in results.

    Returns ``{CVE_ID: [sarif_ref_id, ...]}``.
    """
    out: dict[str, list[str]] = {}
    for d in sarif_dirs:
        if not d.is_dir():
            continue
        # One recursive walk — the earlier top-level glob + recursive
        # glob pair walked the whole tree twice.
        for sarif_file in d.glob("**/*.sarif"):
            _scan_sarif_file(sarif_file, out)
    return out


def _scan_sarif_file(
    path: Path,
    out: dict[str, list[str]],
) -> None:
    # The SARIF glob discovers ANY *.sarif under the given dirs —
    # including files checked into the scanned target tree — so the
    # read must be bounded. load_sarif is the canonical guarded
    # loader (100 MiB stat gate before the read, decode + shape
    # checks); it returns None on any failure, matching the
    # skip-this-file behaviour here.
    sarif = load_sarif(path)
    if sarif is None:
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
    result: dict[str, Any],
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
    result: dict[str, Any],
    run: dict[str, Any],
) -> set[str]:
    """Extract CVE/GHSA IDs from a SARIF result's message, tags, and properties."""
    ids: set[str] = set()

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
        ids.update(m.group(1).upper() for m in _GHSA_RE.finditer(tag))

    return ids
