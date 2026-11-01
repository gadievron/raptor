"""Adapters used by production pipelines; no SQL outside the graph package."""

from __future__ import annotations

import logging
from itertools import islice
from pathlib import Path
from urllib.parse import unquote, urlsplit

from core.paths import to_repo_relative
from core.security.log_sanitisation import sanitise_for_terminal

from .ingest import _scan_snapshot_id, ingest_scan_findings, load_json
from .queries import scan_dedup_chains

logger = logging.getLogger(__name__)

# Optional graph enrichment must not accumulate an unbounded directory of
# individually capped SARIF documents. 64 accommodates multi-tool scan packs;
# 10k matches the evidence-lane record budget. Exceeding either skips this
# update with a warning rather than presenting an arbitrary partial scan.
_SARIF_MAX_FILES = 64
_SARIF_MAX_FINDINGS = 10_000


def ingest_agentic_findings(run_dir: Path, target_path: str, *, findings=None, graph_path=None):
    """Use agentic's actual validation envelope, including no-LLM runs."""
    run_dir = Path(run_dir)
    if findings is None:
        findings = load_json(run_dir / "validation" / "findings.json")
        if findings is None:
            findings = load_json(run_dir / "findings.json")
        if findings is None:
            # --skip-dedup leaves SARIF as the public scanner artifact.
            # Use the shared core parser: core graph memory must not depend
            # on the exploitability-validation capability being installed.
            from core.sarif.parser import parse_sarif_findings
            findings = []
            paths = list(islice(run_dir.glob("*.sarif"), _SARIF_MAX_FILES + 1))
            if len(paths) > _SARIF_MAX_FILES:
                logger.warning("graph SARIF enrichment skipped: file budget exceeded")
                return None
            for path in sorted(paths):
                try:
                    parsed = parse_sarif_findings(
                        path, source_root=Path(target_path) if target_path else None)
                except Exception as exc:  # noqa: BLE001 — isolate malformed optional artifacts
                    logger.warning("graph SARIF skipped %s: %s",
                                   sanitise_for_terminal(path.name),
                                   sanitise_for_terminal(str(exc)))
                    continue
                if len(findings) + len(parsed) > _SARIF_MAX_FINDINGS:
                    logger.warning("graph SARIF enrichment skipped: finding budget exceeded")
                    return None
                for finding in parsed:
                    uri = finding.get("file")
                    if isinstance(uri, str):
                        try:
                            parts = urlsplit(uri)
                        except ValueError:
                            logger.warning("graph SARIF skipped malformed URI: %s",
                                           sanitise_for_terminal(uri))
                            continue
                        if parts.scheme and (parts.scheme != "file" or parts.netloc not in (
                            "", "localhost",
                        )):
                            logger.warning("graph SARIF skipped nonlocal URI: %s",
                                           sanitise_for_terminal(uri))
                            continue
                        # Decode once at the SARIF boundary. JSON finding paths
                        # may contain literal percent signs and are not URIs.
                        decoded = unquote(parts.path if parts.scheme == "file" else uri)
                        normalized = (to_repo_relative(decoded, target_path)
                                      if target_path else decoded)
                        if normalized is None:
                            logger.warning("graph SARIF skipped out-of-root URI: %s",
                                           sanitise_for_terminal(uri))
                            continue
                        finding["file"] = normalized
                    findings.append(finding)
    return ingest_scan_findings(run_dir, target_path, findings=findings, graph_path=graph_path)


def agentic_graph_groups(run_dir: Path, target_path: str, findings: list[dict]) -> list[dict]:
    """Feed shared-path candidates into cross-finding analysis, not suppression.

    Two findings sharing a path can still be distinct vulnerabilities. Group
    them for review while preserving every original finding and verdict.
    """
    try:
        graph = ingest_agentic_findings(run_dir, target_path, findings=findings)
        if graph is None:
            return []
        allowed = {str(f.get("finding_id") or f.get("id")) for f in findings}
        groups: list[dict] = []
        current_snapshot = _scan_snapshot_id(run_dir, str(target_path), findings)
        for chain in scan_dedup_chains(
                graph, target_path, run_dir=run_dir, scan_snapshot=current_snapshot):
            refs = sorted(set(chain["finding_refs"]) & allowed)
            if len(refs) > 1:
                groups.append({
                    "group_id": f"GRAPH-{len(groups) + 1:03d}",
                    "criterion": "graph_path_hint",
                    "criterion_value": f"{chain['entry_id']}->{chain['sink_id']}",
                    "finding_ids": refs,
                })
        return groups
    except Exception:  # noqa: BLE001 — optional memory never prevents analysis
        logger.warning("agentic graph grouping skipped", exc_info=True)
        return []
