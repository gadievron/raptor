"""
SAGE pipeline hooks for RAPTOR.

Pre-analysis and post-analysis hooks that integrate SAGE memory into
the Python scan/analysis pipeline. These enable cross-run learning:
scan 1 stores findings, scan 2 recalls them as context.

All hooks are no-ops when SAGE is unavailable.
"""

import hashlib
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging import get_logger

from .client import SageClient
from .config import SageConfig

logger = get_logger()

# Singleton client — created on first use
_client: Optional[SageClient] = None


def _throttle() -> None:
    """Optional delay between SAGE proposes. Default 0.

    CometBFT's `broadcast_tx_commit` — used by `POST /v1/memory/submit` —
    already blocks until the block containing the tx is finalised
    (1s personal / 3s quorum cadence), so additional client-side throttling
    buys nothing. The previous hardcoded 300ms was inherited verbatim from
    the async-bridge era via 5c5238b and protects nothing in the sync path.

    Retained as `SAGE_PROPOSE_DELAY_MS` env knob purely as a safety valve
    for unusual deployments. Invalid values silently become 0.
    """
    try:
        ms = float(os.getenv("SAGE_PROPOSE_DELAY_MS", "0"))
    except (TypeError, ValueError):
        return
    if ms > 0:
        time.sleep(ms / 1000)


def _get_client() -> Optional[SageClient]:
    """Get or create the SAGE client singleton."""
    global _client
    if _client is None:
        config = SageConfig.from_env()
        _client = SageClient(config)
        if not _client.is_available():
            logger.debug("SAGE unavailable — pipeline hooks disabled")
            _client = None
    return _client


def _repo_key(repo_path: str) -> str:
    # Resolve before hashing so that different paths that reach the same repo
    # (symlinks, relative paths) collapse to the same key, and same-basename
    # repos at different locations stay distinct.
    resolved = str(Path(repo_path).resolve()) if repo_path else ""
    return hashlib.sha256(resolved.encode()).hexdigest()[:12]


def _findings_domain(repo_path: str) -> str:
    return f"raptor-findings-{_repo_key(repo_path)}"


def _exploits_domain(repo_path: str) -> str:
    return f"raptor-exploits-{_repo_key(repo_path)}"


# ─────────────────────────────────────────────────────────────────────────────
# Pre-analysis hook
# ─────────────────────────────────────────────────────────────────────────────

def recall_context_for_scan(
    repo_path: str,
    languages: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """
    Recall relevant historical findings and methodology from SAGE
    before starting a scan.

    Returns a list of recalled memories (content, confidence, domain).
    Empty list if SAGE unavailable.
    """
    client = _get_client()
    if client is None:
        return []

    try:
        repo_name = Path(repo_path).name
        lang_str = ", ".join(languages) if languages else "unknown"

        results = client.query(
            text=f"security findings and vulnerability patterns for {lang_str} project {repo_name}",
            domain_tag=_findings_domain(repo_path),
            top_k=5,
        )
        methodology = client.query(
            text=f"analysis methodology and best practices for {lang_str} security scanning",
            domain_tag="raptor-methodology",
            top_k=3,
        )

        all_results = results + methodology
        if all_results:
            logger.info(
                f"SAGE: Recalled {len(all_results)} historical memories for scan context"
            )
        return all_results

    except Exception as e:
        logger.debug(f"SAGE pre-scan recall failed: {e}")
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Post-analysis hook
# ─────────────────────────────────────────────────────────────────────────────

def store_scan_results(
    repo_path: str,
    findings: List[Dict[str, Any]],
    scan_metrics: Dict[str, Any],
    languages: Optional[List[str]] = None,
) -> int:
    """
    Store scan results in SAGE for cross-run learning.
    Returns number of findings stored (0 if SAGE unavailable or no findings).
    """
    client = _get_client()
    if client is None or not findings:
        return 0

    repo_name = Path(repo_path).name
    lang_str = ", ".join(languages) if languages else "unknown"
    stored = 0

    # Store individual findings (up to 20 most important)
    sorted_findings = sorted(
        findings,
        key=lambda f: {"error": 4, "warning": 3, "note": 2, "none": 1}.get(
            f.get("level", f.get("severity", "none")), 0
        ),
        reverse=True,
    )

    for finding in sorted_findings[:20]:
        try:
            rule_id = finding.get("rule_id", finding.get("check_id", "unknown"))
            level = finding.get("level", finding.get("severity", "unknown"))
            file_path = finding.get("file_path", finding.get("path", "unknown"))
            message = finding.get("message", "")
            is_exploitable = finding.get("is_exploitable", None)

            # Extract a human-readable vuln type from the rule ID
            # e.g. "javascript.express.security.audit.express-open-redirect" → "open redirect"
            vuln_type = rule_id.rsplit(".", 1)[-1].replace("-", " ").replace("_", " ")

            content = (
                f"{vuln_type} vulnerability in {repo_name} ({file_path}): "
                f"{message[:200]}. "
                f"Rule: {rule_id}. Severity: {level}. "
            )
            if is_exploitable is not None:
                content += f"Confirmed exploitable: {is_exploitable}. "

            confidence = {"error": 0.95, "warning": 0.85, "note": 0.75}.get(level, 0.70)

            if client.propose(
                content=content,
                memory_type="observation",
                domain_tag=_findings_domain(repo_path),
                confidence=confidence,
            ):
                stored += 1

            _throttle()
        except Exception as e:
            logger.debug(f"SAGE finding store failed: {e}")

    # Store a scan summary
    try:
        total = scan_metrics.get("total_findings", len(findings))
        by_sev = scan_metrics.get("findings_by_severity", {})
        summary = (
            f"Scan summary for {lang_str} project {repo_name}: "
            f"{total} findings "
            f"(critical={by_sev.get('error', 0)}, "
            f"warning={by_sev.get('warning', 0)}, "
            f"note={by_sev.get('note', 0)}). "
            f"Tools: {', '.join(scan_metrics.get('tools_used', ['Semgrep']))}."
        )
        client.propose(
            content=summary,
            memory_type="observation",
            domain_tag=_findings_domain(repo_path),
            confidence=0.85,
        )
    except Exception:
        pass

    if stored > 0:
        logger.info(f"SAGE: Stored {stored} findings from scan")
    return stored


def store_analysis_results(
    repo_path: str,
    analysis: Dict[str, Any],
    orchestration: Optional[Dict[str, Any]] = None,
) -> None:
    """Store analysis/orchestration results in SAGE."""
    client = _get_client()
    if client is None:
        return

    try:
        repo_name = Path(repo_path).name

        exploitable = analysis.get("exploitable", 0)
        exploits = analysis.get("exploits_generated", 0)
        patches = analysis.get("patches_generated", 0)
        analyzed = analysis.get("analyzed", analysis.get("processed", 0))

        summary = (
            f"Analysis results for project {repo_name}: "
            f"{analyzed} findings analyzed, "
            f"{exploitable} confirmed exploitable, "
            f"{exploits} exploits generated, "
            f"{patches} patches generated."
        )

        client.propose(
            content=summary,
            memory_type="observation",
            domain_tag=_findings_domain(repo_path),
            confidence=0.85,
        )

        if orchestration:
            results = orchestration.get("results", [])
            for r in results[:10]:
                if r.get("is_exploitable"):
                    rule_id = r.get("rule_id", "unknown")
                    reasoning = r.get("reasoning", "")[:200]
                    content = (
                        f"Confirmed exploitable: {rule_id} in {repo_name}. "
                        f"Reasoning: {reasoning}"
                    )
                    client.propose(
                        content=content,
                        memory_type="fact",
                        domain_tag=_exploits_domain(repo_path),
                        confidence=0.90,
                    )
                    _throttle()
    except Exception as e:
        logger.debug(f"SAGE analysis store failed: {e}")


def enrich_analysis_prompt(
    rule_id: str,
    file_path: str,
    language: str = "",
    repo_path: Optional[str] = None,
) -> str:
    """
    Generate additional context from SAGE to enrich an analysis prompt.
    Returns context string, or empty if SAGE unavailable / no matches /
    no repo_path supplied.

    repo_path is required to scope the recall to this repo's findings;
    without it we'd query an empty domain (findings live under
    raptor-findings-<repo_key>) and can't safely fall back to cross-repo
    recall because same-basename repos would contaminate each other.
    """
    client = _get_client()
    if client is None or not repo_path:
        return ""

    try:
        vuln_type = rule_id.rsplit(".", 1)[-1].replace("-", " ").replace("_", " ")
        results = client.query(
            text=f"{vuln_type} vulnerability findings and exploitability in {language} code",
            domain_tag=_findings_domain(repo_path),
            top_k=3,
        )

        if not results:
            return ""

        context_parts = [
            "\n**Historical Context from SAGE (cross-run learning):**"
        ]
        for r in results:
            confidence = r.get("confidence", 0)
            content = r.get("content", "")[:200]
            context_parts.append(f"- [{confidence:.0%}] {content}")

        context = "\n".join(context_parts) + "\n"
        logger.debug(f"SAGE: Enriched prompt with {len(results)} historical memories")
        return context

    except Exception as e:
        logger.debug(f"SAGE prompt enrichment failed: {e}")
        return ""
