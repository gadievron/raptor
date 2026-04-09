"""
SAGE pipeline hooks for RAPTOR.

Pre-analysis and post-analysis hooks that integrate SAGE memory into
the Python scan/analysis pipeline. These enable cross-run learning:
scan 1 stores findings, scan 2 recalls them as context.

All hooks are no-ops when SAGE is unavailable.
"""

import asyncio
import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.logging import get_logger

from .client import SageClient
from .config import SageConfig

logger = get_logger()

# Singleton client — created on first use
_client: Optional[SageClient] = None


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


def _run_async(coro):
    """Run an async coroutine from sync code safely."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)
    except RuntimeError:
        # No event loop — create one
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        return loop.run_until_complete(coro)


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

    Args:
        repo_path: Path to the repository being scanned
        languages: Detected programming languages

    Returns:
        List of recalled memories (content, confidence, domain).
        Empty list if SAGE unavailable.
    """
    client = _get_client()
    if client is None:
        return []

    try:
        repo_name = Path(repo_path).name
        lang_str = ", ".join(languages) if languages else "unknown"
        query = f"security findings and vulnerability patterns for {lang_str} project {repo_name}"

        results = _run_async(client.query(
            text=query,
            domain_tag="raptor-findings",
            top_k=5,
        ))

        # Also recall methodology
        methodology = _run_async(client.query(
            text=f"analysis methodology and best practices for {lang_str} security scanning",
            domain_tag="raptor-methodology",
            top_k=3,
        ))

        all_results = results + methodology
        if all_results:
            logger.info(
                f"SAGE: Recalled {len(all_results)} historical memories for scan context"
            )
        return all_results

    except Exception as e:
        logger.debug(f"SAGE pre-scan recall failed: {e}")
        return []


def recall_exploit_primitives(vuln_types: List[str]) -> List[Dict[str, Any]]:
    """
    Recall exploitation primitives relevant to the detected vulnerability types.

    Args:
        vuln_types: List of vulnerability type strings (e.g., ["sql_injection", "xss"])

    Returns:
        List of recalled primitive memories.
    """
    client = _get_client()
    if client is None:
        return []

    try:
        query = f"exploitation primitives and techniques for {', '.join(vuln_types)}"
        results = _run_async(client.query(
            text=query,
            domain_tag="raptor-primitives",
            top_k=5,
        ))
        if results:
            logger.info(f"SAGE: Recalled {len(results)} exploit primitives")
        return results
    except Exception as e:
        logger.debug(f"SAGE primitive recall failed: {e}")
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

    Args:
        repo_path: Path to the scanned repository
        findings: List of finding dicts (from SARIF or analysis report)
        scan_metrics: Scan metrics dict
        languages: Detected languages

    Returns:
        Number of findings stored. 0 if SAGE unavailable.
    """
    client = _get_client()
    if client is None:
        return 0

    if not findings:
        return 0

    try:
        stored = _run_async(_store_findings_async(
            client, repo_path, findings, scan_metrics, languages
        ))
        return stored
    except Exception as e:
        logger.debug(f"SAGE post-scan store failed: {e}")
        return 0


async def _store_findings_async(
    client: SageClient,
    repo_path: str,
    findings: List[Dict[str, Any]],
    scan_metrics: Dict[str, Any],
    languages: Optional[List[str]],
) -> int:
    """Async implementation of findings storage."""
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

            content = (
                f"Security finding in {lang_str} project {repo_name}: "
                f"{rule_id} ({level}) in {file_path}. "
                f"{message[:200]}. "
            )
            if is_exploitable is not None:
                content += f"Exploitable: {is_exploitable}. "

            confidence = {"error": 0.95, "warning": 0.85, "note": 0.75}.get(level, 0.70)

            success = await client.propose(
                content=content,
                memory_type="observation",
                domain_tag="raptor-findings",
                confidence=confidence,
            )
            if success:
                stored += 1

            await asyncio.sleep(0.3)
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
        await client.propose(
            content=summary,
            memory_type="observation",
            domain_tag="raptor-findings",
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
    """
    Store analysis/orchestration results in SAGE.

    Args:
        repo_path: Repository path
        analysis: Analysis report dict
        orchestration: Orchestration result dict (optional)
    """
    client = _get_client()
    if client is None:
        return

    try:
        _run_async(_store_analysis_async(client, repo_path, analysis, orchestration))
    except Exception as e:
        logger.debug(f"SAGE analysis store failed: {e}")


async def _store_analysis_async(
    client: SageClient,
    repo_path: str,
    analysis: Dict[str, Any],
    orchestration: Optional[Dict[str, Any]],
) -> None:
    """Async implementation of analysis storage."""
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

    await client.propose(
        content=summary,
        memory_type="observation",
        domain_tag="raptor-findings",
        confidence=0.85,
    )

    # Store orchestration details if available
    if orchestration:
        orch = orchestration.get("orchestration", {})
        results = orchestration.get("results", [])

        # Extract and store notable findings
        for r in results[:10]:
            if r.get("is_exploitable"):
                rule_id = r.get("rule_id", "unknown")
                reasoning = r.get("reasoning", "")[:200]
                content = (
                    f"Confirmed exploitable: {rule_id} in {repo_name}. "
                    f"Reasoning: {reasoning}"
                )
                await client.propose(
                    content=content,
                    memory_type="fact",
                    domain_tag="raptor-exploits",
                    confidence=0.90,
                )
                await asyncio.sleep(0.3)


def enrich_analysis_prompt(
    rule_id: str,
    file_path: str,
    language: str = "",
) -> str:
    """
    Generate additional context from SAGE to enrich an analysis prompt.

    Args:
        rule_id: The rule/check ID being analyzed
        file_path: The file being analyzed
        language: Programming language

    Returns:
        Additional context string to append to analysis prompt.
        Empty string if SAGE unavailable or no relevant memories.
    """
    client = _get_client()
    if client is None:
        return ""

    try:
        query = f"historical findings and analysis for {rule_id} in {language} code"
        results = _run_async(client.query(
            text=query,
            domain_tag="raptor-findings",
            top_k=3,
        ))

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
