"""
SAGE pipeline hooks for RAPTOR.

Pre-analysis and post-analysis hooks that integrate SAGE memory into
the Python scan/analysis pipeline. These enable cross-run learning:
scan 1 stores findings, scan 2 recalls them as context.

All hooks are no-ops when SAGE is unavailable.
"""

import math
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.hash import sha256_string
from core.logging import get_logger
from core.security.redaction import redact_secrets

from .client import SageClient
from .config import SageConfig

logger = get_logger()

# Singleton client — created on first use.
# orchestrator.py dispatches via ThreadPoolExecutor, so the first-use
# init must be guarded against concurrent first calls racing on the
# `_client is None` check. Once the init decision is made, it sticks
# for the process lifetime — no retry-storm if SAGE is down.
_client_lock = threading.Lock()
_client: Optional[SageClient] = None
_client_initialised: bool = False
# When `_client` was decided to be None (SAGE unavailable). After
# `_CLIENT_NONE_TTL_S` we re-probe so a SAGE node that came up
# after the process started is picked up. Successful init has no
# TTL — once we have a working client, keep it for the lifetime.
_client_none_decided_at: float = 0.0
_CLIENT_NONE_TTL_S: float = 300.0  # 5 min; balances probe cost vs. recovery latency
_sage_metrics: Dict[str, int] = {
    "propose_attempted": 0,
    "propose_succeeded": 0,
    "propose_failed": 0,
    "recall_attempted": 0,
    "recall_hits": 0,
}


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
    # Reject non-finite (NaN, +/-Infinity). `float("inf") / 1000` is
    # still inf and `time.sleep(inf)` blocks forever — every SAGE
    # propose hangs the parent process. `nan` slips past `> 0` (NaN
    # comparisons are False) so it's harmless on its own, but
    # asserting finiteness is cheaper than auditing every downstream
    # use. Cap at 5 minutes — `SAGE_PROPOSE_DELAY_MS=999999999` is
    # almost certainly a typo, not deliberate, and a 12-day per-call
    # delay is indistinguishable from a hang.
    if not math.isfinite(ms):
        return
    if ms > 0:
        time.sleep(min(ms, 300_000) / 1000)


def _get_client() -> Optional[SageClient]:
    """Get or create the SAGE client singleton.

    Thread-safe: guarded by `_client_lock` because the orchestrator
    dispatches into SAGE hooks from worker threads concurrently.
    Without the lock, two threads can both see `_client is None` and
    each run `is_available()` (duplicate network calls), and a thread
    can briefly observe a non-None `_client` while another resets it.

    The init decision is cached via `_client_initialised` so that a
    down-at-first-use SAGE doesn't trigger an `is_available()` probe
    on every subsequent hook call.

    Re-probe TTL on the unavailable path: pre-fix the latch was
    permanent — once `_client = None` was decided, the process
    never re-checked. Operators bringing SAGE up AFTER starting a
    long-lived RAPTOR session (typical: forgot to start the SAGE
    node before `/agentic`, started it mid-run after seeing the
    "SAGE unavailable" log) saw zero recovery — every subsequent
    hook silently no-op'd until the parent process restarted.
    Re-probe every `_CLIENT_NONE_TTL_S` so a late-coming SAGE
    eventually gets picked up. The successful-init path has no
    TTL — once we have a working client, keep it; refresh is
    only on the negative-cache side where the cost of being
    wrong is "all SAGE features disabled for the rest of the run".
    """
    global _client, _client_initialised, _client_none_decided_at
    with _client_lock:
        needs_init = not _client_initialised
        if (
            _client_initialised
            and _client is None
            and (time.time() - _client_none_decided_at) > _CLIENT_NONE_TTL_S
        ):
            needs_init = True
        if needs_init:
            config = SageConfig.from_env()
            candidate = SageClient(config)
            if candidate.is_available():
                _client = candidate
                _client_none_decided_at = 0.0
            else:
                logger.debug("SAGE unavailable — pipeline hooks disabled")
                _client = None
                _client_none_decided_at = time.time()
            _client_initialised = True
        return _client


def _repo_key(repo_path: str) -> str:
    # Empty path → empty key. Pre-fix the empty-path branch fed `""`
    # through `sha256_string` and returned the SHA-256 prefix of the
    # empty string ("e3b0c44298fc"). Every caller that fired without
    # a known repo (typically a hook fired before the run lifecycle
    # set the active path) ended up writing into the SAME domain
    # `raptor-findings-e3b0c44298fc` — cross-contaminating findings
    # from unrelated runs into a shared bucket. Returning the empty
    # string lets the caller filter (`if not _repo_key(...): return`)
    # without inventing a synthetic-but-shared bucket.
    if not repo_path:
        return ""
    # URL-ish identifiers (web targets): hash normalized URL; avoid cwd resolution.
    if "://" in repo_path:
        return sha256_string(repo_path.strip().lower())[:12]
    # Resolve before hashing so that different paths that reach the same repo
    # (symlinks, relative paths) collapse to the same key, and same-basename
    # repos at different locations stay distinct.
    resolved = str(Path(repo_path).resolve())
    return sha256_string(resolved)[:12]


def _findings_domain(repo_path: str) -> str:
    return f"raptor-findings-{_repo_key(repo_path)}"


def _exploits_domain(repo_path: str) -> str:
    return f"raptor-exploits-{_repo_key(repo_path)}"


def _crashes_domain(repo_path: str) -> str:
    return f"raptor-crashes-{_repo_key(repo_path)}"


def _web_domain(repo_path: str) -> str:
    return f"raptor-web-{_repo_key(repo_path)}"


def _binary_key(binary_path: str) -> str:
    return sha256_string(str(Path(binary_path).resolve()))[:12]


def _propose_redacted(
    *,
    client: SageClient,
    content: str,
    memory_type: str,
    domain_tag: str,
    confidence: float,
) -> bool:
    _sage_metrics["propose_attempted"] += 1
    redacted_content = redact_secrets(content)
    ok = client.propose(
        content=redacted_content,
        memory_type=memory_type,
        domain_tag=domain_tag,
        confidence=confidence,
    )
    if ok:
        _sage_metrics["propose_succeeded"] += 1
    else:
        _sage_metrics["propose_failed"] += 1
    return ok


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


def recall_context_for_crash_analysis(
    repo_path: str,
    binary_fingerprint: Optional[str] = None,
    signal: Optional[str] = None,
    function_name: Optional[str] = None,
) -> List[Dict[str, Any]]:
    client = _get_client()
    if client is None:
        return []
    try:
        _sage_metrics["recall_attempted"] += 1
        query = "Summarize prior crash patterns"
        if signal:
            query += f" for signal {signal}"
        if function_name:
            query += f" near function {function_name}"
        if binary_fingerprint:
            query += f" for binary fingerprint {binary_fingerprint}"
        query += ", including confidence and exploitability hints."
        results = client.query(
            text=query,
            domain_tag=_crashes_domain(repo_path),
            top_k=5,
        )
        _sage_metrics["recall_hits"] += len(results)
        return results
    except Exception as e:
        logger.debug(f"SAGE crash recall failed: {e}")
        return []


def recall_context_for_web_scan(
    repo_path: str,
    target_fingerprint: str,
) -> List[Dict[str, Any]]:
    client = _get_client()
    if client is None:
        return []
    try:
        _sage_metrics["recall_attempted"] += 1
        results = client.query(
            text=(
                "Which payload classes produced differentiated signals "
                f"on targets matching {target_fingerprint}?"
            ),
            domain_tag=_web_domain(repo_path),
            top_k=5,
        )
        _sage_metrics["recall_hits"] += len(results)
        return results
    except Exception as e:
        logger.debug(f"SAGE web recall failed: {e}")
        return []


def recall_context_for_codeql_build(
    repo_path: str,
    languages: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    client = _get_client()
    if client is None:
        return []
    try:
        _sage_metrics["recall_attempted"] += 1
        lang_str = ", ".join(languages or []) or "unknown"
        results = client.query(
            text=(
                "What CodeQL build approach succeeded last time "
                f"for {lang_str} and what failures should we skip retrying?"
            ),
            domain_tag="raptor-methodology",
            top_k=5,
        )
        _sage_metrics["recall_hits"] += len(results)
        return results
    except Exception as e:
        logger.debug(f"SAGE codeql recall failed: {e}")
        return []


def recall_context_for_fuzzing_strategy(
    repo_path: str,
    binary_fingerprint: str,
    strategy_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    client = _get_client()
    if client is None:
        return []
    try:
        _sage_metrics["recall_attempted"] += 1
        query = (
            "What fuzzing strategies produced crashes for this binary "
            f"or similar binaries ({binary_fingerprint})?"
        )
        if strategy_id:
            query += f" Focus on strategy {strategy_id}."
        results = client.query(
            text=query,
            domain_tag="raptor-fuzzing",
            top_k=5,
        )
        _sage_metrics["recall_hits"] += len(results)
        return results
    except Exception as e:
        logger.debug(f"SAGE fuzzing recall failed: {e}")
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

            if _propose_redacted(
                client=client,
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
        _propose_redacted(
            client=client,
            content=summary,
            memory_type="observation",
            domain_tag=_findings_domain(repo_path),
            confidence=0.85,
        )
    except Exception as e:
        logger.debug(f"SAGE scan summary store failed: {e}")

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

        _propose_redacted(
            client=client,
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
                    _propose_redacted(
                        client=client,
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


def store_crash_analysis_pattern(
    repo_path: str,
    binary_path: str,
    signal: str,
    function_name: str,
    crash_type: str,
    source_location: str = "",
    stack_hash: str = "",
    exploitability_hint: str = "unknown",
) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        confidence = 0.90 if exploitability_hint == "exploitable" else 0.85
        content = (
            f"Crash pattern in repo {Path(repo_path).name}: signal {signal}, "
            f"function {function_name}, crash type {crash_type}, "
            f"source {source_location or 'unknown'}, stack signature {stack_hash or 'none'}, "
            f"binary key {_binary_key(binary_path)}, exploitability hint {exploitability_hint}."
        )
        _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag=_crashes_domain(repo_path),
            confidence=confidence,
        )
    except Exception as e:
        logger.debug(f"SAGE crash pattern store failed: {e}")


def store_web_payload_effectiveness(
    repo_path: str,
    target_fingerprint: str,
    payload_class: str,
    evidence_class: str,
    effectiveness: float,
    attempts: int,
    signals: int,
    notes: str = "",
) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        confidence = 0.85 if signals > 0 else 0.75
        content = (
            f"Web payload effectiveness for {target_fingerprint}: "
            f"payload class {payload_class}, evidence {evidence_class}, "
            f"effectiveness {effectiveness:.2f}, attempts {attempts}, signals {signals}. "
            f"Notes: {notes[:200]}"
        )
        _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag=_web_domain(repo_path),
            confidence=confidence,
        )
    except Exception as e:
        logger.debug(f"SAGE web payload store failed: {e}")


def store_codeql_build_reliability(
    repo_path: str,
    languages: List[str],
    build_command: str,
    auto_detect_outcome: str,
    analyses_completed: int,
    failure_modes: Optional[List[str]] = None,
) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        failures = ", ".join(failure_modes or []) or "none"
        lang_str = ", ".join(languages) or "unknown"
        confidence = 0.85 if auto_detect_outcome == "success" else 0.75
        content = (
            f"CodeQL build reliability for repo {Path(repo_path).name}: "
            f"languages {lang_str}, outcome {auto_detect_outcome}, "
            f"build command {build_command}, analyses completed {analyses_completed}, "
            f"failure modes {failures}."
        )
        _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag="raptor-methodology",
            confidence=confidence,
        )
    except Exception as e:
        logger.debug(f"SAGE codeql reliability store failed: {e}")


def store_fuzzing_strategy_outcome(
    repo_path: str,
    binary_fingerprint: str,
    strategy_id: str,
    duration_s: int,
    execs: int,
    unique_crashes: int,
    hangs: int,
    exploitable_crashes: int,
) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        confidence = 0.85 if unique_crashes > 0 else 0.75
        content = (
            f"Fuzzing strategy outcome for repo {Path(repo_path).name}: "
            f"strategy {strategy_id}, binary fingerprint {binary_fingerprint}, "
            f"duration {duration_s}s, executions {execs}, unique crashes {unique_crashes}, "
            f"hangs {hangs}, exploitable crashes {exploitable_crashes}."
        )
        _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag="raptor-fuzzing",
            confidence=confidence,
        )
    except Exception as e:
        logger.debug(f"SAGE fuzzing strategy store failed: {e}")
