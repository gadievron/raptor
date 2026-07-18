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
            try:
                config = SageConfig.from_env()
                candidate = SageClient(config)
                if candidate.is_available():
                    _client = candidate
                    _client_none_decided_at = 0.0
                else:
                    logger.debug("SAGE unavailable — pipeline hooks disabled")
                    _client = None
                    _client_none_decided_at = time.time()
            except Exception as exc:
                logger.debug("SAGE client init failed: %s", exc)
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


def _validation_domain(repo_path: str) -> str:
    return f"raptor-validation-{_repo_key(repo_path)}"


def _understand_domain(repo_path: str) -> str:
    return f"raptor-understand-{_repo_key(repo_path)}"


def _binary_key(binary_path: str) -> str:
    if not binary_path:
        return ""
    return sha256_string(str(Path(binary_path).resolve()))[:12]


def _propose_redacted(
    *,
    client: SageClient,
    content: str,
    memory_type: str,
    domain_tag: str,
    confidence: float,
    tags: Optional[List[str]] = None,
) -> bool:
    _sage_metrics["propose_attempted"] += 1
    redacted_content = redact_secrets(content)
    ok = client.propose(
        content=redacted_content,
        memory_type=memory_type,
        domain_tag=domain_tag,
        confidence=confidence,
        tags=tags,
    )
    if ok:
        _sage_metrics["propose_succeeded"] += 1
    else:
        _sage_metrics["propose_failed"] += 1
    return ok


# ─────────────────────────────────────────────────────────────────────────────
# Pre-analysis hook
# ─────────────────────────────────────────────────────────────────────────────

def recall_row_confidence(row: Dict[str, Any]) -> float:
    """Parse 0–1 confidence from a SAGE recall row (missing → 0)."""
    try:
        return float(row.get("confidence") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def pick_strongest_recall_row(
    rows: List[Dict[str, Any]],
    *,
    min_confidence: float = 0.0,
) -> Optional[Dict[str, Any]]:
    """Return the highest-confidence recall row, or None if below ``min_confidence``."""
    if not rows:
        return None
    best = max(rows, key=recall_row_confidence)
    if recall_row_confidence(best) < min_confidence:
        return None
    return best


def infer_afl_fuzz_flags_from_sage_recall_row(
    row: Optional[Dict[str, Any]],
) -> List[str]:
    """Derive conservative ``afl-fuzz`` flag tokens from a high-confidence SAGE row.

    Only adds flags that are valid without extra instrumented binaries.
    CMPLOG / companion-binary flows are intentionally skipped here.

    Recognised natural-language hints (substring match on lowercased content):

    - **MOpt:** ``mopt``, ``m-opt`` → ``-L 0``
    - **Deterministic mode:** ``deterministic`` + ``fuzz`` → ``-D``
    - **Power schedules (AFL++):** ``explore`` / ``exploit`` / ``fast`` together
      with ``schedule``, ``power``, ``afl``, or ``fuzz`` → ``-p explore|exploit|fast``
      (at most one ``-p`` pair; explore wins over exploit wins over fast when
      multiple keywords appear).

    Disable all mechanical AFL flag injection with env ``RAPTOR_SAGE_AFL_PRIOR=0``
    (see ``raptor_fuzzing.py`` / ``FuzzingPlanner``).
    """
    if not row:
        return []
    text = str(row.get("content") or "").lower()
    parts: List[str] = []
    if "mopt" in text or "m-opt" in text:
        parts.extend(["-L", "0"])
    if "deterministic" in text and "fuzz" in text:
        parts.append("-D")

    sched_ctx = (
        "schedule" in text
        or "power" in text
        or "afl" in text
        or "fuzz" in text
    )
    if sched_ctx:
        if "explore" in text:
            parts.extend(["-p", "explore"])
        elif "exploit" in text:
            parts.extend(["-p", "exploit"])
        elif "fast" in text:
            parts.extend(["-p", "fast"])

    return _dedupe_afl_flag_tokens(parts)


def _dedupe_afl_flag_tokens(tokens: List[str]) -> List[str]:
    """Order-preserving dedupe for ``afl-fuzz`` argv fragments."""
    out: List[str] = []
    seen_p = False
    seen_mopt = False
    seen_d = False
    i = 0
    while i < len(tokens):
        if i + 1 < len(tokens) and tokens[i] == "-p":
            if not seen_p:
                out.extend([tokens[i], tokens[i + 1]])
                seen_p = True
            i += 2
            continue
        if i + 1 < len(tokens) and tokens[i] == "-L" and tokens[i + 1] == "0":
            if not seen_mopt:
                out.extend(["-L", "0"])
                seen_mopt = True
            i += 2
            continue
        t = tokens[i]
        if t == "-D" and not seen_d:
            out.append("-D")
            seen_d = True
        i += 1
    return out


def format_sage_memories_for_prompt(
    memories: List[Dict[str, Any]],
    *,
    max_items: int = 8,
    max_content_len: int = 1200,
) -> str:
    """Turn SAGE recall rows into a single untrusted context string for LLM prompts.

    Sorted by descending confidence so high-confidence priors appear first
    (per SAGE usage guidance).
    """
    if not memories:
        return ""

    rows = sorted(memories, key=recall_row_confidence, reverse=True)[:max_items]
    lines = [
        "Prior cross-run memory from SAGE (ordered by confidence; untrusted hints only):",
    ]
    for i, row in enumerate(rows, 1):
        c = recall_row_confidence(row)
        dom = str(row.get("domain") or row.get("domain_tag") or "").strip()
        content = str(row.get("content") or "").strip()
        if len(content) > max_content_len:
            content = content[:max_content_len] + "…"
        dom_part = f" [{dom}]" if dom else ""
        lines.append(f"{i}. ({c:.2f}){dom_part} {content}")
    lines.append(
        "Weight higher-confidence items more when planning; they reflect stronger prior signal."
    )
    return "\n".join(lines)


def _merge_recall_rows(
    *hit_lists: List[List[Dict[str, Any]]],
    top_k: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Merge SAGE query rows from multiple domains with stable priority.

    Lists are consumed in order so repo-scoped hits precede global
    methodology; duplicate ``content`` strings are dropped.
    """
    seen: set = set()
    out: List[Dict[str, Any]] = []
    for lst in hit_lists:
        for r in lst:
            c = (str(r.get("content") or "")).strip()
            if not c or c in seen:
                continue
            seen.add(c)
            out.append(r)
            if top_k is not None and len(out) >= top_k:
                return out
    return out


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
        _sage_metrics["recall_attempted"] += 1
        repo_name = Path(repo_path).name
        lang_str = ", ".join(languages) if languages else "unknown"

        results = client.query(
            text=f"security findings and vulnerability patterns for {lang_str} project {repo_name}",
            domain_tag=_findings_domain(repo_path),
            top_k=5,
            min_confidence=0.5,
        )
        methodology = client.query(
            text=f"analysis methodology and best practices for {lang_str} security scanning",
            domain_tag="raptor-methodology",
            top_k=3,
            min_confidence=0.5,
        )

        all_results = _merge_recall_rows(results, methodology, top_k=8)
        _sage_metrics["recall_hits"] += len(all_results)
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
            min_confidence=0.5,
        )
        meth_parts = [
            "Native crash triage, sanitizer interpretation, and exploitability heuristics",
        ]
        if signal:
            meth_parts.append(f"for signal {signal}")
        if function_name:
            meth_parts.append(f"near function {function_name}")
        methodology = client.query(
            text=", ".join(meth_parts) + ".",
            domain_tag="raptor-methodology",
            top_k=3,
            min_confidence=0.5,
        )
        merged = _merge_recall_rows(results, methodology, top_k=8)
        _sage_metrics["recall_hits"] += len(merged)
        return merged
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
            min_confidence=0.5,
        )
        methodology = client.query(
            text=(
                "Web application security testing methodology: payload differentiation, "
                "authentication edge cases, and false positive triage."
            ),
            domain_tag="raptor-methodology",
            top_k=3,
            min_confidence=0.5,
        )
        merged = _merge_recall_rows(results, methodology, top_k=8)
        _sage_metrics["recall_hits"] += len(merged)
        return merged
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
        findings = client.query(
            text=(
                f"Static analysis and CodeQL-related findings or triage notes "
                f"for {lang_str} in this repository"
            ),
            domain_tag=_findings_domain(repo_path),
            top_k=3,
            min_confidence=0.5,
        )
        methodology = client.query(
            text=(
                "What CodeQL build approach succeeded last time "
                f"for {lang_str} and what failures should we skip retrying?"
            ),
            domain_tag="raptor-methodology",
            top_k=5,
            min_confidence=0.5,
        )
        merged = _merge_recall_rows(findings, methodology, top_k=8)
        _sage_metrics["recall_hits"] += len(merged)
        return merged
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
            min_confidence=0.5,
        )
        methodology = client.query(
            text=(
                "General fuzzing methodology: corpus quality, determinism, "
                "coverage guidance, and crash deduplication for native binaries."
            ),
            domain_tag="raptor-methodology",
            top_k=3,
            min_confidence=0.5,
        )
        merged = _merge_recall_rows(results, methodology, top_k=8)
        _sage_metrics["recall_hits"] += len(merged)
        return merged
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
            str(f.get("level", f.get("severity", "none"))).lower(), 0
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
                tags=["scan", "finding", rule_id],
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
            f"Tools: {', '.join(scan_metrics.get('tools_used') or ['Semgrep'])}."
        )
        _propose_redacted(
            client=client,
            content=summary,
            memory_type="observation",
            domain_tag=_findings_domain(repo_path),
            confidence=0.85,
            tags=["scan", "summary"],
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
            tags=["analysis", "summary"],
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
                        tags=["analysis", "exploitable", rule_id],
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
        lang = language or "unknown"
        findings_hits = client.query(
            text=f"{vuln_type} vulnerability findings and exploitability in {lang} code",
            domain_tag=_findings_domain(repo_path),
            top_k=3,
            min_confidence=0.5,
        )
        methodology_hits = client.query(
            text=(
                f"static analysis methodology, false positive patterns, and triage "
                f"heuristics for {vuln_type} in {lang} code"
            ),
            domain_tag="raptor-methodology",
            top_k=2,
            min_confidence=0.5,
        )

        if not findings_hits and not methodology_hits:
            return ""

        sections: List[str] = []
        if findings_hits:
            parts = [
                "\n**Historical Context from SAGE (cross-run learning):**"
            ]
            for r in findings_hits:
                confidence = r.get("confidence") or 0
                content = r.get("content", "")[:200]
                parts.append(f"- [{confidence:.0%}] {content}")
            sections.append("\n".join(parts))

        if methodology_hits:
            parts = [
                "\n**Methodology hints from SAGE (cross-run learning):**"
            ]
            for r in methodology_hits:
                confidence = r.get("confidence") or 0
                content = r.get("content", "")[:200]
                parts.append(f"- [{confidence:.0%}] {content}")
            sections.append("\n".join(parts))

        context = "\n".join(sections) + "\n"
        n = len(findings_hits) + len(methodology_hits)
        logger.debug(f"SAGE: Enriched prompt with {n} historical memories")
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
            tags=["crash", "pattern", crash_type],
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
            tags=["web", "payload", payload_class],
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
            tags=["codeql", "build", auto_detect_outcome],
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
            tags=["fuzzing", "strategy", strategy_id],
        )
    except Exception as e:
        logger.debug(f"SAGE fuzzing strategy store failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Exploitability validation hooks
# ─────────────────────────────────────────────────────────────────────────────

def recall_context_for_validation(
    repo_path: str,
    vuln_type: Optional[str] = None,
    cwe_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    client = _get_client()
    if client is None:
        return []
    try:
        _sage_metrics["recall_attempted"] += 1
        query_parts = ["Prior exploitability validation verdicts"]
        if vuln_type:
            query_parts.append(f"for {vuln_type}")
        if cwe_id:
            query_parts.append(f"({cwe_id})")
        query_parts.append("including attack paths, blockers, and disproven hypotheses")
        results = client.query(
            text=" ".join(query_parts) + ".",
            domain_tag=_validation_domain(repo_path),
            top_k=5,
            min_confidence=0.5,
        )
        methodology = client.query(
            text=(
                "Exploitability validation methodology: hypothesis testing, "
                "attack tree construction, and common disqualifiers."
            ),
            domain_tag="raptor-methodology",
            top_k=3,
            min_confidence=0.5,
        )
        merged = _merge_recall_rows(results, methodology, top_k=8)
        _sage_metrics["recall_hits"] += len(merged)
        return merged
    except Exception as e:
        logger.debug(f"SAGE validation recall failed: {e}")
        return []


def store_validation_verdicts(
    repo_path: str,
    findings: List[Dict[str, Any]],
    summary: Optional[Dict[str, Any]] = None,
) -> int:
    client = _get_client()
    if client is None or not findings:
        return 0

    repo_name = Path(repo_path).name
    stored = 0

    for finding in findings[:20]:
        try:
            vuln_type = finding.get("vuln_type", "unknown")
            cwe_id = finding.get("cwe_id", "")
            status = finding.get("final_status") or finding.get("status", "unknown")
            confidence = finding.get("confidence", "medium")
            file_path = finding.get("file", "unknown")
            function = finding.get("function", "unknown")

            ruling = finding.get("ruling", {})
            reason = ruling.get("reason", "")[:200] if ruling else ""
            disqualifier = ruling.get("disqualifier", "")

            content = (
                f"Validation verdict for {vuln_type}"
                f"{f' ({cwe_id})' if cwe_id else ''} "
                f"in {repo_name} ({file_path}:{function}): "
                f"status {status}, confidence {confidence}."
            )
            if reason:
                content += f" Reason: {reason}."
            if disqualifier:
                content += f" Disqualifier: {disqualifier}."

            conf_score = {
                "exploitable": 0.95,
                "likely_exploitable": 0.90,
                "confirmed": 0.90,
                "confirmed_constrained": 0.85,
                "confirmed_blocked": 0.85,
                "ruled_out": 0.90,
                "disproven": 0.90,
            }.get(status, 0.75)

            tags = ["validation", "verdict", vuln_type]
            if cwe_id:
                tags.append(cwe_id)

            if _propose_redacted(
                client=client,
                content=content,
                memory_type="fact",
                domain_tag=_validation_domain(repo_path),
                confidence=conf_score,
                tags=tags,
            ):
                stored += 1
            _throttle()
        except Exception as e:
            logger.debug(f"SAGE validation verdict store failed: {e}")

    if summary:
        try:
            total = summary.get("total_input", 0)
            confirmed = summary.get("confirmed", 0)
            ruled_out = summary.get("ruled_out", 0)
            exploitable = summary.get("exploitable", 0)
            content = (
                f"Validation summary for {repo_name}: "
                f"{total} findings validated, "
                f"{exploitable} exploitable, {confirmed} confirmed, "
                f"{ruled_out} ruled out."
            )
            _propose_redacted(
                client=client,
                content=content,
                memory_type="observation",
                domain_tag=_validation_domain(repo_path),
                confidence=0.85,
                tags=["validation", "summary"],
            )
        except Exception as e:
            logger.debug(f"SAGE validation summary store failed: {e}")

    if stored > 0:
        logger.info(f"SAGE: Stored {stored} validation verdicts")
    return stored


def store_validation_disproven(
    repo_path: str,
    disproven: List[Dict[str, Any]],
) -> None:
    client = _get_client()
    if client is None or not disproven:
        return
    try:
        for entry in disproven[:10]:
            finding_ref = entry.get("finding", "unknown")
            claim = entry.get("original_claim", "")[:200]
            why = entry.get("why_wrong", "")[:200]
            lesson = entry.get("lesson", "")[:200]
            content = (
                f"Disproven hypothesis for {finding_ref} in "
                f"{Path(repo_path).name}: claim was '{claim}'. "
                f"Why wrong: {why}. Lesson: {lesson}."
            )
            _propose_redacted(
                client=client,
                content=content,
                memory_type="inference",
                domain_tag=_validation_domain(repo_path),
                confidence=0.90,
                tags=["validation", "disproven"],
            )
            _throttle()
    except Exception as e:
        logger.debug(f"SAGE disproven store failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Code understanding hooks
# ─────────────────────────────────────────────────────────────────────────────

def recall_context_for_map(
    repo_path: str,
    languages: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    client = _get_client()
    if client is None:
        return []
    try:
        _sage_metrics["recall_attempted"] += 1
        lang_str = ", ".join(languages) if languages else "unknown"
        results = client.query(
            text=(
                f"Attack surface for {lang_str} project {Path(repo_path).name}: "
                f"entry points, sinks, trust boundaries, and unchecked flows"
            ),
            domain_tag=_understand_domain(repo_path),
            top_k=5,
            min_confidence=0.5,
        )
        methodology = client.query(
            text=(
                "Attack surface mapping methodology: entry point enumeration, "
                "sink cataloguing, and trust boundary identification."
            ),
            domain_tag="raptor-methodology",
            top_k=3,
            min_confidence=0.5,
        )
        merged = _merge_recall_rows(results, methodology, top_k=8)
        _sage_metrics["recall_hits"] += len(merged)
        return merged
    except Exception as e:
        logger.debug(f"SAGE map recall failed: {e}")
        return []


def recall_context_for_trace(
    repo_path: str,
    entry_point: Optional[str] = None,
    sink: Optional[str] = None,
) -> List[Dict[str, Any]]:
    client = _get_client()
    if client is None:
        return []
    try:
        _sage_metrics["recall_attempted"] += 1
        query_parts = ["Prior data flow traces"]
        if entry_point:
            query_parts.append(f"from entry point {entry_point}")
        if sink:
            query_parts.append(f"to sink {sink}")
        query_parts.append("including proximity, blockers, and attacker control")
        results = client.query(
            text=" ".join(query_parts) + ".",
            domain_tag=_understand_domain(repo_path),
            top_k=5,
            min_confidence=0.5,
        )
        merged = _merge_recall_rows(results, top_k=5)
        _sage_metrics["recall_hits"] += len(merged)
        return merged
    except Exception as e:
        logger.debug(f"SAGE trace recall failed: {e}")
        return []


def recall_context_for_hunt(
    repo_path: str,
    pattern: Optional[str] = None,
) -> List[Dict[str, Any]]:
    client = _get_client()
    if client is None:
        return []
    try:
        _sage_metrics["recall_attempted"] += 1
        query = "Prior variant hunt results"
        if pattern:
            query += f" for pattern {pattern}"
        query += ", including root cause groups and taint status distribution."
        results = client.query(
            text=query,
            domain_tag=_understand_domain(repo_path),
            top_k=5,
            min_confidence=0.5,
        )
        merged = _merge_recall_rows(results, top_k=5)
        _sage_metrics["recall_hits"] += len(merged)
        return merged
    except Exception as e:
        logger.debug(f"SAGE hunt recall failed: {e}")
        return []


def store_map_results(
    repo_path: str,
    context_map: Dict[str, Any],
) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        repo_name = Path(repo_path).name
        meta = context_map.get("meta", {})
        entry_points = context_map.get("entry_points", [])
        sinks = context_map.get("sink_details", context_map.get("sinks", []))
        boundaries = context_map.get("boundary_details", context_map.get("trust_boundaries", []))
        unchecked = context_map.get("unchecked_flows", [])

        ep_types = {}
        for ep in entry_points:
            t = ep.get("type", "unknown")
            ep_types[t] = ep_types.get(t, 0) + 1
        ep_summary = ", ".join(f"{v} {k}" for k, v in sorted(ep_types.items(), key=lambda x: -x[1]))

        sink_types = {}
        for s in sinks:
            t = s.get("type", "unknown")
            sink_types[t] = sink_types.get(t, 0) + 1
        sink_summary = ", ".join(f"{v} {k}" for k, v in sorted(sink_types.items(), key=lambda x: -x[1]))

        content = (
            f"Attack surface map for {repo_name}: "
            f"{len(entry_points)} entry points ({ep_summary}), "
            f"{len(sinks)} sinks ({sink_summary}), "
            f"{len(boundaries)} trust boundaries, "
            f"{len(unchecked)} unchecked flows."
        )
        if meta.get("frameworks"):
            content += f" Frameworks: {', '.join(meta['frameworks'])}."

        _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag=_understand_domain(repo_path),
            confidence=0.85,
            tags=["understand", "map", "summary"],
        )

        for flow in unchecked[:10]:
            ep_ref = flow.get("entry_point", "unknown")
            sink_ref = flow.get("sink", "unknown")
            missing = flow.get("missing_boundary", "unknown")
            flow_content = (
                f"Unchecked flow in {repo_name}: "
                f"entry {ep_ref} → sink {sink_ref}, "
                f"missing boundary: {missing}."
            )
            _propose_redacted(
                client=client,
                content=flow_content,
                memory_type="observation",
                domain_tag=_understand_domain(repo_path),
                confidence=0.80,
                tags=["understand", "map", "unchecked_flow"],
            )
            _throttle()
    except Exception as e:
        logger.debug(f"SAGE map store failed: {e}")


def store_trace_result(
    repo_path: str,
    trace: Dict[str, Any],
) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        repo_name = Path(repo_path).name
        trace_id = trace.get("id", "unknown")
        meta = trace.get("meta", {})
        entry = meta.get("entry_point", "unknown")
        sink = meta.get("target_sink", "unknown")
        steps = trace.get("steps", [])
        proximity = trace.get("proximity", 0)
        blockers = trace.get("blockers", [])
        attacker = trace.get("attacker_control", {})
        summary = trace.get("summary", {})

        content = (
            f"Flow trace {trace_id} in {repo_name}: "
            f"{entry} → {sink}, "
            f"{len(steps)} steps, proximity {proximity}/10."
        )
        if attacker:
            content += f" Attacker control: {attacker.get('level', 'unknown')}."
        if blockers:
            content += f" Blockers: {', '.join(str(b) for b in blockers[:3])}."
        if summary.get("verdict"):
            content += f" Verdict: {summary['verdict']}."

        confidence = 0.85 if summary.get("flow_confirmed") else 0.75

        _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag=_understand_domain(repo_path),
            confidence=confidence,
            tags=["understand", "trace", trace_id],
        )
    except Exception as e:
        logger.debug(f"SAGE trace store failed: {e}")


def store_hunt_results(
    repo_path: str,
    variants_data: Dict[str, Any],
) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        repo_name = Path(repo_path).name
        meta = variants_data.get("meta", {})
        pattern = meta.get("pattern", "unknown")
        total = meta.get("total_matches", 0)
        confirmed = meta.get("confirmed_tainted", 0)
        likely = meta.get("likely_tainted", 0)
        fp = meta.get("false_positive", 0)
        groups = variants_data.get("root_cause_groups", [])

        content = (
            f"Variant hunt for pattern '{pattern}' in {repo_name}: "
            f"{total} matches ({confirmed} confirmed, {likely} likely, {fp} FP). "
            f"{len(groups)} root cause groups."
        )
        if groups:
            group_names = [g.get("name", "?") for g in groups[:5]]
            content += f" Groups: {', '.join(group_names)}."

        _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag=_understand_domain(repo_path),
            confidence=0.85,
            tags=["understand", "hunt", pattern],
        )

        for group in groups[:5]:
            g_name = group.get("name", "unknown")
            g_count = group.get("count") or 0
            g_fix = group.get("fix_strategy", "")[:200]
            group_content = (
                f"Root cause group '{g_name}' in {repo_name}: "
                f"{g_count} variants. Fix strategy: {g_fix}."
            )
            _propose_redacted(
                client=client,
                content=group_content,
                memory_type="inference",
                domain_tag=_understand_domain(repo_path),
                confidence=0.85,
                tags=["understand", "hunt", "root_cause", g_name],
            )
            _throttle()
    except Exception as e:
        logger.debug(f"SAGE hunt store failed: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Exploit hooks
# ─────────────────────────────────────────────────────────────────────────────

def recall_context_for_exploit(
    repo_path: str,
    vuln_type: Optional[str] = None,
    cwe_id: Optional[str] = None,
    mitigations: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Recall past exploit techniques and outcomes for this repo/vuln class."""
    client = _get_client()
    if client is None:
        return []
    try:
        _sage_metrics["recall_attempted"] += 1
        query_parts = ["Prior exploit attempts, successful techniques, and mitigation bypasses"]
        if vuln_type:
            query_parts.append(f"for {vuln_type}")
        if cwe_id:
            query_parts.append(f"({cwe_id})")
        if mitigations:
            query_parts.append(f"against mitigations: {', '.join(mitigations)}")
        results = client.query(
            text=" ".join(query_parts) + ".",
            domain_tag=_exploits_domain(repo_path),
            top_k=5,
            min_confidence=0.5,
        )
        methodology = client.query(
            text=(
                "Exploit development methodology: technique selection, "
                "mitigation bypass, and PoC construction patterns."
            ),
            domain_tag="raptor-methodology",
            top_k=3,
            min_confidence=0.5,
        )
        merged = _merge_recall_rows(results, methodology, top_k=8)
        _sage_metrics["recall_hits"] += len(merged)
        return merged
    except Exception as e:
        logger.debug(f"SAGE exploit recall failed: {e}")
        return []


def store_exploit_outcomes(
    repo_path: str,
    outcomes: List[Dict[str, Any]],
) -> int:
    """Store exploit attempt outcomes for cross-run learning.

    Each outcome dict may contain:
        finding_id, vuln_type, cwe_id, technique, result
        (success/blocked/partial/not_attempted), mitigations_encountered,
        has_exploit (bool), file_path.

    Returns number of outcomes stored.
    """
    client = _get_client()
    if client is None or not outcomes:
        return 0

    repo_name = Path(repo_path).name
    stored = 0

    for outcome in outcomes[:20]:
        try:
            vuln_type = outcome.get("vuln_type", outcome.get("rule_id", "unknown"))
            result = outcome.get("result", "")
            technique = outcome.get("technique", "")
            mitigations = outcome.get("mitigations_encountered", [])
            cwe_id = outcome.get("cwe_id", "")
            file_path = outcome.get("file_path", outcome.get("file", ""))
            has_exploit = outcome.get("has_exploit", False)

            if not result and has_exploit:
                result = "success"
            elif not result:
                result = "not_attempted"

            parts = [
                f"Exploit attempt for {vuln_type} in {repo_name}",
            ]
            if file_path:
                parts.append(f"({file_path})")
            parts.append(f"— result: {result}.")
            if technique:
                parts.append(f"Technique: {technique}.")
            if mitigations:
                parts.append(f"Mitigations encountered: {', '.join(mitigations)}.")
            if cwe_id:
                parts.append(f"CWE: {cwe_id}.")

            content = " ".join(parts)

            confidence = {
                "success": 0.95,
                "partial": 0.85,
                "blocked": 0.80,
            }.get(result, 0.70)

            tags = ["exploit", result]
            if technique:
                tags.append(technique)

            _propose_redacted(
                client=client,
                content=content,
                memory_type="fact" if result == "success" else "observation",
                domain_tag=_exploits_domain(repo_path),
                confidence=confidence,
                tags=tags,
            )
            stored += 1
            _throttle()
        except Exception as e:
            logger.debug(f"SAGE exploit outcome store failed for {outcome.get('finding_id', '?')}: {e}")

    if stored:
        logger.info(f"SAGE: stored {stored} exploit outcomes for {repo_name}")
    return stored
