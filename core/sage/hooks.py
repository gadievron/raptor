"""
SAGE pipeline hooks for RAPTOR.

Mechanical hooks that make hard decisions (skip, suppress, reorder,
set flags) based on SAGE recall. Every hook is a no-op when SAGE is
unavailable.

Prompt-injection hooks (recalled text dropped into LLM prompts) were
removed — they had no measurable effect and no guarantee the LLM
weighed them correctly.
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

_client_lock = threading.Lock()
_client: Optional[SageClient] = None
_client_initialised: bool = False
_client_none_decided_at: float = 0.0
_CLIENT_NONE_TTL_S: float = 300.0
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
    if not repo_path:
        return ""
    if "://" in repo_path:
        return sha256_string(repo_path.strip().lower())[:12]
    resolved = str(Path(repo_path).resolve())
    return sha256_string(resolved)[:12]


def _findings_domain(repo_path: str) -> str:
    return f"raptor-findings-{_repo_key(repo_path)}"


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
# Recall utilities (used by mechanical consumers)
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


# ─────────────────────────────────────────────────────────────────────────────
# Fuzzing — mechanical AFL flag inference
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# CodeQL build flags — recall + store (upgrade to mechanical pending U1)
# ─────────────────────────────────────────────────────────────────────────────

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


# ─────────────────────────────────────────────────────────────────────────────
# Fuzzing — strategy recall + store (mechanical consumers)
# ─────────────────────────────────────────────────────────────────────────────

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
# Finding verdict — cross-run FP suppression (generalised SCA pattern)
# ─────────────────────────────────────────────────────────────────────────────

_SUPPRESS_VERDICTS = frozenset({"false_positive", "not_exploitable"})

_VERDICT_CONFIDENCE: Dict[str, float] = {
    "false_positive": 0.95,
    "not_exploitable": 0.90,
    "exploitable": 0.95,
    "true_positive": 0.90,
}


def _fp_domain(repo_path: str) -> str:
    return f"raptor-fp-{_repo_key(repo_path)}"


def _finding_fingerprint(rule_id: str, file_path: str, function: str) -> str:
    raw = f"{rule_id}|{file_path}|{function}"
    return sha256_string(raw)[:16]


def compute_finding_source_hash(
    file_path: Path,
    line: int,
    window: int = 10,
) -> str:
    """Hash the source lines around a finding for staleness detection.

    Returns SHA-256[:12] via ``core.staleness.hash_span``, or ``""``
    if the file is unreadable or ``line`` is invalid.
    """
    from core.staleness import hash_span
    start = max(1, line - window)
    end = line + window
    return hash_span(file_path, start, end)


def recall_prior_finding_verdict(
    repo_path: str,
    rule_id: str,
    file_path: str,
    function: str,
    source_hash: str,
) -> Optional[Dict[str, Any]]:
    """Recall a prior finding verdict from SAGE.

    Returns ``{verdict, source_hash, confidence}`` if a suppressible
    prior verdict exists AND the stored source_hash matches.  Returns
    ``None`` otherwise (no prior, hash mismatch, or non-suppressible
    verdict).
    """
    if not source_hash:
        return None
    client = _get_client()
    if client is None:
        return None
    try:
        _sage_metrics["recall_attempted"] += 1
        results = client.query(
            text=(
                f"Finding verdict: rule={rule_id} "
                f"file={file_path} fn={function}"
            ),
            domain_tag=_fp_domain(repo_path),
            top_k=3,
            min_confidence=0.7,
        )
        for row in results:
            content = str(row.get("content") or "")
            if f"||src={source_hash}||" not in content:
                continue
            for v in _SUPPRESS_VERDICTS:
                if f"||verdict={v}||" in content:
                    _sage_metrics["recall_hits"] += 1
                    return {
                        "verdict": v,
                        "source_hash": source_hash,
                        "confidence": recall_row_confidence(row),
                    }
        return None
    except Exception as e:
        logger.debug("SAGE FP recall failed: %s", e)
        return None


def store_finding_verdict(
    repo_path: str,
    rule_id: str,
    file_path: str,
    function: str,
    source_hash: str,
    verdict: str,
) -> bool:
    """Store a finding verdict to SAGE for cross-run FP suppression.

    All verdicts are stored (building the knowledge base), but only
    ``false_positive`` and ``not_exploitable`` trigger suppression on
    future recall.
    """
    if not source_hash:
        return False
    client = _get_client()
    if client is None:
        return False
    try:
        fp = _finding_fingerprint(rule_id, file_path, function)
        return _propose_redacted(
            client=client,
            content=(
                f"Finding verdict: fp={fp} rule={rule_id} "
                f"file={file_path} fn={function} "
                f"||src={source_hash}|| ||verdict={verdict}||"
            ),
            memory_type="fact",
            domain_tag=_fp_domain(repo_path),
            confidence=_VERDICT_CONFIDENCE.get(verdict, 0.80),
            tags=["finding", "verdict", verdict, rule_id],
        )
    except Exception as e:
        logger.debug("SAGE FP store failed: %s", e)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# SCA (Software Composition Analysis) — mechanical short-circuit
# ─────────────────────────────────────────────────────────────────────────────

def _sca_domain(repo_path: str) -> str:
    return f"raptor-sca-{_repo_key(repo_path)}"


def recall_context_for_sca(
    repo_path: str,
    ecosystems: Optional[List[str]] = None,
    dep_names: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Recall prior SCA verdicts and confirmed-bad packages.

    Queries the repo-scoped SCA domain for past dependency findings
    (malicious packages, FP rulings, vulnerability patterns) and
    global methodology for supply-chain analysis.

    Returns recalled memories (content, confidence, domain).
    Empty list if SAGE unavailable.
    """
    client = _get_client()
    if client is None:
        return []
    try:
        _sage_metrics["recall_attempted"] += 1
        query_parts = [
            "Prior SCA findings: confirmed malicious packages,"
            " false-positive rulings, supply-chain attack patterns"
        ]
        if ecosystems:
            query_parts.append(f"for ecosystems: {', '.join(ecosystems)}")
        if dep_names:
            query_parts.append(
                f"involving packages: {', '.join(dep_names[:10])}"
            )

        results = client.query(
            text=" ".join(query_parts) + ".",
            domain_tag=_sca_domain(repo_path),
            top_k=8,
            min_confidence=0.5,
        )
        methodology = client.query(
            text=(
                "Supply-chain security methodology: typosquat detection,"
                " slopsquat identification, malicious package indicators,"
                " dependency confusion patterns."
            ),
            domain_tag="raptor-methodology",
            top_k=3,
            min_confidence=0.5,
        )
        merged = _merge_recall_rows(results, methodology, top_k=10)
        _sage_metrics["recall_hits"] += len(merged)
        if merged:
            logger.info(
                f"SAGE: Recalled {len(merged)} SCA memories for context"
            )
        return merged
    except Exception as e:
        logger.debug(f"SAGE SCA recall failed: {e}")
        return []


def store_sca_outcomes(
    repo_path: str,
    outcomes: List[Dict[str, Any]],
) -> int:
    """Store SCA finding outcomes for cross-run learning.

    Each outcome dict may contain:
        package_name, ecosystem, kind (SupplyChainKind or "vuln"),
        verdict (malicious_confirmed/false_positive/vulnerable/
                 not_applicable/suspect),
        version, detail, severity, cve_ids (list), llm_summary.

    Returns number of outcomes stored.
    """
    client = _get_client()
    if client is None or not outcomes:
        return 0

    repo_name = Path(repo_path).name
    stored = 0

    for outcome in outcomes[:30]:
        try:
            pkg = outcome.get("package_name", "unknown")
            eco = outcome.get("ecosystem", "")
            kind = outcome.get("kind", "")
            verdict = outcome.get("verdict", "suspect")
            version = outcome.get("version", "")
            detail = outcome.get("detail", "")
            severity = outcome.get("severity", "")
            cve_ids = outcome.get("cve_ids") or []
            llm_summary = outcome.get("llm_summary", "")

            parts = [f"SCA: {pkg}"]
            if eco:
                parts.append(f"({eco})")
            if version:
                parts.append(f"v{version}")
            parts.append(f"in {repo_name} — verdict: {verdict}.")
            if kind:
                parts.append(f"Kind: {kind}.")
            if cve_ids:
                parts.append(f"CVEs: {', '.join(cve_ids[:5])}.")
            if severity:
                parts.append(f"Severity: {severity}.")
            if detail:
                parts.append(detail[:200])
            if llm_summary:
                parts.append(f"LLM: {llm_summary[:150]}")

            content = " ".join(parts)

            confidence = {
                "malicious_confirmed": 0.98,
                "false_positive": 0.92,
                "vulnerable": 0.88,
                "not_applicable": 0.85,
                "suspect": 0.75,
            }.get(verdict, 0.70)

            memory_type = "fact" if verdict in (
                "malicious_confirmed", "false_positive"
            ) else "observation"

            tags = ["sca", kind] if kind else ["sca"]
            if eco:
                tags.append(eco)
            tags.append(verdict)

            if _propose_redacted(
                client=client,
                content=content,
                memory_type=memory_type,
                domain_tag=_sca_domain(repo_path),
                confidence=confidence,
                tags=tags,
            ):
                stored += 1
            _throttle()
        except Exception as e:
            logger.debug(
                f"SAGE SCA store failed for {outcome.get('package_name', '?')}: {e}"
            )

    if stored:
        logger.info(f"SAGE: stored {stored} SCA outcomes for {repo_name}")
    return stored
