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
import re
import threading
import time
from pathlib import Path
from typing import Any

from core.config import env_flag
from core.hash import sha256_string
from core.logging import get_logger
from core.security.redaction import redact_secrets

from . import rowmac
from .client import SageClient
from .config import SageConfig

logger = get_logger()

_client_lock = threading.Lock()
_client: SageClient | None = None
_client_initialised: bool = False
_client_none_decided_at: float = 0.0
_CLIENT_NONE_TTL_S: float = 300.0
_metrics_lock = threading.Lock()
_sage_metrics: dict[str, int] = {
    "propose_attempted": 0,
    "propose_succeeded": 0,
    "propose_failed": 0,
    "recall_attempted": 0,
    "recall_hits": 0,
}


def _metric_inc(key: str, n: int = 1) -> None:
    with _metrics_lock:
        _sage_metrics[key] += n

_ollama_has_gpu: bool | None = None


def _ollama_gpu_available() -> bool:
    """Detect GPU by checking size_vram on Ollama's loaded models.

    Cached for the process lifetime. Falls back to False on any error.
    """
    global _ollama_has_gpu
    if _ollama_has_gpu is not None:
        return _ollama_has_gpu
    try:
        import httpx

        from .config import ensure_loopback_no_proxy

        # Without this, a proxied shell routes the probe to the proxy and
        # a GPU host silently misreports as CPU-only (halved recall
        # workers, direct-embed path chosen on a wrong premise).
        ensure_loopback_no_proxy()
        resp = httpx.get("http://localhost:11435/api/ps", timeout=5)
        if resp.status_code == 200:
            for model in resp.json().get("models", []):
                # Full offload (size_vram >= size), not size_vram > 0:
                # Ollama 0.32 reports a non-zero size_vram even when the
                # model runs on pure CPU (server logs library=cpu,
                # total_vram=0B), so the >0 test misdetects GPU and
                # re-introduces the 30s SAGE-side embed ceiling. A truly
                # GPU-resident model is fully offloaded; anything less
                # falls back to the direct-embed path, which works on
                # both CPU and GPU.
                size = model.get("size", 0)
                if size > 0 and model.get("size_vram", 0) >= size:
                    _ollama_has_gpu = True
                    return True
        _ollama_has_gpu = False
    except Exception:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        _ollama_has_gpu = False
    return _ollama_has_gpu


def _recall_workers() -> int:
    """SAGE recall concurrency: 4 with GPU, 2 without. Override: SAGE_RECALL_WORKERS."""
    env = os.getenv("SAGE_RECALL_WORKERS")
    if env:
        try:
            return max(1, min(int(env), 8))
        except (TypeError, ValueError):
            pass
    return 4 if _ollama_gpu_available() else 2


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


def _get_client() -> SageClient | None:
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
            if not _ollama_gpu_available() and not env_flag(
                "SAGE_FORCE_CPU", default=False
            ):
                logger.debug(
                    "SAGE pipeline hooks disabled on CPU — too slow for "
                    "automated use. Set SAGE_FORCE_CPU=1 to override. "
                    "MCP tools (sage_recall etc.) still work for manual use."
                )
                _client = None
                _client_none_decided_at = time.time()
                _client_initialised = True
                return _client
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
            except Exception as exc:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
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
    tags: list[str] | None = None,
) -> bool:
    _metric_inc("propose_attempted")
    redacted_content = redact_secrets(content)
    ok = client.propose(
        content=redacted_content,
        memory_type=memory_type,
        domain_tag=domain_tag,
        confidence=confidence,
        tags=tags,
    )
    if ok:
        _metric_inc("propose_succeeded")
    else:
        _metric_inc("propose_failed")
    return ok


# ─────────────────────────────────────────────────────────────────────────────
# Recall utilities (used by mechanical consumers)
# ─────────────────────────────────────────────────────────────────────────────

def _sanitise_delim(value: str) -> str:
    """Strip ``|`` from a value before embedding in ``||key=value||``."""
    return str(value).replace("|", "")


def _stamp_row(hook: str, content: str, fields: dict[str, str]) -> str:
    """Append the row-MAC token for *fields* to *content* (store side).

    Stamping is unconditional and invisible to SAGE (just longer
    content). If minting fails (e.g. the key directory is unwritable),
    the row is stored unstamped — it then simply never earns mechanical
    effect, which is the safe direction.
    """
    try:
        return rowmac.stamp(content, fields)
    except Exception as exc:  # noqa: BLE001 — stamping must never block a store
        logger.debug("SAGE %s: could not stamp row (%s) — storing unstamped", hook, exc)
        return content


def _row_mac_ok(hook: str, fields: dict[str, str], token: str | None) -> bool:
    """Gate a mechanical decision on the row's MAC token (recall side).

    Returns True only when the row carries a token minted by this
    install over exactly *fields*. On any failure the caller must
    behave as if no memory existed; this helper emits the single debug
    log naming the hook and the reason. Never raises.
    """
    if not token:
        logger.debug(
            "SAGE %s: recall row has no MAC token — mechanical use demoted to hint",
            hook,
        )
        return False
    if not rowmac.verify(fields, token):
        logger.debug(
            "SAGE %s: recall row failed MAC verification — mechanical use demoted to hint",
            hook,
        )
        return False
    return True


def recall_row_confidence(row: dict[str, Any]) -> float:
    """Parse 0–1 confidence from a SAGE recall row (missing → 0)."""
    try:
        return float(row.get("confidence") or 0.0)
    except (TypeError, ValueError):
        return 0.0


def pick_strongest_recall_row(
    rows: list[dict[str, Any]],
    *,
    min_confidence: float = 0.0,
) -> dict[str, Any] | None:
    """Return the highest-confidence recall row, or None if below ``min_confidence``."""
    if not rows:
        return None
    best = max(rows, key=recall_row_confidence)
    if recall_row_confidence(best) < min_confidence:
        return None
    return best


def _merge_recall_rows(
    *hit_lists: list[list[dict[str, Any]]],
    top_k: int | None = None,
) -> list[dict[str, Any]]:
    """Merge SAGE query rows from multiple domains with stable priority.

    Lists are consumed in order so repo-scoped hits precede global
    methodology; duplicate ``content`` strings are dropped.
    """
    seen: set = set()
    out: list[dict[str, Any]] = []
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
    row: dict[str, Any] | None,
) -> list[str]:
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

    Flags are only appended when the row carries a valid MAC token
    (minted by ``store_fuzzing_strategy_outcome`` on this install) over
    the decision fields (kind, strategy, fingerprint, flag set). Rows
    without a valid token contribute no flags — the strategy text still
    surfaces as a hint via the recall log.
    """
    if not row:
        return []
    clean, token = rowmac.strip(str(row.get("content") or ""))
    flags = _afl_flags_from_text(clean)
    if not flags:
        return []
    match = re.search(r": strategy (.+?), binary fingerprint (.+?), duration", clean)
    fields = {
        "kind": "afl_flags",
        "strategy": match.group(1) if match else "",
        "fingerprint": match.group(2) if match else "",
        "flags": " ".join(flags),
    }
    if not _row_mac_ok("afl_flags", fields, token):
        return []
    return flags


def _afl_flags_from_text(text: str) -> list[str]:
    """Derive the conservative ``afl-fuzz`` flag tokens from row text.

    Shared by the store side (to bind the derived flag set into the
    row's MAC fields) and the recall side (to re-derive and verify).
    """
    text = str(text or "").lower()
    parts: list[str] = []
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


def _dedupe_afl_flag_tokens(tokens: list[str]) -> list[str]:
    """Order-preserving dedupe for ``afl-fuzz`` argv fragments."""
    out: list[str] = []
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
    languages: list[str] | None = None,
) -> list[dict[str, Any]]:
    client = _get_client()
    if client is None:
        return []
    try:
        _metric_inc("recall_attempted")
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
        _metric_inc("recall_hits", len(merged))
        return merged
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE codeql recall failed: %s", e)
        return []


def store_codeql_build_reliability(
    repo_path: str,
    languages: list[str],
    build_command: str,
    auto_detect_outcome: str,
    analyses_completed: int,
    failure_modes: list[str] | None = None,
) -> None:
    client = _get_client()
    if client is None:
        return
    try:
        failures = ", ".join(failure_modes or []) or "none"
        lang_str = ", ".join(languages) or "unknown"
        confidence = 0.85 if auto_detect_outcome == "success" else 0.75
        repo_key = _repo_key(repo_path)
        content = (
            f"CodeQL build reliability for repo {Path(repo_path).name}: "
            f"languages {lang_str}, outcome {auto_detect_outcome}, "
            f"build command {build_command}, analyses completed {analyses_completed}, "
            f"failure modes {failures}. ||repo={repo_key}||"
        )
        content = _stamp_row(
            "codeql_build",
            content,
            {
                "kind": "codeql_build",
                "repo": repo_key,
                "outcome": auto_detect_outcome,
                "build_command": build_command,
                "languages": lang_str,
            },
        )
        _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag="raptor-methodology",
            confidence=confidence,
            tags=["codeql", "build", auto_detect_outcome],
        )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE codeql reliability store failed: %s", e)


def infer_codeql_build_from_sage_recall_row(
    row: dict[str, Any] | None,
) -> dict[str, str]:
    """Extract a build hint from a SAGE CodeQL build-reliability row.

    Returns a dict with ``outcome``, and optionally ``build_command``
    and ``languages``.  Empty dict if nothing useful can be parsed.

    Recognised content shape (written by ``store_codeql_build_reliability``)::

      "CodeQL build reliability for repo X: languages cpp, outcome success,
       build command cmake ..., analyses completed 5, failure modes none."

    Only returns ``build_command`` when ``outcome`` is ``success`` — a
    prior failure is useful for avoidance logging but not for mechanical
    override.

    ``build_command`` additionally requires the row's MAC token (minted
    by ``store_codeql_build_reliability`` on this install) to verify
    over the decision fields (kind, repo key, outcome, build command,
    languages). Rows without a valid token still yield ``outcome`` /
    ``languages`` as hints, but never a replayable command — an
    unverified row must not produce a BuildSystem. The parsed command
    is instead surfaced as ``unverified_build_command`` so the consumer
    can show it to the operator as a hint (never execute it).
    """
    if not row:
        return {}
    text, token = rowmac.strip(str(row.get("content") or ""))
    out: dict[str, str] = {}

    m_outcome = re.search(r"outcome (\w+)", text)
    if m_outcome:
        out["outcome"] = m_outcome.group(1)

    m_lang = re.search(r"languages ([^,]+(?:, [^,]+)*), outcome", text)
    if m_lang:
        out["languages"] = m_lang.group(1).strip()

    m_cmd = re.search(r"build command (.+?), analyses completed", text)
    if m_cmd and out.get("outcome") == "success":
        cmd = m_cmd.group(1).strip()
        if cmd and cmd != "auto":
            m_repo = re.search(r"\|\|repo=([0-9a-f]{12})\|\|", text)
            fields = {
                "kind": "codeql_build",
                "repo": m_repo.group(1) if m_repo else "",
                "outcome": out["outcome"],
                "build_command": cmd,
                "languages": out.get("languages", ""),
            }
            if _row_mac_ok("codeql_build", fields, token):
                out["build_command"] = cmd
            else:
                out["unverified_build_command"] = cmd

    return out


# ─────────────────────────────────────────────────────────────────────────────
# Fuzzing — strategy recall + store (mechanical consumers)
# ─────────────────────────────────────────────────────────────────────────────

def recall_context_for_fuzzing_strategy(
    repo_path: str,
    binary_fingerprint: str,
    strategy_id: str | None = None,
) -> list[dict[str, Any]]:
    client = _get_client()
    if client is None:
        return []
    try:
        _metric_inc("recall_attempted")
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
        _metric_inc("recall_hits", len(merged))
        return merged
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE fuzzing recall failed: %s", e)
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
        content = _stamp_row(
            "afl_flags",
            content,
            {
                "kind": "afl_flags",
                "strategy": strategy_id,
                "fingerprint": binary_fingerprint,
                "flags": " ".join(_afl_flags_from_text(content)),
            },
        )
        _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag="raptor-fuzzing",
            confidence=confidence,
            tags=["fuzzing", "strategy", strategy_id],
        )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE fuzzing strategy store failed: %s", e)


# ─────────────────────────────────────────────────────────────────────────────
# Finding verdict — cross-run FP suppression (generalised SCA pattern)
# ─────────────────────────────────────────────────────────────────────────────

_SUPPRESS_VERDICTS = frozenset({"false_positive", "not_exploitable"})

_VERDICT_CONFIDENCE: dict[str, float] = {
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
) -> dict[str, Any] | None:
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
        _metric_inc("recall_attempted")
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
            content, token = rowmac.strip(str(row.get("content") or ""))
            if f"||src={source_hash}||" not in content:
                continue
            for v in _SUPPRESS_VERDICTS:
                if f"||verdict={v}||" in content:
                    fields = {
                        "kind": "finding_verdict",
                        "repo": _repo_key(repo_path),
                        "fp": _finding_fingerprint(rule_id, file_path, function),
                        "verdict": v,
                        "src": source_hash,
                    }
                    if not _row_mac_ok("finding_verdict", fields, token):
                        break
                    _metric_inc("recall_hits")
                    return {
                        "verdict": v,
                        "source_hash": source_hash,
                        "confidence": recall_row_confidence(row),
                    }
        return None
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
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
        _s = _sanitise_delim
        content = (
            f"Finding verdict: fp={fp} rule={_s(rule_id)} "
            f"file={_s(file_path)} fn={_s(function)} "
            f"||src={_s(source_hash)}|| ||verdict={_s(verdict)}||"
        )
        content = _stamp_row(
            "finding_verdict",
            content,
            {
                "kind": "finding_verdict",
                "repo": _repo_key(repo_path),
                "fp": fp,
                "verdict": verdict,
                "src": source_hash,
            },
        )
        return _propose_redacted(
            client=client,
            content=content,
            memory_type="fact",
            domain_tag=_fp_domain(repo_path),
            confidence=_VERDICT_CONFIDENCE.get(verdict, 0.80),
            tags=["finding", "verdict", verdict, rule_id],
        )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE FP store failed: %s", e)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Rule library — proven checker accumulation across runs
# ─────────────────────────────────────────────────────────────────────────────

_RULE_LIBRARY_DOMAIN = "raptor-rule-library"

_RULE_REPLAY_MIN_TP_RATE = 0.8
_RULE_REPLAY_MIN_TARGETS = 3


def store_proven_rule_metadata(
    *,
    engine: str,
    cwe: str,
    rule_id: str,
    rule_body_hash: str,
    rule_path: str,
    tp_count: int,
    fp_count: int,
    total_matches: int,
    dual_control_passed: bool,
    targets_tested: int = 1,
) -> bool:
    """Store metadata for a proven checker rule in SAGE.

    Rule body lives on disk at ``rule_path`` — SAGE holds the index
    only.  Keyed by ``engine + cwe + rule_body_hash`` so duplicate
    rules across targets converge on one memory (SAGE dedupes by
    semantic similarity within the domain).
    """
    client = _get_client()
    if client is None:
        return False
    try:
        confidence = 0.90 if dual_control_passed else 0.75
        _s = _sanitise_delim
        content = (
            f"Proven checker rule: "
            f"||engine={_s(engine)}|| ||cwe={_s(cwe)}|| "
            f"||rule_id={_s(rule_id)}|| "
            f"||rule_body_hash={_s(rule_body_hash)}|| "
            f"||rule_path={_s(rule_path)}|| "
            f"||tp_count={tp_count}|| "
            f"||fp_count={fp_count}|| "
            f"||total_matches={total_matches}|| "
            f"||dual_control={dual_control_passed}|| "
            f"||targets_tested={targets_tested}||"
        )
        # The MAC gates mechanical replay on the recall side
        # (``recall_verified_proven_rules``): only rows minted by this
        # install may join sweeps; everything else is hint-only.
        content = _stamp_row(
            "proven_rule",
            content,
            {
                "kind": "proven_rule",
                "engine": _s(engine),
                "cwe": _s(cwe),
                "rule_id": _s(rule_id),
                "rule_body_hash": _s(rule_body_hash),
                "rule_path": _s(rule_path),
                "tp_count": str(tp_count),
                "fp_count": str(fp_count),
                "total_matches": str(total_matches),
                "dual_control": str(dual_control_passed),
                "targets_tested": str(targets_tested),
            },
        )
        return _propose_redacted(
            client=client,
            content=content,
            memory_type="fact",
            domain_tag=_RULE_LIBRARY_DOMAIN,
            confidence=confidence,
            tags=["rule-library", engine, cwe, rule_id],
        )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE rule library store failed: %s", e)
        return False


def recall_proven_rules(
    engine: str,
    cwe: str,
) -> list[dict[str, Any]]:
    """Recall proven checker rules from SAGE by engine and CWE.

    Returns raw recall rows.  Use ``parse_rule_metadata`` to extract
    structured fields from each row's content.
    """
    client = _get_client()
    if client is None:
        return []
    try:
        _metric_inc("recall_attempted")
        results = client.query(
            text=f"Proven checker rule engine={engine} cwe={cwe}",
            domain_tag=_RULE_LIBRARY_DOMAIN,
            top_k=5,
            min_confidence=0.7,
        )
        if results:
            _metric_inc("recall_hits", len(results))
        return results
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE rule library recall failed: %s", e)
        return []


def parse_rule_metadata(row: dict[str, Any]) -> dict[str, Any]:
    """Extract structured fields from a rule-library recall row.

    Returns a dict with string/int/bool fields parsed from the
    ``||key=value||`` delimiters.  Missing fields are omitted.
    """
    content = str(row.get("content") or "")
    out: dict[str, Any] = {}

    for key in (
        "engine", "cwe", "rule_id", "rule_body_hash", "rule_path",
    ):
        m = re.search(rf"\|\|{key}=(.+?)\|\|", content)
        if m:
            out[key] = m.group(1)

    for key in ("tp_count", "fp_count", "total_matches", "targets_tested"):
        m = re.search(rf"\|\|{key}=(\d+)\|\|", content)
        if m:
            out[key] = int(m.group(1))

    m_dc = re.search(r"\|\|dual_control=(True|False)\|\|", content)
    if m_dc:
        out["dual_control"] = m_dc.group(1) == "True"

    out["confidence"] = recall_row_confidence(row)
    return out


def should_replay_rule(meta: dict[str, Any]) -> bool:
    """Whether a recalled rule qualifies for direct replay (skip synthesis).

    Requires: TP rate >80%, dual control passed, tested on 3+ targets.
    """
    tp = meta.get("tp_count", 0)
    fp = meta.get("fp_count", 0)
    total = tp + fp
    if total == 0:
        return False
    tp_rate = tp / total
    return (
        tp_rate >= _RULE_REPLAY_MIN_TP_RATE
        and meta.get("dual_control", False)
        and meta.get("targets_tested", 0) >= _RULE_REPLAY_MIN_TARGETS
    )


def recall_verified_proven_rules(engine: str, cwe: str) -> list[dict[str, Any]]:
    """Recall proven rules, keeping only HMAC-verified replay-worthy rows.

    Mechanical consumers (sweep replay in
    ``core.audit.checker_synthesis``) must call THIS, not
    ``recall_proven_rules``: unverified recall is hint-only per
    operator policy. A row is returned (as parsed metadata, see
    ``parse_rule_metadata``) only when

    * it carries a row MAC minted by THIS install over exactly the
      parsed decision fields (``_row_mac_ok``), and
    * it passes the ``should_replay_rule`` quality gate (TP rate,
      dual control, targets tested).

    Never raises; returns ``[]`` when SAGE is unavailable.
    """
    verified: list[dict[str, Any]] = []
    for row in recall_proven_rules(engine, cwe):
        try:
            content = str(row.get("content") or "")
            clean, token = rowmac.strip(content)
            meta = parse_rule_metadata({**row, "content": clean})
            fields = {
                "kind": "proven_rule",
                "engine": str(meta.get("engine", "")),
                "cwe": str(meta.get("cwe", "")),
                "rule_id": str(meta.get("rule_id", "")),
                "rule_body_hash": str(meta.get("rule_body_hash", "")),
                "rule_path": str(meta.get("rule_path", "")),
                "tp_count": str(meta.get("tp_count", 0)),
                "fp_count": str(meta.get("fp_count", 0)),
                "total_matches": str(meta.get("total_matches", 0)),
                "dual_control": str(meta.get("dual_control", False)),
                "targets_tested": str(meta.get("targets_tested", 0)),
            }
            if not _row_mac_ok("proven_rule", fields, token):
                continue
            if not should_replay_rule(meta):
                continue
            meta["verified"] = True
            verified.append(meta)
        except Exception:
            logger.debug("SAGE proven-rule row parse failed", exc_info=True)
    return verified


# ─────────────────────────────────────────────────────────────────────────────
# Audit — hypothesis verdict recall + observation transfer
# ─────────────────────────────────────────────────────────────────────────────

_AUDIT_DOMAIN = "raptor-audit"

_AUDIT_SKIP_STATUSES = frozenset({"clean", "dormant"})


def _audit_domain(repo_path: str) -> str:
    return f"{_AUDIT_DOMAIN}-{_repo_key(repo_path)}"


def store_audit_hypothesis_verdict(
    repo_path: str,
    file_path: str,
    function: str,
    hypothesis: str,
    status: str,
    evidence_tool: str,
    source_hash: str,
) -> bool:
    """Store an audit hypothesis verdict to SAGE.

    Keyed on file + function + hypothesis hash + source hash so the
    same hypothesis on unchanged source is recalled and skipped on
    re-audit.
    """
    if not source_hash or not hypothesis:
        return False
    client = _get_client()
    if client is None:
        return False
    try:
        hyp_hash = sha256_string(hypothesis)[:16]
        _s = _sanitise_delim
        confidence = 0.90 if evidence_tool else 0.75
        content = (
            f"Audit hypothesis verdict: "
            f"||file={_s(file_path)}|| ||fn={_s(function)}|| "
            f"||hyp={_s(hyp_hash)}|| ||src={_s(source_hash)}|| "
            f"||status={_s(status)}|| ||tool={_s(evidence_tool)}|| "
            f"hypothesis: {hypothesis[:300]}"
        )
        content = _stamp_row(
            "audit_hypothesis",
            content,
            {
                "kind": "audit_hypothesis",
                "repo": _repo_key(repo_path),
                "file": file_path,
                "fn": function,
                "hyp": hyp_hash,
                "src": source_hash,
                "status": status,
            },
        )
        return _propose_redacted(
            client=client,
            content=content,
            memory_type="fact",
            domain_tag=_audit_domain(repo_path),
            confidence=confidence,
            tags=["audit", "hypothesis", status],
        )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE audit hypothesis store failed: %s", e)
        return False


def recall_audit_hypothesis_verdict(
    repo_path: str,
    file_path: str,
    function: str,
    hypothesis: str = "",
    source_hash: str = "",
) -> dict[str, Any] | None:
    """Recall a prior audit hypothesis verdict from SAGE.

    Returns ``{status, tool, source_hash}`` if a prior verdict exists
    with matching source hash.  Returns ``None`` otherwise.
    Only ``clean`` and ``dormant`` verdicts trigger skip on recall —
    findings and suspicious results are always re-tested.

    When *hypothesis* is empty the query matches by file+function only
    and skips the hypothesis-hash check — used for pre-review skip
    where the LLM hypothesis is not yet known.
    """
    if not source_hash:
        return None
    client = _get_client()
    if client is None:
        return None
    try:
        hyp_hash = sha256_string(hypothesis)[:16] if hypothesis else ""
        _metric_inc("recall_attempted")
        query_text = (
            f"Audit hypothesis verdict: "
            f"file={file_path} fn={function}"
        )
        if hyp_hash:
            query_text += f" hyp={hyp_hash}"
        results = client.query(
            text=query_text,
            domain_tag=_audit_domain(repo_path),
            top_k=3,
            min_confidence=0.7,
        )
        for row in results:
            content, token = rowmac.strip(str(row.get("content") or ""))
            if f"||src={source_hash}||" not in content:
                continue
            if hyp_hash and f"||hyp={hyp_hash}||" not in content:
                continue
            for s in _AUDIT_SKIP_STATUSES:
                if f"||status={s}||" in content:
                    row_hyp = re.search(r"\|\|hyp=([^|]*)\|\|", content)
                    fields = {
                        "kind": "audit_hypothesis",
                        "repo": _repo_key(repo_path),
                        "file": file_path,
                        "fn": function,
                        "hyp": row_hyp.group(1) if row_hyp else "",
                        "src": source_hash,
                        "status": s,
                    }
                    if not _row_mac_ok("audit_hypothesis", fields, token):
                        break
                    tool = ""
                    tool_match = re.search(r"\|\|tool=([^|]*)\|\|", content)
                    if tool_match:
                        tool = tool_match.group(1)
                    _metric_inc("recall_hits")
                    return {
                        "status": s,
                        "tool": tool,
                        "source_hash": source_hash,
                    }
        return None
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE audit hypothesis recall failed: %s", e)
        return None


def store_audit_observation(
    repo_path: str,
    observation: str,
    kind: str,
    source_function: str,
) -> bool:
    """Store a tool-confirmed audit observation to SAGE for cross-target transfer.

    Only stores ``tool_confirmation`` and ``tool_refutation`` kinds —
    these are mechanical verdicts, not LLM opinions.
    """
    if kind not in ("tool_confirmation", "tool_refutation"):
        return False
    if not observation or len(observation) < 20:
        return False
    client = _get_client()
    if client is None:
        return False
    try:
        return _propose_redacted(
            client=client,
            content=(
                f"Audit observation ({kind}): {observation}\n"
                f"  Source: {source_function}"
            ),
            memory_type="observation",
            domain_tag="raptor-methodology",
            confidence=0.85 if kind == "tool_confirmation" else 0.75,
            tags=["audit", "observation", kind],
        )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE audit observation store failed: %s", e)
        return False


def recall_audit_observations(
    subject: str,
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """Recall prior audit observations from the methodology domain.

    Returns tool-confirmed patterns and refutations relevant to a
    subject (e.g. "unchecked return value", "integer overflow").
    """
    client = _get_client()
    if client is None:
        return []
    try:
        _metric_inc("recall_attempted")
        results = client.query(
            text=f"Audit observation: {subject}",
            domain_tag="raptor-methodology",
            top_k=top_k,
            min_confidence=0.7,
        )
        out = [r for r in results if "Audit observation" in str(r.get("content", ""))]
        _metric_inc("recall_hits", len(out))
        return out
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE audit observation recall failed: %s", e)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# SCA (Software Composition Analysis) — mechanical short-circuit
# ─────────────────────────────────────────────────────────────────────────────

def _sca_domain(repo_path: str) -> str:
    return f"raptor-sca-{_repo_key(repo_path)}"


def recall_context_for_sca(
    repo_path: str,
    ecosystems: list[str] | None = None,
    dep_names: list[str] | None = None,
) -> list[dict[str, Any]]:
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
        _metric_inc("recall_attempted")
        query_parts = [
            (
                "Prior SCA findings: confirmed malicious packages,"
                " false-positive rulings, supply-chain attack patterns"
            )
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
        merged = [row for row in merged if _sca_row_mechanically_usable(row)]
        _metric_inc("recall_hits", len(merged))
        if merged:
            logger.info(
                "SAGE: Recalled %d SCA memories for context", len(merged)
            )
        return merged
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE SCA recall failed: %s", e)
        return []


def _sca_row_mechanically_usable(row: dict[str, Any]) -> bool:
    """Gate rows that would trigger the confirmed-malicious short-circuit.

    The SCA pipeline short-circuits packages whose recalled content
    contains ``malicious_confirmed`` — the FAIL direction here is a
    false positive, not a miss, but it is still a mechanical decision.
    Such rows are only returned when their MAC token verifies over the
    decision fields (kind, ecosystem, name, version, verdict) written by
    ``store_sca_outcomes`` on this install. Rows without the trigger
    pass through unchanged as ordinary context.
    """
    clean, token = rowmac.strip(str(row.get("content") or ""))
    if "malicious_confirmed" not in clean:
        return True

    def _field(key: str) -> str:
        match = re.search(rf"\|\|{key}=([^|]*)\|\|", clean)
        return match.group(1) if match else ""

    fields = {
        "kind": "sca_outcome",
        "eco": _field("sca_eco"),
        "name": _field("sca_name"),
        "version": _field("sca_ver"),
        "verdict": _field("sca_verdict"),
    }
    return _row_mac_ok("sca_outcomes", fields, token)


def store_sca_outcomes(
    repo_path: str,
    outcomes: list[dict[str, Any]],
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

            _s = _sanitise_delim
            parts.append(
                f"||sca_eco={_s(eco)}|| ||sca_name={_s(pkg)}|| "
                f"||sca_ver={_s(version)}|| ||sca_verdict={_s(verdict)}||"
            )

            content = " ".join(parts)
            content = _stamp_row(
                "sca_outcomes",
                content,
                {
                    "kind": "sca_outcome",
                    "eco": _s(eco),
                    "name": _s(pkg),
                    "version": _s(version),
                    "verdict": _s(verdict),
                },
            )

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
        except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
            logger.debug(
                "SAGE SCA store failed for %s: %s", outcome.get('package_name', '?'), e
            )

    if stored:
        logger.info("SAGE: stored %d SCA outcomes for %s", stored, repo_name)
    return stored


# ------------------------------------------------------------------
# Study / Teach — concept memory (N1)
# ------------------------------------------------------------------

def _concepts_domain(repo_path: str) -> str:
    return f"raptor-concepts-{_repo_key(repo_path)}"


def _verified_concept_rows(
    rows: list[dict[str, Any]],
    hook: str,
) -> list[dict[str, Any]]:
    """Keep only concept rows whose MAC verifies (recall side).

    Concept rows drive skip/seed decisions in study and teach. The
    per-evidence source hashes already prove freshness; the MAC proves
    authorship — both are required before a row has mechanical effect.
    Rows without a valid token (legacy, foreign, tampered) are dropped
    from the mechanical path, exactly as if no memory existed.
    """
    out: list[dict[str, Any]] = []
    for row in rows or []:
        clean, token = rowmac.strip(str(row.get("content") or ""))
        m_id = re.search(r"Concept \[([^\]]+)\]", clean)
        m_src = re.search(r"Source hash: (\S+)", clean)
        fields = {
            "kind": "study_concept",
            "concept": m_id.group(1) if m_id else "",
            "src": m_src.group(1) if m_src else "",
        }
        if _row_mac_ok(hook, fields, token):
            out.append(row)
    return out


_CONFIDENCE_TO_SAGE: dict[str, float] = {
    "inferred": 0.55,
    "traced": 0.80,
    "corroborated": 0.90,
    "documented": 0.88,
    "tested": 0.95,
}


def store_study_concepts(
    repo_path: str,
    domain_model: Any,
    *,
    study_scope: str = "",
) -> int:
    """Store concepts, invariants, and contracts from a domain model to SAGE.

    Each concept is stored as a separate memory keyed by its identifier,
    with invariants and contracts inlined. This enables per-identifier
    recall for teach and cross-project reuse.

    Args:
        repo_path: Target repository path (for domain scoping).
        domain_model: A DomainModel instance.
        study_scope: The study target scope (e.g. "/usr/src/linux" vs
            "crypto/af_alg"). Stored in content for relevance gating.

    Returns:
        Number of concepts stored.
    """
    client = _get_client()
    if client is None:
        return 0

    stored = 0
    repo_name = Path(repo_path).name
    scope_label = study_scope or repo_name

    concept_invariants: dict[str, list] = {}
    for inv in domain_model.invariants:
        concept_invariants.setdefault(inv.concept, []).append(inv)

    concept_contracts: dict[str, list] = {}
    for contract in domain_model.contracts:
        for concept in domain_model.concepts:
            if any(
                contract.function in (ev.item or "")
                or contract.function in concept.id
                or contract.file in concept.id
                for ev in concept.evidence
            ):
                concept_contracts.setdefault(concept.id, []).append(contract)
                break

    for concept in domain_model.concepts:
        if concept.confidence == "inferred":
            continue

        try:
            parts = [
                (
                    f"Concept [{concept.id}] in {scope_label}: "
                    f"{concept.description}"
                )
            ]

            evidence_files = set()
            evidence_hashes = []
            for ev in concept.evidence:
                loc = f"{ev.file}:{ev.line}" if ev.line else ev.file
                h_tag = f" [h={ev.hash}]" if getattr(ev, "hash", None) else ""
                parts.append(f"  Evidence ({ev.type}): {loc}{h_tag} — {ev.observation}")
                if ev.file:
                    evidence_files.add(ev.file)
                if getattr(ev, "hash", None):
                    evidence_hashes.append(ev.hash)

            invs = concept_invariants.get(concept.id, [])
            for inv in invs:
                parts.append(
                    f"  Invariant [{inv.id}]: {inv.statement} "
                    f"(negation: {inv.negation})"
                )
                if inv.relevant_cwes:
                    parts.append(f"    CWEs: {', '.join(inv.relevant_cwes)}")

            contracts = concept_contracts.get(concept.id, [])
            for ct in contracts:
                ct_parts = [f"  Contract [{ct.function}]"]
                if ct.when:
                    ct_parts.append(f"when: {ct.when}")
                if ct.ownership_transfer:
                    ct_parts.append(f"ownership: {ct.ownership_transfer}")
                parts.append(" ".join(ct_parts))

            parts.append(f"  Study scope: {scope_label}")
            parts.append(f"  Confidence: {concept.confidence}")
            if evidence_files:
                parts.append(
                    f"  Evidence files: {', '.join(sorted(evidence_files))}"
                )
            composite = ""
            if evidence_hashes:
                composite = sha256_string(
                    "|".join(sorted(evidence_hashes))
                )[:12]
                parts.append(f"  Source hash: {composite}")

            content = "\n".join(parts)
            content = _stamp_row(
                "study_concepts",
                content,
                {
                    "kind": "study_concept",
                    "concept": concept.id,
                    "src": composite,
                },
            )

            confidence = _CONFIDENCE_TO_SAGE.get(concept.confidence, 0.70)

            tags = ["study", "concept", concept.id]
            if invs:
                tags.append("has_invariants")
            for inv in invs:
                tags.extend(inv.mechanism_tags[:3])

            if _propose_redacted(
                client=client,
                content=content,
                memory_type="fact",
                domain_tag=_concepts_domain(repo_path),
                confidence=confidence,
                tags=tags,
            ):
                stored += 1
            _throttle()
        except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
            logger.debug("SAGE concept store failed for %s: %s", concept.id, e)

    if stored:
        logger.info(
            "SAGE: stored %d concepts from study of %s", stored, scope_label
        )
    return stored


def store_teach_concepts(
    repo_path: str,
    teach_json: dict,
) -> int:
    """Store structured concepts from a teach session to SAGE.

    Accepts the JSON blob emitted by TEACH-4 and builds a DomainModel
    from it, stamps evidence hashes, then delegates to
    ``store_study_concepts`` for SAGE storage.

    Args:
        repo_path: Target repository path.
        teach_json: Dict with ``concepts``, ``invariants``, ``contracts``
            lists, plus ``subject`` and ``source_root``.

    Returns:
        Number of concepts stored.
    """
    from core.concepts.model import (
        Concept,
        Contract,
        DomainModel,
        Evidence,
        Invariant,
    )
    from core.concepts.study import _stamp_evidence_hashes

    source_root = Path(teach_json.get("source_root", repo_path))
    subject = teach_json.get("subject", "")

    concepts = []
    for c in teach_json.get("concepts", []):
        evidence = [
            Evidence(
                type=e.get("type", "code_path"),
                file=e.get("file", ""),
                observation=e.get("observation", ""),
                line=e.get("line"),
                item=e.get("item"),
            )
            for e in c.get("evidence", [])
        ]
        concepts.append(Concept(
            id=c.get("id", ""),
            description=c.get("description", ""),
            evidence=evidence,
            confidence=c.get("confidence", "traced"),
        ))

    invariants = [
        Invariant(
            id=i.get("id", ""),
            concept=i.get("concept", ""),
            statement=i.get("statement", ""),
            negation=i.get("negation", ""),
            relevant_cwes=i.get("relevant_cwes", []),
            mechanism_tags=i.get("mechanism_tags", []),
        )
        for i in teach_json.get("invariants", [])
    ]

    contracts = [
        Contract(
            function=ct.get("function", ""),
            file=ct.get("file", ""),
            when=ct.get("when", ""),
            input_semantics=ct.get("input_semantics", ""),
            output_semantics=ct.get("output_semantics", ""),
            ownership_transfer=ct.get("ownership_transfer", ""),
        )
        for ct in teach_json.get("contracts", [])
    ]

    all_evidence = [e for c in concepts for e in c.evidence]
    _stamp_evidence_hashes(all_evidence, source_root)

    dm = DomainModel(
        target=str(source_root),
        source_root=str(source_root),
        concepts=concepts,
        invariants=invariants,
        contracts=contracts,
    )

    return store_study_concepts(
        repo_path,
        dm,
        study_scope=subject or Path(repo_path).name,
    )


def recall_concepts_for_teach(
    repo_path: str,
    subject: str,
    *,
    evidence_files: list[str] | None = None,
    inventory_functions: list[str] | None = None,
    min_confidence: float = 0.65,
    top_k: int = 5,
) -> list[dict[str, Any]]:
    """Recall prior study concepts relevant to a teach query.

    Implements the N1 relevance gate: semantic match from SAGE, then
    filtered by file overlap, caller/callee overlap, and confidence
    floor.

    Args:
        repo_path: Target repository path (queries repo-scoped domain
            first, then cross-project via methodology domain).
        subject: The teach subject (e.g. "scatterlists", "struct page").
        evidence_files: Files in the current target — used for file
            overlap check.
        inventory_functions: Functions in the current target — used for
            caller/callee overlap check.
        min_confidence: Minimum SAGE confidence score.
        top_k: Maximum results to return.

    Returns:
        List of recall rows, each with content, confidence, domain,
        and a relevance_score field (0.0–1.0).
    """
    client = _get_client()
    if client is None:
        return []

    try:
        _metric_inc("recall_attempted")

        query = (
            f"Semantic concept for {subject}: ownership, lifetime, "
            f"aliasing, invariants, contracts"
        )

        results = client.query(
            text=query,
            domain_tag=_concepts_domain(repo_path),
            top_k=top_k * 2,
            min_confidence=min_confidence,
        )

        cross_project = client.query(
            text=query,
            domain_tag="raptor-methodology",
            top_k=3,
            min_confidence=0.70,
        )

        all_rows = _merge_recall_rows(results, cross_project, top_k=top_k * 2)
        all_rows = _verified_concept_rows(all_rows, "concepts_for_teach")

        scored = _apply_relevance_gate(
            all_rows,
            evidence_files=evidence_files,
            inventory_functions=inventory_functions,
        )

        scored.sort(key=lambda r: r.get("relevance_score", 0), reverse=True)
        out = scored[:top_k]

        _metric_inc("recall_hits", len(out))
        return out
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE teach recall failed: %s", e)
        return []


def recall_concepts_for_study(
    repo_path: str,
    identifiers: list[str],
    *,
    min_confidence: float = 0.65,
) -> dict[str, list[dict[str, Any]]]:
    """Recall prior concepts for study identifiers (skip/seed/cross-pollinate).

    Returns a dict keyed by identifier name, each value a list of
    matching recall rows. Empty list means no prior knowledge — study
    from scratch.

    Args:
        repo_path: Target repository path.
        identifiers: Identifier names from study-list.json.
        min_confidence: Minimum SAGE confidence score.

    Returns:
        {identifier_name: [recall_rows]}.
    """
    client = _get_client()
    if client is None:
        return {}

    result: dict[str, list[dict[str, Any]]] = {}
    domain = _concepts_domain(repo_path)

    def _recall_one(name: str) -> tuple:
        try:
            rows = client.query(
                text=f"Concept [{name}]: ownership, lifetime, contracts",
                domain_tag=domain,
                top_k=3,
                min_confidence=min_confidence,
            )
            return (name, _verified_concept_rows(rows, "concepts_for_study"))
        except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
            logger.debug("SAGE study recall failed for %s: %s", name, e)
            return (name, None)

    from concurrent.futures import ThreadPoolExecutor, as_completed

    total = len(identifiers)
    workers = _recall_workers()
    logger.info("SAGE: recalling prior concepts for %d identifiers (%d workers)", total, workers)
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_recall_one, n): n for n in identifiers}
        for fut in as_completed(futures):
            name, rows = fut.result()
            done += 1
            _metric_inc("recall_attempted")
            if rows:
                _metric_inc("recall_hits", len(rows))
                result[name] = rows
            if done % 20 == 0 or done == total:
                logger.info("SAGE: recall %d/%d (%d hits)", done, total, len(result))

    if result:
        logger.info(
            "SAGE: recalled prior concepts for %d/%d identifiers",
            len(result), total
        )
    return result


def _apply_relevance_gate(
    rows: list[dict[str, Any]],
    *,
    evidence_files: list[str] | None = None,
    inventory_functions: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Score recall rows by relevance to the current context.

    Relevance signals:
    - File overlap: concept evidence cites files in the current target.
    - Function overlap: concept mentions functions in the current inventory.
    - Confidence: higher SAGE confidence → higher relevance.
    - Scope breadth: broader study scopes score slightly higher for
      universal applicability.

    Each row gets a relevance_score field (0.0–1.0). Rows below 0.3
    are dropped entirely.
    """
    evidence_set = set(evidence_files or [])
    fn_set = set(inventory_functions or [])

    scored: list[dict[str, Any]] = []
    for row in rows:
        content = row.get("content", "")
        sage_confidence = row.get("confidence", 0.5)

        score = 0.0

        score += min(sage_confidence, 1.0) * 0.3

        if evidence_set:
            file_hits = sum(
                1 for f in evidence_set
                if f in content
            )
            if file_hits:
                score += min(file_hits / max(len(evidence_set), 1), 1.0) * 0.35

        if fn_set:
            fn_hits = sum(
                1 for fn in fn_set
                if fn in content
            )
            if fn_hits:
                score += min(fn_hits / max(len(fn_set), 1), 1.0) * 0.25

        if not evidence_set and not fn_set:
            score += 0.2

        if "Study scope:" in content:
            scope_line = [
                ln for ln in content.split("\n")
                if ln.strip().startswith("Study scope:")
            ]
            if scope_line:
                scope = scope_line[0].split(":", 1)[1].strip()
                if "/" not in scope or scope.count("/") <= 1:
                    score += 0.1

        if score >= 0.3:
            row_copy = dict(row)
            row_copy["relevance_score"] = round(score, 3)
            scored.append(row_copy)

    return scored


# ─────────────────────────────────────────────────────────────────────────────
# Generic remember — free-form observation storage
# ─────────────────────────────────────────────────────────────────────────────

def sage_remember(
    *,
    domain: str,
    content: str,
    tags: list[str] | None = None,
    memory_type: str = "observation",
    confidence: float = 0.8,
) -> bool:
    """Store a free-form memory to an explicit domain.

    Prose-only convenience for callers with no mechanical recall side
    (e.g. corpus-learning summaries).  Rows stored here never earn
    mechanical effect — they carry no row MAC by design.
    """
    if not content:
        return False
    client = _get_client()
    if client is None:
        return False
    try:
        return _propose_redacted(
            client=client,
            content=content,
            memory_type=memory_type,
            domain_tag=domain,
            confidence=confidence,
            tags=tags,
        )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE remember failed: %s", e)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Code understanding (/understand) — cross-run result persistence
# ─────────────────────────────────────────────────────────────────────────────

def _understand_domain(repo_path: str) -> str:
    return f"raptor-understand-{_repo_key(repo_path)}"


def _clip(text: str, limit: int = 200) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def store_map_results(repo_path: str, payload: dict[str, Any]) -> bool:
    """Persist a /understand --map summary for cross-run recall.

    Stores counts plus a bounded sample of entry points and sinks as a
    prose observation (hint-only on recall — no mechanical effect).
    """
    if not isinstance(payload, dict):
        return False
    client = _get_client()
    if client is None:
        return False
    try:
        entry_points = payload.get("entry_points") or []
        sinks = payload.get("sinks") or []
        boundaries = payload.get("trust_boundaries") or []

        def _names(items: list[Any], limit: int = 5) -> str:
            out = []
            for it in items[:limit]:
                if isinstance(it, dict):
                    out.append(str(it.get("name") or it.get("function")
                                   or it.get("file") or "?"))
                else:
                    out.append(str(it))
            return ", ".join(out) or "none"

        content = (
            f"Attack-surface map for repo {_repo_key(repo_path)}: "
            f"{len(entry_points)} entry points, {len(sinks)} sinks, "
            f"{len(boundaries)} trust boundaries.\n"
            f"  Entry points: {_clip(_names(entry_points))}\n"
            f"  Sinks: {_clip(_names(sinks))}"
        )
        return _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag=_understand_domain(repo_path),
            confidence=0.8,
            tags=["understand", "map"],
        )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE map store failed: %s", e)
        return False


def store_trace_result(repo_path: str, trace: dict[str, Any]) -> bool:
    """Persist one /understand --trace flow for cross-run recall."""
    if not isinstance(trace, dict):
        return False
    client = _get_client()
    if client is None:
        return False
    try:
        entry = trace.get("entry") or trace.get("source") or "?"
        sink = trace.get("sink") or "?"
        if isinstance(sink, dict):
            sink = sink.get("name") or sink.get("function") or "?"
        verdict = trace.get("verdict") or trace.get("attacker_control") or ""
        steps = trace.get("steps") or trace.get("call_chain") or []
        content = (
            f"Flow trace for repo {_repo_key(repo_path)}: "
            f"{_clip(str(entry), 120)} → {_clip(str(sink), 120)} "
            f"({len(steps)} steps)"
        )
        if verdict:
            content += f"\n  Assessment: {_clip(str(verdict))}"
        return _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag=_understand_domain(repo_path),
            confidence=0.8,
            tags=["understand", "trace"],
        )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE trace store failed: %s", e)
        return False


def store_hunt_results(repo_path: str, hunt_data: dict[str, Any]) -> bool:
    """Persist a /understand --hunt variant sweep for cross-run recall."""
    if not isinstance(hunt_data, dict):
        return False
    client = _get_client()
    if client is None:
        return False
    try:
        meta = hunt_data.get("meta") or {}
        pattern = meta.get("pattern") or "unknown"
        total = meta.get("total_matches", 0)
        groups = hunt_data.get("root_cause_groups") or []
        content = (
            f"Variant hunt for repo {_repo_key(repo_path)}: "
            f"pattern {_clip(str(pattern), 120)} — {total} match(es), "
            f"{len(groups)} root-cause group(s)."
        )
        return _propose_redacted(
            client=client,
            content=content,
            memory_type="observation",
            domain_tag=_understand_domain(repo_path),
            confidence=0.8,
            tags=["understand", "hunt"],
        )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE hunt store failed: %s", e)
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Validation pipeline (/validate) — verdict history across runs
# ─────────────────────────────────────────────────────────────────────────────

def _validation_domain(repo_path: str) -> str:
    return f"raptor-validation-{_repo_key(repo_path)}"


_VALIDATION_STORE_CAP = 20

_MAC_FIELD_RE = re.compile(r"\|\|(\w+)=([^|]*)\|\|")


def store_validation_verdicts(
    repo_path: str,
    findings: list[dict[str, Any]],
    summary: dict[str, Any] | None = None,
) -> bool:
    """Store validation verdicts to SAGE for cross-run recall.

    One MAC-stamped row per finding (bounded) plus one prose summary
    row.  The MAC lets a future mechanical consumer trust the verdict
    fields; recall today is hint-only.
    """
    if not findings:
        return False
    client = _get_client()
    if client is None:
        return False
    stored = False
    try:
        _s = _sanitise_delim
        repo_key = _repo_key(repo_path)
        for finding in findings[:_VALIDATION_STORE_CAP]:
            if not isinstance(finding, dict):
                continue
            file_path = _s(finding.get("file") or finding.get("file_path") or "")
            fn = _s(finding.get("function") or finding.get("function_name") or "")
            verdict = _s(
                finding.get("status") or finding.get("verdict") or "unknown",
            )
            title = _clip(
                str(finding.get("title") or finding.get("rule_id")
                    or finding.get("type") or "finding"), 120,
            )
            content = (
                f"Validation verdict: {title} "
                f"||file={file_path}|| ||fn={fn}|| ||verdict={verdict}||"
            )
            content = _stamp_row(
                "validation_verdict",
                content,
                {
                    "kind": "validation_verdict",
                    "repo": repo_key,
                    "file": file_path,
                    "fn": fn,
                    "verdict": verdict,
                },
            )
            if _propose_redacted(
                client=client,
                content=content,
                memory_type="fact",
                domain_tag=_validation_domain(repo_path),
                confidence=0.85,
                tags=["validation", "verdict", verdict],
            ):
                stored = True
        if summary:
            counts = ", ".join(
                f"{k}={v}" for k, v in sorted(summary.items())
                if isinstance(v, (int, float, str))
            )
            if counts and _propose_redacted(
                client=client,
                content=(
                    f"Validation run summary for repo {repo_key}: "
                    f"{_clip(counts, 400)}"
                ),
                memory_type="observation",
                domain_tag=_validation_domain(repo_path),
                confidence=0.8,
                tags=["validation", "summary"],
            ):
                stored = True
        return stored
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE validation verdict store failed: %s", e)
        return stored


def store_validation_disproven(
    repo_path: str,
    disproven: list[dict[str, Any]],
) -> bool:
    """Store disproven validation hypotheses so future runs skip them."""
    if not disproven:
        return False
    client = _get_client()
    if client is None:
        return False
    stored = False
    try:
        _s = _sanitise_delim
        repo_key = _repo_key(repo_path)
        for item in disproven[:_VALIDATION_STORE_CAP]:
            if not isinstance(item, dict):
                continue
            file_path = _s(item.get("file") or item.get("file_path") or "")
            fn = _s(item.get("function") or item.get("function_name") or "")
            reason = _s(_clip(
                str(item.get("reason") or item.get("why") or "disproven"),
            ))
            desc = _clip(
                str(item.get("hypothesis") or item.get("title")
                    or item.get("description") or "hypothesis"), 120,
            )
            content = (
                f"Validation disproven: {desc} "
                f"||file={file_path}|| ||fn={fn}|| ||reason={reason}||"
            )
            content = _stamp_row(
                "validation_disproven",
                content,
                {
                    "kind": "validation_disproven",
                    "repo": repo_key,
                    "file": file_path,
                    "fn": fn,
                    "reason": reason,
                },
            )
            if _propose_redacted(
                client=client,
                content=content,
                memory_type="fact",
                domain_tag=_validation_domain(repo_path),
                confidence=0.85,
                tags=["validation", "disproven"],
            ):
                stored = True
        return stored
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE validation disproven store failed: %s", e)
        return stored


def recall_context_for_validation(
    repo_path: str,
    top_k: int = 8,
) -> list[dict[str, Any]]:
    """Recall prior validation verdicts + disproven hypotheses.

    Hint-only: rows are returned for prompt/report context, annotated
    with ``mac_verified`` so a consumer can distinguish rows minted by
    this install from arbitrary recall text.  Never raises.
    """
    client = _get_client()
    if client is None:
        return []
    try:
        _metric_inc("recall_attempted")
        results = client.query(
            text="Validation verdict and disproven hypothesis history",
            domain_tag=_validation_domain(repo_path),
            top_k=top_k,
            min_confidence=0.7,
        )
        repo_key = _repo_key(repo_path)
        out: list[dict[str, Any]] = []
        for row in results:
            raw = str(row.get("content") or "")
            if "Validation verdict" not in raw and "Validation disproven" not in raw:
                continue
            content, token = rowmac.strip(raw)
            parsed = dict(_MAC_FIELD_RE.findall(content))
            if "Validation disproven" in content:
                kind, extra = "validation_disproven", "reason"
            else:
                kind, extra = "validation_verdict", "verdict"
            fields = {
                "kind": kind,
                "repo": repo_key,
                "file": parsed.get("file", ""),
                "fn": parsed.get("fn", ""),
                extra: parsed.get(extra, ""),
            }
            out.append({
                "content": content,
                "confidence": recall_row_confidence(row),
                "mac_verified": _row_mac_ok(kind, fields, token),
            })
        _metric_inc("recall_hits", len(out))
        return out
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE validation recall failed: %s", e)
        return []
