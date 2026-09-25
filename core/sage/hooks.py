"""
SAGE pipeline hooks for RAPTOR.

Mechanical hooks that make hard decisions (skip, suppress, reorder,
set flags) based on SAGE recall. Every hook is a no-op when SAGE is
unavailable.

Two hint-tier recall surfaces DO feed recalled rows into prompt/
report context — ``recall_context_for_validation`` and
``recall_context_for_web_scan``. They carry hint authority only
(rows are ``mac_verified``-annotated so consumers can distinguish
rows minted by this install from arbitrary recall text) and must
never suppress or hard-decide anything. The earlier generation of
prompt-injection hooks beyond those two was removed — no measurable
effect and no guarantee the LLM weighed them correctly.
"""

import math
import os
import re
import threading
import time
from collections.abc import Mapping
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
_ollama_gpu_checked_at: float = 0.0


def _ollama_gpu_available() -> bool:
    """Detect GPU by checking size_vram on Ollama's loaded models.

    A positive result is latched for the process lifetime. A negative
    result (probe error, Ollama still starting, no model loaded yet)
    is cached only for ``_CLIENT_NONE_TTL_S`` — the same TTL the
    client's negative cache uses — and re-probed after: a permanently
    latched False here disabled every SAGE pipeline hook for the rest
    of a long run whenever the sidecar came up late. Honours
    ``SAGE_OLLAMA_URL`` (same knob the direct-embed path in
    core/sage/client.py reads); default is the compose-mapped port.
    """
    global _ollama_has_gpu, _ollama_gpu_checked_at
    if _ollama_has_gpu:
        return True
    if (
        _ollama_has_gpu is False
        and (time.time() - _ollama_gpu_checked_at) <= _CLIENT_NONE_TTL_S
    ):
        return False
    try:
        import httpx

        from .config import ensure_loopback_no_proxy

        # Without this, a proxied shell routes the probe to the proxy and
        # a GPU host silently misreports as CPU-only (halved recall
        # workers, direct-embed path chosen on a wrong premise).
        ensure_loopback_no_proxy()
        base = os.environ.get(
            "SAGE_OLLAMA_URL", "http://localhost:11435"
        ).rstrip("/")
        resp = httpx.get(f"{base}/api/ps", timeout=5)
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
    _ollama_gpu_checked_at = time.time()
    return False


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
    *hit_lists: list[dict[str, Any]],
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
    # Gaps bounded: unbounded, every planted head phrase re-scans the
    # rest of a hostile row — quadratic (two gaps: cubic). Writer
    # values sit far below the bounds.
    match = re.search(
        r": strategy (.{1,500}?), binary fingerprint (.{1,500}?), duration",
        clean,
    )
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
        # Stamp the CALLER's repo key onto every returned row so the
        # downstream MAC check (`infer_codeql_build_from_sage_recall_row`)
        # binds to the repo being analysed, not to whatever repo the
        # row claims — see that function's docstring.
        caller_repo = _repo_key(repo_path)
        for row in merged:
            row["_caller_repo_key"] = caller_repo
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
    repo_path: str | None = None,
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
    languages). The ``repo`` field is bound to the CALLER's repo —
    ``repo_path`` when given, else the ``_caller_repo_key`` annotation
    ``recall_context_for_codeql_build`` stamps on every row it returns
    (mirroring ``recall_prior_finding_verdict``). The rows live in the
    global ``raptor-methodology`` domain, so verifying against a repo
    key parsed from the row itself would let repo A's build command
    (possibly synthesised by a hostile repo A) verify — and EXECUTE —
    inside repo B's checkout. Rows without a valid caller-bound token
    still yield ``outcome`` / ``languages`` as hints, but never a
    replayable command — the parsed command is instead surfaced as
    ``unverified_build_command`` so the consumer can show it to the
    operator as a hint (never execute it).
    """
    if not row:
        return {}
    text, token = rowmac.strip(str(row.get("content") or ""))
    out: dict[str, str] = {}

    m_outcome = re.search(r"outcome (\w+)", text)
    if m_outcome:
        out["outcome"] = m_outcome.group(1)

    # List bounded (element length and count): unbounded, every
    # planted "languages " head re-scans the rest of a hostile row —
    # quadratic. Writer rows hold a handful of short names.
    m_lang = re.search(
        r"languages ([^,]{1,100}(?:, [^,]{1,100}){0,32}), outcome", text)
    if m_lang:
        out["languages"] = m_lang.group(1).strip()

    m_cmd = re.search(r"build command (.{1,1000}?), analyses completed", text)
    if m_cmd and out.get("outcome") == "success":
        cmd = m_cmd.group(1).strip()
        if cmd and cmd != "auto":
            if repo_path:
                caller_key = _repo_key(repo_path)
            else:
                caller_key = str(row.get("_caller_repo_key") or "")
            fields = {
                "kind": "codeql_build",
                "repo": caller_key,
                "outcome": out["outcome"],
                "build_command": cmd,
                "languages": out.get("languages", ""),
            }
            if caller_key and _row_mac_ok("codeql_build", fields, token):
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
    line_end: int | None = None,
) -> str:
    """Hash a finding's source context for staleness detection.

    The span is the whole enclosing function when the caller knows its
    bounds (pass ``line_end``; the audit path has line_start/line_end),
    else ``line`` ±``window``. The span hash is folded together with a
    hash of the FULL file content: a change that alters exploitability
    outside the local window — a gutted callee, a changed macro, a
    caller newly passing attacker data — invalidates prior verdicts
    even when the span itself is byte-identical. Coarse by design: the
    fail direction is re-test, never stale suppression.

    Returns SHA-256[:12], or ``""`` if the file is unreadable or the
    range is invalid. Rows stored under the previous span-only format
    can no longer match — they demote to hint (re-test), which is the
    intended migration.
    """
    from core.staleness import hash_span
    if line_end is not None and 0 < line <= line_end:
        start, end = line, line_end
    else:
        start = max(1, line - window)
        end = line + window
    span_hash = hash_span(file_path, start, end)
    if not span_hash:
        return ""
    try:
        file_text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    file_hash = sha256_string(file_text)[:12]
    return sha256_string(f"{span_hash}:{file_hash}")[:12]


def finding_verdict_source_hash(
    repo_root: Path,
    rel_path: str,
    line: int,
) -> str:
    """Source-identity hash for a finding-verdict store row.

    One formula shared by every verdict WRITER (the /agentic analysis
    loop and the operator verdict CLI): a finding with a known line
    (``line > 0``) hashes the window around it via
    :func:`compute_finding_source_hash` — the exact hash the recall
    side recomputes before suppressing. A line-less finding
    (``line == 0``) hashes the capped file prefix instead: recall
    gates on ``line > 0``, so such a row never mechanically
    suppresses, but the stored identity stays stable for the
    knowledge base. The capped read matters — the path points into a
    scanned repo, so an uncapped read of a hostile giant file is an
    OOM lever; a >cap file changes hash iff its capped prefix does.

    Returns ``""`` when the file is unreadable (callers must not
    store a verdict row without a source identity).
    """
    fpath = Path(repo_root) / rel_path
    if line > 0:
        return compute_finding_source_hash(fpath, line)
    from core.source import read_text_capped
    got = read_text_capped(fpath)
    if got is None:
        return ""
    return sha256_string(got[0])[:12]


def finding_source_hashes(
    file_path: Path,
    line_start: int,
    line_end: int,
    window: int = 10,
) -> dict[str, int]:
    """Store-format window hashes for a range of candidate finding lines.

    Same formula as :func:`compute_finding_source_hash` in its
    window form (``line`` ± ``window`` span hash folded with the
    full-file hash), for callers that must match a STORED finding
    hash against a span whose exact finding line is unknown (the
    /audit function-grade primer). The loop-invariant full-file hash
    is computed ONCE and the span hashes batch over a single file
    read — per-line calls to ``compute_finding_source_hash`` re-read
    and re-hash the whole file every iteration (measured near a
    second per no-match scan on real files).

    Returns ``{hash: line}`` for every computable candidate; ``{}``
    when the file is unreadable or the range is empty. Later lines
    overwrite on the (theoretical) collision — callers only test
    membership.
    """
    if line_start <= 0 or line_end < line_start:
        return {}
    from core.staleness import hash_spans
    try:
        file_text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    file_hash = sha256_string(file_text)[:12]
    lines = list(range(line_start, line_end + 1))
    spans = [(max(1, ln - window), ln + window) for ln in lines]
    span_hashes = hash_spans(file_path, spans)
    return {
        sha256_string(f"{sh}:{file_hash}")[:12]: ln
        for ln, sh in zip(lines, span_hashes)
        if sh
    }


# Client-side lifetime bound on suppressible verdicts. Even a verdict
# whose source hash still matches goes stale eventually (build flags,
# dependencies, and reachability drift without touching the file);
# SAGE confidence decay alone keeps rows above the recall floor for
# ~50-60 days. The store side stamps a ``ts`` field into the MAC'd
# field set (so it cannot be forged fresh); the recall side rejects
# rows older than the TTL — the finding simply re-tests.
_SUPPRESS_TTL_DAYS = 30
_SUPPRESS_TTL_S = _SUPPRESS_TTL_DAYS * 86400


def _row_ts_fresh(hook: str, ts: str) -> bool:
    """Whether a MAC-verified row timestamp is within the suppression TTL."""
    try:
        age = time.time() - int(ts)
    except (TypeError, ValueError):
        return False
    if age > _SUPPRESS_TTL_S:
        logger.debug(
            "SAGE %s: prior verdict older than %d days — re-testing",
            hook, _SUPPRESS_TTL_DAYS,
        )
        return False
    return True


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

    Operator override: set ``RAPTOR_SAGE_FP_SUPPRESS=0`` to disable
    this suppression entirely (every finding re-tests). This is the
    force gate for consumers with no ``--force`` flag of their own —
    the /agentic analysis loop suppresses pre-LLM through this hook,
    and without an override a wrong prior verdict would silently
    persist for its whole TTL. (The audit orchestrator additionally
    honours ``config.force`` upstream.)
    """
    if not env_flag("RAPTOR_SAGE_FP_SUPPRESS", default=True):
        logger.debug(
            "SAGE finding_verdict: suppression disabled via "
            "RAPTOR_SAGE_FP_SUPPRESS=0 — re-testing",
        )
        return None
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
            ts_match = re.search(r"\|\|ts=(\d+)\|\|", content)
            if not ts_match:
                # Pre-TTL row (no timestamp in the MAC'd set): demote
                # to hint — the finding re-tests and re-earns a fresh,
                # TTL-bounded verdict.
                continue
            ts = ts_match.group(1)
            for v in _SUPPRESS_VERDICTS:
                if f"||verdict={v}||" in content:
                    fields = {
                        "kind": "finding_verdict",
                        "repo": _repo_key(repo_path),
                        "fp": _finding_fingerprint(rule_id, file_path, function),
                        "verdict": v,
                        "src": source_hash,
                        "ts": ts,
                        **_mint_fields_from_content(content),
                    }
                    if not _row_mac_ok("finding_verdict", fields, token):
                        break
                    if not _row_ts_fresh("finding_verdict", ts):
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


def recall_prior_fp_verdicts(
    repo_path: str,
    file_path: str,
    function: str,
    top_k: int = 3,
) -> list[dict[str, Any]]:
    """MAC-verified suppressible finding verdicts for one function.

    Rule-agnostic companion to :func:`recall_prior_finding_verdict`
    for callers that review whole FUNCTIONS rather than one scanner
    finding (the /audit loop): they know ``file:function`` but not
    which rule produced the prior finding, and the stored source hash
    is windowed around the FINDING line, which they also do not know.
    Returns every suppressible (``false_positive`` /
    ``not_exploitable``) verdict row stored for the function — MAC
    verified against the rule the row itself names, TTL-fresh — each
    carrying the ``source_hash`` the CALLER must still match against
    the current source (scan the function's lines with
    :func:`compute_finding_source_hash`; no match ⇒ stale ⇒ re-test).

    The rule id is recovered from the row content; the MAC fingerprint
    is recomputed from it, so a forged or delimiter-mangled rule value
    fails verification and the row is dropped (fail direction:
    re-test). Honours ``RAPTOR_SAGE_FP_SUPPRESS`` like the rule-keyed
    recall. Returns ``[]`` on any failure or when SAGE is absent.
    """
    if not env_flag("RAPTOR_SAGE_FP_SUPPRESS", default=True):
        logger.debug(
            "SAGE finding_verdict: suppression disabled via "
            "RAPTOR_SAGE_FP_SUPPRESS=0 — re-testing",
        )
        return []
    client = _get_client()
    if client is None:
        return []
    try:
        _metric_inc("recall_attempted")
        results = client.query(
            text=f"Finding verdict: file={file_path} fn={function}",
            domain_tag=_fp_domain(repo_path),
            top_k=top_k,
            min_confidence=0.7,
        )
        _s = _sanitise_delim
        # Semantic retrieval can return neighbours — bind to THIS
        # function before anything else.
        binding = f" file={_s(file_path)} fn={_s(function)} ||src="
        rows: list[dict[str, Any]] = []
        for row in results:
            content, token = rowmac.strip(str(row.get("content") or ""))
            if binding not in content:
                continue
            src_match = re.search(r"\|\|src=([^|]+)\|\|", content)
            rule_match = re.search(r" rule=(.{0,500}?) file=", content)
            ts_match = re.search(r"\|\|ts=(\d+)\|\|", content)
            if not src_match or rule_match is None or not ts_match:
                # Pre-TTL / malformed rows demote to hint — re-test.
                continue
            src = src_match.group(1)
            rule = rule_match.group(1)
            ts = ts_match.group(1)
            for v in _SUPPRESS_VERDICTS:
                if f"||verdict={v}||" not in content:
                    continue
                fields = {
                    "kind": "finding_verdict",
                    "repo": _repo_key(repo_path),
                    "fp": _finding_fingerprint(rule, file_path, function),
                    "verdict": v,
                    "src": src,
                    "ts": ts,
                    **_mint_fields_from_content(content),
                }
                if not _row_mac_ok("finding_verdict", fields, token):
                    break
                if not _row_ts_fresh("finding_verdict", ts):
                    break
                _metric_inc("recall_hits")
                rows.append({
                    "verdict": v,
                    "rule": rule,
                    "source_hash": src,
                    "confidence": recall_row_confidence(row),
                })
                break
        return rows
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE FP recall (function-grade) failed: %s", e)
        return []


def store_finding_verdict(
    repo_path: str,
    rule_id: str,
    file_path: str,
    function: str,
    source_hash: str,
    verdict: str,
    *,
    note: str = "",
    mint: Mapping[str, str] | None = None,
    client: SageClient | None = None,
) -> bool:
    """Store a finding verdict to SAGE for cross-run FP suppression.

    All verdicts are stored (building the knowledge base), but only
    ``false_positive`` and ``not_exploitable`` trigger suppression on
    future recall.

    ``note`` is free-form audit text appended AFTER the marker fields
    (the operator verdict CLI records its provenance stamp there).
    Delimiter-sanitised so it can never forge a ``||key=value||``
    marker; deliberately OUTSIDE the MAC'd decision-field set — the
    recall side's mechanical decision never reads it, so it carries
    hint/audit authority only and pipeline-minted rows verify
    unchanged.

    ``mint`` (operator CLI fp verb only) carries the mint-provenance
    facts — the restricted key set :data:`_MINT_FIELD_KEYS`
    (``minted``/``grant``/``mintctx``) — which land as explicit
    ``||key=value||`` markers AND join the MAC'd decision-field set,
    so a stored row's mint authority cannot be silently edited after
    the fact: readers rebuild the field set from the row's own
    markers (self-describing versioning — rows without mint markers
    verify over the original field set, so existing rows keep
    verifying), and any post-hoc marker edit, strip, or graft changes
    the reconstructed field set and fails MAC verification. Honest
    bound, same as the rest of the row MAC: the binding is only as
    strong as the key file — a same-user process that can read
    ``rowmac.key`` can re-mint whatever fields it likes (that trust
    tier is bounded by the rowmac module's own documentation).

    ``client`` overrides the pipeline singleton — the operator CLI
    passes :func:`operator_client` (no GPU gate; a one-off verdict on
    a CPU-only box is fine), the pipeline keeps the gated default.
    """
    if not source_hash:
        return False
    if client is None:
        client = _get_client()
    if client is None:
        return False
    if mint is not None and (
        not mint
        or any(k not in _MINT_FIELD_KEYS or not str(v)
               for k, v in mint.items())
    ):
        # Fail closed on a malformed mint set: silently dropping the
        # keys would store an unmarked row that reads as pre-mint.
        logger.debug("SAGE finding_verdict: malformed mint fields %r", mint)
        return False
    try:
        fp = _finding_fingerprint(rule_id, file_path, function)
        _s = _sanitise_delim
        ts = str(int(time.time()))
        content = (
            f"Finding verdict: fp={fp} rule={_s(rule_id)} "
            f"file={_s(file_path)} fn={_s(function)} "
            f"||src={_s(source_hash)}|| ||verdict={_s(verdict)}|| "
            f"||ts={ts}||"
        )
        fields = {
            "kind": "finding_verdict",
            "repo": _repo_key(repo_path),
            "fp": fp,
            "verdict": verdict,
            "src": source_hash,
            "ts": ts,
        }
        if mint:
            for key in _MINT_FIELD_KEYS:
                value = mint.get(key)
                if value is None:
                    continue
                clean = _s(str(value))
                content += f" ||{key}={clean}||"
                fields[key] = clean
        if note:
            content += f" {_s(note)}"
        content = _stamp_row("finding_verdict", content, fields)
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
# Finding verdict — operator verbs (the /review verdict CLI)
# ─────────────────────────────────────────────────────────────────────────────
#
# The pipeline hooks above are write-once/recall-only: they have no way
# to CLEAR a wrong prior verdict (the semantic query deliberately drops
# memory ids). The operator verbs below enumerate the repo's fp domain
# through the id-bearing listing so a human can overturn a stored
# verdict. They live beside the store/recall pair because the row
# shape (content grammar + MAC field set) is owned by this section —
# a second module parsing it would drift.

_OPERATOR_LIST_PAGE = 200
_OPERATOR_LIST_MAX_PAGES = 200

_VERDICT_ROW_RE = re.compile(
    r"\|\|src=([^|]+)\|\| \|\|verdict=([^|]+)\|\| \|\|ts=(\d+)\|\|")

# Mint-provenance markers the operator CLI's fp verb stores (HOW the
# standing suppression was authorised): ``minted`` (grant | ceremony),
# ``grant`` (the operator-grant result at mint time), ``mintctx``
# (compact invocation-context stamp). Fixed order, restricted set —
# they join the MAC'd decision-field set on rows that carry them, so
# they are tamper-evident, never free audit text.
_MINT_FIELD_KEYS = ("minted", "grant", "mintctx")
_MINT_FIELD_RES = {
    key: re.compile(r"\|\|" + key + r"=([^|]+)\|\|")
    for key in _MINT_FIELD_KEYS
}
# Reserved field injected by the reader when a row carries a mint
# marker key MORE THAN ONCE. Never a member of _MINT_FIELD_KEYS, so
# no store can ever mint a token covering it — verification of a
# duplicate-marker row necessarily fails (demote to hint).
_MINT_DUP_SENTINEL = "mintdup"


def _mint_fields_from_content(content: str) -> dict[str, str]:
    """Mint-provenance fields a stored row itself declares.

    Self-describing versioning for the row MAC: the store side puts
    each mint fact in the content as an explicit ``||key=value||``
    marker AND in the MAC'd field set, so the verifier rebuilds the
    field set from the markers the row carries. Rows without markers
    (every pre-mint row, and every pipeline row) reconstruct the
    original field set and keep verifying. Any edit is caught by the
    MAC: stripping a marker (the token was minted over more fields),
    grafting one onto an old row (the token was minted over fewer),
    changing a value (field mismatch), or DUPLICATING a marker all
    fail verification and demote the row to hint tier — the fail
    direction is re-test.

    The duplicate rule closes the append shape adversarial re-verify
    found: a first-match rebuild let ``<legit row> ||minted=grant||``
    verify under the legit token while displaying two contradictory
    markers. No store writes a mint key twice
    (:data:`_MINT_FIELD_KEYS` is validated unique at store time), so
    any repeated key is tamper evidence — the rebuild then injects
    the reserved :data:`_MINT_DUP_SENTINEL` field, which no minted
    token ever covers, and verification fails.
    """
    fields: dict[str, str] = {}
    for key in _MINT_FIELD_KEYS:
        values = _MINT_FIELD_RES[key].findall(content)
        if len(values) > 1:
            return {_MINT_DUP_SENTINEL: "duplicate-markers"}
        if values:
            fields[key] = values[0]
    return fields


class VerdictWalkTruncated(RuntimeError):
    """The verdict-row enumeration could not cover the whole store.

    Raised — never swallowed into a partial result — because the
    operator verbs act on the enumeration: a ``retest`` that clears
    only the rows a truncated walk happened to see would report
    success while a suppressing row survives. Fail closed; the caller
    reports and clears nothing.
    """


def operator_client() -> SageClient | None:
    """A SAGE client for one-off operator verbs, or ``None``.

    Unlike :func:`_get_client` this skips the GPU probe — the gate
    exists because pipeline hooks fire per-finding inside automated
    runs where CPU embedding latency is prohibitive; a single
    operator-invoked verdict is fine on CPU. No singleton either:
    operator CLIs are short-lived processes and a fresh client avoids
    the pipeline cache's staleness after a forget.
    """
    try:
        config = SageConfig.from_env()
        candidate = SageClient(config)
        if candidate.is_available():
            return candidate
    except Exception as exc:  # noqa: BLE001 — absence is a normal state
        logger.debug("SAGE operator client init failed: %s", exc)
    return None


def _iter_verdict_rows(
    client: SageClient,
    repo_path: str,
    rule_id: str,
    file_path: str,
    function: str,
    *,
    strict: bool = False,
):
    """Yield ``(memory_id, verdict, source_hash, ts, mac_verified,
    note)`` for every finding-verdict row stored for one finding
    (``note`` = the free-form audit text after the marker fields —
    the operator provenance stamp).

    Deterministic enumeration (bounded id-bearing listing filtered on
    the repo's fp domain + the finding fingerprint), NOT semantic
    recall — an operator clearing a verdict must see every row, not
    the top-k nearest. Bounded like raptor-sage's memory walk (page
    cap plus per-id dedupe), but incompleteness raises
    :class:`VerdictWalkTruncated` instead of ending quietly: the
    walk's consumers CLEAR rows, and a partial enumeration reported
    as success would leave a suppressing row alive. The server's
    ``has_more`` drives continuation when present (a server-capped
    page smaller than our limit must not end the walk); on servers
    that predate it, a short page ends the walk — the same
    convention raptor-sage's fetch applies. ``strict=True`` (the
    CLEARING verbs) additionally raises on a legacy full-page stall
    instead of returning the partial view.
    """
    domain = _fp_domain(repo_path)
    fp = _finding_fingerprint(rule_id, file_path, function)
    binding = f"Finding verdict: fp={fp} "
    seen: set[str] = set()
    offset = 0
    for _ in range(_OPERATOR_LIST_MAX_PAGES):
        resp = client.list_memories(limit=_OPERATOR_LIST_PAGE, offset=offset)
        if resp is None:
            raise VerdictWalkTruncated(
                "SAGE memory listing failed mid-walk")
        memories = getattr(resp, "memories", None) or []
        has_more = bool(getattr(resp, "has_more", False))
        if not memories:
            if has_more:
                raise VerdictWalkTruncated(
                    "server returned an empty page with has_more set")
            return
        new_rows = 0
        for m in memories:
            mid = getattr(m, "memory_id", None)
            if not isinstance(mid, str) or mid in seen:
                continue
            seen.add(mid)
            new_rows += 1
            if getattr(m, "domain_tag", None) != domain:
                continue
            text, token = rowmac.strip(str(getattr(m, "content", "") or ""))
            if not text.startswith(binding):
                continue
            match = _VERDICT_ROW_RE.search(text)
            if not match:
                continue
            src, verdict, ts = match.groups()
            fields = {
                "kind": "finding_verdict",
                "repo": _repo_key(repo_path),
                "fp": fp,
                "verdict": verdict,
                "src": src,
                "ts": ts,
                **_mint_fields_from_content(text),
            }
            mac_ok = _row_mac_ok("finding_verdict", fields, token)
            note = text[match.end():].strip()
            yield (mid, verdict, src, ts, mac_ok, note)
        offset += len(memories)
        if new_rows == 0:
            if has_more:
                raise VerdictWalkTruncated(
                    "pagination stalled (pages of only already-seen "
                    "rows with has_more set)")
            if strict and len(memories) >= _OPERATOR_LIST_PAGE:
                # A FULL page of only already-seen rows from a server
                # that does not report has_more: indistinguishable
                # from a broken/legacy pager repeating itself. The
                # read path tolerates the partial view (raptor-sage's
                # own fetch convention); a CLEARING verb must not —
                # it would then report "cleared" while unseen rows
                # survive.
                raise VerdictWalkTruncated(
                    "pagination stalled on a full page (legacy server "
                    "without has_more)")
            return
        if not has_more and len(memories) < _OPERATOR_LIST_PAGE:
            return
    raise VerdictWalkTruncated(
        f"page cap reached ({_OPERATOR_LIST_MAX_PAGES} pages) before "
        "the server said stop")


def list_finding_verdict_rows(
    repo_path: str,
    rule_id: str,
    file_path: str,
    function: str,
    *,
    client: SageClient | None = None,
) -> list[dict[str, Any]] | None:
    """Every stored verdict row for one finding, with memory ids.

    Returns ``None`` when SAGE is unavailable (distinct from ``[]`` =
    reachable but no rows). Each row:
    ``{memory_id, verdict, source_hash, ts, mac_verified, note}`` —
    ``note`` carries the row's free-form audit text (the operator
    provenance stamp), so where a verdict came from is inspectable.
    Raises :class:`VerdictWalkTruncated` when the enumeration could
    not cover the store — callers must report, never treat the
    partial view as the store's contents. (Read path: a legacy
    server's full-page stall ends the walk quietly, like
    raptor-sage's own fetch — the clearing verbs use the strict
    walk.)
    """
    if client is None:
        client = operator_client()
    if client is None:
        return None
    try:
        return [
            {
                "memory_id": mid,
                "verdict": verdict,
                "source_hash": src,
                "ts": ts,
                "mac_verified": mac_ok,
                "note": note,
            }
            for mid, verdict, src, ts, mac_ok, note
            in _iter_verdict_rows(
                client, repo_path, rule_id, file_path, function)
        ]
    except VerdictWalkTruncated:
        raise
    except Exception as e:  # noqa: BLE001 — operator verbs degrade, never crash the CLI
        logger.debug("SAGE verdict listing failed: %s", e)
        return None


def forget_finding_verdicts(
    repo_path: str,
    rule_id: str,
    file_path: str,
    function: str,
    *,
    verdicts: frozenset[str] | set[str] | None = None,
    reason: str = "",
    client: SageClient | None = None,
) -> tuple[int, int] | None:
    """Deprecate stored verdict rows for one finding.

    ``verdicts`` restricts which verdict values are cleared (pass
    :data:`_SUPPRESS_VERDICTS` for the tp verb — clear only the rows
    that would suppress); ``None`` clears every verdict row (the
    retest verb). MAC-unverified rows are cleared too: they never
    mechanically suppress, but "clear the stored verdict" means the
    whole record, and deprecation is the server's reversible
    soft-delete.

    Returns ``(cleared, failed)`` — rows deprecated, and rows the
    server REFUSED to deprecate. Callers must fail loudly on any
    ``failed``: a surviving suppressing row reported as cleared is
    exactly the false-success the fail-closed walk exists to prevent.
    Returns ``None`` when SAGE is unavailable. Raises
    :class:`VerdictWalkTruncated` when the store could not be fully
    enumerated — a STRICT walk (a legacy server's full-page stall
    truncates too) that completes BEFORE any forget call, so nothing
    is cleared on that path.
    """
    if client is None:
        client = operator_client()
    if client is None:
        return None
    try:
        rows = list(_iter_verdict_rows(
            client, repo_path, rule_id, file_path, function,
            strict=True))
    except VerdictWalkTruncated:
        raise
    except Exception as e:  # noqa: BLE001 — operator verbs degrade, never crash the CLI
        logger.debug("SAGE verdict enumeration failed: %s", e)
        return None
    cleared = 0
    failed = 0
    for mid, verdict, _src, _ts, _mac_ok, _note in rows:
        if verdicts is not None and verdict not in verdicts:
            continue
        if client.forget(mid, reason=reason):
            cleared += 1
        else:
            failed += 1
    return cleared, failed


# Public aliases — CLI consumers name the suppressing set and the
# TTL without reaching into privately-named constants.
SUPPRESS_VERDICTS = _SUPPRESS_VERDICTS
SUPPRESS_TTL_DAYS = _SUPPRESS_TTL_DAYS


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
        ts = str(int(time.time()))
        content = (
            f"Audit hypothesis verdict: "
            f"||file={_s(file_path)}|| ||fn={_s(function)}|| "
            f"||hyp={_s(hyp_hash)}|| ||src={_s(source_hash)}|| "
            f"||status={_s(status)}|| ||tool={_s(evidence_tool)}|| "
            f"||ts={ts}|| "
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
                "ts": ts,
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
            ts_match = re.search(r"\|\|ts=(\d+)\|\|", content)
            if not ts_match:
                # Pre-TTL row (no timestamp in the MAC'd set): demote
                # to hint — the function re-reviews and re-earns a
                # fresh, TTL-bounded verdict.
                continue
            ts = ts_match.group(1)
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
                        "ts": ts,
                    }
                    if not _row_mac_ok("audit_hypothesis", fields, token):
                        break
                    if not _row_ts_fresh("audit_hypothesis", ts):
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


def parse_verified_sca_fields(row: dict[str, Any]) -> dict[str, str] | None:
    """Return the authenticated SCA decision fields for *row*, or ``None``.

    Parses the ``||sca_eco/sca_name/sca_ver/sca_verdict||`` markers from
    the row content and verifies the row MAC over exactly those fields.
    Mechanical consumers (the slopsquat short-circuit in
    ``packages/sca/pipeline.py``) must act on THIS dict — specifically
    ``verdict == "malicious_confirmed"`` plus exact name/ecosystem
    equality — never on substring matches over the prose: the prose
    embeds LLM-generated summary text (prompt-injectable via hostile
    package metadata) and detail strings that legitimately NAME the
    imitated package.

    ``None`` means the row is hint-only (unstamped, foreign, or
    tampered).
    """
    clean, token = rowmac.strip(str(row.get("content") or ""))

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
    if not _row_mac_ok("sca_outcomes", fields, token):
        return None
    return fields


def _sca_row_mechanically_usable(row: dict[str, Any]) -> bool:
    """Gate rows that would trigger the confirmed-malicious short-circuit.

    The SCA pipeline short-circuits packages recalled as confirmed
    malicious — the FAIL direction here is a false positive, not a
    miss, but it is still a mechanical decision. Rows whose content
    mentions ``malicious_confirmed`` anywhere are only returned when
    their MAC token verifies over the decision fields (kind, ecosystem,
    name, version, verdict) written by ``store_sca_outcomes`` on this
    install. Rows without the trigger pass through unchanged as
    ordinary context.
    """
    clean, _token = rowmac.strip(str(row.get("content") or ""))
    if "malicious_confirmed" not in clean:
        return True
    return parse_verified_sca_fields(row) is not None


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

            _s = _sanitise_delim
            # Sanitise EVERY prose component, not just the trailing
            # decision fields: detail and llm_summary embed registry
            # metadata and LLM output (injectable via a hostile package
            # README), and a '|' smuggled into the prose could plant
            # counterfeit ||key=value|| markers ahead of the genuine
            # ones for any parser that regex-scans the content.
            parts = [f"SCA: {_s(pkg)}"]
            if eco:
                parts.append(f"({_s(eco)})")
            if version:
                parts.append(f"v{_s(version)}")
            parts.append(f"in {_s(repo_name)} — verdict: {_s(verdict)}.")
            if kind:
                parts.append(f"Kind: {_s(kind)}.")
            if cve_ids:
                parts.append(
                    f"CVEs: {', '.join(_s(c) for c in cve_ids[:5])}.",
                )
            if severity:
                parts.append(f"Severity: {_s(severity)}.")
            if detail:
                parts.append(_s(detail[:200]))
            if llm_summary:
                parts.append(f"LLM: {_s(llm_summary[:150])}")

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


# Line-anchored (the horizontal-only ``[ \t]*`` form — ``^\s*`` with
# re.M compounds across blank lines): the genuine 'Source hash:' line
# always starts its line; see _verified_concept_rows.
_CONCEPT_SRC_RE = re.compile(r"^[ \t]*Source hash: (\S+)", re.MULTILINE)


def _verified_concept_rows(
    rows: list[dict[str, Any]],
    hook: str,
    expected_concept: str | None = None,
) -> list[dict[str, Any]]:
    """Keep only concept rows whose MAC verifies (recall side).

    Concept rows drive skip/seed decisions in study and teach. The
    per-evidence source hashes already prove freshness; the MAC proves
    authorship — both are required before a row has mechanical effect.
    Rows without a valid token (legacy, foreign, tampered) are dropped
    from the mechanical path, exactly as if no memory existed.

    The MAC proves AUTHORSHIP, not ADDRESSEE: a validly stamped row for
    a semantic neighbor (get_page returned for a put_page query) still
    verifies. When the caller keys results per identifier, it must pass
    *expected_concept* so rows the consumer's matching rule would not
    associate with that identifier are dropped before they drive its
    skip/seed decision. The gate applies the consumer's own rule
    (core.concepts.study.concept_matches_identifier) — stored concept
    ids are routinely semantic names ('scatter_walk_state_machine' for
    identifier 'scatter_walk'), so anything stricter drops legitimate
    self rows.

    The MAC also covers only the header fields {kind, concept, src},
    never the row body, so the third check binds the body's evidence
    lines to the token: the composite re-folded from the row's
    evidence-line hashes (the same per-line extraction and fold the
    store side minted src with) must equal the MAC-bound ``src`` —
    both-empty passes (a concept stored without parseable evidence
    hashes). Without it, a hostile store holding a previously-issued
    genuine header+token could splice forged evidence lines into the
    body whose hashes match CURRENT source; the freshness verifier
    downstream re-hashes whatever locations those lines claim, so such
    a row would sail into the mechanical skip path. The composite
    binds the evidence-hash multiset only — see the scope note at the
    check site.
    """
    # Lazy: core.concepts.study imports this module back (call-time in
    # both directions, so neither import can cycle at load).
    from core.concepts.study import (
        concept_matches_identifier,
        stamped_evidence_composite,
    )
    out: list[dict[str, Any]] = []
    for row in rows or []:
        clean, token = rowmac.strip(str(row.get("content") or ""))
        # Bounded id: an unbounded bracket body re-scans a hostile row
        # from every planted head — quadratic; writer ids are short.
        m_id = re.search(r"Concept \[([^\]]{1,500})\]", clean)
        # The genuine 'Source hash:' line is the LAST one the writer
        # emits, and it starts its line; take the last line-anchored
        # occurrence so a row whose earlier prose merely mentions
        # 'Source hash: ...' at a line start cannot shadow it (an
        # unanchored first-occurrence search let exactly that break MAC
        # verification of a legitimate row). Inline mentions never
        # start a line: the writer folds newlines out of field values.
        src_matches = _CONCEPT_SRC_RE.findall(clean)
        concept = m_id.group(1) if m_id else ""
        fields = {
            "kind": "study_concept",
            "concept": concept,
            "src": src_matches[-1] if src_matches else "",
        }
        # Gate order: MAC first (authorship — everything after trusts
        # the header fields only once the token verifies), then
        # addressee (is this row for the querying identifier), then
        # evidence composite (is the body's evidence what the token
        # was minted for).
        if not _row_mac_ok(hook, fields, token):
            continue
        if expected_concept is not None and not concept_matches_identifier(
            concept, expected_concept,
        ):
            logger.debug(
                "SAGE %s: recall row is for concept %r, not %r — dropped from mechanical path",
                hook, concept, expected_concept,
            )
            continue
        # Evidence-composite binding. Scope: this binds WHICH evidence
        # hashes the row carries (as a multiset), not the surrounding
        # text — observation prose, invariants, contracts, and
        # HASHLESS evidence lines stay outside both the MAC and the
        # composite. A hashless forged evidence line is not mere seed
        # prose: reconstruction still mints it as an Evidence object
        # (file:line + observation) inside a skipped concept; only the
        # hashed lines are pinned, and the freshness verifier
        # separately constrains each hashed line's file:line to a
        # location whose current content matches its hash. Recall-side
        # recomputation rather than a body hash in the MAC fields, so
        # every already-stored stamped row keeps its mechanical effect.
        recomputed = stamped_evidence_composite(clean)
        src = fields["src"]
        # Rows minted before the composite went full-length carry a
        # 12-hex prefix of the same fold; prefix-compare for exactly
        # that src length keeps them verifying. No downgrade surface:
        # src is MAC-bound, so an attacker cannot shorten a full-length
        # row's src without breaking the MAC.
        expected = recomputed[:12] if len(src) == 12 else recomputed
        if expected != src:
            logger.debug(
                "SAGE %s: recall row evidence composite %.16s does not "
                "match MAC-bound source hash %.16s (concept %.80r) — "
                "mechanical use demoted to hint",
                hook, recomputed, src, concept,
            )
            continue
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

    # Shared evidence-row grammar: the core.concepts.study parsers
    # re-derive file/line/hash from this exact shape (drift = silent
    # loss of the cross-run study skip). The composite src is minted
    # by the parser side itself (see below), so the two can never
    # disagree. Call-time imports in both directions — no load cycle.
    from core.concepts.model import fold_ws, sage_evidence_row
    from core.concepts.study import stamped_evidence_composite

    stored = 0
    repo_name = Path(repo_path).name
    scope_label = fold_ws(study_scope or repo_name)

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
            # Every free-text field value folds its whitespace before
            # rendering (fold_ws — sage_evidence_row applies the same
            # rule to its own fields): a raw line boundary inside any
            # value would let the remainder stand as a row line of its
            # own — an invariant statement containing "\nSource hash:
            # x" mints a line-start mention that shadows the genuine
            # field for concepts that store no composite. The concept
            # id folds ONCE and that folded form is used both in the
            # rendered header and in the MAC fields, so the recall
            # side's header extraction re-derives exactly the minted
            # value.
            cid = fold_ws(concept.id)
            parts = [
                (
                    f"Concept [{cid}] in {scope_label}: "
                    f"{fold_ws(concept.description)}"
                )
            ]

            evidence_files = set()
            for ev in concept.evidence:
                parts.append(sage_evidence_row(ev))
                if ev.file:
                    evidence_files.add(fold_ws(ev.file))

            invs = concept_invariants.get(concept.id, [])
            for inv in invs:
                parts.append(
                    f"  Invariant [{fold_ws(inv.id)}]: "
                    f"{fold_ws(inv.statement)} "
                    f"(negation: {fold_ws(inv.negation)})"
                )
                if inv.relevant_cwes:
                    cwes = ", ".join(fold_ws(c) for c in inv.relevant_cwes)
                    parts.append(f"    CWEs: {cwes}")

            contracts = concept_contracts.get(concept.id, [])
            for ct in contracts:
                ct_parts = [f"  Contract [{fold_ws(ct.function)}]"]
                if ct.when:
                    ct_parts.append(f"when: {fold_ws(ct.when)}")
                if ct.ownership_transfer:
                    ct_parts.append(
                        f"ownership: {fold_ws(ct.ownership_transfer)}"
                    )
                parts.append(" ".join(ct_parts))

            parts.append(f"  Study scope: {scope_label}")
            parts.append(f"  Confidence: {fold_ws(concept.confidence)}")
            if evidence_files:
                parts.append(
                    f"  Evidence files: {', '.join(sorted(evidence_files))}"
                )
            # Mint src THROUGH THE PARSER: fold the hashes as the
            # grammar's own extraction reads them back from the
            # rendered content, not from the Evidence objects. Whatever
            # the recall-side recomputation will extract from this row
            # is by construction what gets MAC-bound here — a rendering
            # a parser reads differently can shift WHICH hashes fold,
            # but never make writer and verifier fold different sets.
            composite = stamped_evidence_composite("\n".join(parts))
            if composite:
                parts.append(f"  Source hash: {composite}")

            content = "\n".join(parts)
            content = _stamp_row(
                "study_concepts",
                content,
                {
                    "kind": "study_concept",
                    "concept": cid,
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
            return (
                name,
                _verified_concept_rows(
                    rows, "concepts_for_study", expected_concept=name
                ),
            )
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
            # Shared row-line iteration (hint-tier scoring only, but
            # no consumer keeps a private splitter over row content).
            from core.concepts.study import _iter_row_lines
            scope_line = [
                ln for ln, _m in _iter_row_lines(content)
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
            # Sanitised like every other prose component (the SCA
            # writer's counterfeit-marker rationale): the title is
            # LLM/finding-derived and renders BEFORE the ||key=value||
            # markers, so a '|' smuggled into it could plant
            # counterfeit markers ahead of the genuine ones for any
            # first-match parser of the same grammar.
            title = _s(_clip(
                str(finding.get("title") or finding.get("rule_id")
                    or finding.get("type") or "finding"), 120,
            ))
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
            # Same counterfeit-marker defence as the verdict writer:
            # prose ahead of the markers must never carry '|'.
            desc = _s(_clip(
                str(item.get("hypothesis") or item.get("title")
                    or item.get("description") or "hypothesis"), 120,
            ))
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


# ─────────────────────────────────────────────────────────────────────────────
# CVE fix pointers — /cve-diff discovery short-circuit
# ─────────────────────────────────────────────────────────────────────────────

# Global domain (not repo-scoped): a fix pointer is a public fact about
# the CVE itself, transferable to any project that meets it — same
# rationale as raptor-rule-library.
_CVE_DOMAIN = "raptor-cve"
_CVE_HOOK = "cve_fix_pointer"


def store_cve_fix_pointer(
    cve_id: str,
    repository_url: str,
    fix_commit: str,
    parent_commit: str = "",
    *,
    consensus_count: int = 0,
    shape: str = "",
) -> bool:
    """Store a pipeline-verified CVE → fix-commit pointer.

    Callers must only store pointers that survived /cve-diff's
    mechanical verification (acquire → resolve → diff → shape check);
    the row is MAC-stamped over the decision fields so recall can hand
    it a mechanical effect.
    """
    client = _get_client()
    if client is None or not (cve_id and repository_url and fix_commit):
        return False
    try:
        _s = _sanitise_delim
        cve = _s(cve_id.strip().upper())
        repo = _s(repository_url.strip())
        sha = _s(fix_commit.strip().lower())
        parent = _s((parent_commit or "").strip().lower())

        parts = [f"CVE fix pointer: {cve} is fixed by {repo} @ {sha}."]
        if parent:
            parts.append(f"Parent (pre-fix) commit: {parent}.")
        if consensus_count >= 2:
            parts.append("OSV+NVD pointer consensus agreed.")
        if shape:
            # Caller-supplied prose component: sanitise like every
            # embedded value so it can't forge a ||key=value|| field.
            parts.append(f"Diff shape: {_s(shape)}.")
        parts.append(
            f"||cve_id={cve}|| ||cve_repo={repo}|| "
            f"||cve_fix={sha}|| ||cve_parent={parent}||"
        )
        content = _stamp_row(_CVE_HOOK, " ".join(parts), {
            "kind": _CVE_HOOK,
            "cve": cve,
            "repo": repo,
            "fix": sha,
            "parent": parent,
        })
        # Consensus-confirmed pointers are double-verified (pipeline +
        # OSV/NVD agreement); pipeline-only ones still earned their
        # verdict mechanically.
        confidence = 0.95 if consensus_count >= 2 else 0.9
        return _propose_redacted(
            client=client,
            content=content,
            memory_type="fact",
            domain_tag=_CVE_DOMAIN,
            confidence=confidence,
            tags=["cve-diff", cve],
        )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE cve fix pointer store failed: %s", e)
        return False


def recall_cve_fix_pointer(cve_id: str) -> dict[str, str] | None:
    """Recall a MAC-verified fix pointer for *cve_id*, or None.

    Mechanical consumer: /cve-diff skips its discovery agent loop when
    this returns a pointer — the pipeline still re-verifies the pointer
    by actually cloning and diffing it, and falls back to the agent when
    that verification fails, so a stale row costs one clone, not a wrong
    answer. Because the effect is mechanical, the MAC gate is hard: rows
    without a verifying token are ignored entirely, not demoted to
    hints. Kill-switch: ``RAPTOR_SAGE_CVE_PRIOR=0``.
    """
    if not env_flag("RAPTOR_SAGE_CVE_PRIOR", default=True):
        return None
    client = _get_client()
    if client is None or not cve_id:
        return None
    try:
        _metric_inc("recall_attempted")
        cve = cve_id.strip().upper()
        rows = client.query(
            text=f"CVE fix pointer for {cve}: repository and fix commit",
            domain_tag=_CVE_DOMAIN,
            top_k=5,
            min_confidence=0.85,
        )
        for row in rows:
            clean, token = rowmac.strip(str(row.get("content") or ""))

            def _field(key: str, _clean: str = clean) -> str:
                match = re.search(rf"\|\|{key}=([^|]*)\|\|", _clean)
                return match.group(1) if match else ""

            if _field("cve_id") != cve:
                continue
            fields = {
                "kind": _CVE_HOOK,
                "cve": cve,
                "repo": _field("cve_repo"),
                "fix": _field("cve_fix"),
                "parent": _field("cve_parent"),
            }
            if not fields["repo"] or not fields["fix"]:
                continue
            if not _row_mac_ok(_CVE_HOOK, fields, token):
                continue
            _metric_inc("recall_hits")
            return {
                "cve_id": cve,
                "repository_url": fields["repo"],
                "fix_commit": fields["fix"],
                "parent_commit": fields["parent"],
            }
        return None
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE cve fix pointer recall failed: %s", e)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Web scanning — per-target priors (hint tier ONLY)
# ─────────────────────────────────────────────────────────────────────────────

def _web_domain(target_url: str) -> str:
    return f"raptor-web-{_repo_key(target_url)}"


def recall_context_for_web_scan(target_url: str) -> list[dict[str, Any]]:
    """Prior web-scan knowledge for this target — hint tier only.

    Consumers may reorder vulnerability classes, bias payload prompts,
    or prefer wordlists on recall; they must never suppress a check or
    demote a finding because of it. Memory prioritizes; only the
    current run's oracle concludes.
    """
    client = _get_client()
    if client is None:
        return []
    try:
        from urllib.parse import urlparse
        _metric_inc("recall_attempted")
        host = urlparse(target_url).netloc or target_url
        results = client.query(
            text=(
                f"What is known about the web target {host}: framework "
                "fingerprint, confirmed vulnerability classes, probes "
                "that verification refuted, and which wordlists "
                "produced discovery hits?"
            ),
            domain_tag=_web_domain(target_url),
            top_k=5,
            min_confidence=0.5,
        )
        methodology = client.query(
            text=(
                "Web scanning methodology: injection class selection, "
                "soft-404 calibration, and replay/control verification "
                "discipline."
            ),
            domain_tag="raptor-methodology",
            top_k=2,
            min_confidence=0.5,
        )
        merged = _merge_recall_rows(results, methodology, top_k=6)
        _metric_inc("recall_hits", len(merged))
        return merged
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE web recall failed: %s", e)
        return []


def store_web_scan_observations(
    target_url: str,
    *,
    fingerprint: dict[str, Any],
    findings: list[dict[str, Any]],
    refuted_probes: list[dict[str, Any]] | None = None,
    wordlist_stats: dict[str, int] | None = None,
) -> None:
    """Store one web run's observations (called at report time).

    Three bounded observation rows per run at most: the target's
    fingerprint, the confirmed vulnerability classes, and wordlist
    effectiveness. Refuted probes store as FP-prone HINTS — recall-side
    consumers must treat them as prioritization signal, never as
    suppression (the docstring contract recall_context_for_web_scan
    states).
    """
    client = _get_client()
    if client is None:
        return
    try:
        from urllib.parse import urlparse
        host = urlparse(target_url).netloc or target_url
        domain = _web_domain(target_url)

        if fingerprint:
            pairs = ", ".join(
                f"{key}={_sanitise_delim(str(value))[:80]}"
                for key, value in sorted(fingerprint.items()) if value
            )[:400]
            _propose_redacted(
                client=client,
                content=f"Web target {host} fingerprint: {pairs}.",
                memory_type="observation",
                domain_tag=domain,
                confidence=0.85,
                tags=["web", "fingerprint"],
            )

        confirmed = [
            f for f in findings
            if f.get("confirmed") is True or f.get("status") == "confirmed"
        ]
        if confirmed:
            from urllib.parse import urlparse as _parse
            summary = "; ".join(sorted({
                f"{f.get('vuln_type', 'unknown')} at "
                f"{_parse(str(f.get('url') or '')).path or '/'}"
                for f in confirmed
            }))[:400]
            _propose_redacted(
                client=client,
                content=(
                    f"Confirmed vulnerability classes on {host}: {summary}."
                ),
                memory_type="observation",
                domain_tag=domain,
                confidence=0.9,
                tags=["web", "confirmed"],
            )

        if refuted_probes:
            summary = "; ".join(sorted({
                f"{p.get('vuln_type', 'unknown')} at "
                f"{p.get('endpoint', '')}".strip()
                for p in refuted_probes
            }))[:400]
            _propose_redacted(
                client=client,
                content=(
                    f"Verification refuted probes on {host}: {summary}. "
                    "Treat matching future signals as FP-prone — a hint "
                    "for prioritization only, never suppression."
                ),
                memory_type="observation",
                domain_tag=domain,
                confidence=0.8,
                tags=["web", "refuted"],
            )

        if wordlist_stats:
            summary = ", ".join(
                f"{_sanitise_delim(name)}: {hits} hit(s)"
                for name, hits in sorted(wordlist_stats.items())
            )[:300]
            _propose_redacted(
                client=client,
                content=f"Wordlist effectiveness on {host}: {summary}.",
                memory_type="observation",
                domain_tag=domain,
                confidence=0.7,
                tags=["web", "wordlist"],
            )
    except Exception as e:  # noqa: BLE001 — SAGE is best-effort; a hook failure must never break the pipeline
        logger.debug("SAGE web store failed: %s", e)
