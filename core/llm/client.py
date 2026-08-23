"""
LLM Client with Automatic Fallback and Cost Tracking

Manages multiple LLM providers with:
- Automatic fallback on failure
- Retry logic with exponential backoff
- Cost tracking and budget limits
- Response caching
- Task-specific model selection
"""

import json

# Import for type-based error detection (optional SDKs)
# DEBUG log on import failure so operators can diagnose partial-
# install issues via --verbose. See core/llm/detection.py for the
# canonical probe sites.
import logging as _logging
import re
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

from core.hash import sha256_string
from core.logging import get_logger

from .config import LLMConfig, ModelConfig
from .providers import LLMProvider, LLMResponse, StructuredResponse, create_provider
from .response_validation import SchemaUnknownFieldError, unknown_response_fields

_client_log = _logging.getLogger(__name__)

try:
    import openai as _openai_module
    _OPENAI_AVAILABLE = True
except ImportError as _e:
    _client_log.debug("openai SDK probe failed (client.py): %s", _e)
    _OPENAI_AVAILABLE = False

try:
    import anthropic as _anthropic_module
    _ANTHROPIC_AVAILABLE = True
except ImportError as _e:
    _client_log.debug("anthropic SDK probe failed (client.py): %s", _e)
    _ANTHROPIC_AVAILABLE = False

logger = get_logger()

_MODEL_BANNER_SHOWN = False


def _model_banner_shown() -> bool:
    """Return True (and set flag) if the model banner was already logged."""
    global _MODEL_BANNER_SHOWN
    if _MODEL_BANNER_SHOWN:
        return True
    _MODEL_BANNER_SHOWN = True
    return False


_TRANSPORT_BANNER_SHOWN = False


def _transport_banner_shown() -> bool:
    """Return True (and set flag) if the no-external-LLM transport
    banner was already logged. The claude-CLI transport constructs a
    client per call, so an unguarded banner printed once per worker
    call — 12 copies on one observed run."""
    global _TRANSPORT_BANNER_SHOWN
    if _TRANSPORT_BANNER_SHOWN:
        return True
    _TRANSPORT_BANNER_SHOWN = True
    return False


# After this many consecutive cache write failures, auto-disable
# caching for the rest of the run. Tuned for "transient blip vs
# durable problem" — three retries lets a momentary EBUSY recover,
# but a real disk-full / read-only-FS / permission flip stops
# spamming the log after a few thousand subsequent writes.
_CACHE_WRITE_FAILURE_THRESHOLD = 3

# Floor for the per-call budget reservation. Acquired before each
# provider call to close the check-then-act window that lets concurrent
# dispatchers individually pass the cap and collectively overshoot.
# Reconciled to the actual response cost on success; released on
# exception. The actual reservation is sized per call class from
# observed history (see ``LLMClient._estimate_call_cost``); this floor
# only guards against degenerate near-zero estimates.
_BUDGET_RESERVATION = 0.10

# Conservative per-call cost estimate used before any completed call of
# a class has been observed (locally or in the run's telemetry sink).
# Sized for the expensive end of real call classes (full-context review
# calls land in the $3-5 range; most classes are far cheaper and their
# history takes over after the first completion). A too-small default
# recreates the overshoot this machinery exists to prevent: with N
# workers, N in-flight calls that each reserved $0.10 but cost $4 land
# ~N × $4 past the cap.
_DEFAULT_CALL_COST_ESTIMATE = 2.00

# The DEFAULT (no-history) estimate never exceeds this fraction of the
# cap: a conservative constant must not brick runs whose whole budget
# is smaller than one estimated call, and a refused reservation raises
# the TERMINAL budget error — a fresh class's first concurrent burst
# must not kill workers on a guess. History-derived estimates are
# evidence, so they get the looser _RESERVATION_CAP_MAX_FRACTION
# clamp (which only guarantees a fresh client can admit its first
# call).
_RESERVATION_CAP_FRACTION = 0.20
_RESERVATION_CAP_MAX_FRACTION = 0.95


class LLMBudgetExceededError(RuntimeError):
    """Raised when a call would breach the client's cost cap.

    Budget exhaustion is TERMINAL for the run: callers that dispatch
    LLM calls in a loop must stop dispatching when they see this, not
    convert it into a per-item error and keep going. Subclasses
    ``RuntimeError`` and keeps "budget exceeded" in the message so
    legacy string-match handlers keep working; new code should catch
    by type (or via :func:`is_budget_exceeded_error`).
    """


def is_budget_exceeded_error(exc: BaseException) -> bool:
    """True when *exc* signals LLM budget exhaustion.

    Prefers the typed check; falls back to the historical message
    match for exceptions raised by older code paths or re-wrapped by
    intermediaries that lose the original type.
    """
    if isinstance(exc, LLMBudgetExceededError):
        return True
    return (
        isinstance(exc, RuntimeError)
        and "budget exceeded" in str(exc).lower()
    )


class LLMAuthPersistentError(RuntimeError):
    """Persistent auth-layer refusal — TERMINAL for the consuming phase.

    Raised by phase drivers (via :class:`AuthFailureTracker`) when the
    LLM transport keeps refusing with auth errors: N consecutive
    401/403-class failures, or a single dispatcher-authoritative
    token-death signal ("token expired" / "unknown token" from the
    RAPTOR LLM dispatcher). At that point "the LLM said nothing" and
    "the auth layer refused" have provably diverged: every further
    call is a guaranteed refusal, and converting the refusals into
    empty results reports garbage as success (observed: a >12 h audit
    whose token expired mid-run had iris-assumptions "succeed" with
    0/6 batches and iris.synthesise report 0 assumptions across 690
    straight 401s).

    Callers must ABORT the phase loudly and record the abort in run
    state — never return an empty result set for it. Carries the
    phase name on ``.phase`` for run-state recording.
    """

    def __init__(self, phase: str, message: str) -> None:
        super().__init__(message)
        self.phase = phase


# Dispatcher-authoritative token-death signals: the 401 bodies emitted
# by core/llm/dispatcher/server._validate_token, ANCHORED to the
# error-field shape they actually ride in
# (``{'error': 'token expired (age ...s, ttl ...s)'}`` /
# ``{"error": "unknown token"}``) — never matched as bare substrings,
# because exception text can quote model/target-controlled content
# (a schema-violation message embeds model-chosen field names). One
# anchored sighting is definitive: the dispatcher itself declared the
# credential dead, so there is no transient interpretation to wait out.
_TOKEN_DEATH_RE = re.compile(
    r"error['\"]?\s*[:=]\s*['\"]\s*"
    r"(?:token expired \(age |unknown token['\"])",
    re.IGNORECASE,
)


def _exception_chain(exc: BaseException):
    """Yield *exc* and its causal chain (``__cause__``, falling back to
    non-suppressed ``__context__`` like traceback rendering), bounded
    and cycle-safe."""
    seen: set[int] = set()
    cur: BaseException | None = exc
    while cur is not None and id(cur) not in seen and len(seen) < 8:
        seen.add(id(cur))
        yield cur
        if cur.__cause__ is not None:
            cur = cur.__cause__
        elif not cur.__suppress_context__:
            cur = cur.__context__
        else:
            cur = None


def is_auth_refusal(exc: BaseException) -> bool:
    """True when *exc* signals an auth-layer refusal (401/403 class).

    Classification prefers STRUCTURAL signals over message text, in
    causal-chain order (this client's wrapped ``RuntimeError`` carries
    the original failure on ``__cause__``):

    1. Response-shape failures (schema violations, JSON decode errors)
       are NEVER auth — their messages quote model-chosen content
       and decode coordinates ("line 2 column 401"), which must not
       be able to impersonate a credential failure.
    2. Typed SDK auth errors and a transport-layer ``status_code`` of
       401/403 are auth.
    3. Only when no structural signal exists does the word-boundary,
       status-context-anchored text classifier run — the STRICT auth
       subset (``is_auth_status_text``), not the auth/billing union:
       quota bursts and billing caps have their own handling and must
       not read as credential death.
    """
    if isinstance(exc, LLMAuthPersistentError):
        return True
    if not isinstance(exc, Exception):
        return False
    for e in _exception_chain(exc):
        if isinstance(e, (SchemaUnknownFieldError, json.JSONDecodeError)):
            return False
        if _OPENAI_AVAILABLE:
            try:
                if isinstance(e, _openai_module.AuthenticationError):
                    return True
            except AttributeError:
                pass
        if _ANTHROPIC_AVAILABLE:
            try:
                if isinstance(e, _anthropic_module.AuthenticationError):
                    return True
            except AttributeError:
                pass
        status = getattr(e, "status_code", None)
        if (
            isinstance(status, int)
            and not isinstance(status, bool)
            and status in (401, 403)
        ):
            return True
    from core.llm.structured_call import is_auth_status_text
    return is_auth_status_text(str(exc))


class AuthFailureTracker:
    """Consecutive-auth-failure counter with phase-abort semantics.

    Phase drivers feed every LLM-call outcome through
    :meth:`note_success` / :meth:`note_failure`. The tracker trips
    terminal when ``threshold`` CONSECUTIVE auth-classified failures
    accumulate (any success or non-auth failure resets the streak),
    or immediately when a failure carries an explicit dispatcher
    token-death signal. Once tripped it stays tripped;
    :meth:`raise_if_tripped` converts the state into a phase-named
    :class:`LLMAuthPersistentError`.

    Thread-safe — batch drivers fan calls out via ``run_parallel``.
    """

    def __init__(self, phase: str, threshold: int = 3) -> None:
        self.phase = phase
        self.threshold = max(1, int(threshold))
        self._consecutive = 0
        self._tripped = False
        self._last: str = ""
        self._lock = threading.Lock()

    @property
    def tripped(self) -> bool:
        return self._tripped

    def note_success(self) -> None:
        with self._lock:
            self._consecutive = 0

    def note_failure(self, exc: BaseException) -> bool:
        """Record one failed call; returns the (possibly new) tripped
        state. Non-auth failures reset the consecutive-401 streak —
        they show the auth layer still admits calls. The instant-trip
        arm requires the dispatcher's anchored error-field shape
        (``_TOKEN_DEATH_RE``) on an already-auth-classified failure,
        never a bare substring over arbitrary exception text."""
        if not is_auth_refusal(exc):
            with self._lock:
                self._consecutive = 0
            return self._tripped
        msg = str(exc)
        explicit = bool(_TOKEN_DEATH_RE.search(msg))
        with self._lock:
            self._consecutive += 1
            self._last = msg
            if explicit or self._consecutive >= self.threshold:
                self._tripped = True
            return self._tripped

    def raise_if_tripped(self) -> None:
        if not self._tripped:
            return
        with self._lock:
            last = _sanitize_log_message(self._last)[:500]
            n = self._consecutive
        raise LLMAuthPersistentError(
            self.phase,
            f"{self.phase}: aborting after {n} consecutive auth "
            f"failure(s) — the LLM auth layer is refusing every call "
            f"(last error: {last}). Refusing to report empty results "
            f"as phase success.",
        )


# ── Process-level scorecard flush aggregation ─────────────────────────
#
# Each LLMClient used to register its own atexit flush, and each flush
# printed its own "scorecard: N calls ..." stderr line. Transports that
# spawn a client per call (claude-CLI) made a single run print 16 such
# lines at exit. Clients now register here; ONE atexit handler flushes
# every registered client (each still writes its own window to the
# scorecard — no data loss) and prints a single summed line.

_SCORECARD_FLUSH_LOCK = threading.Lock()
_SCORECARD_FLUSH_CLIENTS: list = []
_SCORECARD_ATEXIT_ARMED = False


def _register_scorecard_flush(client: Any) -> None:
    """Enroll *client* in the process-level run-end scorecard flush."""
    global _SCORECARD_ATEXIT_ARMED
    with _SCORECARD_FLUSH_LOCK:
        _SCORECARD_FLUSH_CLIENTS.append(client)
        if not _SCORECARD_ATEXIT_ARMED:
            import atexit
            atexit.register(_atexit_flush_scorecards)
            _SCORECARD_ATEXIT_ARMED = True


def _scorecard_atexit_suppressed() -> bool:
    """True when the process-exit scorecard flush must not run.

    Under pytest, per-test scorecard isolation (monkeypatched flush
    methods, tmp scorecard paths) is torn down at test teardown —
    BEFORE interpreter exit — so the atexit flush would write every
    registered test client's mock usage window into the real
    ``out/llm_scorecard.json``, corrupting the reliability data that
    ``/scorecard`` and the calibrated cross-model merge weights
    consume, a little more on every dev pytest run.

    ``"pytest" in sys.modules`` rather than ``PYTEST_CURRENT_TEST``:
    atexit handlers run at interpreter shutdown, after pytest has
    already unset the per-test env var (same reasoning as the
    zero-cost summary suppression in :func:`_print_scorecard_summary`).

    ``RAPTOR_SCORECARD_TEST_FLUSH=1`` opts back in — for tests that
    exercise the atexit path end-to-end against an isolated
    ``RAPTOR_SCORECARD_PATH``.
    """
    import os as _os
    import sys as _sys

    if _os.environ.get("RAPTOR_SCORECARD_TEST_FLUSH"):
        return False
    return "pytest" in _sys.modules


def _atexit_flush_scorecards() -> None:
    """Process-exit entrypoint: honour the pytest suppression guard,
    then delegate to :func:`_flush_all_scorecards`. Direct callers
    (manual flushes, tests) use ``_flush_all_scorecards`` and are
    unaffected by the guard.

    When suppressed, the usage windows are read WITHOUT writing to the
    scorecard, and the live-API-leak diagnostic is preserved: a paid
    call recorded during a pytest session means an unstubbed test hit
    a real provider, so the operator still gets the summary line plus
    the offending test names even though the leaked window itself
    never reaches ``out/llm_scorecard.json``."""
    if not _scorecard_atexit_suppressed():
        _flush_all_scorecards()
        return
    with _SCORECARD_FLUSH_LOCK:
        clients = list(_SCORECARD_FLUSH_CLIENTS)
        _SCORECARD_FLUSH_CLIENTS.clear()
    total: dict[str, Any] = {
        "calls": 0, "cost_usd": 0.0, "stub_cost_usd": 0.0,
        "latency_ms_sum": 0, "models": {},
        "paid_test_ctxs": set(),
    }
    for client in clients:
        try:
            with client._stats_lock:
                fired = dict(getattr(client, "_fired_models", {}) or {})
                usage = {
                    k: dict(v)
                    for k, v in (
                        getattr(client, "_fired_usage", {}) or {}
                    ).items()
                }
            ctxs = set(getattr(client, "_paid_test_ctxs", None) or ())
        except Exception as exc:  # noqa: BLE001 — atexit best-effort
            logger.debug("suppressed scorecard summary read failed: %s", exc)
            continue
        for (_prov, alias, _resolved, _role), n in fired.items():
            if not alias:
                continue
            total["calls"] += int(n or 0)
            total["models"][alias] = (
                total["models"].get(alias, 0) + int(n or 0)
            )
        for alias, metrics in usage.items():
            cost = float(metrics.get("cost_usd") or 0.0)
            total["cost_usd"] += cost
            if str(alias).endswith("-stub"):
                total["stub_cost_usd"] += cost
            total["latency_ms_sum"] += int(
                metrics.get("latency_ms_sum") or 0)
        total["paid_test_ctxs"].update(ctxs)
    if total["cost_usd"] > 0.0:
        _print_scorecard_summary(total)


def _flush_all_scorecards() -> None:
    """Run-end aggregator: flush every registered client's usage into
    the scorecard, then print ONE summed summary line. Best-effort;
    never raises (runs inside atexit)."""
    with _SCORECARD_FLUSH_LOCK:
        clients = list(_SCORECARD_FLUSH_CLIENTS)
        _SCORECARD_FLUSH_CLIENTS.clear()
    total: dict[str, Any] = {
        "calls": 0, "cost_usd": 0.0, "stub_cost_usd": 0.0,
        "latency_ms_sum": 0, "models": {},
        "paid_test_ctxs": set(),
    }
    flushed_any = False
    for client in clients:
        try:
            stats = client.flush_usage_to_scorecard(emit_summary=False)
        except TypeError:
            # Monkeypatched / legacy signature without emit_summary
            # (some tests stub the method with ``lambda self: None``).
            try:
                stats = client.flush_usage_to_scorecard()
            except Exception:  # noqa: BLE001
                stats = None
        except Exception:  # noqa: BLE001
            stats = None
        if not stats:
            continue
        flushed_any = True
        total["calls"] += int(stats.get("calls") or 0)
        total["cost_usd"] += float(stats.get("cost_usd") or 0.0)
        total["stub_cost_usd"] += float(stats.get("stub_cost_usd") or 0.0)
        total["latency_ms_sum"] += int(stats.get("latency_ms_sum") or 0)
        for alias, calls in (stats.get("models") or {}).items():
            total["models"][alias] = (
                total["models"].get(alias, 0) + int(calls or 0)
            )
        total["paid_test_ctxs"].update(stats.get("paid_test_ctxs") or ())
    if flushed_any:
        _print_scorecard_summary(total)


def _print_scorecard_summary(stats: dict[str, Any]) -> None:
    """Per-run scorecard delta — the discoverability lever. One line at
    process end so every command's user sees the scorecard active and
    learns the command exists. Best-effort print to stderr."""
    try:
        import os as _os
        import sys as _sys

        tot_calls = int(stats.get("calls") or 0)
        tot_cost = float(stats.get("cost_usd") or 0.0)
        tot_lat_ms = int(stats.get("latency_ms_sum") or 0)
        models: dict[str, int] = stats.get("models") or {}
        # Test-run noise suppression: under pytest, a scorecard
        # line for a zero-cost run (stub providers, cache-only
        # replay) is pure noise — hundreds of $0.0000 lines
        # per test session with no actionable signal. Skip
        # emission in that case. Operator runs (pytest not in
        # sys.modules) still see zero-cost lines so a cache-
        # only replay is visibly distinct from a non-firing
        # command. Paid calls under pytest STILL emit — they
        # indicate a live-API leak the operator wants to see
        # (e.g. an unstubbed pipeline test hitting Gemini).
        #
        # ``"pytest" in sys.modules`` (not
        # ``PYTEST_CURRENT_TEST``) because most of these flushes
        # run in ``atexit`` handlers at interpreter shutdown,
        # after pytest has already unset the per-test env var.
        # sys.modules entry persists for the process lifetime.
        # ``*-stub`` alias costs are deliberately fake (cost-plumbing
        # tests) — excluded from the leak gate so a suite exercising
        # budget accounting doesn't read as live-API spend.  Real paid
        # calls can't hide behind this: the paid-ctx capture in
        # ``_record_usage`` skips ``*-stub`` aliases with the same
        # convention, so any non-stub cost keeps the line (and the
        # culprit-test attribution below) fully loud.
        stub_cost = float(stats.get("stub_cost_usd") or 0.0)
        if "pytest" in _sys.modules and (tot_cost - stub_cost) <= 0.0:
            return
        if _os.environ.get("RAPTOR_LLM_QUIET"):
            return
        avg_ms = (tot_lat_ms // tot_calls) if tot_calls else 0
        # Four-decimal format always: preserves sub-penny
        # detail for small runs (cache-heavy / cheap-tier
        # short-circuit) so a "$0.0042" run is visibly
        # distinct from a truly-zero "$0.0000" one. Trailing
        # zeros on larger numbers (``$3.4900``) read as
        # mild noise but the consistent shape wins for
        # log-grepping across runs.
        cost_s = f"${tot_cost:.4f}"
        models_s = ", ".join(
            f"{a} {models[a]}c"
            for a in sorted(models, key=lambda k: -models[k])
        )
        print(
            f"scorecard: {tot_calls} calls across {len(models)} model(s) "
            f"[{models_s}] · {cost_s} · avg {avg_ms}ms — "
            f"`raptor-llm-scorecard` for details",
            file=_sys.stderr,
        )
        # A paid call under pytest is a live-API leak from an unstubbed
        # test — name the tests so the operator can fix them instead of
        # bisecting suites.
        _ctxs = stats.get("paid_test_ctxs") or ()
        if _ctxs and "pytest" in _sys.modules:
            print(
                "scorecard: paid call(s) fired from test(s): "
                + "; ".join(sorted(_ctxs)),
                file=_sys.stderr,
            )
    except Exception as exc:  # noqa: BLE001
        logger.debug("scorecard summary print failed: %s", exc)


_AUTH_ERROR_INDICATORS = frozenset({
    "401", "403", "authentication", "unauthorized", "invalid api key",
    "invalid x-api-key", "api key not valid", "incorrect api key",
    "permission denied", "access denied",
})


def _sanitize_log_message(msg: str) -> str:
    """
    SECURITY: API Key Sanitization for Application Logs

    Defense-in-depth protection against API key leakage in error messages.

    Searchable tags: #SECURITY #API_KEY_PROTECTION #LOG_SANITIZATION
    Related: Cursor Bot Bug #2, PR #32, defense-in-depth best practice
    """
    # Redact private key material before shorter generic patterns. If a log line
    # is truncated before the END marker, redact through the end of the message.
    msg = re.sub(
        r'-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)',
        '[REDACTED-PRIVATE-KEY]',
        msg,
        flags=re.DOTALL,
    )
    # Redact Anthropic API keys first (sk-ant-*) before general sk-* pattern
    msg = re.sub(r'sk-ant-[a-zA-Z0-9-_]{20,}', '[REDACTED-API-KEY]', msg)
    # Redact OpenAI-style API keys (sk-*, pk-*)
    msg = re.sub(r'sk-[a-zA-Z0-9-_]{20,}', '[REDACTED-API-KEY]', msg)
    msg = re.sub(r'pk-[a-zA-Z0-9-_]{20,}', '[REDACTED-API-KEY]', msg)
    # Redact Google API keys (AIza*)
    msg = re.sub(r'AIza[a-zA-Z0-9-_]{30,}', '[REDACTED-API-KEY]', msg)
    # Redact common authorization header schemes from SDK/tool errors.
    msg = re.sub(
        r'Bearer [a-zA-Z0-9._~+/-]{20,}={0,2}',
        'Bearer [REDACTED]',
        msg,
        flags=re.IGNORECASE,
    )
    msg = re.sub(
        r'Basic\s+[A-Za-z0-9+/]{8,}={0,2}',
        'Basic [REDACTED]',
        msg,
        flags=re.IGNORECASE,
    )
    # Redact GitHub tokens that may appear in git/gh subprocess output
    msg = re.sub(r'gh[oprsu]_[a-zA-Z0-9_]{36,}', '[REDACTED-API-KEY]', msg)
    msg = re.sub(r'github_pat_[a-zA-Z0-9_]{20,}', '[REDACTED-API-KEY]', msg)
    # Redact AWS access key IDs that commonly appear in tool output/traces
    msg = re.sub(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b', '[REDACTED-API-KEY]', msg)
    # Redact key/value or JSON-ish assignments such as API_KEY=*** or "token": "***".
    # Keep these field names intentionally bounded to avoid redacting metadata
    # such as PASSWORD_POLICY, SECRET_ROTATION_DAYS, MAX_API_KEY_LENGTH, or
    # pagination cursors like page_token/next_token.
    secret_field = (
        r'(?:[A-Za-z0-9_-]*(?:API[_-]?KEY|PASSWORD|'
        r'SECRET[_-]?KEY|SECRET[_-]?ACCESS[_-]?KEY)'
        r'|(?:CLIENT|APP|SHARED|API|CONSUMER)[_-]?SECRET'
        r'|(?:ACCESS|AUTH|BEARER|ID|REFRESH|SESSION|SERVICE)[_-]?TOKEN)'
    )
    # Quoted values may be short or contain spaces/commas; the field name marks them sensitive.
    #
    # Pre-fix the value capture was unbounded `(.*?)` plus a
    # quote-backref `(\2)`. The combination is O(n²) on
    # adversarial input containing many quote-shaped chars:
    # the engine tries every position-pair where the leading
    # quote could close, with a lazy match in between, and
    # the backref forces re-checking. A 100KB log line full
    # of mismatched quotes pinned the regex engine for
    # seconds.
    #
    # Cap the value capture at 4096 chars. Real secrets
    # (API keys, passwords, tokens, JWTs) max out at
    # ~2048 chars in extreme cases (long JWT with many
    # claims); 4 KB leaves 2x headroom while bounding the
    # quadratic-shape backtracking. Any value longer than
    # 4 KB inside a quoted string in a log line is almost
    # certainly garbage, not a legitimate credential.
    msg = re.sub(
        rf'(\b{secret_field}\b["\']?\s*[:=]\s*)(["\'])(.{{0,4096}}?)(\2)',
        r'\1\2[REDACTED-API-KEY]\4',
        msg,
        flags=re.IGNORECASE,
    )
    # Unquoted values end at common log/JSON delimiters.
    return re.sub(
        rf'(\b{secret_field}\b\s*[:=]\s*)([^"\'\s,}}]+)',
        r'\1[REDACTED-API-KEY]',
        msg,
        flags=re.IGNORECASE,
    )


def _is_auth_error(error: Exception) -> bool:
    """
    Detect authentication/authorization errors from LLM providers.

    Checks both OpenAI and Anthropic SDK exception types, with
    string-based fallback for edge cases.

    Args:
        error: Exception from provider SDK

    Returns:
        True if error appears to be an auth/key error
    """
    if _OPENAI_AVAILABLE:
        try:
            if isinstance(error, _openai_module.AuthenticationError):
                return True
        except AttributeError:
            pass

    if _ANTHROPIC_AVAILABLE:
        try:
            if isinstance(error, _anthropic_module.AuthenticationError):
                return True
        except AttributeError:
            pass

    error_str = str(error).lower()
    return any(indicator in error_str for indicator in _AUTH_ERROR_INDICATORS)


def _is_quota_error(error: Exception) -> bool:
    """
    Detect quota/rate limit errors using type-based + string-based detection.

    Checks both OpenAI and Anthropic SDK exception types.

    Args:
        error: Exception from provider SDK

    Returns:
        True if error appears to be quota/rate limit related
    """
    if _OPENAI_AVAILABLE:
        try:
            if isinstance(error, _openai_module.RateLimitError):
                return True
        except AttributeError:
            pass

    if _ANTHROPIC_AVAILABLE:
        try:
            if isinstance(error, _anthropic_module.RateLimitError):
                return True
        except AttributeError:
            pass

    error_str = str(error).lower()
    return any((
        "429" in error_str,
        "quota exceeded" in error_str,
        "quota" in error_str and "exceeded" in error_str,
        "rate limit" in error_str,
        "generate_content_free_tier" in error_str,  # Gemini-specific
    ))


def _is_daily_quota_error(error: Exception) -> bool:
    """Detect daily/long-horizon quota exhaustion vs transient rate limits.

    Daily quotas (e.g. Gemini's per_day limit) won't clear for hours.
    Retrying wastes API calls and wall-clock time.
    """
    error_str = str(error).lower()
    return _is_quota_error(error) and any(
        marker in error_str
        for marker in ("per_day", "per day", "daily", "retry in 6h", "retry in 5h",
                        "retry in 4h", "retry in 3h", "retry in 2h", "retry in 1h")
    )


# Timeout-class failures get at most ONE retry (the initial attempt
# plus one more). A timed-out call already consumed its full per-call
# timeout (600s on the claudecode transport); re-dispatching the same
# oversized prompt up to max_retries times mostly re-buys the same
# timeout at full wall-clock and token cost. Parse and 429 failures
# keep the standard max_retries budget — they are cheap and genuinely
# transient. The orchestrator layers ONE further reduced-context
# retry on top (see core.audit.orchestrator timeout recovery).
#
# Callers can tighten this per call via the ``timeout_retry_cap``
# kwarg on ``generate`` / ``generate_structured``. The audit review
# path passes 0: a review call that ran to the transport timeout has
# an oversized prompt, and its recovery path is the orchestrator's
# reduced-context retry — an identical client-level retry in between
# just re-buys the same timeout first. Short call classes (glance
# batches, taint summaries) keep the default single identical retry:
# their timeouts are far more likely transient than prompt-sized.
_TIMEOUT_RETRY_CAP = 1


def _resolve_timeout_retry_cap(raw: Any) -> int:
    """Sanitise a per-call ``timeout_retry_cap`` kwarg.

    ``None`` (kwarg absent) and anything non-coercible or negative
    fall back to the module default. ``0`` is a valid value: fail
    straight through to the caller's own recovery on first timeout.
    """
    if raw is None:
        return _TIMEOUT_RETRY_CAP
    try:
        cap = int(raw)
    except (TypeError, ValueError):
        return _TIMEOUT_RETRY_CAP
    return cap if cap >= 0 else _TIMEOUT_RETRY_CAP


def _transport_http_version() -> str | None:
    """Most recent negotiated HTTP protocol (``h1``/``h2``) seen by
    this process's pooled LLM transports — attached to telemetry
    records so HTTP/2 service is provable from run artifacts. None
    when the transport lives in another process (remote dispatcher)
    or no response has been seen yet."""
    try:
        from core.llm.http_pool import last_http_version

        return last_http_version()
    except Exception:  # noqa: BLE001 — telemetry must never break a call
        return None


def _failure_disposition(error: Exception) -> str:
    """Telemetry label for a failed attempt: how the retry policy saw
    it. Ordering matters — quota beats the message-based timeout
    match, mirroring ``is_timeout_error``'s own exclusion. Blocked
    (content filter / model refusal) is checked before timeout so a
    refusal message never mislabels; it is non-retryable like fatal,
    but the distinct label keeps model-boundary failures separable
    from transport failures in the telemetry rollup."""
    if _is_quota_error(error):
        return "quota"
    from core.llm.structured_call import is_content_filter_text
    if is_content_filter_text(str(error)):
        return "blocked"
    if _is_auth_error(error):
        return "auth"
    from core.llm.providers import is_credit_exhausted
    if is_credit_exhausted(error) or "error_max_budget_usd" in str(error):
        return "budget"
    if is_timeout_error(error):
        return "timeout"
    if _is_retryable_error(error):
        return "retryable"
    return "fatal"


def _is_response_shape_failure(error: Exception) -> bool:
    """True when a failed structured attempt points at the RESPONSE
    SHAPE (parse failure / schema mismatch / validation) — the only
    failure class that belongs in the schema-validity scorecard cell.

    Refusals (``blocked``), auth/billing errors, budget aborts,
    quota, and transport flakes each carry their own disposition and
    say nothing about the model's ability to emit schema-conformant
    output; counting them as schema failures corrupts the
    ``_structured`` decision class (Wilson bounds / calibrated merge
    weights drift toward a model that is merely being refused or
    rate-limited).
    """
    if isinstance(error, SchemaUnknownFieldError):
        # Retryable (a bad sample, like malformed JSON) but still a
        # response-shape failure — record it explicitly.
        return True
    if _failure_disposition(error) != "fatal":
        return False
    # Empty content is a model/transport boundary outcome (refusal
    # variants, output-budget exhaustion), not a shape problem.
    err = str(error).lower()
    return "empty content" not in err and "empty response" not in err


def _safe_counter(obj: Any, name: str) -> int:
    """Read an int counter attribute defensively (0 on anything that
    is not int-coercible — e.g. MagicMock providers in tests)."""
    try:
        return int(getattr(obj, name, 0) or 0)
    except (TypeError, ValueError):
        return 0


def is_timeout_error(error: Exception) -> bool:
    """Classify timeout-class failures distinctly from other
    retryables.

    Covers ``TimeoutError`` (and subclasses), SDK exception types
    carrying ``Timeout`` in their name (``APITimeoutError``,
    ``ReadTimeout``, ``subprocess.TimeoutExpired``), and message-based
    detection for wrapped errors (the claudecode transport raises
    ``RuntimeError("claude -p timed out after Ns")``).

    Quota/rate-limit errors are excluded — a 429 with "retry in ..."
    text is a quota signal, not a timeout, and keeps its own retry
    policy.
    """
    if _is_quota_error(error):
        return False
    if isinstance(error, TimeoutError):
        return True
    if "Timeout" in type(error).__name__:
        return True
    error_str = str(error).lower()
    return "timed out" in error_str or "timeout" in error_str


def _is_retryable_error(error: Exception) -> bool:
    """Check if an error is transient and worth retrying.

    Retryable: rate limits, timeouts, server errors (5xx), connection errors.
    Non-retryable: schema validation, auth errors (401/403), bad request (400),
    Instructor failures, Pydantic validation errors.
    """
    # Credit exhaustion / billing cap — no amount of retrying will fix
    from core.llm.providers import is_credit_exhausted
    if is_credit_exhausted(error):
        return False

    # Daily quotas are NOT retryable — won't clear for hours
    if _is_daily_quota_error(error):
        return False

    # Per-minute rate limits are retryable (with backoff)
    if _is_quota_error(error):
        return True

    # Check exception types
    error_type = type(error).__name__
    retryable_types = ("Timeout", "ConnectionError", "APIConnectionError",
                       "InternalServerError", "ServiceUnavailableError")
    if any(t in error_type for t in retryable_types):
        return True

    # Check error message for retryable patterns
    error_str = str(error).lower()
    retryable_patterns = ("timeout", "timed out", "connection",
                          "502", "503", "504",
                          "internal server error", "service unavailable")
    if any(p in error_str for p in retryable_patterns):
        return True

    # JSON parse failures from LLM output are retryable — the model
    # generated malformed JSON but may succeed on a different sample.
    if isinstance(error, json.JSONDecodeError):
        return True

    # Unknown-field schema violations are the same class of failure as
    # malformed JSON: a bad sample from the model, worth one more try.
    if isinstance(error, SchemaUnknownFieldError):
        return True
    json_parse_patterns = ("unterminated string", "expecting value",
                           "expecting property name", "invalid \\escape")
    # Anything else is non-retryable (schema errors, 400, 401, 403, 404,
    # Instructor failures, Pydantic validation, etc.).
    return any(p in error_str for p in json_parse_patterns)


def _get_quota_guidance(model_name: str, provider: str) -> str:
    """
    Get simple, clear detection message for quota/rate limit errors.

    Args:
        model_name: Model that hit quota limit (for display only)
        provider: Provider name (anthropic, openai, gemini, google, ollama, etc.)

    Returns:
        Simple detection message indicating quota/rate limit error
    """
    provider_lower = provider.lower()

    if provider_lower in ("gemini", "google"):
        return "\n→ Google Gemini quota/rate limit exceeded"
    if provider_lower == "openai":
        return "\n→ OpenAI rate limit exceeded"
    if provider_lower == "anthropic":
        return "\n→ Anthropic rate limit exceeded"
    if provider_lower == "ollama":
        return "\n→ Ollama server limit exceeded"
    if provider_lower:
        return f"\n→ {provider.title()} rate limit exceeded"
    # Pre-fix the catch-all branch ran for empty-provider strings,
    # producing the cosmetically-broken `"\n→  rate limit exceeded"`
    # (double space, no provider name) that operators saw in
    # error logs as "what's empty? did the framework break?".
    # Empty provider is a real case for in-process tests and
    # for failures where the model_config wasn't yet wired up.
    # Surface a generic message that doesn't pretend to know the
    # provider.
    return "\n→ Rate limit exceeded (provider unspecified)"


def _ollama_check_url() -> str:
    """Return a /api/tags URL the operator can hit to verify Ollama.

    Respects ``RaptorConfig.OLLAMA_HOST``. For remote hosts (anything
    not localhost / 127.0.0.1) returns the literal ``[REMOTE-OLLAMA]/api/tags``
    so error messages don't disclose the operator's remote endpoint
    (CLAUDE.md rule: "never disclose remote OLLAMA server location"),
    matching the convention already used by ``core.llm.detection``.
    """
    from core.config import RaptorConfig
    from core.llm.detection import _host_is_local
    host = RaptorConfig.OLLAMA_HOST.rstrip("/")
    base = host if _host_is_local(host) else "[REMOTE-OLLAMA]"
    return f"{base}/api/tags"


def _pinned_llm_config(model_name: str) -> 'LLMConfig':
    """Build a minimal :class:`LLMConfig` for a caller-pinned model.

    Bypasses the auto-resolution path entirely — no thinking-model
    scoring, no fallback chain.  Calls the inferred provider's builder
    directly via ``_PROVIDER_BUILDERS``, so the resolver's lenient
    "fall through to whatever provider IS configured" behaviour can't
    substitute a different provider for the one the caller pinned.

    Provider inference: explicit ``provider/model`` syntax beats inference;
    otherwise infer from the model-name prefix (``claude*`` -> anthropic,
    ``gpt*`` -> openai, anything containing ``gemini`` -> gemini; default
    anthropic).  When the inferred provider has no credentials configured,
    returns a bare uncredentialed ``ModelConfig`` — callers that
    authenticate by other means (e.g. Bedrock with AWS env credentials)
    can still construct a working request; pure-key-auth callers will
    hit the same auth error they would have at call time anyway.
    """
    from dataclasses import replace

    from core.llm.config import (
        _PROVIDER_BUILDERS,
        ModelConfig,
        _get_configured_models,
    )

    if model_name in _PROVIDER_BUILDERS:
        # The pin names a provider, not a model ("claudecode",
        # "ollama"): use that provider builder's config verbatim — its
        # own model_name (e.g. the CC session sentinel) is the correct
        # pin. Without this the name falls through provider inference,
        # defaults to anthropic, and dies with a keyless-SDK auth error.
        base = _PROVIDER_BUILDERS[model_name]()
        if base is None:
            raise ValueError(
                f"pinned provider '{model_name}' is not available "
                f"(backend not installed or not running)"
            )
        return LLMConfig(primary_model=replace(base, role="code"),
                         fallback_models=[])

    if "/" in model_name:
        provider, model_name = model_name.split("/", 1)
    else:
        from core.security.llm_family import (
            provider_of as _provider_of,
        )
        from core.security.llm_family import (
            resolve_model_shorthand as _resolve_shorthand,
        )
        configured = [
            e.get("model", "")
            for e in _get_configured_models()
            if e.get("model")
        ]
        resolved = _resolve_shorthand(model_name, configured)
        if resolved is not None:
            model_name = resolved
        provider = _provider_of(model_name) or "anthropic"

    # Credential discovery, in this order:
    #   1. env-var-based provider builder (covers the common case)
    #   2. operator's ``models.json`` — needed when keys aren't in env
    #      (the previous version silently skipped this path and produced
    #      auth failures when the operator's credentials lived only in
    #      the config file)
    from core.llm.model_data import resolve_model_limits
    limits = resolve_model_limits(model_name) or {}
    max_tokens = limits.get("max_output", 4096)
    max_context = limits.get("max_context", 32000)

    builder = _PROVIDER_BUILDERS.get(provider)
    base = builder() if builder is not None else None
    if base is None:
        for entry in _get_configured_models():
            if entry.get("provider") == provider and entry.get("api_key"):
                base = ModelConfig(
                    provider=provider,
                    model_name=entry.get("model", model_name),
                    api_key=entry["api_key"],
                    api_base=entry.get("api_base"),
                    max_tokens=max_tokens,
                    max_context=max_context,
                )
                break
    if base is None:
        primary = ModelConfig(
            provider=provider, model_name=model_name, role="code",
            max_tokens=max_tokens, max_context=max_context,
        )
    else:
        primary = replace(base, model_name=model_name, role="code",
                          max_tokens=max(base.max_tokens, max_tokens))
    return LLMConfig(primary_model=primary, fallback_models=[])


class LLMClient:
    """Unified LLM client with multi-provider support and fallback."""

    # Lazily-created per-run accounting attributes (created on first use
    # by _record_usage / _record_schema_validity).
    _fired_usage: dict[str, dict[str, Any]]
    _paid_test_ctxs: set[str]
    _fired_schema: dict[str, dict[str, int]]

    def __init__(self, config: LLMConfig | None = None,
                 *, pinned_model: str | None = None) -> None:
        """Construct the LLM client.

        When ``pinned_model`` is set the caller commits to overriding the
        model on every call.  We then BUILD a minimal :class:`LLMConfig`
        targeted at the inferred provider — short-circuiting Step 1 of
        ``_get_default_primary_model`` (env-var probe for that provider)
        and skipping the thinking-model scoring path AND the fallback
        chain entirely.  The previous behaviour resolved both, then
        ignored them and logged a misleading "Primary model:
        gemini-2.5-pro" banner; this skips the resolution at the source.

        ``config`` takes precedence over ``pinned_model`` when both are
        passed (caller knows what they want).
        """
        if config is not None:
            self.config = config
        elif pinned_model is not None:
            self.config = _pinned_llm_config(pinned_model)
        else:
            self.config = LLMConfig()
        self._pinned_model = pinned_model
        self.providers: dict[str, LLMProvider] = {}
        self.total_cost = 0.0
        self.request_count = 0
        self.cache_hits = 0
        # Entries whose provenance token was PRESENT but invalid — a
        # genuine tamper signal (only editing a stamped entry produces
        # it; legacy/unstamped entries miss silently). Surfaced in
        # get_stats so a cache-corruption campaign (forcing full-price
        # re-generation) is operator-visible, not just DEBUG noise.
        self.cache_tamper_events = 0
        self.task_type_costs: dict[str, float] = {}  # task_type → cumulative cost
        # Distinct models actually invoked during this client's lifetime,
        # keyed by (provider, alias, resolved, role) → call count. Feeds the
        # run provenance manifest. Cache hits are NOT recorded — a cache hit
        # fired no provider call. Guarded by _stats_lock.
        self._fired_models: dict[tuple, int] = {}
        # Number of full ANALYSE calls avoided because the scorecard
        # trusted the cheap-tier verdict and the consumer short-
        # circuited. Bumped by consumers via ``record_short_circuit``;
        # surfaced in /codeql's summary so the scorecard's effect on
        # cost shows up as a concrete line.
        self.short_circuits = 0
        # Models whose daily quota is exhausted. Keyed by
        # (provider, model_name). Checked before each attempt
        # so we skip straight to fallback instead of burning
        # 3 retries on guaranteed 429s.
        self._daily_quota_exhausted: set[tuple[str, str]] = set()
        # Per-call-class completed-call cost history:
        # call_class → (count, total_cost). Feeds the reservation
        # estimate so in-flight calls pre-debit roughly what they will
        # actually cost instead of a token $0.10. Guarded by
        # _stats_lock.
        self._call_cost_history: dict[str, tuple[int, float]] = {}
        # First budget-exceeded refusal logs at INFO (a designed
        # stop, not a failure); the rest at DEBUG. Every post-
        # exhaustion dispatch attempt hits the budget check, so an
        # unconditional log printed the same line once per doomed
        # call (observed 3x+ per run). Guarded by _stats_lock.
        self._budget_exceeded_logged = False
        # Held-back slice of max_cost_per_scan that ordinary dispatch
        # may not spend (see hold_budget_reserve). Lets a late phase
        # (e.g. the audit deepen pass) guarantee itself headroom that
        # the discovery loop cannot exhaust first. Guarded by
        # _stats_lock.
        self._budget_reserve = 0.0
        self._stats_lock = threading.RLock()
        # Per-cache-key locks. Two threads issuing the same cache key
        # serialise on its lock so only one calls the provider; the
        # second observes the first's freshly-written cache entry on
        # its own check. Held in an ``OrderedDict`` so we can evict
        # least-recently-used entries once the cap is hit — pre-fix a
        # long-running daemon process (cve-diff bench sweep at 50k+
        # distinct prompts) saw unbounded growth here. The ~80 B per
        # lock isn't dramatic but it's monotonic and the dict never
        # garbage-collects on its own; the cap turns it into a fixed
        # working-set ceiling. 4096 distinct in-flight keys is more
        # than any current consumer needs — even agentic at 1k
        # findings × full multi-pass chain doesn't sustain that many
        # CONCURRENT keys.
        self._key_locks: OrderedDict[str, threading.Lock] = OrderedDict()
        self._key_locks_guard = threading.Lock()
        self._key_locks_cap = 4096
        # Lazy-built model scorecard. Stays None until a consumer
        # asks for it via the ``scorecard`` property; constructing
        # one is cheap but it does open a file handle and create
        # the parent dir, so we defer until needed.
        self._scorecard = None

        # Route in-process LLM SDK calls through the in-process
        # egress proxy (matches what cc_dispatch.py already does for
        # the CC subprocess). Idempotent across multiple LLMClient
        # constructions in the same process; no-op on Ollama-only or
        # autodetect-empty configs. See core/llm/egress.py for the
        # full rationale (chokepoint, hostname allowlist, corporate
        # proxy chain, subprocess-env separation).
        from .egress import enable_llm_egress
        try:
            enable_llm_egress(self.config)
        except Exception as e:                          # noqa: BLE001
            # Fail open: a proxy bring-up failure must not block LLM
            # calls entirely. Log and continue with direct egress.
            # Operator who needs the chokepoint will see the warning.
            logger.warning(
                "LLM egress proxy bring-up failed (%s) — falling back "
                "to direct outbound. Allowlist enforcement disabled "
                "for this run.", e,
            )

        # HEALTH CHECK: Warn if no API keys configured. When the
        # claude CLI transport is the resolved primary (the claudecode
        # fallback), calls will NOT "likely fail" — warning so said
        # anyway and sent operators chasing API keys while dispatches
        # were succeeding through the CLI. Say what is actually true.
        from .detection import detect_llm_availability
        availability = detect_llm_availability()
        # Once per PROCESS, not per client: transports that spawn a
        # client per call (claude CLI) otherwise print this banner on
        # every worker call.
        if not availability.external_llm and not _transport_banner_shown():
            primary = self.config.primary_model
            if primary is not None and primary.provider.startswith("claudecode"):
                logger.info(
                    "No external LLM configured — using the claude CLI "
                    "transport (provider %s). Slower than SDK access; "
                    "configure models.json for direct API calls.",
                    primary.provider,
                )
            elif availability.claude_code:
                logger.info(
                    "No external LLM configured; Claude Code is available "
                    "and will do the reasoning for prep-only pipelines."
                )
            else:
                logger.warning(
                    "No external LLM available (no API keys, no config file, "
                    "no Ollama, no claude CLI). LLMClient constructed but "
                    "calls will likely fail. Configure at least one LLM "
                    "provider."
                )

        # Initialize cache
        if self.config.enable_caching:
            try:
                self.config.cache_dir.mkdir(parents=True, exist_ok=True)
            except OSError:
                self.config.enable_caching = False
                logger.warning("Cannot create cache dir %s — caching disabled", self.config.cache_dir)

        # Consecutive cache-write failure counter. Auto-disable
        # caching after `_CACHE_WRITE_FAILURE_THRESHOLD` in a row to
        # stop log-spamming when the cache dir runs out of space /
        # permission flips / filesystem goes read-only mid-run.
        self._cache_write_failures = 0

        logger.debug("LLM Client initialized")
        if not _model_banner_shown():
            if self._pinned_model:
                logger.info(
                    "Pinned model: %s (caller override; RAPTOR config defaults bypassed)",
                    self._pinned_model,
                )
            elif self.config.primary_model:
                logger.info("Primary model: %s/%s", self.config.primary_model.provider, self.config.primary_model.model_name)
                if self.config.enable_fallback:
                    logger.info("Fallback models: %d", len(self.config.fallback_models))
            else:
                logger.warning("LLM Client initialized with no primary model — all calls will fail")

        # Warn if using Ollama for exploit generation
        if self.config.primary_model and self.config.primary_model.provider.lower() == "ollama":
            logger.warning(
                "Using local Ollama model for security analysis. "
                "Local models may generate unreliable exploit PoCs. "
                "For production security research, consider using cloud models "
                "(Anthropic Claude, OpenAI GPT, Google Gemini) which have better "
                "code generation and security analysis capabilities."
            )

    def _get_provider(self, model_config: ModelConfig) -> LLMProvider:
        """Get or create provider for model config.

        Thread-safe: the check-then-create pattern is wrapped under
        `_stats_lock` (already RLock) so concurrent calls with the
        same model can't both pass the membership check and end up
        constructing two provider instances — the earlier one would
        be silently leaked when the later write replaces it.
        Provider construction is cheap (no network) so holding the
        lock across `create_provider` is fine.
        """
        key = f"{model_config.provider}:{model_config.model_name}"

        with self._stats_lock:
            if key not in self.providers:
                logger.debug("Creating provider: %s", key)
                self.providers[key] = create_provider(model_config)
            return self.providers[key]

    @property
    def primary_provider(self) -> LLMProvider:
        """The :class:`LLMProvider` for the configured ``primary_model``.

        Exposed publicly so consumers that need direct provider access
        — typically for tool-use loops via :class:`core.llm.tool_use.ToolUseLoop` —
        can reach it without going through :meth:`generate`. Cached;
        the same instance is returned across calls.

        Raises ``RuntimeError`` if no primary model is configured (the
        client should normally not have been constructed in that
        case — :func:`packages.llm_analysis.get_client` returns
        ``None`` instead).
        """
        if self.config.primary_model is None:
            msg = (
                "LLMClient has no primary_model configured; cannot "
                "expose primary_provider. Use packages.llm_analysis."
                "get_client() which returns None when no provider is "
                "available, instead of constructing LLMClient directly."
            )
            raise RuntimeError(msg)
        return self._get_provider(self.config.primary_model)

    @property
    def model_name(self) -> str:
        """Primary model name, or ``""`` when unknown."""
        if self._pinned_model:
            return self._pinned_model
        pm = self.config.primary_model
        return pm.model_name if pm else ""

    @property
    def recommended_max_workers(self) -> int:
        """Safe concurrency cap derived from the primary model's RPM."""
        from core.llm.concurrency import derive_max_workers
        return derive_max_workers(self.model_name)

    @property
    def scorecard(self):
        """The :class:`~core.llm.scorecard.ModelScorecard` for this
        client's config, or ``None`` when scorecard is disabled.

        Lazy-built on first access — the constructor doesn't pay the
        directory-creation cost for clients that never consult the
        scorecard. Returns the same instance across calls so per-key
        flock contention is bounded by physical concurrency, not by
        accidental property re-evaluation.
        """
        if not self.config.scorecard_enabled:
            return None
        if self._scorecard is None:
            from .scorecard import ModelScorecard
            # Operator's currently-configured models. Auto-GC
            # preserves cells for these regardless of last_seen_at
            # age — an operator who steps away for a quarter and
            # comes back shouldn't lose Wilson-bound calibration
            # data on models still listed in their config. Only
            # cells for *deprecated* models age out. Includes
            # primary + every fallback so multi-tier configs are
            # fully covered.
            keep_models: set[str] = set()
            if self.config.primary_model is not None:
                keep_models.add(self.config.primary_model.model_name)
            for fb in (self.config.fallback_models or []):
                if fb is not None:
                    keep_models.add(fb.model_name)
            self._scorecard = ModelScorecard(
                self.config.scorecard_path,
                retain_samples=self.config.scorecard_retain_samples,
                shadow_rate=self.config.scorecard_shadow_rate,
                keep_models=keep_models or None,
                freshness_half_life_days=self.config.scorecard_freshness_half_life_days,
            )
        return self._scorecard

    def record_short_circuit(self) -> None:
        """Bump the avoided-full-call counter. Called by consumers
        (codeql's autonomous_analyzer and dataflow_validator) right
        after they take the scorecard-trusted short-circuit path so
        the saving shows up in the run summary."""
        with self._stats_lock:
            self.short_circuits += 1

    def _key_lock(self, cache_key: str) -> "threading.Lock":
        """Return (creating if needed) a per-key lock used to dedupe
        concurrent calls with the same cache key. The guard lock is
        only held briefly to insert into the dict; the per-key lock
        itself is acquired by the caller for the duration of the
        check-call-save sequence."""
        with self._key_locks_guard:
            lock = self._key_locks.get(cache_key)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[cache_key] = lock
                # LRU evict the oldest entry if we've exceeded the
                # cap, BUT only when the candidate lock is currently
                # uncontended — try-acquiring it tells us whether
                # any thread is mid-cache-fill on that key. Pre-fix
                # we blindly popped the LRU entry; under pathological
                # working-set concurrency (>cap distinct in-flight
                # keys) we could evict a lock that another thread
                # was still holding. The next caller for the same
                # ``cache_key`` would then build a FRESH lock, two
                # threads run the provider call concurrently for the
                # same key, and the second writes a half-baked cache
                # entry over the first.
                #
                # ``acquire(blocking=False)`` probes without waiting:
                # success means no one's holding the lock so we can
                # safely drop it (lock goes out of scope after the
                # release, GC'd when the last reference clears);
                # failure means we leave the entry in place and
                # walk further back. If the whole dict is contended
                # (every entry held), we exit the loop and let the
                # cap silently exceed — better than dropping an
                # active lock. Bounded scan: walk at most
                # ``self._key_locks_cap`` candidates so an entirely
                # contended dict doesn't burn O(N) CPU per insert.
                evict_budget = self._key_locks_cap
                while len(self._key_locks) > self._key_locks_cap and evict_budget > 0:
                    candidate_key, candidate_lock = next(
                        iter(self._key_locks.items()),
                    )
                    if candidate_lock.acquire(blocking=False):
                        # No-one holds it — release and drop.
                        candidate_lock.release()
                        self._key_locks.pop(candidate_key, None)
                    else:
                        # In-flight; move to end and try the next
                        # LRU candidate.
                        self._key_locks.move_to_end(candidate_key)
                    evict_budget -= 1
            else:
                # Touch existing entries so the LRU eviction picks the
                # genuinely cold keys, not a still-active one.
                self._key_locks.move_to_end(cache_key)
            return lock

    @staticmethod
    def _kwargs_for_cache_key(kwargs: dict[str, Any] | None) -> str:
        """Canonicalise generation kwargs (temperature, max_tokens, …)
        for inclusion in a cache key.

        Without this, two calls that share prompt + system_prompt + model
        but differ in temperature collide in the cache and the second
        caller silently gets the first caller's result. Sorted JSON
        keeps the digest order-independent; ``default=str`` swallows
        any non-serialisable values a future caller might pass."""
        if not kwargs:
            return ""
        try:
            return json.dumps(kwargs, sort_keys=True, default=str)
        except (TypeError, ValueError):
            # Schemas should always serialise; fall back to a stable
            # repr if a caller passes something weird.
            return repr(sorted(kwargs.items()))

    def _record_fired_model(self, provider: str, alias: str,
                            resolved: str | None, role: str) -> None:
        """Record that a provider call fired for (provider, alias, role).

        ``resolved`` is the provider-served snapshot when the SDK exposed one,
        else None (alias-only — never guessed). Deduped by the full key so the
        manifest stays compact; repeated calls bump the count.

        Never raises. This runs inside the generation try-block, and provenance
        bookkeeping must not be able to fail a real LLM call — including on a
        client built via ``__new__`` that skipped ``__init__`` (some test and
        dispatcher paths do this), where ``_fired_models`` / ``_stats_lock`` may
        be absent. Lazily initialises the map and swallows any error.
        """
        try:
            key = (provider, alias, resolved, role)
            with self._stats_lock:
                fired = getattr(self, "_fired_models", None)
                if fired is None:
                    fired = self._fired_models = {}
                fired[key] = fired.get(key, 0) + 1
            # Lazily arm the run-end usage flush — only on the FIRST real fire,
            # so mocked/cached clients that never call a provider never register
            # an atexit handler or write to the scorecard.
            self._arm_usage_flush()
        except Exception as exc:  # noqa: BLE001
            logger.debug("_record_fired_model failed: %s", exc)

    def _record_usage(
        self, alias: str, *, cost: float = 0.0, tokens: int = 0,
        input_tokens: int = 0, output_tokens: int = 0,
        duration_s: float = 0.0,
    ) -> None:
        """Accumulate per-alias cost / tokens / latency for the run-end flush
        into the scorecard. Cheap dict update under ``_stats_lock`` — zero new
        I/O on the hot path; the batched write happens once at lifecycle end.
        Never raises (best-effort, like ``_record_fired_model``)."""
        try:
            ms = int(max(0.0, duration_s) * 1000)
            with self._stats_lock:
                usage = getattr(self, "_fired_usage", None)
                if usage is None:
                    usage = self._fired_usage = {}
                cur = usage.setdefault(alias, {
                    "cost_usd": 0.0, "tokens": 0,
                    "input_tokens": 0, "output_tokens": 0,
                    "latency_ms_sum": 0, "latency_ms_max": 0,
                })
                cur["cost_usd"] += float(cost or 0.0)
                cur["tokens"] += int(tokens or 0)
                cur["input_tokens"] += int(input_tokens or 0)
                cur["output_tokens"] += int(output_tokens or 0)
                cur["latency_ms_sum"] += ms
                cur["latency_ms_max"] = max(cur["latency_ms_max"], ms)
                # Live-API-leak attribution: a PAID call under pytest is
                # flagged by the run-end scorecard line, but the flag
                # alone cannot say WHICH test fired it (observed as an
                # unattributable one-shot $0.27 session-default call
                # during a combined suite run; PYTEST_CURRENT_TEST is
                # unset by the time the atexit flush runs). Capture the
                # test id at record time; the aggregated flush prints
                # the culprits.
                # ``*-stub`` aliases are the repo convention for
                # deliberately mocked providers whose fake responses
                # carry nonzero cost because cost PLUMBING is what the
                # test exercises (telemetry, scorecard aggregation) —
                # those are stubbed by construction, not leaks. A real
                # paid model aliased "-stub" in models.json would be an
                # operator's own misdirection; the detector trusts the
                # operator's alias vocabulary.
                if (cost and float(cost) > 0.0
                        and not str(alias).endswith("-stub")):
                    import os as _os_mod
                    _test_ctx = _os_mod.environ.get("PYTEST_CURRENT_TEST")
                    if _test_ctx:
                        ctxs = getattr(self, "_paid_test_ctxs", None)
                        if ctxs is None:
                            ctxs = self._paid_test_ctxs = set()
                        ctxs.add(_test_ctx.split(" (")[0])
        except Exception as exc:  # noqa: BLE001
            logger.debug("_record_usage failed: %s", exc)

    def _record_schema_validity(self, alias: str, *, success: bool) -> None:
        """Accumulate per-alias schema-validation outcomes for the run-end
        flush — one ``correct`` per structured call whose response parsed and
        matched the schema, one ``incorrect`` per call that didn't.

        Recorded under the ``_structured`` decision_class at flush time so it
        becomes a universal "how reliably does this model follow the schema"
        signal across every ``generate_structured`` use. Cheap dict update
        under ``_stats_lock``; never raises."""
        try:
            with self._stats_lock:
                schema = getattr(self, "_fired_schema", None)
                if schema is None:
                    schema = self._fired_schema = {}
                cur = schema.setdefault(alias, {"pass": 0, "fail": 0})
                if success:
                    cur["pass"] += 1
                else:
                    cur["fail"] += 1
        except Exception as exc:  # noqa: BLE001
            logger.debug("_record_schema_validity failed: %s", exc)

    def _arm_usage_flush(self) -> None:
        """Register the run-end usage flush exactly once, the first time a real
        provider call fires. Guarded so it's a no-op when the scorecard is
        disabled."""
        if getattr(self, "_usage_flush_armed", False):
            return
        self._usage_flush_armed = True
        try:
            if not getattr(self.config, "scorecard_enabled", True):
                return
            # One PROCESS-level atexit aggregator instead of one atexit
            # per client instance. The claude-CLI transport spawns a
            # client per call, so a single run used to print 16
            # separate "scorecard: 1 calls ..." lines at exit; now each
            # client still writes its own window to the scorecard, but
            # the operator sees one summed line.
            _register_scorecard_flush(self)
        except Exception as exc:  # noqa: BLE001
            logger.debug("_arm_usage_flush failed: %s", exc)

    def _snapshot_and_clear_fired(self) -> tuple:
        """Atomically copy + clear ``_fired_models`` / ``_fired_usage`` /
        ``_fired_schema`` under a single ``_stats_lock``. Used by
        :meth:`flush_usage_to_scorecard` to (1) tighten the snapshot the
        adversarial review flagged — previously the flush re-acquired the lock
        between the three reads, allowing an in-flight ``_record_*`` to land in
        an inconsistent snapshot; and (2) let subsequent fires accumulate into a
        fresh window so a manual mid-run flush isn't a one-shot."""
        with self._stats_lock:
            fm = dict(getattr(self, "_fired_models", {}) or {})
            fu = {
                k: dict(v)
                for k, v in (getattr(self, "_fired_usage", {}) or {}).items()
            }
            fs = {
                k: dict(v)
                for k, v in (getattr(self, "_fired_schema", {}) or {}).items()
            }
            self._fired_models = {}
            self._fired_usage = {}
            self._fired_schema = {}
        return fm, fu, fs

    def flush_usage_to_scorecard(
        self, *, emit_summary: bool = True,
    ) -> dict[str, Any] | None:
        """Flush this run's per-model usage into the scorecard — at run end
        (armed lazily on first fire via :meth:`_arm_usage_flush`). Aggregates
        per-alias call counts + cost / tokens / latency + schema validity, and
        records them under the ``_usage`` (volume) and ``_structured`` (schema)
        decision classes so a model that was *used* but never *scored* against
        an oracle still appears in the scorecard.

        Uses :meth:`_snapshot_and_clear_fired` so repeated flushes (atexit +
        any explicit caller) each process a fresh window — no double-count, no
        lost data after the first flush. Best-effort; never raises.

        Returns the flushed window's stats
        (``{"calls", "cost_usd", "latency_ms_sum", "models": {alias: calls}}``)
        or None when nothing fired / the scorecard is disabled. With
        ``emit_summary=False`` the scorecard write still happens but the
        per-instance stderr line is suppressed — that's the process-level
        aggregator's mode (:func:`_flush_all_scorecards`), which prints ONE
        summed line instead of one per client instance."""
        try:
            if not getattr(self.config, "scorecard_enabled", True):
                return None
            fired_dict, usage_metrics, schema_dict = self._snapshot_and_clear_fired()
            if not fired_dict:
                return None
            # Build the same list shape get_fired_models() returns, from the
            # snapshot. (provider, alias, resolved, role) -> count.
            fired = [
                {"provider": p, "alias": a, "resolved": r,
                 "role": role, "calls": int(n)}
                for (p, a, r, role), n in fired_dict.items()
            ]
            agg: dict[str, dict[str, Any]] = {}
            for f in fired:
                alias = f.get("alias")
                if not alias:
                    continue
                cur = agg.setdefault(alias, {"calls": 0, "resolved": None})
                cur["calls"] += int(f.get("calls") or 0) or 1
                if f.get("resolved"):
                    cur["resolved"] = f["resolved"]
            uses = []
            tot_calls = 0
            tot_cost = 0.0
            stub_cost = 0.0
            tot_lat_ms = 0
            for a, v in agg.items():
                m = usage_metrics.get(a, {})
                calls = int(v["calls"])
                cost = float(m.get("cost_usd") or 0.0)
                lat_sum = int(m.get("latency_ms_sum") or 0)
                tot_calls += calls
                tot_cost += cost
                # ``*-stub`` aliases carry deliberately fake nonzero
                # costs (cost-plumbing tests) — tracked separately so
                # the pytest noise gate can treat them as zero without
                # hiding real spend.  Same convention as the
                # paid-test-ctx capture in ``_record_usage``.
                if str(a).endswith("-stub"):
                    stub_cost += cost
                tot_lat_ms += lat_sum
                uses.append({
                    "model": a, "decision_class": "_usage",
                    "calls": calls, "model_version": v["resolved"],
                    "cost_usd": cost,
                    "tokens": int(m.get("tokens") or 0),
                    "input_tokens": int(m.get("input_tokens") or 0),
                    "output_tokens": int(m.get("output_tokens") or 0),
                    "latency_ms_sum": lat_sum,
                    "latency_ms_max": int(m.get("latency_ms_max") or 0),
                })
            # Append _structured entries for schema-validity outcomes. Different
            # decision_class from _usage so the schema reliability signal is
            # cleanly separable in `list` views and consumes the standard
            # Wilson-over-events machinery on the schema_valid slot.
            for alias, counts in schema_dict.items():
                if not alias:
                    continue
                p = int(counts.get("pass") or 0)
                fail_count = int(counts.get("fail") or 0)
                if not (p or fail_count):
                    continue
                uses.append({
                    "model": alias, "decision_class": "_structured",
                    "calls": p + fail_count,
                    "schema_valid_pass": p, "schema_valid_fail": fail_count,
                })
            self.scorecard.register_uses(uses)
            stats: dict[str, Any] = {
                "calls": tot_calls,
                "cost_usd": tot_cost,
                "stub_cost_usd": stub_cost,
                "latency_ms_sum": tot_lat_ms,
                "models": {a: int(v["calls"]) for a, v in agg.items()},
                "paid_test_ctxs": sorted(
                    getattr(self, "_paid_test_ctxs", None) or ()),
            }
            if emit_summary:
                _print_scorecard_summary(stats)
            return stats
        except Exception as e:  # pragma: no cover - shutdown-path best effort  # noqa: BLE001
            logger.debug("scorecard usage flush failed: %s", e)
            return None

    def get_fired_models(self) -> list:
        """Distinct models invoked during this run (cache hits excluded).

        Each entry: ``{provider, alias, resolved, role, calls}``. ``resolved``
        is the served snapshot or None. Powers the provenance manifest's model
        attribution. Empty when no provider call fired (a fully cached re-run,
        or a non-LLM command) — which is the honest record, not a gap.
        """
        fired = getattr(self, "_fired_models", None)
        if not fired:
            return []
        with self._stats_lock:
            items = list(fired.items())
        return [
            {"provider": p, "alias": a, "resolved": r, "role": role, "calls": n}
            for (p, a, r, role), n in items
        ]

    def _get_cache_key(
        self, prompt: str, system_prompt: str | None, model: str,
        kwargs: dict[str, Any] | None = None,
    ) -> str:
        """Generate cache key for prompt."""
        content = (
            f"{model}:{system_prompt or ''}:{prompt}:"
            f"{self._kwargs_for_cache_key(kwargs)}"
        )
        return sha256_string(content)

    def _is_entry_stale(self, data: dict[str, Any]) -> bool:
        """Return True if a cache entry's ``timestamp`` is older than
        ``cache_ttl_seconds``. Entries without a timestamp are treated
        as fresh here — but only entries that passed the provenance
        gate (``cache_integrity.verify_entry``) reach this check, and
        this install's writer always stamps a timestamp, so the
        lenient branch is a belt-and-braces default, not a trust
        decision."""
        ttl = self.config.cache_ttl_seconds
        if not ttl:
            return False
        ts = data.get("timestamp")
        if not isinstance(ts, (int, float)):
            return False
        return (time.time() - ts) > ttl

    def _reject_cache_entry(self, cache_file, data, cache_key: str) -> None:
        """Handle a cache entry that failed the provenance gate.

        Two distinct classes, split for attribution:

        * unstamped (no token) — pre-MAC legacy or a naive plant;
          benign shape, DEBUG, plain miss (the refill overwrites it).
        * token present but INVALID — only produced by editing a
          stamped entry (or replaying another slot's): a genuine
          tamper signal. WARNING + ``cache_tamper_events`` counter
          (surfaced in get_stats), and the entry is QUARANTINED aside
          (``<name>.json.unverified``, scorecard precedent) so the
          honest refill does not destroy the evidence.
        """
        from core.llm import cache_integrity
        if cache_integrity.extract_token(data) is None:
            logger.debug(
                "Cache entry unstamped — miss: %s", cache_key)
            return
        with self._stats_lock:
            self.cache_tamper_events += 1
        import os
        quarantine = cache_file.with_name(cache_file.name + ".unverified")
        try:
            # Evidence budget: keep at most a handful of quarantined
            # entries — a corruption CAMPAIGN must not turn the
            # evidence trail into a disk-filler (the counter carries
            # the magnitude; the samples carry the forensics).
            existing = list(cache_file.parent.glob("*.unverified"))
            if len(existing) >= 8:
                os.unlink(cache_file)
                where = "evidence budget reached; entry removed"
            else:
                os.replace(cache_file, quarantine)
                where = str(quarantine)
        except OSError:
            where = "quarantine failed; entry left in place"
        logger.warning(
            "Cache entry failed provenance verification (stamped but "
            "invalid — tampered or foreign): %s. Entry quarantined "
            "(%s); response will be re-fetched.", cache_key, where,
        )

    def _get_cached_response(self, cache_key: str) -> str | None:
        """Retrieve cached response if available."""
        if not self.config.enable_caching:
            return None

        from core.json import load_json
        cache_file = self.config.cache_dir / f"{cache_key}.json"
        # Non-strict: corrupt cache is silently skipped (regenerated on next call)
        data = load_json(cache_file)
        if data is None:
            return None
        # Provenance gate: cache entries replay into review verdicts,
        # and the cache dir is same-user-writable plain JSON — an
        # unstamped or tampered entry is a MISS (re-fetched, honest
        # result overwrites), never replayed. See core.llm.cache_integrity.
        from core.llm import cache_integrity
        if not cache_integrity.verify_entry(cache_file.stem, data):
            self._reject_cache_entry(cache_file, data, cache_key)
            return None
        if self._is_entry_stale(data):
            logger.debug("Cache stale (TTL): %s", cache_key)
            return None
        logger.debug("Cache hit: %s", cache_key)
        return data.get("content")

    def _save_to_cache(self, cache_key: str, response: LLMResponse) -> None:
        """Save response to cache.

        Mode 0o600 — LLM responses can contain proprietary code, scan
        findings, vulnerability details, and other content the user
        wouldn't want world-readable. The default umask on most systems
        produces 0o644 (world-readable) which is wrong for this content.
        Same posture as `LLMConfig.to_file` and the migration helper.
        """
        if not self.config.enable_caching:
            return

        from core.json import save_json
        from core.llm import cache_integrity
        cache_file = self.config.cache_dir / f"{cache_key}.json"
        try:
            save_json(cache_file, cache_integrity.stamp(cache_file.stem, {
                    "content": response.content,
                    "model": response.model,
                    "provider": response.provider,
                    "tokens_used": response.tokens_used,
                    "timestamp": time.time(),
                }), mode=0o600)
            # Reset failure counter on a successful write — recovery
            # from a transient EBUSY shouldn't carry the strike count
            # forward. _stats_lock protects against torn writes under
            # concurrent dispatch from ThreadPoolExecutor.
            with self._stats_lock:
                self._cache_write_failures = 0
        except Exception as e:  # noqa: BLE001
            # _stats_lock — `+= 1` decomposes to load/incr/store; under
            # ThreadPoolExecutor dispatch the counter can lose increments
            # without a lock, and the `enable_caching = False` flip would
            # be a torn write across threads.
            with self._stats_lock:
                self._cache_write_failures += 1
                failures = self._cache_write_failures
                if failures >= _CACHE_WRITE_FAILURE_THRESHOLD:
                    # Persistent problem (disk full, read-only FS,
                    # permission flip mid-run). Stop spamming the log
                    # and stop attempting subsequent writes.
                    self.config.enable_caching = False
            if failures >= _CACHE_WRITE_FAILURE_THRESHOLD:
                logger.warning(
                    "Cache write error #%s: %s. Caching disabled for the remainder of this run.", failures, e
                )
            else:
                logger.warning(
                    "Cache write error #%s: %s", failures, e
                )
            return
        self._maybe_evict_cache()

    def _maybe_evict_cache(self) -> None:
        """If ``cache_max_entries`` is configured, drop the oldest
        entries (by mtime) until at or under the cap. Called from the
        savers after a successful write. Walks both unstructured and
        ``structured-`` files in the same cache dir so the cap applies
        across the namespace as a whole — operators reason about a
        single budget, not two."""
        cap = self.config.cache_max_entries
        if not cap:
            return
        try:
            entries = list(self.config.cache_dir.glob("*.json"))
        except OSError:
            return
        if len(entries) <= cap:
            return
        # Stat each file once. A file may disappear between glob and
        # stat (concurrent eviction in another process); treat missing
        # as already-gone.
        with_mtime: list[tuple[float, Path]] = []
        for p in entries:
            try:
                with_mtime.append((p.stat().st_mtime, p))
            except OSError:
                continue
        with_mtime.sort(key=lambda pair: pair[0])
        drop = len(with_mtime) - cap
        for _, victim in with_mtime[:drop]:
            try:
                victim.unlink()
            except OSError:
                # Lost a race with another process — that's fine, our
                # only job is to bring count down, and that's happening.
                continue

    # Bump when schema-to-Pydantic conversion changes behaviour so
    # cached results validated under old rules are not replayed.
    _STRUCTURED_CACHE_VERSION = 3  # v3: nested schema recursion

    def _get_structured_cache_key(
        self, prompt: str, system_prompt: str | None,
        model: str, schema: dict[str, Any],
        kwargs: dict[str, Any] | None = None,
    ) -> str:
        """Cache key for generate_structured. Includes schema so two callers
        who share a prompt but ask for different shapes don't collide,
        and includes generation kwargs so callers passing different
        temperatures (etc.) don't collide either — even though provider
        impls don't currently honour those kwargs, future plumbing is
        cache-correct from day one."""
        # sort_keys → stable digest regardless of dict insertion order.
        # default=str → swallow non-serialisable schema embellishments.
        try:
            schema_json = json.dumps(schema, sort_keys=True, default=str)
        except (TypeError, ValueError):
            # Schemas should always serialise; if a caller passes something
            # weird, fall back to repr — still deterministic for that caller.
            schema_json = repr(schema)
        content = (
            f"v{self._STRUCTURED_CACHE_VERSION}:"
            f"{model}:{system_prompt or ''}:{prompt}:{schema_json}:"
            f"{self._kwargs_for_cache_key(kwargs)}"
        )
        return sha256_string(content)

    def _get_cached_structured_response(
        self, cache_key: str,
    ) -> tuple[dict[str, Any], str] | None:
        """Retrieve cached (result_dict, raw) tuple if available."""
        if not self.config.enable_caching:
            return None

        from core.json import load_json
        cache_file = self.config.cache_dir / f"structured-{cache_key}.json"
        data = load_json(cache_file)
        if data is None:
            return None
        # Provenance gate — see _get_cached_response for the rationale.
        from core.llm import cache_integrity
        if not cache_integrity.verify_entry(cache_file.stem, data):
            self._reject_cache_entry(cache_file, data, cache_key)
            return None
        # Both fields are required for a usable replay; treat partial
        # entries (e.g. truncated by an interrupted writer) as a miss.
        if "result" not in data or "raw" not in data:
            return None
        if self._is_entry_stale(data):
            logger.debug("Structured cache stale (TTL): %s", cache_key)
            return None
        logger.debug("Structured cache hit: %s", cache_key)
        return data["result"], data["raw"]

    def _save_structured_to_cache(
        self, cache_key: str, response: "StructuredResponse",
    ) -> None:
        """Persist a successful structured response for later replay."""
        if not self.config.enable_caching:
            return

        from core.json import save_json
        from core.llm import cache_integrity
        cache_file = self.config.cache_dir / f"structured-{cache_key}.json"
        try:
            # mode=0o600 — structured LLM responses can contain proprietary
            # code, scan findings, and vulnerability details. Symmetric with
            # the unstructured _save_to_cache path at line 539.
            save_json(cache_file, cache_integrity.stamp(cache_file.stem, {
                "result": response.result,
                "raw": response.raw,
                "model": response.model,
                "provider": response.provider,
                "tokens_used": response.tokens_used,
                "timestamp": time.time(),
            }), mode=0o600)
        except Exception as e:  # noqa: BLE001
            # _stats_lock — see _save_to_cache above for the rationale.
            with self._stats_lock:
                self._cache_write_failures += 1
                failures = self._cache_write_failures
                if failures >= _CACHE_WRITE_FAILURE_THRESHOLD:
                    self.config.enable_caching = False
            if failures >= _CACHE_WRITE_FAILURE_THRESHOLD:
                logger.warning(
                    "Structured cache write error #%s: %s. Caching disabled for the remainder of this run.", failures, e
                )
            else:
                logger.warning(
                    "Structured cache write error #%s: %s", failures, e
                )
            return
        self._maybe_evict_cache()

    def _log_budget_exceeded_locked(self, estimated_cost: float) -> None:
        """Log a budget refusal — INFO the first time, DEBUG after.

        Callers hold ``_stats_lock``. Every post-exhaustion dispatch
        attempt hits the budget check, so an unconditional log printed
        the identical line once per doomed call. INFO, not ERROR: the
        refusal is the cost cap working as designed (the run continues
        to a successful exit and the loop driver prints the operator-
        facing stop summary) — an ERROR here made every clean budget
        stop read like a failure.
        """
        # getattr: tests build clients via ``__new__`` without the
        # constructor-initialised flag.
        emit = (
            logger.debug
            if getattr(self, "_budget_exceeded_logged", False)
            else logger.info
        )
        self._budget_exceeded_logged = True
        reserve = getattr(self, "_budget_reserve", 0.0) or 0.0
        if reserve:
            emit(
                "Budget exceeded: $%.2f + $%.2f > $%.2f "
                "($%.2f cap - $%.2f held in reserve)",
                self.total_cost, estimated_cost,
                self._effective_cap_locked(),
                self.config.max_cost_per_scan, reserve,
            )
        else:
            emit(
                "Budget exceeded: $%.2f + $%.2f > $%.2f",
                self.total_cost, estimated_cost,
                self.config.max_cost_per_scan,
            )

    def _effective_cap_locked(self) -> float:
        """The cap ordinary dispatch may spend up to: the configured
        per-scan cap minus any held reserve. Callers hold _stats_lock.
        getattr: tests build clients via ``__new__`` without the
        constructor-initialised reserve."""
        return (
            self.config.max_cost_per_scan
            - (getattr(self, "_budget_reserve", 0.0) or 0.0)
        )

    @property
    def provider_spend_usd(self) -> float:
        """Spend recorded on THIS client's own provider instances.

        Each provider's ``track_usage`` books every completed SDK call
        — including calls whose result was later discarded (JSON parse
        failures, schema violations, instructor retries). The client
        ledger (``total_cost``) books only attributable outcomes, so
        the provider ledger is the honest floor for "money actually
        gone". Budget enforcement gates on the max of the two (see
        ``_effective_spent_locked``)."""
        with self._stats_lock:
            providers = list(getattr(self, "providers", {}).values())
        total = 0.0
        for p in providers:
            try:
                total += float(getattr(p, "total_cost", 0.0) or 0.0)
            except (TypeError, ValueError):
                continue
        return total

    def _effective_spent_locked(self) -> float:
        """The spend figure budget checks gate on. Callers hold
        _stats_lock (RLock — the provider-ledger read re-enters it).

        ``total_cost`` carries attributable outcomes plus in-flight
        reservations; the provider ledger carries every completed SDK
        call including failed-attempt spend the client deliberately
        does not book per-call (per-call attribution from shared
        counters is impossible under parallel workers). The max of
        the two never double-counts and misses neither surface."""
        return max(self.total_cost, self.provider_spend_usd)

    def hold_budget_reserve(self, amount: float) -> float:
        """Hold back ``amount`` of the per-scan cap from ordinary
        dispatch.

        Every budget check then gates against ``cap - reserve``, so a
        late phase that calls :meth:`release_budget_reserve` first is
        guaranteed that much headroom regardless of how hungry the
        earlier phases were. Replaces any previously-held reserve
        (idempotent under repeat holds). Returns the amount actually
        held (clamped to [0, cap])."""
        with self._stats_lock:
            cap = self.config.max_cost_per_scan
            held = max(0.0, min(float(amount), cap or 0.0))
            self._budget_reserve = held
            return held

    def release_budget_reserve(self) -> float:
        """Release any held reserve back to ordinary dispatch.
        Idempotent. Returns the amount released."""
        with self._stats_lock:
            held = getattr(self, "_budget_reserve", 0.0) or 0.0
            self._budget_reserve = 0.0
            # A released reserve re-opens headroom: allow the next
            # refusal to log loudly again instead of hiding at DEBUG.
            if held:
                self._budget_exceeded_logged = False
            return held

    def _check_budget(self, estimated_cost: float = 0.1) -> bool:
        """Read-only budget check (thread-safe). Returns whether ``estimated_cost``
        would fit under the cap RIGHT NOW. Does not reserve — concurrent callers
        may all pass this check and then collectively overshoot the cap as their
        actual costs land. Use ``_acquire_budget`` for the atomic
        check-and-reserve required by parallel dispatch."""
        if not self.config.enable_cost_tracking:
            return True

        with self._stats_lock:
            if (
                self._effective_spent_locked() + estimated_cost
                > self._effective_cap_locked()
            ):
                self._log_budget_exceeded_locked(estimated_cost)
                return False

        return True

    def is_budget_exhausted(self, estimated_cost: float = 0.1) -> bool:
        """True when the next call (at ``estimated_cost``) would breach
        the cost cap. Read-only and quiet — unlike :meth:`_check_budget`
        it never logs, so loop drivers can poll it cheaply before doing
        expensive per-item prep work. Always False when cost tracking
        is disabled."""
        if not self.config.enable_cost_tracking:
            return False
        with self._stats_lock:
            return (
                self._effective_spent_locked() + estimated_cost
                > self._effective_cap_locked()
            )

    def _estimate_call_cost(self, call_class: str) -> float:
        """Reservation size for one call of ``call_class``.

        Priority: this client's own completed-call mean for the class,
        then the run telemetry sink's cross-client mean, then the
        conservative ``_DEFAULT_CALL_COST_ESTIMATE``. The result is
        floored at ``_BUDGET_RESERVATION`` (degenerate near-zero
        estimates would reopen the concurrency window) and capped at
        ``_RESERVATION_CAP_FRACTION`` of the cap (a conservative
        default must not refuse every call on a small-cap run).

        Reserving the estimate before dispatch is what bounds budget
        overshoot to ONE call's estimate error instead of
        workers × call cost: each in-flight call's expected spend is
        visible to every other dispatcher via the pre-debit.
        """
        if not self.config.enable_cost_tracking:
            return 0.0
        estimate = 0.0
        with self._stats_lock:
            # getattr: tests build clients via ``__new__`` without the
            # constructor-initialised history dict.
            hist_map = getattr(self, "_call_cost_history", None)
            hist = hist_map.get(call_class) if hist_map else None
            if hist and hist[0] > 0:
                estimate = hist[1] / hist[0]
        if estimate <= 0.0:
            # No local history — the run-wide telemetry sink may have
            # observed this class through another client instance.
            try:
                from core.llm.telemetry import current_sink
                sink = current_sink()
                if sink is not None:
                    mean = sink.mean_call_cost(call_class)
                    if mean is not None and mean > 0.0:
                        estimate = mean
            except Exception:  # telemetry is advisory
                logger.debug(
                    "telemetry cost-estimate probe failed", exc_info=True,
                )
        from_history = estimate > 0.0
        if not from_history:
            estimate = _DEFAULT_CALL_COST_ESTIMATE
        cap = self.config.max_cost_per_scan
        if cap and cap > 0:
            fraction = (
                _RESERVATION_CAP_MAX_FRACTION if from_history
                else _RESERVATION_CAP_FRACTION
            )
            estimate = min(estimate, cap * fraction)
        return max(_BUDGET_RESERVATION, estimate)

    def _note_call_cost(self, call_class: str, cost: float) -> None:
        """Record one completed call's actual cost for ``call_class``
        so subsequent reservations track observed reality."""
        with self._stats_lock:
            hist_map = getattr(self, "_call_cost_history", None)
            if hist_map is None:
                # Clients built via ``__new__`` (test helpers) skip the
                # constructor — lazily create the history dict.
                hist_map = self._call_cost_history = {}
            n, total = hist_map.get(call_class, (0, 0.0))
            hist_map[call_class] = (
                n + 1, total + max(0.0, float(cost or 0.0)),
            )

    def _acquire_budget(self, reservation: float) -> bool:
        """Atomically check + pre-debit ``reservation`` against the budget.
        Returns True if the reservation was held, False if it would breach.

        Pre-debiting under the same lock prevents the check-then-act race
        that lets N concurrent callers each see (total_cost + estimate) < cap
        and then collectively spend N × actual. After this returns True,
        callers MUST eventually reconcile to the actual cost (by adding
        ``actual − reservation``) or release the reservation
        (``_release_budget(reservation)``) so the held amount doesn't
        strand on the running total.
        """
        if not self.config.enable_cost_tracking:
            return True

        with self._stats_lock:
            if (
                self._effective_spent_locked() + reservation
                > self._effective_cap_locked()
            ):
                self._log_budget_exceeded_locked(reservation)
                return False
            self.total_cost += reservation
            return True

    def _release_budget(self, reservation: float) -> None:
        """Atomically undo a previously-held reservation. Call on the failure
        path so the held amount doesn't strand on the running total.
        Idempotent only in the sense that callers must not call it twice
        for the same acquire — that would under-count actual spend."""
        if not self.config.enable_cost_tracking:
            return
        with self._stats_lock:
            self.total_cost -= reservation

    def generate(self, prompt: str, system_prompt: str | None = None,
                 task_type: str | None = None, **kwargs) -> LLMResponse:
        """
        Generate completion with automatic fallback.

        Args:
            prompt: User prompt
            system_prompt: System prompt
            task_type: Task type for model selection
            **kwargs: Additional generation parameters
                model_config: Optional ModelConfig to override default model selection
                exclude_fallback_to: Optional set[str] of model names that
                    should NOT be selected as fallback targets, even if
                    configured globally as fallbacks. Used by multi-model
                    dispatch to prevent silent fallback into another active
                    model in the dispatch set (which would create duplicate
                    analysed_by entries in the model panel). Cross-family
                    fallbacks not in the set still work normally.

        Returns:
            LLMResponse with generated content

        Thread-safe: stats tracking uses _stats_lock for concurrent access.
        """
        # Check budget
        if not self._check_budget():
            msg = (
                f"LLM budget exceeded: ${self.total_cost:.4f} spent > ${self.config.max_cost_per_scan:.4f} limit. "
                f"Increase budget with: LLMConfig(max_cost_per_scan={self.config.max_cost_per_scan * 2:.1f})"
            )
            raise LLMBudgetExceededError(msg)

        # Get appropriate model for task (priority: explicit model_config > task_type > primary)
        model_config = kwargs.pop('model_config', None)
        # exclude_fallback_to: optional set[str] of model names that should
        # NOT be fallback targets even if configured globally. Used by
        # multi-model dispatch to prevent a primary's failure from silently
        # falling back into another model that's already in the active
        # dispatch set — which would create a duplicate (the same model
        # showing up under two slots in the model panel). Pop here so the
        # value doesn't propagate to providers via **kwargs.
        exclude_fallback_to: set | None = kwargs.pop('exclude_fallback_to', None)
        # Per-call timeout retry budget — see _TIMEOUT_RETRY_CAP. Popped
        # before the cache key is computed so retry policy never splits
        # otherwise-identical prompts into separate cache entries.
        timeout_retry_cap = _resolve_timeout_retry_cap(
            kwargs.pop('timeout_retry_cap', None),
        )
        # Telemetry label — which call class spent the time/money.
        # Popped before cache-key computation (labels must not split
        # cache entries); defaults to the task_type when unset.
        call_class = str(
            kwargs.pop('call_class', None) or task_type or "unclassified",
        )
        if not model_config:
            if task_type:
                model_config = self.config.get_model_for_task(task_type)
            else:
                model_config = self.config.primary_model

        # Resolution may return None when:
        #   * primary_model is unconfigured AND no task_type-specific
        #     fallback registered (LLMClient was constructed bare —
        #     normally `packages.llm_analysis.get_client` returns None
        #     instead, but a direct `LLMClient(LLMConfig())` call hits
        #     this path).
        #   * task_type is supplied but `get_model_for_task` returns
        #     None (no model registered for that role).
        # Pre-fix the next line `model_config.max_context * 0.8` raised
        # AttributeError on `None.max_context`. Surface a structured
        # error instead — the caller has no way to recover from a
        # missing model except by configuring one, and an
        # AttributeError mid-stack is no help.
        if model_config is None:
            msg = (
                "LLMClient.generate: no model resolved "
                f"(task_type={task_type!r}, primary_model="
                f"{self.config.primary_model!r}). Construct via "
                "packages.llm_analysis.get_client (which returns None "
                "when no provider is available) or supply an explicit "
                "model_config= kwarg."
            )
            raise RuntimeError(msg)

        # Warn if prompt likely exceeds context window (~4 chars per token)
        estimated_tokens = (len(prompt) + len(system_prompt or "")) // 4
        if estimated_tokens > model_config.max_context * 0.8:
            logger.warning(
                "Prompt ~%s tokens may exceed %s context window (%s)", estimated_tokens, model_config.model_name, model_config.max_context)

        # Check cache. Generation kwargs (temperature, max_tokens, …)
        # are part of the cache key — without that, two callers with
        # the same prompt but different temperatures would collide.
        cache_key = self._get_cache_key(
            prompt, system_prompt, model_config.model_name, kwargs,
        )
        # Per-key lock dedupes concurrent identical calls: the first
        # arrival pays the provider round-trip; serial-ordered followers
        # observe its freshly-written cache entry on their own check
        # below. Without this, N concurrent threads on the same key all
        # miss the cache, all call the provider, and all write — burning
        # N× the cost for a result they'd have shared.
        with self._key_lock(cache_key):
            cached_content = self._get_cached_response(cache_key)
            if cached_content is not None:
                logger.debug("Using cached response for %s/%s", model_config.provider, model_config.model_name)
                with self._stats_lock:
                    self.request_count += 1
                    self.cache_hits += 1
                from core.llm.telemetry import emit as _t_emit
                _t_emit(
                    event="call",
                    disposition="cache_hit",
                    call_class=call_class,
                    provider=model_config.provider.lower(),
                    model=model_config.model_name,
                    cost_usd=0.0,
                    duration_s=0.0,
                )
                return LLMResponse(
                    content=cached_content,
                    model=model_config.model_name,
                    # Lowercase to match the provider field that fresh
                    # `provider.generate()` returns. Pre-fix the cached
                    # path passed `model_config.provider` verbatim, so
                    # an LLMConfig with `provider="Anthropic"` (capital
                    # A — accepted by the constructor since the
                    # downstream lookup is case-insensitive) returned
                    # `"Anthropic"` from cached calls and `"anthropic"`
                    # from fresh ones. Downstream consumers grouping by
                    # provider (telemetry summaries, cost rollups) split
                    # the two into separate buckets silently.
                    provider=model_config.provider.lower(),
                    tokens_used=0,
                    cost=0.0,
                    finish_reason="cached",
                )

            # Try models in order with fallback (same tier only: local→local, cloud→cloud)
            models_to_try = [model_config]
            if self.config.enable_fallback:
                # Filter fallbacks to same tier as primary
                is_local_primary = model_config.provider.lower() == "ollama"
                for fallback in self.config.fallback_models:
                    if not fallback.enabled:
                        continue
                    # Skip if different tier (don't mix local and cloud)
                    is_local_fallback = fallback.provider.lower() == "ollama"
                    if is_local_primary == is_local_fallback:  # noqa: SIM102
                        # Skip if same as primary (already trying it)
                        if fallback.model_name != model_config.model_name:
                            # Skip if caller marked this name as already-active
                            # in a parallel dispatch (multi-model duplicate guard).
                            if exclude_fallback_to and fallback.model_name in exclude_fallback_to:
                                continue
                            models_to_try.append(fallback)

            last_error = None
            attempts_count = 0
            for model_idx, model in enumerate(models_to_try):
                if not model.enabled:
                    continue

                model_key = (model.provider, model.model_name)
                if model_key in self._daily_quota_exhausted:
                    logger.debug(
                        "Skipping %s/%s — daily quota exhausted",
                        model.provider, model.model_name,
                    )
                    continue

                attempts_count += 1

                if model_idx == 0:
                    logger.debug("Using model: %s/%s", model.provider, model.model_name)
                else:
                    logger.warning("Falling back to: %s/%s", model.provider, model.model_name)
                if model.provider.lower() == "ollama":
                    logger.warning("Local model — exploit PoCs may be unreliable")

                logger.debug("Trying model: %s/%s", model.provider, model.model_name)

                timeout_failures = 0
                last_safe_e = ""
                for attempt in range(self.config.max_retries):
                    attempt_start = time.monotonic()
                    try:
                        if attempt > 0:
                            # DEBUG, not INFO: the prior attempt's
                            # WARNING ("Attempt N/M failed ...") already
                            # signalled that a retry will follow. The
                            # next attempt either succeeds (silent) or
                            # fails (another WARNING) — operator infers
                            # the retry from either. Adding an INFO
                            # bookend produces operator log noise
                            # without new signal.
                            logger.debug("Retrying %s/%s (attempt %d/%d)", model.provider, model.model_name, attempt + 1, self.config.max_retries)

                        provider = self._get_provider(model)
                        # Acquire budget reservation immediately before the
                        # provider call. The pre-debit closes the
                        # check-then-act window so concurrent dispatchers
                        # see this one's pending spend instead of all
                        # reading the same baseline and individually
                        # passing the cap. Sized per call class from
                        # observed history so overshoot is bounded by
                        # one call's estimate error, not workers × call
                        # cost. Reconciled to actual cost below;
                        # released on exception.
                        reservation = self._estimate_call_cost(call_class)
                        if not self._acquire_budget(reservation):
                            msg = (
                                f"LLM budget exceeded: ${self.total_cost:.4f} spent "
                                f"+ ${reservation:.4f} estimated > "
                                f"${self.config.max_cost_per_scan:.4f} limit. Increase budget "
                                f"with: LLMConfig(max_cost_per_scan="
                                f"{self.config.max_cost_per_scan * 2:.1f})"
                            )
                            raise LLMBudgetExceededError(msg)
                        # monotonic() — wall clock can jump under NTP/DST,
                        # producing negative durations or fake-fast calls.
                        t_start = time.monotonic()
                        try:
                            response = provider.generate(prompt, system_prompt, **kwargs)
                        except Exception:
                            self._release_budget(reservation)
                            raise
                        duration = time.monotonic() - t_start

                        # Reconcile: cancel the reservation pre-debit and
                        # add the actual cost. Net effect on total_cost
                        # is +response.cost. When cost-tracking is
                        # disabled, _acquire_budget was a no-op so the
                        # reservation cancellation must also be skipped —
                        # otherwise total_cost drifts negative by the
                        # reservation amount per call.
                        with self._stats_lock:
                            if self.config.enable_cost_tracking:
                                self.total_cost += response.cost - reservation
                            else:
                                self.total_cost += response.cost
                            self.request_count += 1
                            if task_type:
                                self.task_type_costs[task_type] = self.task_type_costs.get(task_type, 0.0) + response.cost
                        self._note_call_cost(call_class, response.cost)

                        # Cache response
                        self._save_to_cache(cache_key, response)

                        # Record provenance: this provider call fired. role is
                        # primary for the first model tried, fallback otherwise.
                        self._record_fired_model(
                            model.provider, model.model_name,
                            response.resolved_model,
                            "primary" if model_idx == 0 else "fallback",
                        )
                        self._record_usage(
                            model.model_name,
                            cost=response.cost,
                            tokens=response.tokens_used,
                            input_tokens=response.input_tokens,
                            output_tokens=response.output_tokens,
                            duration_s=duration,
                        )

                        from core.llm.telemetry import emit as _t_emit
                        _t_emit(
                            event="call",
                            disposition="ok",
                            call_class=call_class,
                            provider=model.provider.lower(),
                            model=model.model_name,
                            attempt=attempt + 1,
                            timeout_retries=timeout_failures,
                            duration_s=round(duration, 3),
                            cost_usd=response.cost,
                            http_version=_transport_http_version(),
                            tokens_in=getattr(response, "input_tokens", 0),
                            tokens_out=getattr(response, "output_tokens", 0),
                            cache_read_tokens=getattr(
                                response, "cache_read_tokens", 0),
                            cache_write_tokens=getattr(
                                response, "cache_write_tokens", 0),
                        )

                        logger.debug("Generation successful: %s/%s (tokens: %s, cost: $%.4f, duration: %.1fs)", model.provider, model.model_name, response.tokens_used, response.cost, duration)

                        if attempt > 0:
                            # One line per retry SEQUENCE: the per-
                            # attempt failures logged at DEBUG; a
                            # recovery states how many attempts the
                            # call actually burned.
                            logger.info(
                                "%s/%s recovered after %d attempt(s)",
                                model.provider, model.model_name,
                                attempt + 1,
                            )

                        return response

                    except LLMBudgetExceededError:
                        # Budget exhaustion is TERMINAL for the run
                        # (see the class docstring): re-raise so
                        # callers catching by type actually see it.
                        # Letting the blanket handler below treat it
                        # as a per-attempt failure would iterate every
                        # fallback model (each failing the same budget
                        # check) and surface a generic "All models
                        # failed" RuntimeError, losing the typed
                        # contract.
                        raise
                    except Exception as e:  # noqa: BLE001
                        last_error = e

                        if getattr(e, "status_code", None) == 429:
                            from core.llm.throttle import broadcast_rate_limit
                            broadcast_rate_limit()

                        if _is_daily_quota_error(e):
                            self._daily_quota_exhausted.add(model_key)
                            from core.security.log_sanitisation import (
                                escape_nonprintable as _esc,
                            )
                            logger.warning(
                                "Daily quota exhausted for %s/%s — "
                                "skipping for remainder of session",
                                _esc(model.provider), _esc(model.model_name),
                            )
                            break
                        if _is_quota_error(e):
                            quota_guidance = _get_quota_guidance(model.model_name, model.provider)
                            # escape_nonprintable on provider/model
                            # — config-loaded strings, could carry
                            # ANSI/BIDI/control bytes from a hostile
                            # models.json edit. Defence in depth.
                            from core.security.log_sanitisation import (
                                escape_nonprintable as _esc,
                            )
                            logger.warning(
                                "Quota error for %s/%s:%s",
                                _esc(model.provider), _esc(model.model_name),
                                _esc(quota_guidance),
                            )

                        # Sanitisation is the BROADER of the two
                        # available paths: redact_secrets covers more
                        # patterns than _sanitize_log_message's API-key
                        # regex; escape_nonprintable defangs ANSI/control
                        # bytes; [:1024] caps the length. This was the
                        # sanitisation the (now-demoted) provider ERROR
                        # used; moving it to the surviving operator-
                        # visible line preserves the safety properties
                        # at the right level. See the retry-dedupe
                        # adversarial-review notes for rationale.
                        from core.security.log_sanitisation import (
                            escape_nonprintable as _esc_np,
                        )
                        from core.security.redaction import (
                            redact_secrets as _redact,
                        )
                        _safe_e = _esc_np(_redact(str(e)))[:1024]
                        last_safe_e = _safe_e
                        # Timeout-class failures log at WARNING: each
                        # one already burned the FULL per-request read
                        # budget (600s on the bedrock/claudecode
                        # transports), so during an upstream brownout
                        # the review loop stalls for tens of minutes
                        # (observed 50 min: client attempts plus the
                        # orchestrator's reduced-context retry, each
                        # re-buying the read budget) with nothing
                        # operator-visible until the terminal line.
                        # Unlike 429s, timeouts cannot storm — the
                        # read budget itself throttles them to a
                        # handful per hour per worker.
                        # Everything else stays DEBUG: intermediate
                        # attempts are noise — a 429 storm printed
                        # ~370 near-identical retry WARNINGs. The
                        # terminal per-model WARNING below carries the
                        # attempt count and last error; a recovery
                        # logs one INFO.
                        _attempt_log = (
                            logger.warning if is_timeout_error(e)
                            else logger.debug
                        )
                        _attempt_log(
                            "Attempt %d/%d failed for %s/%s after "
                            "%.0fs: %s",
                            attempt + 1, self.config.max_retries,
                            _esc_np(model.provider),
                            _esc_np(model.model_name),
                            time.monotonic() - attempt_start, _safe_e,
                        )

                        from core.llm.telemetry import emit as _t_emit
                        _t_emit(
                            event="attempt_failed",
                            disposition=_failure_disposition(e),
                            call_class=call_class,
                            provider=model.provider.lower(),
                            model=model.model_name,
                            attempt=attempt + 1,
                            duration_s=round(
                                time.monotonic() - attempt_start, 3),
                            http_version=_transport_http_version(),
                            error=_safe_e[:200],
                        )

                        if not _is_retryable_error(e):
                            logger.info("Non-retryable error — skipping remaining retries for %s/%s", model.provider, model.model_name)
                            break

                        if is_timeout_error(e):
                            timeout_failures += 1
                            if timeout_failures > timeout_retry_cap:
                                logger.info(
                                    "Timeout retry cap (%d) reached for "
                                    "%s/%s — skipping remaining retries",
                                    timeout_retry_cap,
                                    model.provider, model.model_name,
                                )
                                break

                        if attempt < self.config.max_retries - 1:
                            delay = min(self.config.retry_delay * (2 ** attempt), 30)
                            logger.debug("Retrying in %ss...", delay)
                            time.sleep(delay)

                logger.warning(
                    "%s/%s: giving up after %d failed attempt(s), "
                    "trying next model. Last error: %s",
                    model.provider, model.model_name, attempt + 1,
                    last_safe_e or "(not recorded)",
                )

            # All models in tier failed
            _prov = model_config.provider.lower()
            if _prov == "ollama":
                tier = "local (Ollama)"
            elif _prov.startswith("claudecode"):
                tier = "claude CLI"
            else:
                tier = "cloud"
            error_msg = f"All {tier} models failed (tried {attempts_count} model(s))."

            # Check if last error was quota-related
            if last_error and _is_quota_error(last_error):
                error_msg += _get_quota_guidance(model_config.model_name, model_config.provider)
                error_msg += f"\nProvider message: {_sanitize_log_message(str(last_error))}"
            elif last_error:
                error_msg += f"\nLast error: {_sanitize_log_message(str(last_error))}"
                if tier == "local (Ollama)":
                    error_msg += f"\n→ Check Ollama server: {_ollama_check_url()}"
                elif tier == "claude CLI":
                    error_msg += (
                        "\n→ claude CLI transport — the cause is in the "
                        "error above (timeout / per-call budget / CLI "
                        "failure), not API keys. Verify `claude -p` works."
                    )
                else:
                    error_msg += "\n→ Check API keys and network connectivity"
            else:
                error_msg += "\nNo enabled models available in this tier."
                if tier == "local (Ollama)":
                    error_msg += f"\n→ Check Ollama server: {_ollama_check_url()}"
                elif tier == "claude CLI":
                    error_msg += (
                        "\n→ claude CLI transport — the cause is in the "
                        "error above (timeout / per-call budget / CLI "
                        "failure), not API keys. Verify `claude -p` works."
                    )
                else:
                    error_msg += "\n→ Check API keys and network connectivity"

            logger.error(error_msg)
            # ``from last_error`` preserves the causal chain: consumers
            # that classify failures structurally (the persistent-auth
            # phase-abort tracker walks __cause__ for typed SDK errors
            # and response-shape failures) must not be reduced to
            # substring-matching over a message that may quote
            # model/target-controlled text.
            raise RuntimeError(error_msg) from last_error

    def supports_prompt_caching_for(
        self, model_config: ModelConfig | None = None,
    ) -> bool:
        """True when cache-aligned prompt composition pays off on the
        provider serving ``model_config`` (default: the primary
        model) — i.e. placing run-stable material in the system
        prompt where the backend bills it at the cached-input rate.

        Consults ``prefers_stable_system_prefix()`` rather than the
        raw ``supports_prompt_caching()`` capability: the claudecode
        transport has no cache_control API, yet its backend
        prefix-caches byte-stable system prompts across subprocess
        calls, so composition-wise it behaves like a caching
        provider. For providers without the newer capability method,
        falls back to ``supports_prompt_caching()``."""
        cfg = model_config or self.config.primary_model
        if cfg is None:
            return False
        try:
            provider = self._get_provider(cfg)
            prefers = getattr(provider, "prefers_stable_system_prefix", None)
            if callable(prefers):
                return bool(prefers())
            return provider.supports_prompt_caching()
        except Exception:
            logger.debug(
                "supports_prompt_caching_for probe failed", exc_info=True,
            )
            return False

    def generate_structured(self, prompt: str, schema: dict[str, Any],
                           system_prompt: str | None = None,
                           task_type: str | None = None, **kwargs):
        """
        Generate structured JSON output with automatic fallback.

        Args:
            prompt: User prompt
            schema: JSON schema for expected output
            system_prompt: System prompt
            task_type: Task type for model selection
            **kwargs: Additional generation parameters
                model_config: Optional ModelConfig to override default model selection
                exclude_fallback_to: Optional set[str] of model names that
                    should NOT be selected as fallback targets. Same
                    semantics as ``generate``.

        Returns:
            StructuredResponse with result dict, raw content, cost, and metadata.
            For backwards compatibility, can be unpacked as a 2-tuple: result, raw = ...

        Thread-safe: stats tracking uses _stats_lock for concurrent access.
        """
        # Check budget
        if not self._check_budget():
            msg = (
                f"LLM budget exceeded: ${self.total_cost:.4f} spent > ${self.config.max_cost_per_scan:.4f} limit. "
                f"Increase budget with: LLMConfig(max_cost_per_scan={self.config.max_cost_per_scan * 2:.1f})"
            )
            raise LLMBudgetExceededError(msg)

        # Get appropriate model (priority: explicit model_config > task_type > primary)
        model_config = kwargs.pop('model_config', None)
        # See ``generate`` for the rationale on exclude_fallback_to.
        exclude_fallback_to: set | None = kwargs.pop('exclude_fallback_to', None)
        # Per-call timeout retry budget — see ``generate``.
        timeout_retry_cap = _resolve_timeout_retry_cap(
            kwargs.pop('timeout_retry_cap', None),
        )
        # Telemetry label — see ``generate``.
        call_class = str(
            kwargs.pop('call_class', None) or task_type or "unclassified",
        )
        if not model_config:
            if task_type:
                model_config = self.config.get_model_for_task(task_type)
            else:
                model_config = self.config.primary_model

        # Same None-guard as `generate` — see comment there for the
        # full rationale. Without this, the next line crashes with
        # AttributeError on `None.max_context`.
        if model_config is None:
            msg = (
                "LLMClient.generate_structured: no model resolved "
                f"(task_type={task_type!r}, primary_model="
                f"{self.config.primary_model!r}). Construct via "
                "packages.llm_analysis.get_client (which returns None "
                "when no provider is available) or supply an explicit "
                "model_config= kwarg."
            )
            raise RuntimeError(msg)

        # Provider impls of generate_structured now accept **kwargs
        # (batch 331 — temperature plumbing). The previous warning
        # here always fired in production because every DispatchTask
        # passes `temperature=task.temperature`; downstream the kwarg
        # was dropped, so structured analysis ran at provider-default
        # temperature regardless of the task's declared value. We
        # forward kwargs to provider.generate_structured() below;
        # cache key already incorporates them via
        # `_get_structured_cache_key(... kwargs)` so two calls with
        # the same prompt + schema + model but different temperatures
        # don't collide.

        # Warn if prompt likely exceeds context window (~4 chars per token)
        estimated_tokens = (len(prompt) + len(system_prompt or "")) // 4
        if estimated_tokens > model_config.max_context * 0.8:
            logger.warning(
                "Prompt ~%s tokens may exceed %s context window (%s)", estimated_tokens, model_config.model_name, model_config.max_context)

        # Check cache. Key includes schema so two callers who share a
        # prompt but ask for different output shapes don't collide.
        # Pinned to model_config.model_name (the configured first-choice
        # model), not whichever fallback we actually use — replays come
        # back as if the configured model was queried, matching how
        # generate() does it.
        cache_key = self._get_structured_cache_key(
            prompt, system_prompt, model_config.model_name, schema, kwargs,
        )
        # Per-key lock dedupes concurrent identical calls (see generate()
        # for full rationale).
        with self._key_lock(cache_key):
            cached = self._get_cached_structured_response(cache_key)
            if cached is not None:
                cached_result, cached_raw = cached
                # Strict schema floor applies to cache replays too —
                # entries written before the floor existed (or by an
                # older RAPTOR) may carry smuggled fields. Treat a
                # violating entry as a cache miss and regenerate.
                stale_unknown = unknown_response_fields(cached_result, schema)
                if stale_unknown:
                    logger.debug(
                        "Cached structured response rejected (unknown "
                        "fields %s) — regenerating", stale_unknown,
                    )
                    cached = None
            if cached is not None:
                logger.debug(
                    "Using cached structured response for %s/%s", model_config.provider, model_config.model_name
                )
                with self._stats_lock:
                    self.request_count += 1
                    self.cache_hits += 1
                from core.llm.telemetry import emit as _t_emit
                _t_emit(
                    event="call",
                    disposition="cache_hit",
                    call_class=call_class,
                    provider=model_config.provider.lower(),
                    model=model_config.model_name,
                    structured=True,
                    cost_usd=0.0,
                    duration_s=0.0,
                )
                return StructuredResponse(
                    result=cached_result,
                    raw=cached_raw,
                    cost=0.0,
                    tokens_used=0,
                    model=model_config.model_name,
                    # Lowercase — same normalisation as generate()'s
                    # cached path (see the comment there): a mixed-case
                    # LLMConfig provider would otherwise split
                    # cached/fresh responses into separate buckets for
                    # consumers grouping by provider.
                    provider=model_config.provider.lower(),
                    duration=0.0,
                    cached=True,
                )

            # Try models in order (same tier only: local→local, cloud→cloud)
            models_to_try = [model_config]
            if self.config.enable_fallback:
                is_local_primary = model_config.provider.lower() == "ollama"
                for fallback in self.config.fallback_models:
                    if not fallback.enabled:
                        continue
                    is_local_fallback = fallback.provider.lower() == "ollama"
                    if is_local_primary == is_local_fallback:  # noqa: SIM102
                        if fallback.model_name != model_config.model_name:
                            # Multi-model duplicate guard — see ``generate``.
                            if exclude_fallback_to and fallback.model_name in exclude_fallback_to:
                                continue
                            models_to_try.append(fallback)

            last_error = None
            attempts_count = 0
            for model_idx, model in enumerate(models_to_try):
                if not model.enabled:
                    continue

                model_key = (model.provider, model.model_name)
                if model_key in self._daily_quota_exhausted:
                    logger.debug(
                        "Skipping %s/%s (structured) — daily quota exhausted",
                        model.provider, model.model_name,
                    )
                    continue

                attempts_count += 1

                if model_idx == 0:
                    logger.debug("Using model: %s/%s (structured)", model.provider, model.model_name)
                else:
                    logger.warning("Falling back to: %s/%s (structured)", model.provider, model.model_name)
                if model.provider.lower() == "ollama":
                    logger.warning("Local model — exploit PoCs may be unreliable")

                timeout_failures = 0
                last_safe_e = ""
                for attempt in range(self.config.max_retries):
                    attempt_start = time.monotonic()
                    try:
                        if attempt > 0:
                            # DEBUG, not INFO — see ``generate`` above
                            # for the same noise-vs-signal rationale.
                            logger.debug("Retrying %s/%s (attempt %d/%d)", model.provider, model.model_name, attempt + 1, self.config.max_retries)

                        provider = self._get_provider(model)

                        # See `generate` for the acquire/reconcile rationale —
                        # same race shape applies to structured calls.
                        # History-sized reservation: overshoot bounded
                        # by one call's estimate error.
                        reservation = self._estimate_call_cost(call_class)
                        if not self._acquire_budget(reservation):
                            msg = (
                                f"LLM budget exceeded: ${self.total_cost:.4f} spent "
                                f"+ ${reservation:.4f} estimated > "
                                f"${self.config.max_cost_per_scan:.4f} limit. Increase budget "
                                f"with: LLMConfig(max_cost_per_scan="
                                f"{self.config.max_cost_per_scan * 2:.1f})"
                            )
                            raise LLMBudgetExceededError(msg)

                        # Capture cost before call
                        cost_before = provider.total_cost
                        tokens_before = provider.total_tokens
                        # Token-split + prompt-cache counters, diffed
                        # after the call. Providers return a bare
                        # (result, raw) tuple on some paths, so the
                        # per-call usage has to come from the
                        # aggregate counters track_usage maintains.
                        in_before = _safe_counter(
                            provider, "total_input_tokens")
                        out_before = _safe_counter(
                            provider, "total_output_tokens")
                        cread_before = _safe_counter(
                            provider, "total_cache_read_tokens")
                        cwrite_before = _safe_counter(
                            provider, "total_cache_write_tokens")

                        # monotonic() — wall clock can jump under NTP/DST.
                        t_start = time.monotonic()
                        try:
                            result_tuple = provider.generate_structured(
                                prompt, schema, system_prompt, **kwargs,
                            )
                        except Exception:
                            # Release the reservation and book NOTHING.
                            # The old path recorded the provider-counter
                            # delta (total_cost - cost_before) as this
                            # call's failed spend — but the counters are
                            # SHARED across parallel workers, so a call
                            # failing after a 6-minute timeout booked
                            # every concurrent worker's spend from that
                            # window into the enforced ledger a second
                            # time (observed live: 11 timeouts booked
                            # ~$26 each on a run whose real total spend
                            # was $38, tripping the cap at 25/40
                            # reviews). Money genuinely spent by a
                            # failed attempt (e.g. the JSON fallback
                            # completed an API call before the parse
                            # failed) is already on the provider's own
                            # ledger — budget enforcement reads
                            # ``max(total_cost, provider_spend_usd)``
                            # (see ``_effective_spent_locked``) so it
                            # still counts, exactly once.
                            self._release_budget(reservation)
                            raise
                        duration = time.monotonic() - t_start

                        # Calculate cost delta
                        cost_delta = provider.total_cost - cost_before
                        tokens_delta = provider.total_tokens - tokens_before
                        in_delta = max(
                            0, _safe_counter(
                                provider, "total_input_tokens",
                            ) - in_before)
                        out_delta = max(
                            0, _safe_counter(
                                provider, "total_output_tokens",
                            ) - out_before)
                        cread_delta = max(
                            0, _safe_counter(
                                provider, "total_cache_read_tokens",
                            ) - cread_before)
                        cwrite_delta = max(
                            0, _safe_counter(
                                provider, "total_cache_write_tokens",
                            ) - cwrite_before)

                        # Exact per-call usage reported by the provider
                        # takes precedence over the aggregate-counter
                        # deltas above: the provider counters are SHARED
                        # across parallel workers, so a before/after
                        # diff swallows every concurrent call's spend
                        # and multiply-books the same money into this
                        # ledger (observed live: $38 of real spend
                        # enforced as budget-exhausted, terminating a
                        # run at 25/40 reviews with 62% of the cap
                        # unspent). Deltas remain the fallback for
                        # legacy providers that return no usage.
                        _pc_cost = float(
                            getattr(result_tuple, "cost", 0.0) or 0.0)
                        _pc_tokens = int(
                            getattr(result_tuple, "tokens_used", 0) or 0)
                        if _pc_cost > 0 or _pc_tokens > 0:
                            cost_delta = _pc_cost
                            tokens_delta = _pc_tokens
                            in_delta = int(getattr(
                                result_tuple, "input_tokens", 0) or 0)
                            out_delta = int(getattr(
                                result_tuple, "output_tokens", 0) or 0)
                            cread_delta = int(getattr(
                                result_tuple, "cache_read_tokens", 0) or 0)
                            cwrite_delta = int(getattr(
                                result_tuple, "cache_write_tokens", 0) or 0)

                        # Reconcile reservation → actual. Skip the
                        # reservation cancel when cost-tracking is
                        # disabled (see ``generate`` for the rationale).
                        with self._stats_lock:
                            if self.config.enable_cost_tracking:
                                self.total_cost += cost_delta - reservation
                            else:
                                self.total_cost += cost_delta
                            self.request_count += 1
                            if task_type:
                                self.task_type_costs[task_type] = self.task_type_costs.get(task_type, 0.0) + cost_delta
                        self._note_call_cost(call_class, cost_delta)

                        logger.debug("Structured generation successful: %s/%s (tokens: %s, cost: $%.4f, duration: %.1fs)", model.provider, model.model_name, tokens_delta, cost_delta, duration)

                        result_dict, raw = result_tuple
                        # Strict schema floor — mandatory last hop for
                        # every structured response. Provider-side
                        # constrained decoding guarantees shape but not
                        # the rejection of smuggled extra fields; a
                        # hijacked model (or a provider silently
                        # ignoring the schema) could otherwise pass
                        # unrequested keys into downstream consumers.
                        # A violation is treated exactly like a
                        # malformed response: raised into the retry /
                        # fallback loop below, recorded against the
                        # model's schema-validity scorecard cell.
                        # Open-ended shapes must be exempted explicitly
                        # (``additionalProperties: true`` or
                        # ``_OPEN_SCHEMA_SIGNATURES`` in
                        # core.llm.response_validation).
                        unknown = unknown_response_fields(result_dict, schema)
                        if unknown:
                            msg = (
                                f"structured response carried fields "
                                f"outside the requested schema: {unknown}"
                            )
                            raise SchemaUnknownFieldError(msg)
                        # Lift the resolved snapshot the provider attached
                        # (StructuredResponse carries it; a bare-tuple return
                        # yields None — alias-only, never guessed).
                        resolved = getattr(result_tuple, "resolved_model", None)
                        structured_response = StructuredResponse(
                            result=result_dict,
                            raw=raw,
                            cost=cost_delta,
                            tokens_used=tokens_delta,
                            model=model.model_name,
                            # Lowercase — keeps cached and fresh
                            # structured responses in the same
                            # provider bucket (matches the providers'
                            # own ``config.provider.lower()``).
                            provider=model.provider.lower(),
                            duration=duration,
                            resolved_model=resolved,
                            input_tokens=in_delta,
                            output_tokens=out_delta,
                            cache_read_tokens=cread_delta,
                            cache_write_tokens=cwrite_delta,
                        )
                        self._record_fired_model(
                            model.provider, model.model_name, resolved,
                            "primary" if model_idx == 0 else "fallback",
                        )
                        self._record_usage(
                            model.model_name,
                            cost=cost_delta,
                            tokens=tokens_delta,
                            input_tokens=in_delta,
                            output_tokens=out_delta,
                            duration_s=duration,
                        )
                        from core.llm.telemetry import emit as _t_emit
                        _t_emit(
                            event="call",
                            disposition="ok",
                            call_class=call_class,
                            provider=model.provider.lower(),
                            model=model.model_name,
                            structured=True,
                            attempt=attempt + 1,
                            timeout_retries=timeout_failures,
                            duration_s=round(duration, 3),
                            cost_usd=cost_delta,
                            http_version=_transport_http_version(),
                            tokens_in=in_delta,
                            tokens_out=out_delta,
                            cache_read_tokens=cread_delta,
                            cache_write_tokens=cwrite_delta,
                        )
                        # Schema reliability signal — the response parsed and
                        # matched the schema (otherwise we'd be in the except
                        # branch). Recorded under _structured at flush time.
                        self._record_schema_validity(model.model_name, success=True)
                        # Cache before returning so repeated identical calls
                        # short-circuit the provider entirely. Cache key is
                        # tied to model_config (the first-choice model), so
                        # a fallback's output is filed under the original
                        # request's identity — matches generate()'s behaviour.
                        self._save_structured_to_cache(cache_key, structured_response)
                        if attempt > 0:
                            logger.info(
                                "%s/%s recovered after %d attempt(s) "
                                "(structured)",
                                model.provider, model.model_name,
                                attempt + 1,
                            )
                        return structured_response

                    except LLMBudgetExceededError:
                        # Terminal for the run — re-raise past the
                        # blanket handler so typed callers see it.
                        # See ``generate`` above for the rationale.
                        raise
                    except Exception as e:  # noqa: BLE001
                        last_error = e
                        # Schema reliability signal — only record the model as
                        # schema-failing when the error class points at a
                        # response-shape problem (parse / schema-mismatch /
                        # validation), not at infra (network 5xx, timeouts,
                        # quota) or model/account boundaries (refusals,
                        # auth, budget aborts, empty content — each keeps
                        # its own disposition). Otherwise we'd attribute
                        # those as this model's schema unreliability and
                        # the SCHEMA_VALID cell would drift to nonsense.
                        if _is_response_shape_failure(e):
                            self._record_schema_validity(model.model_name, success=False)

                        if getattr(e, "status_code", None) == 429:
                            from core.llm.throttle import broadcast_rate_limit
                            broadcast_rate_limit()

                        if _is_daily_quota_error(e):
                            self._daily_quota_exhausted.add(model_key)
                            from core.security.log_sanitisation import (
                                escape_nonprintable as _esc,
                            )
                            logger.warning(
                                "Daily quota exhausted for %s/%s — "
                                "skipping for remainder of session",
                                _esc(model.provider), _esc(model.model_name),
                            )
                            break
                        if _is_quota_error(e):
                            quota_guidance = _get_quota_guidance(model.model_name, model.provider)
                            # escape_nonprintable on provider/model
                            # — config-loaded strings, could carry
                            # ANSI/BIDI/control bytes from a hostile
                            # models.json edit. Defence in depth.
                            from core.security.log_sanitisation import (
                                escape_nonprintable as _esc,
                            )
                            logger.warning(
                                "Quota error for %s/%s:%s",
                                _esc(model.provider), _esc(model.model_name),
                                _esc(quota_guidance),
                            )

                        # Broader sanitisation — same rationale as the
                        # ``generate`` retry loop above.
                        from core.security.log_sanitisation import (
                            escape_nonprintable as _esc_np,
                        )
                        from core.security.redaction import (
                            redact_secrets as _redact,
                        )
                        _safe_e = _esc_np(_redact(str(e)))[:1024]
                        last_safe_e = _safe_e
                        # DEBUG — collapsed to one WARNING per retry
                        # sequence (see ``generate`` above).
                        logger.debug(
                            "Structured generation attempt %d failed: %s",
                            attempt + 1, _safe_e,
                        )

                        from core.llm.telemetry import emit as _t_emit
                        _t_emit(
                            event="attempt_failed",
                            disposition=_failure_disposition(e),
                            call_class=call_class,
                            provider=model.provider.lower(),
                            model=model.model_name,
                            structured=True,
                            attempt=attempt + 1,
                            duration_s=round(
                                time.monotonic() - attempt_start, 3),
                            http_version=_transport_http_version(),
                            error=_safe_e[:200],
                        )

                        if not _is_retryable_error(e):
                            logger.info("Non-retryable error — skipping remaining retries for %s/%s", model.provider, model.model_name)
                            break

                        if is_timeout_error(e):
                            timeout_failures += 1
                            if timeout_failures > timeout_retry_cap:
                                logger.info(
                                    "Timeout retry cap (%d) reached for "
                                    "%s/%s — skipping remaining retries",
                                    timeout_retry_cap,
                                    model.provider, model.model_name,
                                )
                                break

                        if attempt < self.config.max_retries - 1:
                            delay = min(self.config.retry_delay * (2 ** attempt), 30)
                            logger.debug("Retrying in %ss...", delay)
                            time.sleep(delay)

                logger.warning(
                    "%s/%s: structured generation giving up after %d "
                    "failed attempt(s), trying next model. "
                    "Last error: %s",
                    model.provider, model.model_name, attempt + 1,
                    last_safe_e or "(not recorded)",
                )

            # All models in tier failed
            _prov = model_config.provider.lower()
            if _prov == "ollama":
                tier = "local (Ollama)"
            elif _prov.startswith("claudecode"):
                tier = "claude CLI"
            else:
                tier = "cloud"
            error_msg = f"Structured generation failed for all {tier} models (tried {attempts_count} model(s))."

            if last_error and _is_quota_error(last_error):
                error_msg += _get_quota_guidance(model_config.model_name, model_config.provider)
                error_msg += f"\nProvider message: {_sanitize_log_message(str(last_error))}"
            elif last_error:
                error_msg += f"\nLast error: {_sanitize_log_message(str(last_error))}"
                if tier == "local (Ollama)":
                    error_msg += f"\n→ Check Ollama server: {_ollama_check_url()}"
                elif tier == "claude CLI":
                    error_msg += (
                        "\n→ claude CLI transport — the cause is in the "
                        "error above (timeout / per-call budget / CLI "
                        "failure), not API keys. Verify `claude -p` works."
                    )
                else:
                    error_msg += "\n→ Check API keys and network connectivity"
            else:
                error_msg += "\nNo enabled models available in this tier."
                if tier == "local (Ollama)":
                    error_msg += f"\n→ Check Ollama server: {_ollama_check_url()}"
                elif tier == "claude CLI":
                    error_msg += (
                        "\n→ claude CLI transport — the cause is in the "
                        "error above (timeout / per-call budget / CLI "
                        "failure), not API keys. Verify `claude -p` works."
                    )
                else:
                    error_msg += "\n→ Check API keys and network connectivity"

            logger.error(error_msg)
            # ``from last_error`` preserves the causal chain: consumers
            # that classify failures structurally (the persistent-auth
            # phase-abort tracker walks __cause__ for typed SDK errors
            # and response-shape failures) must not be reduced to
            # substring-matching over a message that may quote
            # model/target-controlled text.
            raise RuntimeError(error_msg) from last_error

    def get_stats(self) -> dict[str, Any]:
        """Get usage statistics with per-provider, per-task-type, and token split breakdowns."""
        provider_stats = {}
        # Snapshot under the lock: ``_get_provider`` inserts into
        # ``self.providers`` under ``_stats_lock`` from concurrent
        # dispatch threads, so iterating the live dict here can raise
        # RuntimeError("dictionary changed size during iteration")
        # when progress reporting polls stats mid-run.
        with self._stats_lock:
            providers_snapshot = list(self.providers.items())
        for key, provider in providers_snapshot:
            avg_duration = (provider.total_duration / provider.call_count
                           if provider.call_count > 0 else 0.0)
            pstat: dict[str, Any] = {
                "call_count": provider.call_count,
                "total_tokens": provider.total_tokens,
                "input_tokens": provider.total_input_tokens,
                "output_tokens": provider.total_output_tokens,
                "total_cost": provider.total_cost,
                "total_duration": round(provider.total_duration, 2),
                "avg_duration": round(avg_duration, 2),
            }
            if provider.total_cache_read_tokens or provider.total_cache_write_tokens:
                pstat["cache_read_tokens"] = provider.total_cache_read_tokens
                pstat["cache_write_tokens"] = provider.total_cache_write_tokens
            provider_stats[key] = pstat

        with self._stats_lock:
            stats = {
                "total_requests": self.request_count,
                "total_cost": self.total_cost,
                "budget_remaining": self.config.max_cost_per_scan - self.total_cost,
                "providers": provider_stats,
                "task_type_costs": dict(self.task_type_costs),
            }
            if self.cache_hits:
                stats["cache_hits"] = self.cache_hits
            if self.cache_tamper_events:
                stats["cache_tamper_events"] = self.cache_tamper_events
            return stats

