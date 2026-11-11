"""Provider-independent budget exceptions and terminal-error classification.

Schedulers can check a budget stop without importing model SDKs. The client
re-exports these objects for compatibility with existing callers.
"""

import json

from .response_validation import SchemaUnknownFieldError


class LLMCallAdmissionRefused(RuntimeError):
    """A task-scoped refusal: stop this call without exhausting the run."""


class LLMBudgetExceededError(RuntimeError):
    """Raised when a call would breach the client's cost cap.

    Budget exhaustion is TERMINAL for the run: callers that dispatch
    LLM calls in a loop must stop dispatching when they see this, not
    convert it into a per-item error and keep going. Subclasses
    ``RuntimeError`` and keeps "budget exceeded" in the message so
    legacy string-match handlers keep working; new code should catch
    by type (or via :func:`is_budget_exceeded_error`).
    """


class LLMDegradedModeError(LLMBudgetExceededError):
    """Sustained aggregate LLM degradation — TERMINAL for the run.

    Raised at dispatch entry once the run-level degraded-mode breaker
    (:mod:`core.llm.breaker`) has latched: a sliding window of
    provider outcomes shows a sustained majority of transport-class
    failures (provider brown-out, systematic truncation/parse loop,
    wire flakiness), so further dispatch mostly buys failed attempts.

    Subclasses :class:`LLMBudgetExceededError` DELIBERATELY: budget
    exhaustion already carries the graceful run-terminal contract this
    stop needs — loop drivers stop dispatching, in-flight work drains,
    run state and spend evidence persist (e.g. the audit executor's
    budget-stop predicate) — and every consumer keys on the type via
    :func:`is_budget_exceeded_error`. The message names the dominant
    failure class and the retry/resume story, so a stop recorded under
    the budget label still reads as what it is: a provider incident,
    not a spend cap.
    """


class LLMGovernorExceededError(LLMBudgetExceededError):
    """Raised when a call would breach a NON-dollar resource cap
    (wall-clock deadline, total call count, or aggregate tokens).

    Subclasses :class:`LLMBudgetExceededError` deliberately: resource
    exhaustion is just as terminal as dollar exhaustion, and every
    existing catch site (``isinstance(LLMBudgetExceededError)`` /
    :func:`is_budget_exceeded_error`) must handle it identically — stop
    dispatching, drain, report. The distinct type only lets callers that
    care tell a time/call/token stop from a dollar stop. The message
    deliberately avoids the "budget exceeded" phrase so the legacy
    string-match path doesn't mislabel a resource stop as a cost stop;
    the isinstance check (tried first above) catches it regardless.
    """


def is_budget_exceeded_error(exc: BaseException) -> bool:
    """True when *exc* signals LLM budget exhaustion.

    This verdict is RUN-TERMINAL: the audit executor's budget-stop
    predicate re-raises budget-classified exceptions out of the review
    loop, so model-echoed content must not be able to impersonate it.
    Classification therefore prefers STRUCTURAL signals over message
    text, in causal-chain order — the same discipline as
    :func:`is_auth_refusal`:

    1. the typed :class:`LLMBudgetExceededError` anywhere on the
       chain is definitive;
    2. typed task-admission refusals stop only their logical call;
       their text or stale exception context cannot stop the run;
    3. response-shape failures (schema violations, JSON decode
       errors, pydantic validation) anywhere on the chain are NEVER
       budget — their messages quote MODEL-CHOSEN content (the strict
       schema floor embeds unknown field names verbatim), and the
       all-models-failed wrapper relays that text into a bare
       ``RuntimeError``: one injected key literally named "budget
       exceeded" would otherwise stop the entire remaining run with
       zero transport failure and zero real spend;
    4. only then does the historical message fallback run, for
       exceptions raised by older code paths or re-wrapped by
       intermediaries that lose both the type and the causal chain.
    """
    if not isinstance(exc, Exception):
        return False
    for e in _exception_chain(exc):
        if isinstance(e, LLMBudgetExceededError):
            return True
        if isinstance(e, LLMCallAdmissionRefused):
            # Task policy owns this refusal. Its text and stale exception
            # context cannot promote it into global budget exhaustion.
            return False
        if isinstance(e, (SchemaUnknownFieldError, json.JSONDecodeError)):
            return False
        if type(e).__name__ == "ValidationError":
            # pydantic/instructor shape failures, matched by name so
            # the classifier stays import-light.
            return False
    return (
        isinstance(exc, RuntimeError)
        and "budget exceeded" in str(exc).lower()
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
