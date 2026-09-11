"""Batch GLANCE review — send multiple low-complexity functions in one LLM call.

GLANCE reviews use a minimal prompt (~500 tokens per function).  Batching
N functions into a single API call eliminates (N-1) system-prompt
repetitions and (N-1) round trips.  For 600 GLANCE items at batch size
10, that's 540 fewer API calls and ~1M fewer input tokens.
"""

from __future__ import annotations

import json
import logging
import time
from collections import deque
from typing import Any, TYPE_CHECKING

from core.security.prompt_framing import with_audit_framing

from .orchestrator import OrchestratorConfig, ReviewOutcome

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# Audit-purpose framing: same gap class as the refused summary /
# spec_inference prompts (bare code + one-line security question);
# unexercised in the final audit run (0 glances) but the shape is
# identical. See core.security.prompt_framing.
_BATCH_SYSTEM_PROMPT = with_audit_framing(
    "You are a security auditor doing a quick triage pass over multiple "
    "functions. For each function, determine whether it is security-relevant "
    "and could contain a vulnerability.\n\n"
    "Respond with a JSON array, one object per function, in the same order "
    "as presented. Each object must have:\n"
    '  {"file": "<file>", "function": "<name>", "line_start": <number>, '
    '"status": "clean"|"suspicious", "body": "<one sentence>"}\n\n'
    "Copy file, function, and line_start EXACTLY from the function list "
    "entry (line_start is the first number of its line range) — they key "
    "your answer back to the right function.\n\n"
    'Use "suspicious" only when there is a concrete reason (e.g. unchecked '
    "input, missing bounds check, unsafe pattern). Default to \"clean\".",
)

# Per-function triage question, keyed by review mode. Lives in the
# trusted system text — the per-function data arrives as envelope
# blocks whose origin attribute carries file:function:lines.
_GLANCE_QUESTION_QUALITY = (
    "For each function: does it contain a potential defect — logic "
    "error, resource leak, error handling gap, or incorrect "
    "assumption? Answer in one sentence per function."
)
_GLANCE_QUESTION_SECURITY = (
    "For each function: is it security-relevant? Could it contain a "
    "vulnerability (memory safety, injection, auth bypass, "
    "information disclosure, logic flaw)? Answer in one sentence per "
    "function."
)


def format_batch_prompt(
    contexts: list[dict[str, Any]],
    *,
    model_id: str = "",
) -> tuple[str, str]:
    """Build a single enveloped prompt containing N GLANCE reviews.

    Each function's source travels in its own ``UntrustedBlock`` whose
    origin attribute carries ``file:function:lines``; the function
    index list rides in a slot; instructions stay in the system text.
    Returns ``(user, system)``.
    """
    from core.security.prompt_envelope import TaintedString, UntrustedBlock

    from ._util import envelope_prompt

    mode = contexts[0].get("review_mode", "security") if contexts else "security"
    question = (
        _GLANCE_QUESTION_QUALITY
        if mode in ("bug_first", "quality")
        else _GLANCE_QUESTION_SECURITY
    )
    system = (
        f"{_BATCH_SYSTEM_PROMPT}\n\n"
        f"Review {len(contexts)} functions: each arrives in its own "
        "untrusted source-code block whose origin attribute is "
        "file:function:line-range, in the order listed in the "
        "function_list slot.\n\n"
        f"{question}\n\n"
        f"Respond with a JSON array of exactly {len(contexts)} objects."
    )

    blocks = []
    listing = []
    for i, ctx in enumerate(contexts, 1):
        origin = (
            f"{ctx['file']}:{ctx['function']}"
            f":{ctx.get('line_start', '?')}-{ctx.get('line_end', '?')}"
        )
        blocks.append(UntrustedBlock(
            content=ctx.get("source", "(not available)"),
            kind="source-code",
            origin=origin,
        ))
        # line range in the listing: same-file same-name siblings
        # (static #if branches, overloads) are only distinguishable by
        # line_start, which the response schema echoes back.
        listing.append(
            f"{i}. {ctx['file']}:{ctx['function']}"
            f":{ctx.get('line_start', '?')}-{ctx.get('line_end', '?')}"
        )

    slots = {
        "function_list": TaintedString(
            value="; ".join(listing), trust="untrusted",
        ),
    }
    # Datamarked-plaintext rendering: the glance ask is verdict-shaped
    # ("classify these functions"), and its base64 form joins the
    # measured hard-refusal conjunction (opaque payload + security
    # ask) — see envelope_prompt's no_base64_payload notes for the
    # measurements. Datamarking stays: it still breaks up
    # instruction-shaped sequences inside the reviewed source.
    return envelope_prompt(
        system, blocks, slots, model_id=model_id, no_base64_payload=True,
    )


# Strict element schema for the batch response (mirrors
# _BATCH_SYSTEM_PROMPT's contract). Unknown fields are REJECTED — the
# element is dropped and the affected function falls back to individual
# review, exactly like any other malformed element. Same floor policy
# as core.llm.response_validation.unknown_response_fields.
# ``line_start`` is the disambiguating echo field: without it, results
# keyed file:function collapsed same-file same-name siblings and their
# verdicts swapped. It stays OPTIONAL at parse time (an element without
# it still matches when its file:function is unique in the batch).
_BATCH_ELEMENT_KEYS = frozenset({
    "file", "function", "line_start", "status", "body",
})
_BATCH_STATUSES = frozenset({"clean", "suspicious"})


def parse_batch_response(
    raw: str,
    contexts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Parse the LLM batch response into per-function result dicts.

    Falls back to empty results if the response is malformed —
    those functions will be individually re-reviewed. Elements that
    are not dicts, carry fields outside :data:`_BATCH_ELEMENT_KEYS`,
    or report a status outside :data:`_BATCH_STATUSES` are dropped
    individually (schema-invalid == malformed; the keyed lookup in
    ``batch_review_fn`` then error-routes the affected functions).
    """
    text = raw.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        lines = [ln for ln in lines if not ln.startswith("```")]
        text = "\n".join(lines)
    try:
        results = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("[")
        end = text.rfind("]")
        if start >= 0 and end > start:
            try:
                results = json.loads(text[start:end + 1])
            except json.JSONDecodeError:
                return []
        else:
            return []

    if not isinstance(results, list):
        return []

    accepted: list[dict[str, Any]] = []
    for item in results:
        if not isinstance(item, dict):
            logger.debug("batch glance: dropping non-object element")
            continue
        unknown = sorted(k for k in item if k not in _BATCH_ELEMENT_KEYS)
        if unknown:
            logger.debug(
                "batch glance: dropping element with unknown fields %s",
                unknown,
            )
            continue
        if item.get("status") not in _BATCH_STATUSES:
            logger.debug(
                "batch glance: dropping element with invalid status %r",
                item.get("status"),
            )
            continue
        accepted.append(item)
    return accepted


def _response_text(response: Any) -> str:
    """Extract the model output text from a generate() response.

    ``LLMResponse`` carries it in ``content``; duck-typed responses
    may use ``text``. Non-string attributes are skipped so mocks or
    exotic response objects degrade to ``str(response)`` instead of
    propagating non-text into the parser.
    """
    for attr in ("content", "text"):
        value = getattr(response, attr, None)
        if isinstance(value, str) and value:
            return value
    return str(response)


def _is_refusal_error(exc: BaseException) -> bool:
    """MODEL refusal (never a transport/content block): a refusal must
    not bucket retryable — an identical retry cannot change it — and a
    transport block must not trigger paid bisection. Vocabulary and
    chain walk live in the one shared home."""
    from core.llm.structured_call import is_refusal_error

    return is_refusal_error(exc)


def _classify_batch_error(exc: Exception) -> str:
    # Refusal first: the aggregate wrapper message also contains
    # "failed"/transport-looking text, and a refusal must never be
    # bucketed retryable — an identical retry cannot change it.
    if _is_refusal_error(exc):
        return "refusal"
    msg = str(exc).lower()
    if "rate limit" in msg or "timeout" in msg or "overloaded" in msg:
        return "api_error"
    if isinstance(exc, (TimeoutError, ConnectionError, OSError)):
        return "api_error"
    if "budget exceeded" in msg:
        return "budget"
    if isinstance(exc, json.JSONDecodeError):
        return "json_parse"
    return "api_error"


# Refusal-bisection retry budget, as a multiple of the original batch
# size. Full binary bisection of an all-refused batch of N members
# issues at most 2N-2 retry calls (a binary tree with N leaves has
# 2N-1 nodes; the root call is not a retry), so a factor of 2 never
# truncates a legitimate bisection — it is a backstop that bounds
# spend if the split invariant ever regressed. Lower would abandon
# still-recoverable functions mid-split on large refused batches;
# higher buys nothing (the worst case already fits) and would only
# extend runaway spend under a splitting-logic bug.
_BISECTION_CALL_CAP_FACTOR = 2


def make_batch_review_fn(
    llm_client: Any,
    *,
    model_name: str | None = None,
    task_type: str = "audit",
) -> Callable[[list[dict[str, Any]], OrchestratorConfig], list[ReviewOutcome]]:
    """Build a batch review function for GLANCE-bucket items.

    Returns a callable that accepts a list of contexts and returns
    a list of ReviewOutcomes — one per context, in order.
    Functions that can't be parsed from the batch response get
    status='error' so the caller can fall back to individual review.

    A refusal-classified dispatch failure bisects the batch and
    retries each half (down to singletons, bounded by
    :data:`_BISECTION_CALL_CAP_FACTOR`) so one refusal-bait member
    does not error-route its N-1 unrelated batch mates; refused
    singletons and every non-refusal failure error-route as before.
    """
    model_config_override = None
    if model_name:
        try:
            model_config_override = llm_client.config.config_for_model(model_name)
        except (ValueError, AttributeError):
            logger.warning("model override %r not resolved — using default", model_name)

    def _call_sub_batch(
        contexts: list[dict[str, Any]],
    ) -> list[ReviewOutcome]:
        """One batch LLM call over *contexts*: prompt, dispatch, parse,
        keyed match. Raises whatever ``generate`` raises — the caller
        decides between error-routing and refusal bisection.
        """
        prompt, system_prompt = format_batch_prompt(
            contexts,
            model_id=model_name or getattr(llm_client, "model_name", "") or "",
        )
        t0 = time.monotonic()

        kwargs: dict[str, Any] = {}
        if model_config_override is not None:
            kwargs["model_config"] = model_config_override
        else:
            kwargs["task_type"] = task_type

        # Short call class: N minimal glance prompts in one call.
        # Per-call ceiling honoured by the claudecode transport (SDK
        # providers ignore it); timeout retries keep the client
        # default of one identical retry — cheap for this class, and
        # the per-item fallback to individual review covers repeated
        # failure.
        from .llm_review import SHORT_CALL_TIMEOUT_S
        kwargs["timeout_s"] = SHORT_CALL_TIMEOUT_S
        # Telemetry label: distinguish batched glances from full
        # reviews. Refusal-bisected sub-batches keep the same label —
        # they are the same call class, just smaller.
        kwargs["call_class"] = "glance_batch"

        response = llm_client.generate(
            prompt,
            system_prompt=system_prompt,
            **kwargs,
        )

        # LLMResponse carries the model output in ``content`` (there
        # is no ``text`` attribute) — falling through to
        # ``str(response)`` produced the dataclass repr, which the
        # JSON-array parse rejected and every batch silently fell
        # back to individual reviews. ``text`` is kept as a fallback
        # for duck-typed responses.
        raw_text = _response_text(response)
        duration = time.monotonic() - t0
        model = getattr(response, "model", "")
        cost = getattr(response, "cost", 0.0)
        per_cost = cost / len(contexts) if contexts else 0.0

        results = parse_batch_response(raw_text, contexts)

        # Keyed lookup by file:function:line_start (line_start is the
        # echo field the schema requires the model to copy). A bare
        # file:function key collapsed same-file same-name siblings —
        # one result served BOTH contexts and verdicts swapped.
        # Fallback: an element without a usable line_start still
        # matches by file:function, but ONLY when that pair is unique
        # among the batch's contexts (ambiguous pairs error-route to
        # individual review rather than guess). Positional matching
        # stays intentionally omitted — if the LLM reorders items,
        # index-based matching misattributes verdicts.
        def _echo_line(value: Any) -> int:
            try:
                return int(value)
            except (TypeError, ValueError):
                return -1

        ctx_pair_counts: dict[str, int] = {}
        for ctx in contexts:
            pair = f"{ctx['file']}:{ctx['function']}"
            ctx_pair_counts[pair] = ctx_pair_counts.get(pair, 0) + 1

        results_by_key: dict[str, dict[str, Any]] = {}
        results_by_pair: dict[str, dict[str, Any]] = {}
        for r in results:
            if isinstance(r, dict) and r.get("file") and r.get("function"):
                pair = f"{r['file']}:{r['function']}"
                line = _echo_line(r.get("line_start"))
                if line >= 0:
                    results_by_key[f"{pair}:{line}"] = r
                results_by_pair[pair] = r

        outcomes: list[ReviewOutcome] = []
        for _i, ctx in enumerate(contexts):
            pair = f"{ctx['file']}:{ctx['function']}"
            ckey = f"{pair}:{ctx.get('line_start', 0)}"
            r = results_by_key.get(ckey)
            if r is None and ctx_pair_counts.get(pair, 0) == 1:
                r = results_by_pair.get(pair)
            if r is not None:
                status = r.get("status", "suspicious")
                if status not in ("clean", "suspicious"):
                    logger.warning(
                        "batch glance returned invalid status %r for "
                        "%s:%s — falling back to suspicious",
                        status, ctx["file"], ctx["function"],
                    )
                    status = "suspicious"
                outcomes.append(ReviewOutcome(
                    file=ctx["file"],
                    function=ctx["function"],
                    status=status,
                    body=r.get("body", ""),
                    cost_usd=per_cost,
                    model=model,
                    duration_s=duration / len(contexts),
                    evidence_tool="triage:batch",
                ))
            else:
                outcomes.append(ReviewOutcome(
                    file=ctx["file"],
                    function=ctx["function"],
                    status="error",
                    body="batch response missing or malformed for this function",
                ))

        logger.info(
            "batch glance: %d functions in %.1fs, $%.4f",
            len(contexts), duration, cost,
        )
        return outcomes

    def batch_review_fn(
        contexts: list[dict[str, Any]],
        _config: OrchestratorConfig,
    ) -> list[ReviewOutcome]:
        if not contexts:
            return []

        total = len(contexts)
        # Refusal bisection: ONLY refusal-shaped failures split the
        # batch — a refusal is content-dependent, so isolating the
        # bait member rescues the unrelated functions sharing its
        # call. Timeouts / transport errors keep whole-batch
        # error-routing exactly as before (they are not
        # content-dependent; splitting just multiplies cost).
        retry_cap = _BISECTION_CALL_CAP_FACTOR * total
        retries_used = 0
        first_call = True
        bisected = False
        slots: list[ReviewOutcome | None] = [None] * total
        pending: deque[tuple[int, ...]] = deque([tuple(range(total))])

        while pending:
            idxs = pending.popleft()
            if first_call:
                first_call = False
            elif retries_used >= retry_cap:
                for i in idxs:
                    slots[i] = ReviewOutcome(
                        file=contexts[i]["file"],
                        function=contexts[i]["function"],
                        status="error",
                        body=(
                            "batch review failed: refusal bisection "
                            "call cap reached — error-routed without "
                            "a further call"
                        ),
                        error_class="refusal",
                    )
                continue
            else:
                retries_used += 1

            sub = [contexts[i] for i in idxs]
            try:
                sub_outcomes = _call_sub_batch(sub)
            except Exception as exc:  # noqa: BLE001 — any dispatch failure error-routes (or bisects on refusal)
                if _is_refusal_error(exc) and len(idxs) > 1:
                    bisected = True
                    mid = len(idxs) // 2
                    lo, hi = idxs[:mid], idxs[mid:]
                    logger.info(
                        "glance batch refused — bisecting %dx%d "
                        "(sub-batches of %d and %d)",
                        len(idxs), 2, len(lo), len(hi),
                    )
                    pending.append(lo)
                    pending.append(hi)
                    continue
                logger.warning("batch glance review failed: %s", exc)
                ec = _classify_batch_error(exc)
                for i in idxs:
                    slots[i] = ReviewOutcome(
                        file=contexts[i]["file"],
                        function=contexts[i]["function"],
                        status="error",
                        body=f"batch review failed: {exc}",
                        error_class=ec,
                    )
                continue

            for i, oc in zip(idxs, sub_outcomes):
                slots[i] = oc

        if bisected:
            recovered = sum(
                1 for o in slots if o is not None and o.status != "error"
            )
            logger.info(
                "batch glance: recovered %d of %d functions from "
                "refused batch",
                recovered, total,
            )

        outcomes: list[ReviewOutcome] = []
        for i, slot in enumerate(slots):
            if slot is None:
                # Unreachable by construction (every popped sub-batch
                # either fills or re-queues each member) — error-route
                # rather than misalign the positional contract with
                # the executor.
                slot = ReviewOutcome(
                    file=contexts[i]["file"],
                    function=contexts[i]["function"],
                    status="error",
                    body="batch review failed: member never dispatched",
                    error_class="api_error",
                )
            outcomes.append(slot)
        return outcomes

    return batch_review_fn
