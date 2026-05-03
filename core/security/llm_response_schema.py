"""Pydantic-schema validation of LLM-returned text with single re-prompt.

Used by every consumer that expects structured output from an LLM. Failure
mode is **None**, never an exception — the caller decides whether to fall
back to a "treat conservatively" verdict, retry the whole pipeline, or
surface a "review failed" status. Bounded cost: at most one extra LLM call.

Pairs with prompt_envelope at the input side: where the envelope quarantines
the prompt, this module rejects model outputs that don't match the agreed
schema. Together they form the input/output sides of the anti-injection
floor — even a hijacked model that produces well-formed JSON cannot smuggle
free-form instructions through, because anything outside the schema is
rejected.

A model that consistently fails schema validation on a particular task is a
signal worth telemetering — see project_anti_prompt_injection memory entry
on the per-model defence-profile registry. (Telemetry collection is a
separate module; this one only reports up via return value.)
"""

from __future__ import annotations

from typing import Callable, Optional, TypeVar

from pydantic import BaseModel, ValidationError


T = TypeVar("T", bound=BaseModel)


def validate_response(
    raw: str,
    schema: type[T],
    *,
    llm_call: Optional[Callable[[], str]] = None,
) -> Optional[T]:
    """Parse `raw` against `schema`; on failure, optionally re-prompt once.

    `llm_call` is a thunk returning a freshly-generated raw string from
    the same provider — typically a closure that re-issues the request
    with a stricter "you must return valid JSON matching schema X"
    instruction. The thunk is invoked at most once. If the second
    response also fails, returns None.

    Never raises. Pydantic's `ValidationError` is converted to None;
    any other exception from `llm_call` is also swallowed (treated as a
    validation failure) so the caller's fallback path is uniform.
    """
    try:
        return schema.model_validate_json(raw)
    except ValidationError:
        pass

    if llm_call is None:
        return None

    try:
        retry = llm_call()
    except Exception:
        return None

    try:
        return schema.model_validate_json(retry)
    except ValidationError:
        return None
