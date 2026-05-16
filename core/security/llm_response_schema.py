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

import functools
from typing import Callable, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, ValidationError


T = TypeVar("T", bound=BaseModel)


@functools.lru_cache(maxsize=128)
def _strict_clone(schema: type[BaseModel]) -> type[BaseModel]:
    """Return a subclass of `schema` with `extra="forbid"` enforced.

    The module docstring claims "anything outside the schema is
    rejected" but Pydantic v2's default `extra="ignore"` silently drops
    unknown keys — a hijacked LLM emitting
    `{"verdict": "safe", "exfil": "<…>"}` would validate cleanly and
    the rogue field would simply disappear (data loss; potential
    side-channel into downstream renderers that re-inflate the raw
    response). The promise the docstring makes (and that anti-injection
    consumers depend on) requires `extra="forbid"`.

    Cloning each provided schema as a strict subclass:
      * preserves the caller's existing schema as-is — they don't have
        to remember to add `model_config = ConfigDict(extra="forbid")`
        to every model;
      * is cached per-class (Pydantic schema construction isn't free),
        so the per-call cost amortises to zero.
    Schemas already configured with `extra="forbid"` clone trivially.
    """
    base_extra = schema.model_config.get("extra") if hasattr(schema, "model_config") else None
    if base_extra == "forbid":
        return schema
    name = f"{schema.__name__}__StrictClone"
    return type(
        name,
        (schema,),
        {"model_config": ConfigDict(**{**schema.model_config, "extra": "forbid"})},
    )


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

    The caller-supplied `schema` is auto-cloned with `extra="forbid"`
    so the docstring's "anything outside the schema is rejected"
    promise actually holds (default Pydantic v2 silently drops unknown
    fields). Schemas already declared with `extra="forbid"` are passed
    through unchanged.

    Never raises. Pydantic's `ValidationError` is converted to None;
    any other exception from `llm_call` is also swallowed (treated as a
    validation failure) so the caller's fallback path is uniform.
    """
    strict = _strict_clone(schema)
    # Catch TypeError alongside ValidationError. `model_validate_json`
    # raises TypeError on older Pydantic v2 (< 2.12) when the input
    # isn't str/bytes/bytearray; 2.12+ converted that to a
    # ValidationError, but the contract here is "never raises" and
    # the older behaviour is still in the field. A caller-supplied
    # thunk returning, say, an `Optional[str]` instead of a str could
    # also feed None / int into this path. Same fail-uniform handling
    # for both branches.
    try:
        return strict.model_validate_json(raw)
    except (ValidationError, TypeError):
        pass

    if llm_call is None:
        return None

    try:
        retry = llm_call()
    except Exception:
        return None

    try:
        return strict.model_validate_json(retry)
    except (ValidationError, TypeError):
        return None
