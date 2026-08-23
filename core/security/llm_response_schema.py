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

import copy
import types
import typing
from typing import Annotated, Callable, Optional, TypeVar, Union

from pydantic import BaseModel, ConfigDict, ValidationError


T = TypeVar("T", bound=BaseModel)


# Clone cache — replaces the previous lru_cache so the recursive
# builder can share one identity map (a nested model reached from two
# parents must clone once, and self-referential models need the
# under-construction clone visible to their own field rewrite).
_STRICT_CLONE_CACHE: dict[type[BaseModel], type[BaseModel]] = {}


def _rewrite_annotation(tp: object, in_progress: dict) -> object:
    """Rewrite a field annotation so every nested BaseModel becomes its
    strict clone — through Optional/Union (both spellings), containers
    (list/dict/tuple/set/...), and Annotated metadata."""
    if isinstance(tp, type) and issubclass(tp, BaseModel):
        return _build_strict_clone(tp, in_progress)
    origin = typing.get_origin(tp)
    if origin is None:
        return tp
    args = typing.get_args(tp)
    if not args:
        return tp
    new_args = tuple(_rewrite_annotation(a, in_progress) for a in args)
    if all(n is o for n, o in zip(new_args, args)):
        return tp
    if origin is Annotated or origin is typing.Annotated:
        return Annotated[tuple([new_args[0], *args[1:]])]
    if origin is types.UnionType:  # PEP 604 `X | Y` — not subscriptable
        return Union[new_args]
    try:
        return origin[new_args]
    except TypeError:
        # Unsubscriptable exotic origin — leave the annotation alone
        # rather than break validation of the whole schema; the
        # top-level forbid still applies.
        return tp


def _build_strict_clone(schema: type[BaseModel],
                        in_progress: dict) -> type[BaseModel]:
    cached = _STRICT_CLONE_CACHE.get(schema)
    if cached is not None:
        return cached
    pending = in_progress.get(schema)
    if pending is not None:
        return pending  # self-referential model: use the clone in flight
    base_extra = (schema.model_config.get("extra")
                  if hasattr(schema, "model_config") else None)
    # NOTE: even an already-forbid model may have LENIENT nested
    # models, so "extra == forbid" alone is not a shortcut anymore —
    # its fields still need the rewrite. Only shortcut when nothing
    # changes (handled below by the `changed` check).
    name = f"{schema.__name__}__StrictClone"
    clone = type(
        name,
        (schema,),
        {"model_config": ConfigDict(
            **{**schema.model_config, "extra": "forbid"})},
    )
    in_progress[schema] = clone
    try:
        changed = False
        for fname, finfo in list(clone.model_fields.items()):
            new_ann = _rewrite_annotation(finfo.annotation, in_progress)
            if new_ann is not finfo.annotation:
                new_info = copy.copy(finfo)
                new_info.annotation = new_ann
                clone.model_fields[fname] = new_info
                changed = True
        if changed:
            clone.model_rebuild(force=True)
        elif base_extra == "forbid":
            # Nothing to rewrite and the original already forbids —
            # keep the caller's class identity (isinstance stability).
            clone = schema
    finally:
        in_progress.pop(schema, None)
    _STRICT_CLONE_CACHE[schema] = clone
    return clone


def _strict_clone(schema: type[BaseModel]) -> type[BaseModel]:
    """Return a subclass of `schema` with `extra="forbid"` enforced —
    RECURSIVELY, through every nested BaseModel annotation.

    The module docstring claims "anything outside the schema is
    rejected" but Pydantic v2's default `extra="ignore"` silently drops
    unknown keys — a hijacked LLM emitting
    `{"verdict": "safe", "exfil": "<…>"}` would validate cleanly and
    the rogue field would simply disappear (data loss; potential
    side-channel into downstream renderers that re-inflate the raw
    response). Subclassing only the top level restored the promise at
    depth 0 while `{"verdict": "safe", "inner": {"note": "n",
    "exfil": "…"}}` still validated cleanly — nested models kept their
    lenient config. Every nested model annotation is therefore
    rewritten to its own strict clone (through Optional/Union,
    containers, and Annotated), with cycle-safe handling for
    self-referential models.

    Cloning each provided schema:
      * preserves the caller's existing schema as-is — they don't have
        to remember to add `model_config = ConfigDict(extra="forbid")`
        to every model;
      * is cached per-class (Pydantic schema construction isn't free),
        so the per-call cost amortises to zero.
    Schemas already strict all the way down pass through unchanged.
    """
    return _build_strict_clone(schema, {})


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
