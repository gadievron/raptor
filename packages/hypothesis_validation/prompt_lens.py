"""Prompt lens — formalise `<untrusted_tool_output>` as a put/get pair.

The hardening commit's tag-neutralisation logic is exactly the `put`
half of a lens on the LLM prompt context. Making it explicit means
future changes to the prompt format cannot accidentally bypass
neutralisation: `put` always runs `neutralise_tags` before splicing,
and the lens laws are CI-checkable properties.

Lens laws (verified by `tests/test_typed_layer.py`):

  get(put(s, a)) == neutralise_tags(a)   # put-then-get returns the
                                         # *neutralised* projection,
                                         # not the raw input — the
                                         # security of the lens is in
                                         # this fact

  put(s, get(s)) == s                    # round-tripping an unchanged
                                         # value is the identity

Strict lawfulness (`get . put = id`) is intentionally *not* satisfied:
that would require `put` to faithfully store attacker-controlled bytes,
which is the bug the lens exists to prevent. We document the relaxed
law instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Generic, List, TypeVar


# Single source of truth: the same regex used by `runner._neutralize_forged_tags`.
# Imported there to keep one definition; keep this in sync if either changes.
_FORGED_TAG_RE = re.compile(r"</?\s*untrusted_tool_output\b", re.IGNORECASE)


def neutralise_tags(text: str) -> str:
    """Replace the leading `<` of any literal envelope tag with `&lt;`.

    A match (file path, message) that contains `</untrusted_tool_output>`
    could trick the LLM into thinking the untrusted block has ended and
    the next tokens are trusted instructions. We break the leading `<`
    so the model sees a visibly-broken tag rather than a forged closing
    one. The transform is idempotent: applying it twice is the same as
    once.
    """
    return _FORGED_TAG_RE.sub(lambda m: "&lt;" + m.group(0)[1:], text)


def neutralise_matches(matches: List[dict]) -> List[dict]:
    """Apply `neutralise_tags` to every string field of every match."""
    out: List[dict] = []
    for m in matches:
        if not isinstance(m, dict):
            out.append(m)
            continue
        clean: dict = {}
        for k, v in m.items():
            clean[k] = neutralise_tags(v) if isinstance(v, str) else v
        out.append(clean)
    return out


S = TypeVar("S")
A = TypeVar("A")


@dataclass(frozen=True)
class Lens(Generic[S, A]):
    """A focus-and-update pair on an immutable structure S with focus type A.

    Use the `prompt_lens` instance below for the untrusted-output
    section of an LLM prompt context; the type is generic so other parts
    of the pipeline (e.g. system-prompt slot, tool-selection schema)
    can declare their own lenses with the same laws.
    """

    get: Callable[[S], A]
    put: Callable[[S, A], S]

    def modify(self, s: S, f: Callable[[A], A]) -> S:
        return self.put(s, f(self.get(s)))


@dataclass(frozen=True)
class PromptCtx:
    """The slot layout of an evaluation prompt.

    `tool_section` is the raw match list as the adapter produced it;
    rendering through `prompt_lens.put` neutralises it.
    """

    system_prompt: str = ""
    user_prompt: str = ""
    tool_section: tuple = ()  # tuple of dicts so the ctx can be frozen


def _put_tool_section(ctx: PromptCtx, matches: List[dict]) -> PromptCtx:
    safe = tuple(neutralise_matches(list(matches)))
    return PromptCtx(
        system_prompt=ctx.system_prompt,
        user_prompt=ctx.user_prompt,
        tool_section=safe,
    )


prompt_lens: Lens[PromptCtx, List[dict]] = Lens(
    get=lambda ctx: list(ctx.tool_section),
    put=_put_tool_section,
)


__all__ = [
    "Lens",
    "PromptCtx",
    "neutralise_tags",
    "neutralise_matches",
    "prompt_lens",
]
