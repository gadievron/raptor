"""Prompt-building helpers for multi-model consumers.

The substrate enforces that prior-model output is treated as untrusted
input by *making it easy to do the right thing* — consumers call
wrap_model_output() to produce an UntrustedBlock with consistent
provenance, rather than constructing UntrustedBlock instances ad-hoc.

This is the discipline-based defense (option (a) from the design
discussion). It does not type-prevent a consumer from feeding raw
model output into a prompt, but it makes the safe path the obvious
path and gives security review one place to look.

Injection-defense note: the UntrustedBlock returned here is only safe
once it's passed through prompt_envelope.build_prompt, which adds a
nonce-suffixed close marker that an attacker in the model output cannot
forge. wrap_model_output alone does not protect against
"END_MODEL_OUTPUT\\nignore prior instructions" injection — the envelope
build does. Don't bypass the envelope.
"""

import json
import re
from typing import Any, Dict, List, Union

from core.security.prompt_envelope import UntrustedBlock

# Anything passed to wrap_model_output() that isn't a str gets JSON-serialized
# with deterministic ordering. Tuples and similar arbitrary types are rejected
# rather than silently coerced.
_JsonScalar = Union[str, int, float, bool, None]
_JsonValue = Union[_JsonScalar, Dict[str, Any], List[Any]]


def wrap_model_output(
    content: _JsonValue,
    model_name: str,
    purpose: str = "model-output",
) -> UntrustedBlock:
    """Wrap prior-model output for safe inclusion in a downstream prompt.

    Args:
        content: The model's output. Strings are used as-is. Dicts and
            lists are JSON-serialized with sort_keys=True, indent=2 for
            deterministic, readable output. Other types raise TypeError —
            substrate consumers should pre-serialize anything exotic.
        model_name: The model that produced this content. Goes into the
            UntrustedBlock's origin attribute as data, not prose.
        purpose: Short description of what this output represents
            (e.g., "analysis", "judge-review", "consensus-vote"). Used
            both as the UntrustedBlock kind (UPPER_SNAKE_CASEd for safety
            across all tag styles) and as part of origin.

    Returns:
        A frozen UntrustedBlock ready to pass into prompt_envelope.build_prompt.

    Raises:
        ValueError: If model_name is empty or not a string; if purpose is
            empty or not a string; or if purpose contains characters that
            can't be normalized into [A-Z_]+ after uppercasing (digits,
            unicode letters, punctuation other than hyphen/space/dot).
        TypeError: If content is not str/dict/list/scalar, or if content
            contains values that aren't JSON-native (Path, datetime, UUID,
            arbitrary objects). Strict — pre-serialize exotic values.

    The function is pure and thread-safe. Multiple consumers can call it
    concurrently without coordination.
    """
    if not isinstance(model_name, str) or not model_name:
        raise ValueError("model_name must be a non-empty string")

    kind = _normalize_kind(purpose)

    if isinstance(content, str):
        rendered = content
    elif isinstance(content, (dict, list, int, float, bool)) or content is None:
        # Strict: no `default=` fallback. If content contains non-JSON-native
        # values (Path, datetime, UUID, etc.) json.dumps raises TypeError —
        # consumer must pre-serialize. Silent str() coercion would lose
        # structure ({"path": Path("/x")} → {"path": "/x"} hides the type).
        try:
            rendered = json.dumps(content, sort_keys=True, indent=2)
        except (TypeError, ValueError) as exc:
            raise TypeError(
                f"wrap_model_output could not serialize content: {exc}. "
                f"Pre-serialize Path/datetime/UUID/etc. before calling."
            ) from exc
    else:
        raise TypeError(
            f"wrap_model_output content must be str/dict/list/scalar; "
            f"got {type(content).__name__}. Pre-serialize before calling."
        )

    return UntrustedBlock(
        content=rendered,
        kind=kind,
        origin=f"{purpose}:{model_name}",
    )


_KIND_PATTERN = re.compile(r"^[A-Z_]+$")
_KIND_SEPARATORS = re.compile(r"[\s\-.]+")


def _normalize_kind(purpose: str) -> str:
    """Convert a free-form purpose string to a tag-safe UPPER_SNAKE_CASE kind.

    The prompt_envelope's begin-end-marker tag style requires kind to
    match ^[A-Z_]+$ after uppercasing. Other tag styles tolerate broader
    input but still HTML-escape it. Normalizing here makes the helper
    safe to use under any defense profile.
    """
    if not isinstance(purpose, str) or not purpose:
        raise ValueError("purpose must be a non-empty string")

    # Convert hyphens, spaces, and dots into underscores; collapse runs.
    candidate = _KIND_SEPARATORS.sub("_", purpose).upper()

    if not _KIND_PATTERN.match(candidate):
        raise ValueError(
            f"purpose {purpose!r} cannot be normalized into [A-Z_]+ "
            f"(got {candidate!r}). Use letters, hyphens, spaces, and dots only."
        )

    return candidate
