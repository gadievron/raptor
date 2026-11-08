"""Model-name request policies without provider or SDK initialization."""

import re


_TEMPERATURE_DEPRECATED_FROM = (4, 7)
# The optional minor group is capped at 7 digits with a trailing
# digit-boundary so a dated snapshot suffix can never be read as a
# minor version: ``claude-opus-4-20250514`` is major-only (the 8-digit
# date is NOT the minor — an unbounded ``(\d+)`` parsed it as
# (4, 20250514) >= (4, 7) and silently dropped ``temperature`` for a
# 4.0 model that accepts it), while ``claude-sonnet-4-7-20260115``
# still parses as (4, 7).
_CLAUDE_VERSION_RE = re.compile(r"claude-[a-z]+-(\d+)(?:-(\d{1,7})(?!\d))?")


def supports_temperature(model_name: str) -> bool:
    """Whether ``model_name`` accepts the ``temperature`` request parameter.

    Anthropic deprecated ``temperature`` for the reasoning tier from 4.7:
    verified empirically that opus-4-7 / opus-4-8 reject it with a 400, while
    opus-4-6-and-older and all sonnet/haiku (<=4-6) still accept it. We gate on
    version >= 4.7 across tiers — every model that is actually >4.6 today is a
    deprecated opus, and omitting ``temperature`` is harmless (the model falls
    back to its default) whereas sending it to a deprecated model is a hard 400,
    so we err toward omitting for >=4.7 (over-omitting a future tier that still
    accepts it costs nothing). The regex matches the ``claude-<tier>-<major>``
    core (with an optional ``-<minor>``; absent = 0, so the 5-family's
    single-number versions gate as (5, 0) — verified live: they 400 on
    ``temperature`` too) anywhere in the identifier, so Bedrock region
    prefixes (``us.anthropic.claude-opus-4-7``), bare Bedrock ids
    (``anthropic.claude-sonnet-5``) and dated snapshots
    (``claude-opus-4-7-20260301``) are handled. Non-claude / unparseable names
    keep ``temperature``.
    """
    m = _CLAUDE_VERSION_RE.search(model_name or "")
    if not m:
        return True
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) is not None else 0
    return (major, minor) < _TEMPERATURE_DEPRECATED_FROM


# Same version boundary as the temperature deprecation: 4.7 is where
# the reasoning tier's request surface changed (verified empirically
# for temperature; the thinking-parameter removal shipped in the same
# generation per the provider's migration notes).
_THINKING_SHARES_OUTPUT_FROM = (4, 7)


def thinking_shares_output_budget(model_name: str) -> bool:
    """Whether ``model_name`` bills thinking inside ``max_tokens``
    with no way to cap it per request.

    The operative contract from the 4.7 reasoning tier onward: the
    fixed thinking-budget request parameter is rejected, and whenever
    the model DOES think (always on the 5 family; whenever thinking is
    enabled on 4.7/4.8), those tokens count against the response's
    ``max_tokens`` — so a caller cannot reserve text room by capping
    thinking. The only lever left is a larger shared ceiling: a
    ``max_tokens`` sized for the TEXT alone can be consumed entirely
    by reasoning, ending the turn at ``stop_reason=max_tokens`` with a
    thinking-only (or empty) content list — a full-price call with
    zero yield, deterministic on identical retry. Callers that cap
    structured output below the model's ceiling (the study lane)
    consult this to add thinking headroom on top of their text budget;
    where thinking is off the extra headroom is harmless (billing is
    per generated token — an unused ceiling costs nothing).

    Same identifier parsing as :func:`supports_temperature` (Bedrock
    prefixes, bare ids, dated snapshots; the 5-family's single-number
    versions gate as (5, 0)). Non-claude / unparseable names return
    False — an unknown model keeps the caller's plain text budget.
    """
    m = _CLAUDE_VERSION_RE.search(model_name or "")
    if not m:
        return False
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) is not None else 0
    return (major, minor) >= _THINKING_SHARES_OUTPUT_FROM
