"""Session-transport fallback for dispatcher-only model chains.

The Bedrock provider is dispatcher-only by design: workers never hold
AWS credentials, so ``create_provider`` hard-refuses without
``RAPTOR_LLM_SOCKET`` (the guard is correct and stays). Launcher runs
inherit a route from the parent; standalone CLIs self-serve one via
``core.llm.dispatcher.lifecycle.ensure_route_for_client``. But that
bootstrap is fire-and-forget — when it cannot come up (agent-dispatched
process without seedable credentials, socket-dir failure), the client
is left with a chain that refuses EVERY call: the default config on a
Bedrock-routed host resolves ``Primary: bedrock / Fallbacks: 0``, so
there is no claudecode entry to catch the fall-through, and each call
pays a provider-guard failure cascade. (A world-readable
``models.json`` with inline keys is NOT one of these cases: the
shared permission gate refuses at client construction —
``core.llm.detection._read_config_models`` — so no client reaches
this module and the security refusal is never converted into
continued LLM use.)

:func:`client_with_session_fallback` closes that gap the way the
/agentic --gap-audit path already works on claude-code-only installs
(``core.audit.gap_ranking`` builds a default client whose autodetect
lands on the claudecode session transport when nothing else is
configured): after the normal self-serve attempt, a chain that is
entirely dispatcher-only with still no route falls back to the
claudecode session transport — the same ``_build_claudecode_config``
the default resolution order ends on. No session transport either →
exactly ONE operator-facing notice and ``None``, so the caller can
degrade cleanly instead of paying one refusal cascade per call.

The provider guard itself is untouched: this module never routes a
dispatcher-only model without a socket — it swaps the transport.

Consent posture: a dispatcher-only primary exists only when the
operator explicitly configured Bedrock (``models.json`` /
``_config_bedrock_primary`` — ambient AWS credentials never produce
one), so the swap reroutes prompts away from that explicit choice to
the claude CLI's backend. The fallback-taken notice names the opt-out
so the operator learns of it exactly when it first fires:
``RAPTOR_NO_SESSION_FALLBACK=1`` disables the swap entirely and
restores the plain refusal behaviour.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from core.llm.client import LLMClient

logger = logging.getLogger(__name__)

#: Providers that cannot be called in-process without the dispatcher
#: route (``create_provider`` raises without ``RAPTOR_LLM_SOCKET``).
#: Currently Bedrock only — workers never hold AWS credentials.
_DISPATCHER_ONLY_PROVIDERS = frozenset({"bedrock"})

#: The one operator-facing line for the no-transport degrade. Named as
#: a constant so consumers and tests share the spelling.
NO_TRANSPORT_NOTICE = (
    "no LLM transport available — the launcher dispatcher socket is "
    "absent, the self-serve dispatcher did not come up, and no "
    "claudecode session transport (claude CLI) is installed"
)

FALLBACK_TAKEN_NOTICE = (
    "launcher dispatcher socket absent and the self-serve dispatcher "
    "did not come up — falling back to the claudecode session transport "
    "(prompts now go to the claude CLI's backend instead of the "
    "configured provider route; set RAPTOR_NO_SESSION_FALLBACK=1 to "
    "disable this fallback)"
)

#: Operator opt-out for the transport swap (``=1``; canonical boolean
#: spellings via ``core.config.env_flag``). Set → the configured chain
#: is kept even though every call will refuse — the pre-fallback
#: behaviour. The self-serve route attempt still runs either way.
OPT_OUT_ENV = "RAPTOR_NO_SESSION_FALLBACK"


def _chain_configs(client: Any) -> list[Any] | None:
    """The client's resolved model chain (primary + fallbacks), or
    ``None`` when the client cannot be inspected (test fakes, hostile
    shapes) — inspection failure must preserve the caller's client."""
    try:
        cfg = client.config
        chain = [getattr(cfg, "primary_model", None)]
        chain += list(getattr(cfg, "fallback_models", []) or [])
    except Exception:  # noqa: BLE001 — uninspectable client, not an error
        return None
    return [mc for mc in chain if mc is not None]


def client_with_session_fallback(
    client: "LLMClient",
    label: str,
    *,
    run_dir: "Path | None" = None,
    notice: "Callable[[str], None] | None" = None,
) -> "LLMClient | None":
    """Return a client whose transport can actually serve calls.

    1. Self-serve the dispatcher route first
       (:func:`~core.llm.dispatcher.lifecycle.ensure_route_for_client`,
       unchanged semantics — no-op when a route exists or none is
       needed).
    2. Chain has a route, or any model that works without one →
       *client* unchanged.
    3. Chain is entirely dispatcher-only and still routeless → fall
       back to the claudecode session transport (the gap-audit
       mechanism), announced via one *notice* line that names the
       opt-out. ``RAPTOR_NO_SESSION_FALLBACK=1`` disables this step
       (and step 4's degrade) entirely: the configured chain is
       returned as-is, refusals and all.
    4. No session transport either → one *notice* line naming the gap,
       return ``None`` — the caller degrades without paying a
       provider-refusal cascade per call.

    ``notice`` receives at most ONE message per call (cases 3/4);
    default is a warning on this module's logger, prefixed with
    *label*. Never raises: unexpected errors preserve the original
    client, matching the bootstrap's fire-and-forget contract.
    """
    def _say(msg: str) -> None:
        # Shielded: a raising notice sink must not discard the decided
        # outcome (a constructed session client would leak away as the
        # dead client via the outer never-raise net, and the None
        # degrade would silently vanish).
        try:
            if notice is not None:
                notice(msg)
            else:
                logger.warning("%s: %s", label, msg)
        except Exception:  # noqa: BLE001 — notice sink is best-effort
            logger.debug("%s: notice sink errored", label, exc_info=True)

    try:
        from core.llm.dispatcher.lifecycle import ensure_route_for_client
        ensure_route_for_client(client, label, run_dir=run_dir)
    except Exception:  # noqa: BLE001 — bring-up is fire-and-forget
        logger.debug("%s: dispatcher self-serve errored", label,
                     exc_info=True)

    try:
        configs = _chain_configs(client)
        if not configs:
            return client  # uninspectable/empty chain: preserve behaviour
        dispatcher_only = [
            mc for mc in configs
            if getattr(mc, "provider", "") in _DISPATCHER_ONLY_PROVIDERS
        ]
        if not dispatcher_only:
            return client  # nothing needs the dispatcher route
        if os.environ.get("RAPTOR_LLM_SOCKET"):
            return client  # route exists (launcher- or self-served)
        if len(dispatcher_only) < len(configs):
            # A non-dispatcher model remains in the chain to catch the
            # per-call fall-through; swapping the whole client would
            # discard the operator's configured fallbacks.
            return client
        from core.config import env_flag
        if env_flag(OPT_OUT_ENV, False):
            # Operator opt-out: keep the explicitly configured chain
            # and its refusal behaviour — no swap, no session client,
            # no notice (the refusals themselves are the signal the
            # operator chose to keep).
            logger.debug("%s: %s set — session-transport fallback "
                         "disabled", label, OPT_OUT_ENV)
            return client

        # Entirely dispatcher-only, still no route: every call is a
        # guaranteed provider refusal. Mirror the gap-audit path — the
        # claudecode session transport (claude CLI on PATH, no API key).
        from core.llm.config import LLMConfig, _build_claudecode_config
        cc = _build_claudecode_config()
        if cc is None:
            _say(NO_TRANSPORT_NOTICE)
            return None
        from core.llm.factory import get_client
        # fallback_models pinned empty: the default factory could
        # re-add dispatcher-only entries, reintroducing per-call
        # refusal noise behind the session transport.
        fallback = get_client(LLMConfig(primary_model=cc,
                                        fallback_models=[]))
        if fallback is None:
            _say(NO_TRANSPORT_NOTICE)
            return None
        _say(FALLBACK_TAKEN_NOTICE)
        return fallback
    except Exception:  # noqa: BLE001 — never raise; call-time errors surface
        logger.debug("%s: session-transport fallback errored", label,
                     exc_info=True)
        return client


__all__ = [
    "FALLBACK_TAKEN_NOTICE",
    "NO_TRANSPORT_NOTICE",
    "OPT_OUT_ENV",
    "client_with_session_fallback",
]
