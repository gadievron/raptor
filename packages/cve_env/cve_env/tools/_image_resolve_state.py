"""Per-CVE state for ``cve_env.tools.image_resolve``.

Separates the state surface (rate-limit / arch-incompat counters +
cooldowns) from the resolution logic:

* All module-level globals live here.
* All read sites in ``image_resolve.py`` access them via ``_state.<name>``.
* All mutation sites in ``image_resolve.py`` use the helpers exported
  from this module (``bump_*``, ``take_*``, ``record_rate_limit_for_product``).
* ``image_resolve.py`` contains zero ``global _RATE_LIMIT_*`` /
  ``global _TRANSPORT_*`` / ``global _ARCH_*`` statements (locked by
  ``tests/unit/test_refactor_specific.py::test_image_resolve_uses_state_via_helpers``).

One-way dep: ``image_resolve -> _state``, never the reverse (locked by
``test_image_resolve_state_module_self_contained``).

Loop-side reset: ``cve_env.agent.loop`` imports ``reset_rate_limit_budget``
from ``image_resolve`` (back-compat re-export).

Contract: every name in ``_RESET_GLOBALS`` must have a default declared at
module scope AND be cleared by ``reset_rate_limit_budget``.
"""

from __future__ import annotations

import os


def _safe_int(name: str, default: int) -> int:
    """Parse an int from env ``name``; fall back to ``default`` on absence or
    malformed value (never raises at module scope)."""
    try:
        return int(os.environ.get(name) or default)
    except (ValueError, TypeError):
        return default


# Per-product rate-limit budget. After 2 rate-limited resolves for the same
# product (case-insensitive), the third call returns rate_limited_persistent
# immediately.
_RATE_LIMIT_BUDGET: dict[str, int] = {}
_RATE_LIMIT_THRESHOLD: int = 2

# CVE-level cumulative rate-limit counter. Threshold of 3: agent gets 2 free
# attempts at different products/strategies; the 3rd image_resolve that hits
# rate_limit returns rate_limited_persistent.
_RATE_LIMIT_TOTAL: int = 0
_RATE_LIMIT_TOTAL_THRESHOLD: int = 3

# One-shot cooldown + retry per CVE when ALL candidates in the initial loop
# returned rate_limited.
_RATE_LIMIT_COOLDOWN_DONE: bool = False
_RATE_LIMIT_COOLDOWN_S: int = _safe_int("CVE_ENV_RATE_LIMIT_COOLDOWN_S", 30)

# One-shot cooldown + retry per CVE when ALL candidates returned
# transport-class (5xx / timeout / connection-reset).
_TRANSPORT_COOLDOWN_DONE: bool = False
_TRANSPORT_COOLDOWN_S: int = _safe_int("CVE_ENV_TRANSPORT_COOLDOWN_S", 30)

# CVE-level cumulative arch_incompatible counter. After 2 different products
# fail arch_incompatible, the 3rd image_resolve call returns
# arch_incompatible_persistent immediately.
_ARCH_INCOMPATIBLE_TOTAL: int = 0
_ARCH_INCOMPATIBLE_THRESHOLD: int = 2


# Explicit registry of every per-CVE module-level global so adding a new one
# without wiring it into ``reset_rate_limit_budget`` is the bug shape. Locked
# by ``test_phase67_image_resolve_globals_isolated_per_cve``.
_RESET_GLOBALS: tuple[str, ...] = (
    "_RATE_LIMIT_BUDGET",
    "_RATE_LIMIT_TOTAL",
    "_RATE_LIMIT_COOLDOWN_DONE",
    "_TRANSPORT_COOLDOWN_DONE",
    "_ARCH_INCOMPATIBLE_TOTAL",
)


def reset_rate_limit_budget() -> None:
    """Clear per-product + cumulative rate-limit counters + cooldown flags
    and the arch_incompatible cumulative counter. Bench loop calls this
    between CVEs.

    See ``_RESET_GLOBALS`` above for the canonical registry of state cleared
    here.
    """
    global _RATE_LIMIT_TOTAL  # noqa: PLW0603 -- module-level CVE-level state
    global _RATE_LIMIT_COOLDOWN_DONE  # noqa: PLW0603 -- module-level CVE-level state
    global _ARCH_INCOMPATIBLE_TOTAL  # noqa: PLW0603 -- module-level CVE-level state
    global _TRANSPORT_COOLDOWN_DONE  # noqa: PLW0603 -- module-level CVE-level state
    _RATE_LIMIT_BUDGET.clear()
    _RATE_LIMIT_TOTAL = 0
    _RATE_LIMIT_COOLDOWN_DONE = False
    _ARCH_INCOMPATIBLE_TOTAL = 0
    _TRANSPORT_COOLDOWN_DONE = False


def _bump_arch_incompatible_total() -> None:
    """Increment the CVE-level cumulative arch_incompatible counter.
    Called when image_resolve returns arch_incompatible.
    """
    global _ARCH_INCOMPATIBLE_TOTAL  # noqa: PLW0603 -- module-level CVE-level state
    _ARCH_INCOMPATIBLE_TOTAL += 1


def _bump_rate_limit_total() -> None:
    """Increment the CVE-level cumulative rate-limit counter.
    Called after each rate_limited probe inside image_resolve.
    """
    global _RATE_LIMIT_TOTAL  # noqa: PLW0603 -- module-level CVE-level state
    _RATE_LIMIT_TOTAL += 1


def _take_rate_limit_cooldown() -> bool:
    """Returns True the FIRST time it's called this CVE (and sets the flag),
    False thereafter. Caller is expected to sleep ``_RATE_LIMIT_COOLDOWN_S``
    seconds and retry the candidate loop once.
    """
    global _RATE_LIMIT_COOLDOWN_DONE  # noqa: PLW0603 -- module-level CVE-level state
    if _RATE_LIMIT_COOLDOWN_DONE:
        return False
    _RATE_LIMIT_COOLDOWN_DONE = True
    return True


def _take_transport_cooldown() -> bool:
    """Returns True the FIRST time it's called this CVE (and sets the flag),
    False thereafter. Caller sleeps ``_TRANSPORT_COOLDOWN_S`` seconds and
    retries the candidate loop once. Distinct from the rate_limit cooldown so
    a CVE may use both budgets if it hits both classes during one
    image_resolve call.
    """
    global _TRANSPORT_COOLDOWN_DONE  # noqa: PLW0603 -- module-level CVE-level state
    if _TRANSPORT_COOLDOWN_DONE:
        return False
    _TRANSPORT_COOLDOWN_DONE = True
    return True


def record_rate_limit_for_product(product_key: str) -> None:
    """Bump the per-product rate-limit budget for ``product_key``
    (case-normalised by caller) and the cumulative total.
    """
    _RATE_LIMIT_BUDGET[product_key] = _RATE_LIMIT_BUDGET.get(product_key, 0) + 1
    _bump_rate_limit_total()
