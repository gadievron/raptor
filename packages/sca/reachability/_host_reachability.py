"""Host-function reachability check used by every per-ecosystem
function-level reachability module.

When ``core.inventory.reachability.function_called`` says the
project demonstrably calls an OSV-affected dep function, that
verdict says nothing about whether the call site itself is
reachable from any externally-callable project entry. If every
call site is in a project function that has zero callers
(1-hop AND transitive), the vulnerable code path isn't
exercised at runtime under normal use — informally, the call
is "dead code".

This module exposes two helpers:

  * :func:`enclosing_function` — given an inventory + (file_path,
    line) pair, return the :class:`InternalFunction` whose
    ``[line_start, line_end]`` contains ``line``. Picks the
    innermost match for nested defs.

  * :func:`is_host_dead` — given an inventory + InternalFunction
    host, return True iff the host has no incoming call edges
    (1-hop ``callers_of`` AND transitive ``reverse_closure``
    both empty), with test-file callers excluded by default.

Both are language-agnostic — they consume the substrate's
:class:`InternalFunction` identity, not anything PyPI-specific
— so all eight ``*_function_level.py`` modules share them.

## Why both 1-hop AND closure?

Consider a small chain ``A → B → host``. The substrate's
``reverse_closure(host)`` returns ``{A, B}`` — non-empty, host
has transitive callers. ``callers_of(host).all_callers``
returns ``{B}`` — non-empty, host has direct callers. Either
check on its own would correctly say "host is alive".

But ``reverse_closure`` walks DEFINITIVE edges only. If B's
file uses ``getattr`` on host's name (uncertain edge), the
substrate doesn't add B to host's reverse closure. ``callers_of``
DOES surface B in its ``uncertain`` list. Without the 1-hop
check, an uncertain caller wouldn't keep host "alive".

We want the conservative answer: ANY signal of a caller
(definitive or uncertain) → host is alive. Both checks
together give that.

## What "dead host" actually means

It means: no project function we can see calls this host. The
host might still be:

  * An externally-callable entry point (CLI main, HTTP handler
    registered via decorator, pytest fixture, ``__main__``
    module, ``setup.py`` ``entry_points`` declaration).
  * Wired up via reflection / dynamic dispatch beyond our
    indirection-flag tracking.

These don't appear as callers in the substrate. So a "dead
host" verdict isn't "definitively unreachable" — it's "we have
no static evidence it's reachable". The caller (the
ReachabilityVerdict assignment in each ecosystem module)
should set ``confidence="medium"`` to reflect this, not
``"high"``.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from core.inventory.reachability import (
    InternalFunction,
    callers_of,
    enclosing_function,
    parse_evidence_entry,
    reverse_closure,
)

from ..models import Confidence, Reachability

logger = logging.getLogger(__name__)

# ``enclosing_function`` and ``parse_evidence_entry`` were
# originally defined here. They've moved to the substrate
# (core.inventory.reachability) so /validate, /agentic, and
# /understand can share one implementation. Re-exported above so
# any downstream consumer that imports them from here keeps
# working without churn.


# Function names that conventionally serve as runtime / framework
# entry points across languages we care about. They typically have
# no static callers in the project — the language runtime, test
# harness, or web framework invokes them. Treat any function with
# one of these names as ALIVE regardless of caller status, to avoid
# falsely flagging every call inside a CLI tool's main() as dead
# code.
#
# This is necessarily inexact: a project that defines an internal
# helper named ``main`` (uncommon but legal) gets the same
# exemption. Documented rather than fixed — the cost of false-
# positive "alive" is a single operator-visible "likely_called"
# verdict; the cost of false-positive "dead" is a downgraded
# severity for every dep call inside main(). The asymmetry favours
# exempting.
_ENTRY_POINT_NAMES = frozenset({
    "main",          # C / C++ / Rust / Go / Java
    "_main",         # Python convention for under-`if __name__` mains
    "__main__",      # Python module-callable main
    "Main",          # C# / Java (sometimes capitalised)
})


def _looks_internal(name: str) -> bool:
    """Heuristic: does this function name follow a "private /
    internal" naming convention?

    True for Python ``_helper`` / ``__internal``,
    JS / TS ``_unexposed``. These are the patterns where "no
    static callers" is reliable signal that the function is
    truly dead — public-API code might still be called from
    outside the static call graph (framework, library
    consumer).

    False for everything else. Without project-specific
    knowledge (visibility modifiers, declared exports), we
    can't tell whether a public-named function with no
    callers is dead code or a framework entry point. The
    safer policy is to NOT flag it as dead.

    Intentionally narrow: false positives in "not-internal"
    are tolerable (we miss some dead code), but false
    positives in "internal" let us downgrade severity for
    code that's actually live API surface — worse outcome.
    """
    if not name:
        return False
    return name.startswith("_")


def is_host_dead(
    inventory: Dict[str, Any],
    host: InternalFunction,
    *,
    exclude_test_files: bool = True,
) -> bool:
    """Return True iff ``host`` has no incoming call edges in
    the project's call graph (definitive or uncertain).

    Both ``callers_of`` (1-hop union of definitive + uncertain
    + over-inclusive method match) AND ``reverse_closure``
    (transitive, definitive-only) must come back empty. If
    either has any caller, the host is alive.

    Test-file callers are filtered when ``exclude_test_files``
    is True (the default). A test-only caller doesn't count
    toward production reachability.

    Conventional entry-point names (``main``, ``_main``,
    ``__main__``, ``Main``) are always treated as alive — the
    language runtime invokes them and we wouldn't see that as a
    static caller anyway. This avoids falsely flagging every
    dep call inside a CLI tool's ``main()`` as dead code.

    Hosts whose names DON'T follow a private-convention
    (Python ``_foo`` / ``__bar``, JS / TS ``_unexposed``) are
    also treated as alive even when they have no static
    callers. Public-API code is often invoked from outside the
    static graph (frameworks, library consumers) and we can't
    distinguish "dead" from "framework-invoked" without
    project-specific knowledge. Confining the dead-code
    verdict to internally-named hosts keeps false positives
    low; the trade-off is missing some dead code in projects
    that don't follow naming conventions.
    """
    if host.name in _ENTRY_POINT_NAMES:
        return False
    if not _looks_internal(host.name):
        return False
    one_hop = callers_of(
        inventory, host, exclude_test_files=exclude_test_files,
    )
    if one_hop.all_callers:
        return False
    transitive = reverse_closure(
        inventory, host, exclude_test_files=exclude_test_files,
    )
    return not transitive.nodes


def all_call_sites_in_dead_code(
    inventory: Dict[str, Any],
    evidence: List[str],
    *,
    exclude_test_files: bool = True,
) -> bool:
    """Convenience for the per-ecosystem function-level modules.

    ``evidence`` is the list of ``"path:line"`` strings emitted
    by ``function_called`` (or composed by the ecosystem module
    from a result's ``evidence`` tuple). Returns True iff EVERY
    parseable evidence entry resolves to an enclosing
    InternalFunction whose ``is_host_dead`` is True.

    Returns False if:
      * Any evidence entry is at module scope (no enclosing
        function) — module-level calls run unconditionally on
        import, so they're definitively NOT dead code.
      * Any host is alive (has callers).
      * Evidence list is empty (nothing to evaluate).

    Unparseable entries (malformed strings) are skipped — they
    can't be evaluated either way and shouldn't influence the
    verdict.
    """
    if not evidence:
        return False
    saw_evaluable = False
    for entry in evidence:
        path, line = parse_evidence_entry(entry)
        if path is None:
            continue
        host = enclosing_function(inventory, path, line)
        if host is None:
            # Module-level call: runs at import time, NOT dead.
            return False
        saw_evaluable = True
        if not is_host_dead(
            inventory, host, exclude_test_files=exclude_test_files,
        ):
            return False
    return saw_evaluable


def classify_called_or_dead(
    inventory: Dict[str, Any],
    evidence_lines: List[str],
    *,
    likely_called_reason: str,
    affected_summary: str,
) -> Reachability:
    """Decide between ``likely_called`` and ``called_in_dead_code``.

    Called by every per-ecosystem function-level module after
    ``function_called`` returns CALLED. The two outcomes:

      * ``likely_called`` (confidence high) — at least one call
        site lives in a project function that itself has callers,
        so the vulnerable code path sits on a live execution
        path. ``likely_called_reason`` is the ecosystem-specific
        reason string passed by the caller.
      * ``called_in_dead_code`` (confidence medium) — every call
        site is in a host with no callers (1-hop empty AND
        reverse closure empty). Confidence is medium because a
        no-caller host might still be an entry point we can't
        see (CLI main, HTTP handler registered via decorator,
        pytest fixture, packaging entry-point). The reason
        explains the gap so operators reading the verdict know
        why we backed off from "high".

    ``affected_summary`` is the human-readable name (or names)
    of the affected functions, surfaced in the dead-code reason
    so operators can grep for them.

    The decision uses :func:`all_call_sites_in_dead_code`, which
    requires EVERY parseable evidence entry to resolve to a
    dead host. Module-level evidence (no enclosing function) or
    any live host short-circuits to ``likely_called``.
    """
    if all_call_sites_in_dead_code(inventory, evidence_lines):
        # Reason text is bounded: ``Confidence`` truncates at 200
        # chars. Lead with the affected-symbol summary so the most
        # useful info survives truncation.
        return Reachability(
            verdict="called_in_dead_code",
            confidence=Confidence(
                "medium",
                reason=(
                    f"{affected_summary} called only from project "
                    "functions with no internal callers — likely "
                    "dead code, but host may be an unseen entry "
                    "point (CLI / framework / fixture); confidence "
                    "medium accordingly"
                ),
            ),
            evidence=evidence_lines[:5],
        )
    return Reachability(
        verdict="likely_called",
        confidence=Confidence("high", reason=likely_called_reason),
        evidence=evidence_lines[:5],
    )


__all__ = [
    "all_call_sites_in_dead_code",
    "classify_called_or_dead",
    "enclosing_function",
    "is_host_dead",
]
