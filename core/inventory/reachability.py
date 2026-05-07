"""Function-level reachability resolver.

Answers "is qualified-function ``X.Y.Z`` actually called from this
project?" using the call-graph data captured by
:mod:`core.inventory.call_graph` and stored in the inventory
artefact.

The resolver is language-agnostic. The first-cut data producer
(``call_graph.extract_call_graph_python``) is Python-only, so
non-Python files contribute neither evidence-for nor evidence-
against — they're skipped as "no data". Other-language consumers
get added when a producer for that language ships.

## Verdict semantics

  * ``CALLED`` — at least one call site in non-test project code
    demonstrably resolves to the queried qualified name via its
    file's import map.
  * ``NOT_CALLED`` — no call site resolves to the qualified name,
    AND no file with a tail-name candidate has an indirection flag
    (``getattr`` / ``importlib.import_module`` / ``__import__`` /
    wildcard import) that could plausibly mask such a call.
  * ``UNCERTAIN`` — no call site resolves, but at least one file
    that could plausibly call this function uses indirection. We
    refuse to claim NOT_CALLED in that case.

Consumers translate UNCERTAIN to "do not downgrade severity" — it's
the safe choice for security work, where false-confidence in
non-reachability is the worst outcome.

## Out of scope (UNCERTAIN by design — documented, not "fix
later")

  * Decorator-driven dispatch, plugin registries, dynamic
    ``setattr`` injection.
  * Method dispatch on subclassed instances (e.g. subclass
    ``requests.Session``, override ``get``). This is *module-
    function* reachability, not method-resolution-order
    reachability.
  * String-based reflective dispatch beyond ``getattr`` /
    ``importlib`` / ``__import__`` (eval / exec / pickle / RPC).
  * Cross-package re-exports the resolver hasn't been told about.
    A package that re-exports ``requests.utils.extract_zipped_paths``
    as ``mypkg.helpers.ezp`` won't be matched on the
    ``mypkg.helpers.ezp`` qualified name unless the inventory
    captures the re-export — and at first cut, it doesn't.

If the consumer cares about any of those, CodeQL's call-graph
queries are the right tool — at the cost of a ~30s DB build.
This resolver is meant to be sub-second.

## Test-file exclusion

By default, files matching a test path pattern (``tests/``,
``test_*.py``, ``*_test.py``, ``conftest.py``) are NOT counted as
evidence-for. ``mock.patch("requests.get")`` mentions a qualified
name without calling it; counting test-file uses as CALLED would
keep severities pinned high purely because the project has good
test coverage. Pass ``exclude_test_files=False`` to opt out.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from .call_graph import (
    INDIRECTION_BRACKET_DISPATCH,
    INDIRECTION_DUNDER_IMPORT,
    INDIRECTION_DYNAMIC_IMPORT,
    INDIRECTION_EVAL,
    INDIRECTION_GETATTR,
    INDIRECTION_IMPORTLIB,
    INDIRECTION_REFLECT,
    INDIRECTION_WILDCARD_IMPORT,
)

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    """Reachability verdict for a queried qualified name."""
    CALLED = "called"
    NOT_CALLED = "not_called"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class ReachabilityResult:
    """Verdict plus diagnostic detail.

    ``evidence`` lists the (file_path, line) pairs that demonstrate
    a CALLED verdict — empty for NOT_CALLED / UNCERTAIN. Consumers
    can surface these to operators ("called from src/handler.py:42").

    ``uncertain_reasons`` lists ``(file_path, indirection_flag)``
    pairs that explain UNCERTAIN — e.g.
    ``[("src/dynamic.py", "getattr")]`` says we couldn't rule out a
    call because that file uses ``getattr``-by-name dispatch.
    """
    verdict: Verdict
    evidence: Tuple[Tuple[str, int], ...] = ()
    uncertain_reasons: Tuple[Tuple[str, str], ...] = ()


# Test-file pattern. Matches paths that look like pytest /
# unittest / nose conventions — covers ``tests/x.py``,
# ``tests/sub/x.py``, ``test_x.py``, ``x_test.py``, ``conftest.py``,
# and the conventional ``tests`` directory at any depth.
_TEST_FILE_PATTERN = re.compile(
    r"(^|/)("
    r"tests?/.*|"
    r"test_[^/]+\.py|"
    r"[^/]+_test\.py|"
    r"conftest\.py"
    r")$"
)


# Indirection flags that can mask a static "not called" claim.
# Python flags first; JS flags second. The resolver doesn't
# distinguish — any present flag → file is a confounder when it
# also mentions the target tail name.
_MASKING_FLAGS: Set[str] = {
    INDIRECTION_GETATTR,
    INDIRECTION_IMPORTLIB,
    INDIRECTION_DUNDER_IMPORT,
    INDIRECTION_WILDCARD_IMPORT,
    INDIRECTION_BRACKET_DISPATCH,
    INDIRECTION_DYNAMIC_IMPORT,
    INDIRECTION_EVAL,
    INDIRECTION_REFLECT,
}


def function_called(
    inventory: Dict[str, Any],
    qualified_name: str,
    *,
    exclude_test_files: bool = True,
) -> ReachabilityResult:
    """Determine whether ``qualified_name`` is called by the project
    described by ``inventory``.

    ``inventory`` is the dict shape emitted by
    :func:`core.inventory.build_inventory` — has a top-level
    ``files`` list, each entry potentially carrying a
    ``call_graph`` field (Python files only at first cut).

    ``qualified_name`` is dotted, e.g.
    ``"requests.utils.extract_zipped_paths"``. Bare function name
    (no dots) is treated as a top-level module function in an
    unknown module — useful only for builtins (``"open"``) and
    raises ``ValueError`` because the resolver can't validate
    against an empty import-chain prefix.
    """
    if not qualified_name or "." not in qualified_name:
        raise ValueError(
            "qualified_name must be dotted (module.function); got "
            f"{qualified_name!r}",
        )

    target_parts = qualified_name.split(".")
    target_func = target_parts[-1]
    target_module_parts = target_parts[:-1]
    target_module = ".".join(target_module_parts)

    evidence: List[Tuple[str, int]] = []
    uncertain_reasons: List[Tuple[str, str]] = []

    for file_record in inventory.get("files", []):
        path = file_record.get("path") or ""
        if exclude_test_files and _is_test_file(path):
            continue
        cg = file_record.get("call_graph")
        if not cg:
            continue
        imports = cg.get("imports") or {}
        calls = cg.get("calls") or []
        flags = set(cg.get("indirection") or [])

        getattr_targets = set(cg.get("getattr_targets") or [])

        file_has_evidence = False
        for call in calls:
            chain = call.get("chain") or []
            if not chain:
                continue
            if _resolves_to(chain, imports, target_module, target_func):
                file_has_evidence = True
                evidence.append((path, int(call.get("line", 0) or 0)))

        if file_has_evidence:
            continue

        # Indirection is only a confounder when there's *some*
        # signal that this file might be calling the target. A file
        # that uses getattr but doesn't mention the target name in
        # any form isn't suspect.
        file_mentions_tail = (
            target_func in getattr_targets
            or any(
                (c.get("chain") or [])[-1:] == [target_func]
                for c in calls
            )
            or any(
                qualified.split(".")[-1] == target_func
                for qualified in imports.values()
            )
        )

        # getattr / importlib / __import__ flags taint a file IFF
        # the file mentions the target tail name (chain tail, import
        # tail, or getattr literal). Wildcard imports are routed
        # through _wildcard_could_provide because they only mask
        # what their source module could plausibly export.
        non_wildcard_flags = (flags & _MASKING_FLAGS) - {
            INDIRECTION_WILDCARD_IMPORT,
        }
        if non_wildcard_flags and file_mentions_tail:
            for flag in sorted(non_wildcard_flags):
                uncertain_reasons.append((path, flag))

        if INDIRECTION_WILDCARD_IMPORT in flags and (
            _wildcard_could_provide(imports, target_module, target_func)
        ):
            uncertain_reasons.append((path, INDIRECTION_WILDCARD_IMPORT))

    if evidence:
        return ReachabilityResult(
            verdict=Verdict.CALLED,
            evidence=tuple(evidence),
            uncertain_reasons=tuple(uncertain_reasons),
        )
    if uncertain_reasons:
        return ReachabilityResult(
            verdict=Verdict.UNCERTAIN,
            uncertain_reasons=tuple(uncertain_reasons),
        )
    return ReachabilityResult(verdict=Verdict.NOT_CALLED)


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


def _resolves_to(
    chain: List[str],
    imports: Dict[str, str],
    target_module: str,
    target_func: str,
) -> bool:
    """Return True iff ``chain`` (in this file's namespace) refers to
    ``target_module.target_func``.

    Two main shapes:

    1. Bare-name call: ``ezp(...)`` → ``chain == ["ezp"]``. Resolve
       via ``imports[chain[0]]`` and require it equal the full
       ``target_module.target_func``.
    2. Attribute-chain call: ``requests.utils.foo(...)`` →
       ``chain == ["requests", "utils", "foo"]``. Resolve the head
       (``"requests"``) via the import map, then concatenate the
       middle parts with the resolved head and require equality.
    """
    if len(chain) == 1:
        # Bare-name call. Must be in the import map and resolve
        # exactly to the full target.
        bound = imports.get(chain[0])
        if bound is None:
            return False
        return bound == f"{target_module}.{target_func}"

    head = chain[0]
    bound = imports.get(head)
    if bound is None:
        return False
    middle = ".".join(chain[1:-1])
    if middle:
        resolved_module = f"{bound}.{middle}"
    else:
        resolved_module = bound
    return resolved_module == target_module and chain[-1] == target_func


def _wildcard_could_provide(
    imports: Dict[str, str],
    target_module: str,
    target_func: str,
) -> bool:
    """Heuristic: does this file have any import map entry whose
    qualified prefix matches ``target_module``?

    Wildcard imports (``from x.y import *``) don't end up in the
    import map at all, so we can't see whether they would have
    bound ``target_func``. This is best-effort: if any other import
    in this file targets the same module prefix as ``target_module``,
    treat the wildcard as plausible cover. Avoids spamming
    UNCERTAIN for a wildcard from a totally unrelated module.

    Without this, a wildcard import of ``json.*`` would mask
    NOT_CALLED claims about ``requests.utils.foo``, which is
    nonsense.
    """
    # If any other recorded import in this file shares the target
    # module's first component, treat the wildcard as plausible.
    target_root = target_module.split(".", 1)[0]
    for qualified in imports.values():
        if qualified.split(".", 1)[0] == target_root:
            return True
    return False


def _is_test_file(path: str) -> bool:
    """Conventional test-file detection. Matches paths under any
    ``tests/`` or ``test/`` directory, plus ``test_*.py``,
    ``*_test.py``, ``conftest.py``."""
    norm = path.replace(os.sep, "/")
    return bool(_TEST_FILE_PATTERN.search(norm))


__all__ = [
    "ReachabilityResult",
    "Verdict",
    "function_called",
]
