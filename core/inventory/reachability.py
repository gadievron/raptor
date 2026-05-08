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
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple, Union

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


# ---------------------------------------------------------------------------
# Adjacency primitives — 1-hop callers / callees
# ---------------------------------------------------------------------------
#
# ``function_called`` (above) answers "is some call site in the project
# resolved to ``X``?" — a *forward 1-hop* query specialised for external
# targets. Consumers like ``/audit`` need a richer set of primitives:
# given a project-internal function, who calls it and what does it call?
# Given a CVE-affected dep function, walk back to find every caller chain
# in the project.
#
# The primitives below are language-agnostic and operate on the same
# inventory shape ``function_called`` consumes. They share a per-
# inventory adjacency index built lazily on first query and memoised
# weakly so batch queries (every function in the project) amortise.
#
# **Node identity.** A node in the call graph is one of:
#
#   * :class:`InternalFunction` — a project-defined function. Identity:
#     ``(file_path, name, line)``. The line disambiguates same-name
#     overloads / nested defs / methods of different classes that
#     happen to share a name.
#
#   * :class:`ExternalFunction` — a dotted dep-name resolved via the
#     containing file's import map. Identity: ``qualified_name``.
#
# **Method-call policy.** When a call site's chain is rooted in a name
# that *isn't* in the file's import map — e.g. ``self.foo()``,
# ``obj.foo()`` — we can't know which class's ``foo`` was invoked. Two
# directions, two policies:
#
#   * **Caller direction (``callers_of``)**: over-inclusive. We add the
#     enclosing function as a candidate caller of every project
#     ``foo`` we know of. False positives in caller lists show up as
#     visible noise; missing a real caller can lead a downstream
#     consumer to demote a real vulnerability. Bias toward inclusion.
#
#   * **Callee direction (``callees_of``)**: under-inclusive +
#     UNCERTAIN flag. We don't enumerate every possible ``foo`` in the
#     project as a callee; instead we record an indirection-style
#     uncertainty entry on the result. ``/audit``'s context slice
#     would otherwise be flooded with non-callees.
#
# The asymmetry is deliberate. Documented; not "fix later".


@dataclass(frozen=True)
class InternalFunction:
    """A project-defined function. Identity: ``(file_path, name, line)``.

    ``line`` is the function's ``line_start`` from the inventory's item
    record. Disambiguates two functions with the same name in the same
    file (nested defs, methods of different classes inside one module).
    """

    file_path: str
    name: str
    line: int

    def __str__(self) -> str:
        return f"{self.file_path}:{self.name}@{self.line}"


@dataclass(frozen=True)
class ExternalFunction:
    """A dep-defined function referenced by qualified name."""

    qualified_name: str

    def __str__(self) -> str:
        return self.qualified_name


FunctionId = Union[InternalFunction, ExternalFunction]


@dataclass(frozen=True)
class CallersResult:
    """1-hop callers of a queried target.

    ``definitive`` lists internal functions whose call sites
    statically resolve to the target via the import map.

    ``uncertain`` lists internal functions that *might* call the
    target — typically because their enclosing file has masking
    indirection flags (``getattr`` / wildcard import) AND mentions
    the target's tail name. Consumers SHOULD NOT downgrade severity
    based on an empty ``definitive`` if ``uncertain`` is non-empty.

    ``method_match_overinclusive`` lists internal functions whose
    enclosing function has a call chain rooted in an unresolved
    name (``self.foo()``, ``obj.foo()``) where ``foo`` matches the
    target's tail. These are over-inclusive matches per the
    documented method-call policy.
    """

    definitive: Tuple[InternalFunction, ...] = ()
    uncertain: Tuple[InternalFunction, ...] = ()
    method_match_overinclusive: Tuple[InternalFunction, ...] = ()

    @property
    def all_callers(self) -> Tuple[InternalFunction, ...]:
        """Union of definitive + uncertain + over-inclusive method
        matches, deduplicated, in stable order. Useful when the
        consumer just wants "everyone who might call this"."""
        seen: Set[InternalFunction] = set()
        out: List[InternalFunction] = []
        for group in (self.definitive, self.uncertain,
                      self.method_match_overinclusive):
            for c in group:
                if c not in seen:
                    seen.add(c)
                    out.append(c)
        return tuple(out)


@dataclass(frozen=True)
class CalleesResult:
    """1-hop callees of a queried internal source.

    ``definitive`` lists callees the source's call sites statically
    resolve to — a mix of :class:`InternalFunction` (project-internal
    edges) and :class:`ExternalFunction` (dep-call edges).

    ``uncertain`` lists qualified-name strings the source *mentions*
    but for which the source's file has masking indirection. The
    string form (rather than ``ExternalFunction``) reflects that we
    don't know whether these are real callees.

    ``has_method_dispatch`` is True iff the source contains call
    chains rooted in unresolved names (``self.foo()`` etc.); the
    actual callees can't be enumerated and consumers should treat
    the source's internal callee set as incomplete.
    """

    definitive: Tuple[FunctionId, ...] = ()
    uncertain: Tuple[str, ...] = ()
    has_method_dispatch: bool = False


# ---------------------------------------------------------------------------
# Adjacency index — internal substrate
# ---------------------------------------------------------------------------


@dataclass
class _AdjacencyIndex:
    """Per-inventory derived call-graph indices.

    Built once per ``inventory`` dict (memoised on object identity)
    on first query, then reused. All maps are keyed by frozen,
    hashable :class:`FunctionId` instances so consumers can dedup /
    set-intersect cheaply.

    Fields:

    * ``forward[src] -> {callees}`` — mixed Internal+External nodes
      reachable in 1 hop from ``src`` (which is always Internal).
    * ``reverse[dst] -> {callers}`` — Internal callers of ``dst``,
      where ``dst`` may be Internal or External.
    * ``uncertain_callers[dst] -> {callers}`` — internal functions
      flagged uncertain for ``dst`` (file has masking indirection +
      mentions the target tail).
    * ``method_match[tail] -> {callers}`` — internal functions whose
      bodies contain unresolved ``...foo()`` chains where the tail
      is ``foo``. Used to fill in ``method_match_overinclusive`` on
      lookup against any internal target named ``foo``.
    * ``uncertain_callees[src] -> {qualified_or_local_strings}`` —
      see :class:`CalleesResult`.
    * ``has_method_dispatch[src]`` — True iff ``src``'s body uses
      unresolved-head method calls.
    * ``definitions[(file_path, name)] -> {InternalFunction, ...}``
      — every project-defined function indexed by its file+name
      tuple. Multiple entries means name overloading within one
      file (same-name nested defs). Used by callers_of when the
      target is Internal: we need to find every InternalFunction
      whose body has a call resolving to the target.
    """

    forward: Dict[InternalFunction, Set[FunctionId]] = field(default_factory=dict)
    reverse: Dict[FunctionId, Set[InternalFunction]] = field(default_factory=dict)
    # Uncertain callers are stashed by *target tail name*, not target
    # FunctionId, because the same file-level masking flag taints
    # every internal function in that file as a possible caller for
    # any target the file mentions by tail. callers_of() looks up by
    # the target's tail when assembling its result.
    uncertain_callers_by_tail: Dict[str, Set[Tuple[InternalFunction, str]]] = (
        field(default_factory=dict)
    )
    method_match: Dict[str, Set[InternalFunction]] = field(default_factory=dict)
    uncertain_callees: Dict[InternalFunction, Set[str]] = field(default_factory=dict)
    has_method_dispatch: Dict[InternalFunction, bool] = field(default_factory=dict)
    definitions: Dict[Tuple[str, str], Set[InternalFunction]] = (
        field(default_factory=dict)
    )
    # ``qualified_name -> InternalFunction`` for project-defined
    # functions reachable via cross-package import. Used by
    # callers_of() to follow ExternalFunction → InternalFunction
    # aliasing at lookup time (the index already canonicalises
    # forward edges; this map preserves the reverse lookup).
    qualified_to_internal: Dict[str, InternalFunction] = (
        field(default_factory=dict)
    )
    # ``(src, dst) -> sorted tuple of line numbers`` recording every
    # call site where ``src`` calls ``dst``. ``forward`` is dedup'd
    # by edge; ``call_lines`` preserves multiplicity for evidence
    # rendering ("X calls Y at lines 12, 27, 45"). Lines are 1-based
    # source-file lines from the call_graph extractor; 0 when the
    # extractor couldn't attribute a line.
    call_lines: Dict[
        Tuple[InternalFunction, FunctionId], Tuple[int, ...],
    ] = field(default_factory=dict)
    # Set of file paths classified as test files (cached).
    test_paths: FrozenSet[str] = frozenset()


# Memoisation: keyed on ``id(inventory)``. Cache entries hold a
# strong reference to BOTH the inventory dict AND its index, so:
#
#   * The inventory can't be GC'd while the entry lives, which means
#     ``id(inventory)`` cannot be reused for a different dict — the
#     classic "stale id-keyed cache returns the wrong index" bug.
#
#   * On lookup we still verify ``cache[id(inv)][0] is inv`` as a
#     belt-and-braces guard against eviction-then-reuse races.
#
# Bound: ``_CACHE_MAX_ENTRIES``. When full, drop the oldest entry
# (insertion order; ``dict`` preserves it). 64 inventories is a
# generous ceiling — typical workflows have at most one "active"
# inventory plus the occasional historical comparison.
_INDEX_CACHE: Dict[int, Tuple[Dict[str, Any], "_AdjacencyIndex"]] = {}
_CACHE_MAX_ENTRIES = 64


def _get_or_build_index(
    inventory: Dict[str, Any],
    *,
    exclude_test_files: bool,
) -> _AdjacencyIndex:
    """Return the memoised adjacency index for ``inventory``.

    Test-file exclusion is part of the cache key implicitly: we always
    build the index over the FULL inventory and let the public API
    filter results, so ``exclude_test_files`` doesn't change which
    nodes / edges exist.
    """
    inv_id = id(inventory)
    cached = _INDEX_CACHE.get(inv_id)
    if cached is not None:
        cached_inv, cached_idx = cached
        # Identity check: id() reuse can't happen while the cache
        # holds the dict, but a paranoid check costs nothing.
        if cached_inv is inventory:
            return cached_idx
        # Stale slot — collision after eviction. Drop and rebuild.
        _INDEX_CACHE.pop(inv_id, None)

    idx = _AdjacencyIndex()
    test_paths: Set[str] = set()

    # Pass 1: gather every project-defined function as an
    # InternalFunction and seed `definitions`.
    for file_record in inventory.get("files", []):
        path = file_record.get("path") or ""
        if _is_test_file(path):
            test_paths.add(path)
        for item in file_record.get("items", []) or []:
            if not isinstance(item, dict):
                continue
            if item.get("kind") not in (None, "function"):
                # KIND_FUNCTION is the default; skip globals / macros / classes.
                continue
            name = item.get("name") or ""
            if not name:
                continue
            line = int(item.get("line_start") or 0)
            fn = InternalFunction(file_path=path, name=name, line=line)
            idx.definitions.setdefault((path, name), set()).add(fn)

    idx.test_paths = frozenset(test_paths)

    # Pass 1.5: build a qualified-name → InternalFunction map so that
    # external edges resolving to project-defined physical functions
    # get rewritten into internal edges in pass 2.
    #
    # Without this, consumers asking ``callers_of(InternalFunction(F))``
    # miss every caller that reaches ``F`` via a cross-file
    # ``from pkg.mod import F`` import — those resolve through the
    # file's import map to ``ExternalFunction("pkg.mod.F")``, which is
    # a different graph node than the InternalFunction. The two are
    # the same physical function; the substrate canonicalises on the
    # InternalFunction.
    #
    # Heuristic: derive candidate dotted forms from each file path:
    #   * ``a/b/c.py`` → ``a.b.c``
    #   * ``a/b/__init__.py`` → ``a.b``
    #   * ``src/a/b/c.py`` → also ``a.b.c`` (src-layout)
    #
    # Limitations (documented; consumer should be aware):
    #   * Non-Python files: file-path-to-module heuristic doesn't run;
    #     no internal aliasing for JS/Go/Java/etc.
    for (file_path, fn_name), fns in idx.definitions.items():
        # Pick the lowest-line def as canonical — typically the
        # module-level one, which is the only one externally
        # importable. Same-name nested defs aren't reachable from
        # outside; we don't disambiguate further.
        canonical = min(fns, key=lambda f: f.line)
        for candidate in _candidate_qualified_names(file_path, fn_name):
            idx.qualified_to_internal.setdefault(candidate, canonical)

    # Pass 1.6: ``__init__.py`` re-export aliasing.
    # ``pkg/__init__.py`` doing ``from .helpers import foo`` makes
    # ``pkg.foo`` an alias for ``pkg.helpers.foo``. Without this pass,
    # consumers reaching the function via ``from pkg import foo`` end
    # up with an ``ExternalFunction("pkg.foo")`` edge that doesn't
    # canonicalise — mirror image of the cross-package gap PR-A's
    # heuristic closed.
    #
    # We resolve relative imports ourselves (the call_graph extractor
    # records ``(level, module, name, asname)`` quads but doesn't
    # resolve them — package roots come from file paths, which the
    # per-file extractor doesn't know).
    #
    # Repeat the alias-discovery pass until fixed-point so that
    # transitive re-exports (``pkg/__init__.py`` re-exports from
    # ``pkg/sub/__init__.py`` which re-exports from ``pkg/sub/impl.py``)
    # all collapse to the same canonical InternalFunction. Bounded
    # by a small iteration count — re-export chains in real codebases
    # are at most 3-4 deep.
    idx._inventory_for_reexport_pass = inventory  # type: ignore[attr-defined]
    try:
        for _ in range(8):
            added = _apply_reexport_aliases(idx)
            if not added:
                break
    finally:
        # Don't keep a strong ref to the inventory on the index past
        # build time — the cache layer manages inventory lifetime.
        try:
            del idx._inventory_for_reexport_pass        # type: ignore[attr-defined]
        except AttributeError:
            pass

    qualified_to_internal = idx.qualified_to_internal

    # Pass 2: walk every call site, resolve to a callee FunctionId
    # (Internal or External), record forward + reverse edges.
    for file_record in inventory.get("files", []):
        path = file_record.get("path") or ""
        cg = file_record.get("call_graph")
        if not cg:
            continue
        imports: Dict[str, str] = cg.get("imports") or {}
        flags: Set[str] = set(cg.get("indirection") or [])
        getattr_targets: Set[str] = set(cg.get("getattr_targets") or [])
        non_wildcard_masking = (flags & _MASKING_FLAGS) - {
            INDIRECTION_WILDCARD_IMPORT,
        }
        has_wildcard = INDIRECTION_WILDCARD_IMPORT in flags

        for call in cg.get("calls") or []:
            chain: List[str] = list(call.get("chain") or [])
            if not chain:
                continue
            line = int(call.get("line", 0) or 0)
            caller_name: Optional[str] = call.get("caller")
            caller_node = _resolve_caller(idx, path, caller_name, line)
            if caller_node is None:
                # Module-level call OR enclosing function not in the
                # inventory's items (rare; could happen for code
                # extracted from a file the items pass skipped).
                # Edges from "module level" aren't useful for the
                # primitives we expose; drop them.
                continue

            callee = _resolve_callee_chain(chain, imports)
            if callee is not None:
                # Canonicalise: if this external qualified name
                # actually resolves to a project-defined function,
                # use the InternalFunction node. Otherwise the
                # callers_of(InternalFunction) lookup misses every
                # caller reaching it via cross-package import.
                aliased = qualified_to_internal.get(callee.qualified_name)
                if aliased is not None:
                    callee = aliased
                idx.forward.setdefault(caller_node, set()).add(callee)
                idx.reverse.setdefault(callee, set()).add(caller_node)
                _record_call_line(idx, caller_node, callee, line)
                continue

            # Couldn't resolve via import map. Two sub-cases:
            #   (a) chain head is unbound — likely a method call
            #       (``self.foo()`` / ``obj.foo()``). Tail name is
            #       useful for the over-inclusive method-match index.
            #   (b) chain is a single unbound name (``foo()`` where
            #       ``foo`` is defined locally). Could be a call to
            #       a peer function in the same file.
            tail = chain[-1]
            if len(chain) == 1:
                # Sub-case (b): bare-name call. If this file defines
                # a function with that name, record an internal edge.
                local_defs = idx.definitions.get((path, tail))
                if local_defs:
                    for d in local_defs:
                        idx.forward.setdefault(caller_node, set()).add(d)
                        idx.reverse.setdefault(d, set()).add(caller_node)
                        _record_call_line(idx, caller_node, d, line)
                    continue
                # Local name not defined in this file — likely a
                # builtin (open, len, ...) or a wildcard-imported
                # name. Record nothing definitive; method-match
                # index doesn't apply (no head-attr).
                if has_wildcard:
                    idx.uncertain_callees.setdefault(caller_node, set()).add(
                        f"*.{tail}",
                    )
                continue

            # Sub-case (a): unresolved attribute chain. Index for
            # method-match over-inclusive caller lookup.
            idx.method_match.setdefault(tail, set()).add(caller_node)
            idx.has_method_dispatch[caller_node] = True
            # And surface it on the source's callee set as
            # uncertain-string so callees_of can flag it.
            idx.uncertain_callees.setdefault(caller_node, set()).add(
                ".".join(chain),
            )

        # Indirection flags on the file → every internal function
        # defined IN this file inherits "uncertain caller" status
        # for any target the file mentions by tail. We record this
        # at file level: the keys we care about are tail names that
        # appear in (a) call chains tail-side, (b) getattr_targets,
        # (c) imports' tail components.
        if non_wildcard_masking or has_wildcard:
            file_internal_fns = [
                fn for (p, _name), fns in idx.definitions.items()
                if p == path for fn in fns
            ]
            mentioned_tails: Set[str] = set(getattr_targets)
            for call in cg.get("calls") or []:
                chain = list(call.get("chain") or [])
                if chain:
                    mentioned_tails.add(chain[-1])
            for qualified in imports.values():
                if not qualified:
                    continue
                mentioned_tails.add(qualified.rsplit(".", 1)[-1])
            for tail in mentioned_tails:
                for fn in file_internal_fns:
                    # We don't know the *target* yet — that's keyed
                    # on the lookup. Stash the (caller, tail, flag)
                    # tuple under tail so callers_of can pick it
                    # up.
                    flag_label = (
                        sorted(non_wildcard_masking)[0]
                        if non_wildcard_masking
                        else INDIRECTION_WILDCARD_IMPORT
                    )
                    idx.uncertain_callers_by_tail.setdefault(
                        tail, set(),
                    ).add((fn, flag_label))

    _INDEX_CACHE[inv_id] = (inventory, idx)
    if len(_INDEX_CACHE) > _CACHE_MAX_ENTRIES:
        # Drop the oldest entry. dict preserves insertion order.
        oldest = next(iter(_INDEX_CACHE))
        _INDEX_CACHE.pop(oldest, None)
    return idx


def _resolve_caller(
    idx: _AdjacencyIndex,
    file_path: str,
    caller_name: Optional[str],
    call_line: int,
) -> Optional[InternalFunction]:
    """Map ``caller_name`` (lexical enclosing fn-name in ``file_path``)
    to its :class:`InternalFunction` definition record.

    When multiple definitions share the same ``(file_path, name)``
    (rare: same-name nested defs), pick the one whose ``line`` is
    the largest value ≤ ``call_line``. That's the lexically
    innermost match. Falls through to the first def if heuristics
    fail.
    """
    if not caller_name:
        return None
    candidates = idx.definitions.get((file_path, caller_name))
    if not candidates:
        return None
    if len(candidates) == 1:
        return next(iter(candidates))
    # Pick the def with greatest line ≤ call_line.
    eligible = [c for c in candidates if c.line <= call_line]
    if eligible:
        return max(eligible, key=lambda c: c.line)
    return min(candidates, key=lambda c: c.line)


def _record_call_line(
    idx: _AdjacencyIndex,
    caller: InternalFunction,
    callee: FunctionId,
    line: int,
) -> None:
    """Append ``line`` to ``idx.call_lines[(caller, callee)]``,
    keeping the tuple sorted with no duplicates.

    Forward / reverse edges are deduplicated; this side-index keeps
    multiplicity for evidence rendering ("X calls Y at lines …").
    """
    key = (caller, callee)
    existing = idx.call_lines.get(key, ())
    if line in existing:
        return
    merged = existing + (line,)
    idx.call_lines[key] = tuple(sorted(merged))


def _apply_reexport_aliases(idx: _AdjacencyIndex) -> int:
    """One iteration of ``__init__.py`` re-export alias discovery.

    Walks every ``__init__.py`` in the inventory's call-graph data,
    resolves each relative import to a fully-qualified source, and
    when that source is in ``qualified_to_internal``, registers the
    re-exported alias as another entry pointing at the same
    InternalFunction. Returns the number of new aliases added so the
    caller can iterate to fixed-point (transitive re-exports).

    The re-export pass needs the call_graph data, which lives on
    ``file_record["call_graph"]`` not on the ``_AdjacencyIndex`` —
    we receive the index because that's what we mutate, but reading
    the data requires the inventory. We stash the inventory on the
    index temporarily during build so this helper can find it.
    """
    inv = getattr(idx, "_inventory_for_reexport_pass", None)
    if inv is None:
        return 0
    added = 0
    for file_record in inv.get("files", []):
        path = file_record.get("path") or ""
        if not (path.endswith("/__init__.py") or path == "__init__.py"):
            continue
        cg = file_record.get("call_graph")
        if not cg:
            continue
        rel_imports = cg.get("relative_imports") or []
        abs_imports = cg.get("imports") or {}
        if not rel_imports and not abs_imports:
            continue
        # Package this __init__.py defines (path → dotted form).
        if path == "__init__.py":
            pkg_path = ""
        else:
            pkg_path = path[: -len("/__init__.py")]
        pkg_dotted_candidates: List[str] = []
        if pkg_path:
            pkg_dotted_candidates.append(pkg_path.replace("/", "."))
            if pkg_path.startswith("src/"):
                stripped = pkg_path[len("src/"):]
                if stripped:
                    pkg_dotted_candidates.append(stripped.replace("/", "."))
        else:
            pkg_dotted_candidates.append("")
        for ri in rel_imports:
            if not isinstance(ri, (list, tuple)) or len(ri) < 3:
                continue
            level = int(ri[0])
            module = str(ri[1] or "")
            name = str(ri[2] or "")
            asname = ri[3] if len(ri) > 3 else None
            if level <= 0 or not name:
                continue
            for pkg_dotted in pkg_dotted_candidates:
                # Walk up ``level - 1`` package levels from the
                # file's package. Level 1 means current package.
                parts = pkg_dotted.split(".") if pkg_dotted else []
                ascend = level - 1
                if ascend > len(parts):
                    # ``from ..`` from a top-level package — skip;
                    # there's no further ancestor.
                    continue
                ancestor = ".".join(
                    parts[: len(parts) - ascend] if ascend > 0 else parts
                )
                # Compose the source qualified name: ancestor + module
                if module:
                    source_module = (
                        f"{ancestor}.{module}" if ancestor else module
                    )
                else:
                    source_module = ancestor
                if not source_module:
                    continue
                source_full = f"{source_module}.{name}"
                target_internal = idx.qualified_to_internal.get(source_full)
                if target_internal is None:
                    continue
                alias_name = asname or name
                alias_full = (
                    f"{pkg_dotted}.{alias_name}" if pkg_dotted
                    else alias_name
                )
                if alias_full not in idx.qualified_to_internal:
                    idx.qualified_to_internal[alias_full] = target_internal
                    added += 1
        # Absolute-import re-exports: ``core/__init__.py`` doing
        # ``from core.config import RaptorConfig`` makes
        # ``core.RaptorConfig`` available to callers via ``from core
        # import RaptorConfig``. Walk this file's imports map and
        # treat each entry as a potential re-export from this package.
        # (The local-name → qualified-name map is exactly what we
        # need: local_name is the alias-as-seen-from-outside, and
        # qualified is the source we look up in qualified_to_internal.)
        for local_name, qualified in abs_imports.items():
            if not qualified:
                continue
            target_internal = idx.qualified_to_internal.get(qualified)
            if target_internal is None:
                continue
            for pkg_dotted in pkg_dotted_candidates:
                alias_full = (
                    f"{pkg_dotted}.{local_name}" if pkg_dotted
                    else local_name
                )
                if alias_full == qualified:
                    # Trivial self-alias — qualified is already in
                    # the map under itself. Skip (would be a no-op
                    # but for the ``added`` counter, which would
                    # let us re-process every iteration).
                    continue
                if alias_full not in idx.qualified_to_internal:
                    idx.qualified_to_internal[alias_full] = target_internal
                    added += 1
    return added


def _candidate_qualified_names(file_path: str, fn_name: str) -> List[str]:
    """Heuristic: derive plausible Python qualified names for an
    InternalFunction defined at ``(file_path, fn_name)``.

    Returns at most a handful of candidates (typically 1-2). Used by
    the index builder to canonicalise external callee edges that
    actually resolve to project-defined functions.

    Non-Python files: returns empty list. Other-language internal
    aliasing isn't modelled.
    """
    if not (file_path.endswith(".py") or file_path.endswith(".pyi")):
        return []
    base = file_path
    for suffix in (".pyi", ".py"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    if base.endswith("/__init__"):
        base = base[: -len("/__init__")]
    candidates: List[str] = []
    if base:
        candidates.append(f"{base.replace('/', '.')}.{fn_name}")
    # ``src/`` layout: ``src/mypkg/foo.py`` is imported as
    # ``mypkg.foo``, not ``src.mypkg.foo``. Generate both candidates.
    if base.startswith("src/"):
        stripped = base[len("src/"):]
        if stripped:
            candidates.append(f"{stripped.replace('/', '.')}.{fn_name}")
    return candidates


def _resolve_callee_chain(
    chain: List[str],
    imports: Dict[str, str],
) -> Optional[ExternalFunction]:
    """Map a call chain to an :class:`ExternalFunction` via the file's
    import map. Returns None if the chain head isn't in the import
    map.

    Note: this never returns :class:`InternalFunction` — internal
    edges via local bare-name calls are handled by the caller (the
    fall-through path in ``_get_or_build_index`` looks up
    ``definitions[(path, tail)]``).
    """
    if not chain:
        return None
    if len(chain) == 1:
        bound = imports.get(chain[0])
        if bound is None:
            return None
        return ExternalFunction(qualified_name=bound)
    head = chain[0]
    bound = imports.get(head)
    if bound is None:
        return None
    middle = ".".join(chain[1:-1])
    if middle:
        qualified = f"{bound}.{middle}.{chain[-1]}"
    else:
        qualified = f"{bound}.{chain[-1]}"
    return ExternalFunction(qualified_name=qualified)


# ---------------------------------------------------------------------------
# Public API: callers_of / callees_of
# ---------------------------------------------------------------------------


def callers_of(
    inventory: Dict[str, Any],
    target: FunctionId,
    *,
    exclude_test_files: bool = True,
) -> CallersResult:
    """Return 1-hop callers of ``target``.

    ``target`` may be :class:`InternalFunction` (a project-defined
    function — find every internal caller) or :class:`ExternalFunction`
    (a dep-defined function — find every internal caller, same
    semantics as ``function_called`` but returning structured caller
    identities rather than evidence pairs).

    Test-file callers are filtered when ``exclude_test_files`` is
    True (the default; matches existing ``function_called``
    behaviour).
    """
    idx = _get_or_build_index(
        inventory, exclude_test_files=exclude_test_files,
    )

    # Aliasing: if the caller passes ``ExternalFunction("pkg.mod.fn")``
    # but ``pkg.mod.fn`` is a project-defined function, follow the
    # alias so we return the same callers as
    # ``callers_of(InternalFunction(...))``. The index canonicalises
    # forward edges to InternalFunction, so without this lookup the
    # External form would silently return 0.
    if isinstance(target, ExternalFunction):
        aliased = idx.qualified_to_internal.get(target.qualified_name)
        if aliased is not None:
            target = aliased

    definitive_set: Set[InternalFunction] = set(
        idx.reverse.get(target, set())
    )

    # Uncertain: file-level masking flags on the caller's file +
    # target tail mention. Indexed by tail (see _AdjacencyIndex).
    target_tail = (
        target.name if isinstance(target, InternalFunction)
        else target.qualified_name.rsplit(".", 1)[-1]
    )
    uncertain_pairs = idx.uncertain_callers_by_tail.get(target_tail, set())
    # Drop callers that are already definitive — uncertain only
    # matters when there's NO definitive evidence in that file. But
    # uncertain is per-fn, not per-file, so we filter by fn.
    uncertain_set: Set[InternalFunction] = {
        fn for (fn, _flag) in uncertain_pairs
        if fn not in definitive_set
    }

    # Method-match overinclusive: only meaningful when target is
    # internal (we're saying "any unresolved-head ...foo() chain
    # might call this target named foo"). For external targets,
    # method-match doesn't apply.
    method_match_set: Set[InternalFunction] = set()
    if isinstance(target, InternalFunction):
        candidates = idx.method_match.get(target.name, set())
        method_match_set = candidates - definitive_set - uncertain_set

    if exclude_test_files:
        definitive_set = {fn for fn in definitive_set
                          if fn.file_path not in idx.test_paths}
        uncertain_set = {fn for fn in uncertain_set
                         if fn.file_path not in idx.test_paths}
        method_match_set = {fn for fn in method_match_set
                            if fn.file_path not in idx.test_paths}

    return CallersResult(
        definitive=tuple(_sorted_internal(definitive_set)),
        uncertain=tuple(_sorted_internal(uncertain_set)),
        method_match_overinclusive=tuple(_sorted_internal(method_match_set)),
    )


def callees_of(
    inventory: Dict[str, Any],
    source: InternalFunction,
    *,
    exclude_test_files: bool = True,
) -> CalleesResult:
    """Return 1-hop callees of ``source``.

    ``source`` must be :class:`InternalFunction` (the question
    "what does ``X`` call?" only makes sense when we have a
    project-internal function whose body we've parsed).

    Result mixes :class:`InternalFunction` (calls to peer project
    functions) and :class:`ExternalFunction` (calls to dep
    functions), reflecting that consumers like ``/audit`` want both
    in their context slice.
    """
    idx = _get_or_build_index(
        inventory, exclude_test_files=exclude_test_files,
    )

    definitive_set: Set[FunctionId] = set(idx.forward.get(source, set()))
    uncertain: Set[str] = set(idx.uncertain_callees.get(source, set()))
    has_method_dispatch = bool(idx.has_method_dispatch.get(source, False))

    if exclude_test_files:
        definitive_set = {
            c for c in definitive_set
            if not (isinstance(c, InternalFunction)
                    and c.file_path in idx.test_paths)
        }

    return CalleesResult(
        definitive=tuple(_sorted_callees(definitive_set)),
        uncertain=tuple(sorted(uncertain)),
        has_method_dispatch=has_method_dispatch,
    )


def call_lines_of(
    inventory: Dict[str, Any],
    caller: InternalFunction,
    callee: FunctionId,
) -> Tuple[int, ...]:
    """Source lines where ``caller`` calls ``callee``.

    Returns the sorted, dedup'd tuple of 1-based line numbers
    recorded at index-build time, or ``()`` when no edge exists.
    Useful for evidence rendering (``"X calls Y at lines 12, 27,
    45"``) where ``callees_of`` only tells you the edge exists.

    For ``callee`` aliasing: an ``ExternalFunction`` whose
    qualified name resolves to a project-internal function is
    canonicalised to that ``InternalFunction`` (matches
    ``callers_of`` / closure semantics). A consumer holding the
    ``ExternalFunction`` form gets the same line numbers as one
    holding the ``InternalFunction`` form.
    """
    idx = _get_or_build_index(inventory, exclude_test_files=False)
    if isinstance(callee, ExternalFunction):
        aliased = idx.qualified_to_internal.get(callee.qualified_name)
        if aliased is not None:
            callee = aliased
    return idx.call_lines.get((caller, callee), ())


def _sorted_internal(s: Iterable[InternalFunction]) -> List[InternalFunction]:
    """Stable order: by file path, then name, then line."""
    return sorted(s, key=lambda fn: (fn.file_path, fn.name, fn.line))


def _sorted_callees(s: Iterable[FunctionId]) -> List[FunctionId]:
    """Stable order: Internal first (by path/name/line), External
    second (by qualified_name)."""
    internals = [c for c in s if isinstance(c, InternalFunction)]
    externals = [c for c in s if isinstance(c, ExternalFunction)]
    internals.sort(key=lambda fn: (fn.file_path, fn.name, fn.line))
    externals.sort(key=lambda fn: fn.qualified_name)
    return list(internals) + list(externals)


# ---------------------------------------------------------------------------
# Closure primitives — transitive reverse / forward / shortest-path
# ---------------------------------------------------------------------------
#
# 1-hop adjacency (``callers_of`` / ``callees_of``) answers "who DIRECTLY
# calls X?" The closure primitives below answer the transitive question:
# given a target, which project functions can reach it through ANY chain
# of internal calls? Or symmetrically: from a set of entry points, what's
# the full forward-reachable set?
#
# All three primitives walk the same definitive call-graph edges captured
# by the adjacency index in pass 2. **Uncertain edges are NOT walked.**
# A consumer wanting "could-possibly-reach" coverage should drill into
# the boundary using ``callers_of`` / ``callees_of`` directly to inspect
# the 1-hop uncertain neighbours; closure semantics are "demonstrably
# reachable".
#
# This split is deliberate: the SCA / audit consumer that wants to demote
# severity for unreachable code wants to be conservative — empty closure
# under definitive-only walk, plus a non-empty 1-hop uncertain frontier,
# means "we don't know" and severity should NOT be demoted. The two
# halves of the answer come from separate primitives.
#
# **Termination at External nodes.** Forward closure expands
# InternalFunction nodes only — ``ExternalFunction`` is recorded in the
# closure when reached but its callees are unknown to the index (it's
# a dep). Reverse closure has no analogous distinction: every caller of
# anything is by definition an Internal project function (we don't
# index how the project's deps call each other).
#
# **Cycles.** Visited-set BFS handles cycles trivially. We don't surface
# strongly-connected-component structure — consumers that need it can
# layer it on top of a closure result.


@dataclass(frozen=True)
class ClosureResult:
    """Result of a transitive closure walk.

    ``nodes`` is the set of project functions reachable from the seed
    (forward) or that can reach the target (reverse), excluding the
    seed/target itself, in stable order.

    ``paths`` maps each reached node to a representative shortest call
    chain. For ``forward_closure``, the chain runs entry → ... → node.
    For ``reverse_closure``, the chain runs node → ... → target.
    Useful for evidence rendering — a /validate consumer showing "this
    sink is reachable from the HTTP entry via this chain" wants the
    chain itself, not just the membership.

    ``truncated`` is True iff the BFS hit ``max_depth`` on at least one
    path. The closure is still useful (everything in ``nodes`` IS
    reachable) but may be incomplete; consumers who care can re-run
    with a higher ``max_depth``.
    """

    nodes: Tuple[FunctionId, ...] = ()
    paths: Dict[FunctionId, Tuple[FunctionId, ...]] = field(
        default_factory=dict,
    )
    truncated: bool = False


def reverse_closure(
    inventory: Dict[str, Any],
    target: FunctionId,
    *,
    max_depth: int = 50,
    exclude_test_files: bool = True,
) -> ClosureResult:
    """Project functions that can transitively reach ``target``.

    BFS up the reverse-adjacency graph starting at ``target``. The
    closure includes only :class:`InternalFunction` nodes — Externals
    can't be callers in our model. The seed (``target``) is excluded
    from the result.

    ``target`` may be Internal or External. If External, the
    qualified-name-to-internal alias is followed (same semantics as
    ``callers_of``).

    ``max_depth`` bounds the BFS depth. ``exclude_test_files``
    filters test-file callers out of the result; the BFS itself
    walks them so paths through tests reach internal seed functions
    correctly.
    """
    from collections import deque

    idx = _get_or_build_index(
        inventory, exclude_test_files=exclude_test_files,
    )
    if isinstance(target, ExternalFunction):
        aliased = idx.qualified_to_internal.get(target.qualified_name)
        if aliased is not None:
            target = aliased

    paths: Dict[FunctionId, Tuple[FunctionId, ...]] = {target: (target,)}
    queue: "deque[Tuple[FunctionId, int]]" = deque([(target, 0)])
    truncated = False
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            truncated = True
            continue
        for caller in idx.reverse.get(node, set()):
            if caller in paths:
                continue
            # Don't traverse test-file functions when filtering them
            # out — otherwise a non-test function reachable ONLY via
            # a test caller ends up in the closure with a path that
            # crosses test code, surprising the consumer. Symmetric
            # with shortest_path's behaviour.
            if exclude_test_files and isinstance(caller, InternalFunction) \
                    and caller.file_path in idx.test_paths:
                continue
            paths[caller] = (caller,) + paths[node]
            queue.append((caller, depth + 1))

    nodes_list: List[FunctionId] = []
    out_paths: Dict[FunctionId, Tuple[FunctionId, ...]] = {}
    for n, p in paths.items():
        if n == target:
            continue
        nodes_list.append(n)
        out_paths[n] = p
    nodes_list.sort(key=_closure_sort_key)
    return ClosureResult(
        nodes=tuple(nodes_list),
        paths=out_paths,
        truncated=truncated,
    )


def forward_closure(
    inventory: Dict[str, Any],
    entries: Iterable[InternalFunction],
    *,
    max_depth: int = 50,
    exclude_test_files: bool = True,
) -> ClosureResult:
    """Functions transitively callable from any of ``entries``.

    BFS down the forward-adjacency graph, seeding from every entry
    in ``entries``. The closure includes both :class:`InternalFunction`
    (project edges) and :class:`ExternalFunction` (dep calls) nodes
    — the distinction matters for /validate Stage F asking "does the
    chain reach this sink?" where the sink can be either form.

    External nodes are TERMINAL: we record them but don't expand.
    The substrate doesn't know an external dep's callees, only that
    it was called.

    ``entries`` is excluded from the result. Test-file results are
    filtered when ``exclude_test_files`` is True.
    """
    from collections import deque

    idx = _get_or_build_index(
        inventory, exclude_test_files=exclude_test_files,
    )

    entry_set: Set[FunctionId] = set(entries)
    paths: Dict[FunctionId, Tuple[FunctionId, ...]] = {}
    queue: "deque[Tuple[FunctionId, int]]" = deque()
    for entry in entry_set:
        if entry not in paths:
            paths[entry] = (entry,)
            queue.append((entry, 0))

    truncated = False
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            truncated = True
            continue
        if not isinstance(node, InternalFunction):
            # External — terminal. We have no internal definition,
            # so no outgoing edges to expand.
            continue
        for callee in idx.forward.get(node, set()):
            if callee in paths:
                continue
            # Don't traverse through test-file functions when
            # excluding them — symmetric with reverse_closure /
            # shortest_path. Reachability through tests isn't
            # production reachability.
            if exclude_test_files and isinstance(callee, InternalFunction) \
                    and callee.file_path in idx.test_paths:
                continue
            paths[callee] = paths[node] + (callee,)
            queue.append((callee, depth + 1))

    nodes_list: List[FunctionId] = []
    out_paths: Dict[FunctionId, Tuple[FunctionId, ...]] = {}
    for n, p in paths.items():
        if n in entry_set:
            continue
        nodes_list.append(n)
        out_paths[n] = p
    nodes_list.sort(key=_closure_sort_key)
    return ClosureResult(
        nodes=tuple(nodes_list),
        paths=out_paths,
        truncated=truncated,
    )


def shortest_path(
    inventory: Dict[str, Any],
    source: InternalFunction,
    target: FunctionId,
    *,
    max_depth: int = 50,
    exclude_test_files: bool = False,
) -> Optional[Tuple[FunctionId, ...]]:
    """Shortest call chain ``source`` → ``target``, or None.

    BFS forward from ``source`` with early-exit on hitting
    ``target``. Returns the chain inclusive of both endpoints, or
    ``None`` if ``target`` is not reachable within ``max_depth``
    hops. ``source == target`` returns ``(source,)``.

    ``target`` may be Internal or External. External targets have
    their qualified-name-to-internal alias followed (matches
    callers_of / reverse_closure semantics).

    ``exclude_test_files`` defaults to False here — when /validate
    renders an evidence path, it usually wants the genuine chain
    even if it crosses a test helper. Consumers that want the
    audit-style filter pass ``exclude_test_files=True`` explicitly;
    in that mode, the BFS rejects paths whose intermediate hops
    cross a test file (endpoints are the consumer's responsibility).
    """
    from collections import deque

    idx = _get_or_build_index(
        inventory, exclude_test_files=exclude_test_files,
    )
    if isinstance(target, ExternalFunction):
        aliased = idx.qualified_to_internal.get(target.qualified_name)
        if aliased is not None:
            target = aliased
    if source == target:
        return (source,)

    visited: Dict[FunctionId, Tuple[FunctionId, ...]] = {source: (source,)}
    queue: "deque[Tuple[FunctionId, int]]" = deque([(source, 0)])
    while queue:
        node, depth = queue.popleft()
        if depth >= max_depth:
            continue
        if not isinstance(node, InternalFunction):
            continue
        for callee in idx.forward.get(node, set()):
            if callee in visited:
                continue
            chain = visited[node] + (callee,)
            if callee == target:
                if exclude_test_files:
                    intermediate_in_test = any(
                        isinstance(s, InternalFunction)
                        and s.file_path in idx.test_paths
                        for s in chain[1:-1]
                    )
                    if intermediate_in_test:
                        # Reject this chain as evidence — but don't
                        # mark target visited (a different chain
                        # via a non-test path may still reach it).
                        # Don't enqueue target either: it has no
                        # outgoing edges we'd want to walk.
                        continue
                return chain
            # Same logic for intermediates: paths whose body crosses
            # a test-file function shouldn't be propagated further
            # under exclude_test_files=True. Otherwise we explore
            # them and only filter at the endpoint, which can prune
            # a clean sibling path that happened to be discovered
            # through the same intermediate.
            if exclude_test_files and isinstance(callee, InternalFunction) \
                    and callee.file_path in idx.test_paths:
                continue
            visited[callee] = chain
            queue.append((callee, depth + 1))
    return None


def all_paths(
    inventory: Dict[str, Any],
    source: InternalFunction,
    target: FunctionId,
    *,
    max_paths: int = 10,
    max_depth: int = 50,
    exclude_test_files: bool = False,
) -> Tuple[Tuple[FunctionId, ...], ...]:
    """All simple call chains ``source`` → ``target``, sorted by
    length (shortest first), bounded by ``max_paths`` and
    ``max_depth``.

    Useful for evidence diversity when ``shortest_path``'s pick
    isn't the chain a consumer wants — e.g. /validate sees the
    LLM proposed a different chain and wants to confirm there are
    multiple valid evidence paths to choose between.

    "Simple": no node repeats within a single path. Cycles are
    handled via the per-path visited set rather than a global one,
    so multiple distinct paths through a shared intermediate are
    discoverable.

    Cost: bounded DFS, worst case O(b^max_depth) where b is the
    branching factor. Real codebases are sparse; ``max_depth``
    bounds the runaway. Returns early on hitting ``max_paths``.

    External targets follow the qualified-name → Internal alias
    (matches ``shortest_path`` / closure semantics).
    """
    idx = _get_or_build_index(
        inventory, exclude_test_files=exclude_test_files,
    )
    if isinstance(target, ExternalFunction):
        aliased = idx.qualified_to_internal.get(target.qualified_name)
        if aliased is not None:
            target = aliased
    if source == target:
        return ((source,),)

    found: List[Tuple[FunctionId, ...]] = []

    def _dfs(node: FunctionId, path: Tuple[FunctionId, ...],
              visited: Set[FunctionId]) -> None:
        if len(found) >= max_paths:
            return
        if len(path) > max_depth:
            return
        if not isinstance(node, InternalFunction):
            return
        for callee in idx.forward.get(node, set()):
            if callee in visited:
                continue
            if exclude_test_files and isinstance(callee, InternalFunction) \
                    and callee.file_path in idx.test_paths:
                continue
            new_path = path + (callee,)
            if callee == target:
                found.append(new_path)
                if len(found) >= max_paths:
                    return
                continue
            visited.add(callee)
            _dfs(callee, new_path, visited)
            visited.discard(callee)
            if len(found) >= max_paths:
                return

    _dfs(source, (source,), {source})
    found.sort(key=len)
    return tuple(found[:max_paths])


def _closure_sort_key(fn: FunctionId) -> Tuple:
    """Stable order across mixed Internal+External: Internal first by
    (path, name, line); External after by qualified_name. Use a
    tuple-with-discriminant so heterogeneous comparison works."""
    if isinstance(fn, InternalFunction):
        return (0, fn.file_path, fn.name, fn.line, "")
    return (1, "", "", 0, fn.qualified_name)


# ---------------------------------------------------------------------------
# Evidence-line helpers
# ---------------------------------------------------------------------------
#
# Substrate consumers that walk evidence (``"path:line"`` pairs)
# back to enclosing functions need a couple of small primitives.
# These started life inside ``packages/sca/reachability/`` but every
# consumer ends up needing them — /validate Stage F resolves
# attack-path entry/sink to InternalFunctions; /agentic triage
# resolves a finding's source line to its host for caller-summary
# context; /understand --map renders host context for entry points.
# Hoisted to share one implementation.


def enclosing_function(
    inventory: Dict[str, Any],
    file_path: str,
    line: int,
) -> Optional[InternalFunction]:
    """Return the project-internal function whose body contains
    ``line`` in ``file_path``, or ``None`` if the line lives at
    module scope (no enclosing def).

    When two defs nest (``def outer(): ... def inner(): ...``)
    and ``line`` falls in the inner body, the innermost match
    wins — the def with the largest ``line_start`` ≤ ``line``
    that also has ``line`` ≤ ``line_end`` (or no
    ``line_end``).

    Returns ``None`` for any of:
      * file_path not in the inventory
      * file has no items list
      * line falls outside every function's range
    """
    file_record = _find_file_record(inventory, file_path)
    if file_record is None:
        return None
    items = file_record.get("items") or []
    if not isinstance(items, list):
        return None

    best: Optional[Dict[str, Any]] = None
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("kind") not in (None, "function"):
            continue
        line_start = item.get("line_start")
        line_end = item.get("line_end")
        if not isinstance(line_start, int) or line_start <= 0:
            continue
        if line_start > line:
            continue
        # When line_end is missing, treat the def's range as
        # open-ended — pick the lexically last def that started
        # before our line. Same line_start-greatest-match
        # heuristic the substrate uses for nested-def
        # disambiguation.
        if isinstance(line_end, int) and line_end >= 0 and line_end < line:
            continue
        if best is None or item["line_start"] > best["line_start"]:
            best = item

    if best is None:
        return None
    name = best.get("name") or ""
    if not name:
        return None
    return InternalFunction(
        file_path=file_path,
        name=name,
        line=int(best["line_start"]),
    )


def parse_evidence_entry(entry: str) -> Tuple[Optional[str], int]:
    """Split a ``"path:line"`` evidence string into ``(path, line)``.

    Returns ``(None, 0)`` for malformed inputs. Handles paths
    containing colons (``C:\\path`` on Windows, IPv6 fragments)
    by ``rsplit``-ing on the LAST colon and requiring the suffix
    to be a decimal int.
    """
    if not isinstance(entry, str) or ":" not in entry:
        return None, 0
    path, _, line_str = entry.rpartition(":")
    if not path or not line_str:
        return None, 0
    try:
        return path, int(line_str)
    except ValueError:
        return None, 0


def _find_file_record(
    inventory: Dict[str, Any],
    path: str,
) -> Optional[Dict[str, Any]]:
    """Linear scan of the inventory's files for a path match.

    Files lists are typically hundreds of entries; linear scan is
    fast in practice (single-digit microseconds per query).
    Consumers needing sub-millisecond latency across many queries
    can pre-build a path→record map.
    """
    for file_record in inventory.get("files", []):
        if file_record.get("path") == path:
            return file_record
    return None


__all__ = [
    "CallersResult",
    "CalleesResult",
    "ClosureResult",
    "ExternalFunction",
    "FunctionId",
    "InternalFunction",
    "ReachabilityResult",
    "Verdict",
    "all_paths",
    "call_lines_of",
    "callees_of",
    "callers_of",
    "enclosing_function",
    "forward_closure",
    "function_called",
    "parse_evidence_entry",
    "reverse_closure",
    "shortest_path",
]
