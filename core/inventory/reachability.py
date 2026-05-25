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
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Set, Tuple, Union

from . import _reach_cache
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


@dataclass(frozen=True)
class _FunctionCalledIndex:
    """Inverse index over ``inventory['files']`` so ``function_called``
    can narrow the per-call file iteration from O(N_files) to
    O(N_candidates_for_target).

    Built once per inventory; ``function_called`` reuses across the
    many (dep × affected_function) queries every SCA function-level
    tier emits. Pre-fix the bare loop scanned all ~30k Grafana files
    for every query — 8 tiers × dozens of deps × multiple affected
    funcs/dep = tens of millions of file-record walks, the dominant
    cost of a 12-min reach stage. Indexed: only the small set of
    files that mention the target gets the per-file check.

    Conservatism: each bucket is over-inclusive, never under. A file
    in a bucket still pays the full per-file branch logic; a file
    NOT in any bucket has zero possible match under the existing
    semantics. False positives only cost cycles, not correctness.

    Buckets use sorted ``Tuple[int, ...]`` rather than ``FrozenSet[int]``
    — for the typical Grafana-shape distribution (64% of tokens hold
    one file, 27% hold 2–5) the tuple cuts per-bucket overhead from
    ~232 bytes (frozenset header + hash table) to ~64 bytes (tuple
    header). The consumer in ``function_called`` only iterates each
    bucket once into a set union; tuple iteration is faster than set
    iteration anyway, so there's no perf cost.
    """

    # token (module head / dotted prefix / func tail / fully-qualified
    # dotted chain / getattr-target name) → file indices that mention
    # it in some role function_called might consult.
    files_by_token: Dict[str, Tuple[int, ...]]
    # Files with any non-wildcard masking flag — visited regardless
    # of token bucket so the indirection branch can yield UNCERTAIN
    # when ``file_mentions_tail`` matches the query.
    files_with_non_wildcard_masking: Tuple[int, ...]
    # Files with a wildcard import — visited so the wildcard branch
    # can yield UNCERTAIN via ``_wildcard_could_provide``.
    files_with_wildcard_import: Tuple[int, ...]
    # U4: function name → file paths whose function-like macro bodies
    # invoke it (C/C++). A function reachable only via such a macro reads
    # NOT_CALLED in the static graph (tree-sitter doesn't expand macros);
    # the resolver maps a hit here to UNCERTAIN. Global membership —
    # consulted independent of the per-token candidate buckets, because
    # the macro-defining file may not otherwise mention the target.
    macro_targets: Dict[str, Tuple[str, ...]] = field(default_factory=dict)


# Keyed on ``id(inventory)``; identity-checked on read so a fresh
# inventory dict reusing the address of a GC'd one doesn't return
# the wrong index. Capped — matches the ``_INDEX_CACHE`` policy
# already used by ``callers_of`` / ``callees_of``.
_FN_CALLED_INDEX_CACHE: Dict[int, Tuple[Dict[str, Any], _FunctionCalledIndex]] = {}
_FN_CALLED_INDEX_CACHE_MAX = 8


def _build_function_called_index(
    inventory: Dict[str, Any],
) -> _FunctionCalledIndex:
    files = inventory.get("files") or []
    files_by_token: Dict[str, Set[int]] = {}
    non_wildcard: Set[int] = set()
    wildcard: Set[int] = set()
    macro_targets: Dict[str, Set[str]] = {}

    def _add(token: str, i: int) -> None:
        if not token:
            return
        files_by_token.setdefault(token, set()).add(i)

    for i, fr in enumerate(files):
        if not isinstance(fr, dict):
            continue
        cg = fr.get("call_graph")
        if not cg:
            continue
        # Imports: target_module matches `bound == target_module`,
        # `bound == target_dot_func`, or `bound.startswith(
        # target_module + ".")`. Indexing every dotted prefix of
        # ``bound`` covers all three.
        for bound in (cg.get("imports") or {}).values():
            if not isinstance(bound, str) or not bound:
                continue
            parts = bound.split(".")
            for k in range(1, len(parts) + 1):
                _add(".".join(parts[:k]), i)
            # Tail of the import name is what
            # ``file_mentions_tail`` checks against — index the
            # final segment too so target_func lookups hit it.
            _add(parts[-1], i)
        # Calls: chain tail + fully-qualified dotted chain.
        for call in (cg.get("calls") or []):
            chain = call.get("chain") or []
            if not chain:
                continue
            _add(chain[-1], i)
            if len(chain) >= 2:
                _add(".".join(chain), i)
        # getattr literals.
        for name in (cg.get("getattr_targets") or []):
            _add(name, i)
        # Indirection flags split into the two buckets the resolver
        # treats differently.
        flags = set(cg.get("indirection") or [])
        if (flags & _MASKING_FLAGS) - {INDIRECTION_WILDCARD_IMPORT}:
            non_wildcard.add(i)
        if INDIRECTION_WILDCARD_IMPORT in flags:
            wildcard.add(i)
        # U4: function-like-macro call targets (C/C++).
        mpath = fr.get("path") or ""
        for name in (cg.get("macro_call_targets") or []):
            macro_targets.setdefault(name, set()).add(mpath)

    return _FunctionCalledIndex(
        files_by_token={
            k: tuple(sorted(v)) for k, v in files_by_token.items()
        },
        files_with_non_wildcard_masking=tuple(sorted(non_wildcard)),
        files_with_wildcard_import=tuple(sorted(wildcard)),
        macro_targets={
            k: tuple(sorted(v)) for k, v in macro_targets.items()
        },
    )


def _get_function_called_index(
    inventory: Dict[str, Any],
) -> _FunctionCalledIndex:
    inv_id = id(inventory)
    cached = _FN_CALLED_INDEX_CACHE.get(inv_id)
    if cached is not None and cached[0] is inventory:
        return cached[1]
    if cached is not None:
        # id reuse after GC — drop the stale entry.
        _FN_CALLED_INDEX_CACHE.pop(inv_id, None)
    idx = _build_function_called_index(inventory)
    _FN_CALLED_INDEX_CACHE[inv_id] = (inventory, idx)
    if len(_FN_CALLED_INDEX_CACHE) > _FN_CALLED_INDEX_CACHE_MAX:
        oldest = next(iter(_FN_CALLED_INDEX_CACHE))
        _FN_CALLED_INDEX_CACHE.pop(oldest, None)
    return idx


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

    target_dot_func = f"{target_module}.{target_func}"
    target_module_dot = target_module + "."

    # Narrow the file iteration to those the inverse index says
    # could possibly match. Buckets:
    #   - ``target_module`` token: file's imports mention it (as a
    #     prefix or full match) — feeds the case-1 import-bound check.
    #   - ``target_func`` token: file has a call whose chain tail
    #     matches, or imports the bare name, or uses the name as a
    #     getattr literal — feeds cases 2, 3, and 4 (file_mentions_tail).
    #   - ``qualified_name`` token: file has a fully-qualified
    #     dotted-chain call exactly matching — feeds case 3 directly.
    #   - non-wildcard masking files: always considered for case 4.
    #   - wildcard-import files: always considered for the wildcard
    #     branch.
    # Files NOT in any of those buckets have no possible role under
    # the existing per-file branches, so dropping them is semantic-
    # preserving.
    files = inventory.get("files") or []
    index = _get_function_called_index(inventory)
    candidate_idx: Set[int] = set()
    candidate_idx.update(
        index.files_by_token.get(target_module, ()),
    )
    candidate_idx.update(
        index.files_by_token.get(target_func, ()),
    )
    candidate_idx.update(
        index.files_by_token.get(qualified_name, ()),
    )
    candidate_idx.update(index.files_with_non_wildcard_masking)
    candidate_idx.update(index.files_with_wildcard_import)

    for i in sorted(candidate_idx):
        file_record = files[i]
        if not isinstance(file_record, dict):
            continue
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

        # Fast-path skip: when no import in this file binds to
        # target_module (or its bare-name form), no call chain can
        # resolve to target. The indirection branch below still runs
        # because it depends only on target_func, not target_module.
        # For Go's istio-scale inventory (~770 files × ~3000 deps),
        # this drops _resolves_to invocations from 74M to ~hundreds —
        # the main istio-1.4 scan-perf fix (cProfile flagged
        # _resolves_to + its inner generator at >190s of 410s total).
        target_in_imports = False
        for bound in imports.values():
            if (bound == target_module
                    or bound == target_dot_func
                    or bound.startswith(target_module_dot)):
                target_in_imports = True
                break

        file_has_evidence = False
        if target_in_imports:
            for call in calls:
                chain = call.get("chain") or []
                if not chain:
                    continue
                if _resolves_to(chain, imports, target_module, target_func):
                    file_has_evidence = True
                    evidence.append((path, int(call.get("line", 0) or 0)))

        # Class-aware receiver_class fast-path: when the chain
        # tail is the target_func AND the call carries a
        # ``receiver_class``, synthesise the qualified name
        # ``<file_package>.<receiver_class>.<tail>`` and compare
        # against the target. This catches Java's implicit-this
        # (``helper()`` inside a class method), Ruby's
        # ``self.helper``, C#'s implicit-this, etc. — bare calls
        # the import-map path can't resolve because their head
        # isn't in imports.
        if not file_has_evidence:
            file_pkg = cg.get("package_name")
            for call in calls:
                chain = call.get("chain") or []
                if not chain or chain[-1] != target_func:
                    continue
                rc = call.get("receiver_class")
                if rc is None:
                    continue
                # Construct the resolved qualified name. For
                # languages with a declared package_name the form
                # is ``<pkg>.<Class>.<method>``. For languages
                # where the file IS the module (Python / JS /
                # Ruby class-less), fall back to path-derived form.
                candidates: List[str] = []
                if file_pkg:
                    candidates.append(f"{file_pkg}.{rc}.{target_func}")
                else:
                    candidates.extend(
                        _path_derived_module(path, rc, target_func),
                    )
                if qualified_name in candidates:
                    file_has_evidence = True
                    evidence.append((path, int(call.get("line", 0) or 0)))

        # Fully-qualified-call fast-path: when the chain itself
        # spells out the qualified name (e.g. C++ ``ns::Util::
        # helper()`` → chain ``["ns", "Util", "helper"]``, or Java
        # ``com.foo.Util.helper()``, or PHP ``\Foo\Bar::method()``),
        # the import map is bypassed entirely in source. The
        # import-map path can't see these; receiver_class isn't
        # set either. Strict equality of the joined dotted form
        # to the target catches them with no false-positive risk:
        # if the chain literally spells the target, it IS the
        # target. Most useful for C/C++ (no symbol-level imports)
        # and any cross-language fully-qualified call shape.
        if not file_has_evidence:
            for call in calls:
                chain = call.get("chain") or []
                if len(chain) >= 2 and ".".join(chain) == qualified_name:
                    file_has_evidence = True
                    evidence.append((path, int(call.get("line", 0) or 0)))

        # Same-file bare-name fast-path. When chain is
        # ``[target_func]`` AND this file's path-derived module
        # matches target_module, treat as a hit. The import-map
        # path can't address this case: a function defined in the
        # same file isn't "imported", so it has no import-map
        # entry for its name to resolve against.
        #
        # Particularly load-bearing for C/C++ (no symbol-level
        # imports for in-file functions) — pre-fix the resolver
        # said NOT_CALLED for every C bare-name same-file call,
        # which cascaded to false-negative reachability for any
        # function called only by another same-file function in
        # a longer reach chain. Also fixes the equivalent Python
        # / JS / Go / Rust gap when a same-file caller uses the
        # bare-name form.
        #
        # Defensive: skip when the bare name is shadowed by an
        # import in THIS file. The import-map path above is
        # authoritative for shadowed bare-name calls (Python
        # shadows the local def with the import at module scope;
        # JS / TS behaves the same with named-import binding).
        if not file_has_evidence:
            file_module = _file_path_to_module(path)
            if file_module == target_module:
                for call in calls:
                    chain = call.get("chain") or []
                    if len(chain) != 1 or chain[0] != target_func:
                        continue
                    if chain[0] in imports:
                        continue
                    file_has_evidence = True
                    evidence.append(
                        (path, int(call.get("line", 0) or 0)),
                    )
                    break

        if file_has_evidence:
            continue

        # getattr / importlib / __import__ flags taint a file IFF
        # the file mentions the target tail name (chain tail, import
        # tail, or getattr literal). Wildcard imports are routed
        # through _wildcard_could_provide because they only mask
        # what their source module could plausibly export.
        non_wildcard_flags = (flags & _MASKING_FLAGS) - {
            INDIRECTION_WILDCARD_IMPORT,
        }

        # Lazy-compute file_mentions_tail — required only by the
        # non-wildcard indirection branch. Files without any non-
        # wildcard masking flag (the common case at istio scale,
        # ~770 files × ~3000 deps) skip the genexpr over ``calls``,
        # which was the hot path after the imports-fast-path fix.
        if non_wildcard_flags:
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
            if file_mentions_tail:
                for flag in sorted(non_wildcard_flags):
                    uncertain_reasons.append((path, flag))

        if INDIRECTION_WILDCARD_IMPORT in flags and (
            _wildcard_could_provide(imports, target_module, target_func)
        ):
            uncertain_reasons.append((path, INDIRECTION_WILDCARD_IMPORT))

    # U4: function-like-macro masking (C/C++). A function whose only
    # invocation is inside a macro body reads NOT_CALLED — tree-sitter
    # sees the macro name, not the expanded call. Map such targets to
    # UNCERTAIN (never suppress). Global membership: the macro-defining
    # file need not appear in the per-token candidate buckets, so this is
    # checked off the index directly. Skipped when direct evidence exists
    # (CALLED wins anyway) — but harmless either way since CALLED takes
    # precedence over uncertain_reasons below.
    for mpath in index.macro_targets.get(target_func, ()):
        if exclude_test_files and _is_test_file(mpath):
            continue
        uncertain_reasons.append((mpath, "func_like_macro"))

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
    # ``method_match[tail]`` entries pair a candidate caller with an
    # optional receiver-class name. The receiver class is set when
    # the call site is a ``self.foo()`` / ``cls.foo()`` inside a
    # class body; ``None`` means "unknown receiver, stay over-
    # inclusive". ``callers_of`` narrows entries by class hierarchy
    # before returning method_match_overinclusive.
    method_match: Dict[
        str, Set[Tuple[InternalFunction, Optional[str]]],
    ] = field(default_factory=dict)
    uncertain_callees: Dict[InternalFunction, Set[str]] = field(default_factory=dict)
    has_method_dispatch: Dict[InternalFunction, bool] = field(default_factory=dict)
    definitions: Dict[Tuple[str, str], Set[InternalFunction]] = (
        field(default_factory=dict)
    )
    # ``method → owning class name`` (None when method is module-
    # level rather than inside a class body). Lets ``callers_of``
    # narrow method_match by class hierarchy.
    class_of_method: Dict[InternalFunction, str] = field(default_factory=dict)
    # ``(file, class_name) → tuple of base class names`` as they
    # appeared in the source. Used to compute the receiver's
    # ancestor chain at query time, scoped to same-file classes.
    class_bases: Dict[Tuple[str, str], Tuple[str, ...]] = field(
        default_factory=dict,
    )
    # Functions whose decorators match a framework-dispatch
    # registration pattern (``@app.route``, ``@router.get``,
    # ``@cli.command``, ``@task.fixture``, etc.). These are reachable
    # from outside the static graph — the framework invokes them
    # via internal dispatch. ``callers_of`` may return an empty
    # ``definitive`` set for these, but they are NOT dead code;
    # consumers should treat them as entry points.
    framework_callable: Set[InternalFunction] = field(default_factory=set)
    # Functions referenced as identifier arguments to a framework
    # registration call (``http.HandleFunc("/x", handler)``,
    # ``app.get("/users", listUsers)``, etc.). Sister to
    # ``framework_callable`` but covers the JS / Go pattern where
    # the framework registers handlers via call arguments rather
    # than decorators. Populated from CallSite.argument_identifiers
    # which the JS + Go extractors emit (other languages populate
    # an empty list — the set just stays empty for them).
    framework_registered: Set[InternalFunction] = field(default_factory=set)
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
#
# Concurrency: ``_INDEX_CACHE_LOCK`` guards all reads + writes.
# Reachability lookups fan out from /agentic, /validate, and SCA
# reachability worker pools — concurrent first-time queries on
# different inventories would otherwise race the eviction sequence
# (``len > _CACHE_MAX_ENTRIES`` check then ``next(iter(...))``
# then ``pop``), and dict iteration is not safe across concurrent
# mutation.
# OrderedDict so eviction picks the least-recently-USED entry rather
# than the oldest-by-insertion. Pre-fix the eviction at
# ``next(iter(_INDEX_CACHE))`` always dropped the FIRST-inserted slot,
# even if it had just been read 1ms before — anti-LRU semantics that
# hurt the hot-cache case worst. Cache hits now ``move_to_end`` to
# keep recently-touched entries warm.
_INDEX_CACHE: "OrderedDict[int, Tuple[Dict[str, Any], _AdjacencyIndex]]" = OrderedDict()
_CACHE_MAX_ENTRIES = 64
_INDEX_CACHE_LOCK = threading.Lock()


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
    with _INDEX_CACHE_LOCK:
        cached = _INDEX_CACHE.get(inv_id)
        if cached is not None:
            cached_inv, cached_idx = cached
            # Identity check: id() reuse can't happen while the cache
            # holds the dict, but a paranoid check costs nothing.
            if cached_inv is inventory:
                # Move to end to mark as recently-used for LRU
                # eviction. Cheap under the existing lock.
                _INDEX_CACHE.move_to_end(inv_id)
                return cached_idx
            # Stale slot — collision after eviction. Drop and rebuild.
            _INDEX_CACHE.pop(inv_id, None)

    # Persistent on-disk cache lookup. Cold-start path otherwise pays
    # the ~300ms build cost every time the operator launches a fresh
    # raptor process against the same source tree. Fingerprint folds
    # per-file sha256 + a schema version, so any inventory content
    # change (or any index-shape change) auto-invalidates. When the
    # inventory lacks sha256 (test fixtures), the fingerprint returns
    # None and the persistent layer is a no-op.
    persistent_fp = _reach_cache.compute_fingerprint(inventory)
    persisted = _reach_cache.load_index(persistent_fp)
    if persisted is not None:
        with _INDEX_CACHE_LOCK:
            _INDEX_CACHE[inv_id] = (inventory, persisted)
            while len(_INDEX_CACHE) > _CACHE_MAX_ENTRIES:
                _INDEX_CACHE.popitem(last=False)
        return persisted

    idx = _AdjacencyIndex()
    test_paths: Set[str] = set()

    # Pass 1: gather every project-defined function as an
    # InternalFunction and seed `definitions`.
    for file_record in inventory.get("files", []):
        if not isinstance(file_record, dict):
            continue
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

    # Pass 1.3: scan decorator metadata for framework-callable
    # functions. A decorator chain like ``@app.route(...)`` /
    # ``@cli.command`` registers the function with a framework
    # that will dispatch to it at runtime. Such functions look
    # "uncalled" in the static graph, but they aren't dead code.
    # Consumers (SCA reachability, /audit caller context, codeql
    # pre-filter) check ``framework_callable`` to keep these on
    # the entry-point list.
    for file_record in inventory.get("files", []):
        if not isinstance(file_record, dict):
            continue
        path = file_record.get("path") or ""
        cg = file_record.get("call_graph")
        if not cg:
            continue
        for df in cg.get("decorated_functions") or []:
            df_name = df.get("name")
            df_line = int(df.get("line", 0) or 0)
            if not df_name:
                continue
            decorators = df.get("decorators") or []
            if not _decorators_indicate_framework_dispatch(decorators):
                continue
            candidates = idx.definitions.get((path, df_name), set())
            for fn in candidates:
                if fn.line == df_line:
                    idx.framework_callable.add(fn)
                    break

    # Pass 1.3b: scan call sites for framework registration —
    # ``http.HandleFunc("/x", handler)``, ``app.get("/users",
    # listUsers)``, etc. The JS / Go pattern that mirrors Python's
    # decorator-based framework dispatch: a handler function is
    # passed as an identifier argument to a recognised registration
    # method. The CallSite.argument_identifiers field carries the
    # identifier args; ``_FRAMEWORK_REGISTRATION_TAILS`` curates
    # the chain tails we treat as registration. Chain-length-2
    # gate parallels the decorator detector — bare ``get(handler)``
    # calls don't qualify (too generic), but ``app.get(handler)``
    # does.
    #
    # Same-file matching only: the registered function must be
    # defined in the same file as the registration call. Cross-file
    # resolution (handler in handlers.js, registration in
    # routes.js) is a follow-up — would require resolving the
    # identifier through the file's import map, which is more
    # invasive. Same-file covers the common Go pattern (handlers
    # + main in same file or small package) and small Express apps.
    for file_record in inventory.get("files", []):
        if not isinstance(file_record, dict):
            continue
        path = file_record.get("path") or ""
        cg = file_record.get("call_graph")
        if not cg:
            continue
        for call in cg.get("calls") or []:
            if not isinstance(call, dict):
                continue
            chain = call.get("chain") or []
            if len(chain) < 2:
                continue
            tail = str(chain[-1])
            if tail not in _FRAMEWORK_REGISTRATION_TAILS:
                continue
            arg_idents = call.get("argument_identifiers") or []
            for ident in arg_idents:
                candidates = idx.definitions.get((path, ident), set())
                # Function defined in same file — register all
                # matching InternalFunctions (only one per
                # (path, name) typically, unless overloaded).
                for fn in candidates:
                    idx.framework_registered.add(fn)

    # Pass 1.4: capture class metadata from call_graph data. Maps
    # each method's InternalFunction to its owning class, and
    # records same-file class hierarchies for ancestor resolution
    # at query time. Cross-file inheritance isn't resolved here —
    # the resolver's narrowing falls through to "stay over-
    # inclusive" when a class's bases can't all be resolved
    # within the same file (which is correct: we'd rather over-
    # report callers than drop a real one).
    for file_record in inventory.get("files", []):
        if not isinstance(file_record, dict):
            continue
        path = file_record.get("path") or ""
        cg = file_record.get("call_graph")
        if not cg:
            continue
        for cls_data in cg.get("classes") or []:
            cls_name = cls_data.get("name")
            if not cls_name:
                continue
            if cls_data.get("nested"):
                # Nested classes (inside another class or function)
                # have shadow scoping the narrowing logic doesn't
                # model. Skip — leave their methods unmarked and
                # the resolver treats them as over-inclusive.
                continue
            bases = tuple(b for b in (cls_data.get("bases") or []) if b)
            idx.class_bases[(path, cls_name)] = bases
            for method_entry in cls_data.get("methods") or []:
                if not isinstance(method_entry, (list, tuple)) \
                        or len(method_entry) < 2:
                    continue
                m_name = str(method_entry[0])
                m_line = int(method_entry[1] or 0)
                # Look up the InternalFunction registered in pass 1.
                # We match on (path, name) and pick the one whose
                # line matches the method def line — handles same-
                # name methods on multiple classes in one file.
                candidates = idx.definitions.get((path, m_name), set())
                for fn in candidates:
                    if fn.line == m_line:
                        idx.class_of_method[fn] = cls_name
                        break

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
    # For non-Python files the qualified-name shape isn't derivable
    # from the file path alone:
    #   * Go: ``package <name>`` in the source decides the dotted
    #     prefix — directory name is NOT authoritative
    #   * Java: ``package com.foo.bar;`` declared in the source
    #   * Rust: chain of ``mod foo;`` declarations
    #   * C#: ``namespace Foo.Bar``
    #   * PHP: ``namespace Foo\Bar``
    # Each non-Python extractor that knows its own package
    # declaration writes it into ``FileCallGraph.package_name``;
    # we read it here and combine with the function name to seed
    # ``qualified_to_internal``.
    file_packages: Dict[str, Optional[str]] = {}
    for file_record in inventory.get("files", []):
        if not isinstance(file_record, dict):
            continue
        path = file_record.get("path") or ""
        cg = file_record.get("call_graph")
        if cg:
            pkg = cg.get("package_name")
            if pkg:
                file_packages[path] = pkg

    for (file_path, fn_name), fns in idx.definitions.items():
        # Pick the lowest-line def as canonical — typically the
        # module-level one, which is the only one externally
        # importable. Same-name nested defs aren't reachable from
        # outside; we don't disambiguate further.
        canonical = min(fns, key=lambda f: f.line)
        # Class-qualified candidates — for Java / C# / PHP / Rust
        # impl-blocks / JS classes the externally-visible name is
        # ``<pkg>.<Class>.<method>`` (or ``<file_module>.<Class>.
        # <method>`` for path-derived languages). ``class_of_method``
        # is populated above (line ~743) from each FileCallGraph's
        # classes[].methods list. Pass None when no class — the
        # candidate function emits the module-level form.
        cls_name = idx.class_of_method.get(canonical)
        for candidate in _candidate_qualified_names(
                file_path, fn_name,
                package_name=file_packages.get(file_path),
                class_name=cls_name,
        ):
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
        if not isinstance(file_record, dict):
            continue
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

            # Fully-qualified-call index path: when the chain itself
            # spells out a project-defined function's qualified name
            # (e.g. C++ ``ns::Util::helper()`` → chain ``["ns",
            # "Util", "helper"]``), the import-map path can't see it
            # because namespace names aren't in the imports dict.
            # If the dotted-join matches a seeded
            # ``qualified_to_internal`` entry, record a definitive
            # internal edge — parity with the function_called
            # fast-path. Strict equality keeps the rule
            # over-conservative: chains that don't literally spell
            # a known qualified name fall through to method_match.
            if len(chain) >= 2:
                dotted = ".".join(chain)
                aliased = qualified_to_internal.get(dotted)
                if aliased is not None:
                    idx.forward.setdefault(caller_node, set()).add(aliased)
                    idx.reverse.setdefault(aliased, set()).add(caller_node)
                    _record_call_line(idx, caller_node, aliased, line)
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
            # method-match over-inclusive caller lookup. The
            # extractor tagged ``self.foo()`` / ``cls.foo()`` calls
            # with the enclosing class name so ``callers_of`` can
            # narrow by hierarchy; other unresolved chains carry
            # ``receiver_class=None`` and remain fully over-
            # inclusive.
            receiver_class = call.get("receiver_class")
            idx.method_match.setdefault(tail, set()).add(
                (caller_node, receiver_class),
            )
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

    with _INDEX_CACHE_LOCK:
        _INDEX_CACHE[inv_id] = (inventory, idx)
        # LRU eviction (``popitem(last=False)``) — same shape as the
        # paired insert site above. ``while`` rather than ``if`` so a
        # future cap reduction (or test bumping max=0) doesn't leak
        # extra entries.
        while len(_INDEX_CACHE) > _CACHE_MAX_ENTRIES:
            _INDEX_CACHE.popitem(last=False)

    # Persist for the next process. Best-effort: any IO failure is
    # logged at debug and swallowed (the in-process cache is hot;
    # next cold start re-pays the build cost but nothing else
    # breaks).
    _reach_cache.save_index(persistent_fp, idx)
    return idx


# Decorator tails that indicate framework-dispatch registration.
# A decorator chain like ``[app, route]`` ending in one of these
# names is treated as registering the decorated function with a
# framework that will invoke it at runtime. Curated against:
# Flask/FastAPI/Starlette (route/get/post/put/patch/delete/...),
# click/typer (command/group), Celery/RQ (task/periodic_task/
# shared_task), Django signals (receiver/connect), pytest
# (fixture/parametrize), generic event/registry shapes
# (listener/handler/register/dispatch/subscribe/hook). Bare
# pass-through decorators (``cache``, ``lru_cache``, ``property``,
# ``staticmethod``, ``dataclass``) MUST NOT be in this set —
# they don't register entry points.
#
# The chain-length-2 gate in ``_decorators_indicate_framework_dispatch``
# excludes naked single-name decorators (``@receiver(...)``,
# ``@shared_task``). For names where the framework-dispatch
# interpretation is unambiguous even at length 1, see
# ``_FRAMEWORK_DISPATCH_NAKED_NAMES`` below — these get an exception
# to the chain-length gate.
_FRAMEWORK_DISPATCH_TAILS: FrozenSet[str] = frozenset({
    # HTTP route methods (Flask / FastAPI / Starlette / Bottle / etc.)
    "route", "get", "post", "put", "patch", "delete", "head", "options",
    "endpoint", "websocket", "errorhandler", "exception_handler",
    "before_request", "after_request", "teardown_request",
    "middleware", "on_event",
    # CLI (click / typer)
    "command", "group", "callback",
    # Task queues (Celery / RQ / dramatiq / huey)
    "task", "periodic_task", "shared_task", "actor",
    # Signals / events (Django / blinker / pyee)
    "receiver", "connect", "listener", "subscriber", "subscribe",
    "on", "emit_handler",
    # Generic registries / hooks
    "register", "hook", "provider", "consumer", "handler", "dispatch",
    "rule",
    # Test frameworks
    "fixture", "parametrize", "mark",
    # GraphQL / RPC
    "query", "mutation", "subscription", "field", "resolver",
    # Build tools (e.g. nox, doit, pyinvoke)
    "session", "module_task",
})


# Chain tails recognised as framework registration calls — the JS /
# Go pattern where a handler is passed as an identifier argument to a
# routing or middleware-registration method. For
# ``app.get("/x", handler)``, the chain tail is ``get`` and ``handler``
# is the registered function. The set is curated against:
# Express / Fastify / Koa / Hono (HTTP verb methods + ``use`` + ``route``),
# Go net/http (``Handle``, ``HandleFunc``), gin / echo (capitalised HTTP
# verbs + ``Use`` + ``Group``), chi (mixed-case verbs + ``Method`` /
# ``MethodFunc`` / ``Mount``). The chain-length-2 gate (matching
# ``_decorators_indicate_framework_dispatch``'s philosophy) keeps bare
# ``get(...)`` / ``use(...)`` calls from being treated as registration:
# they're far more likely user-defined helpers than framework calls.
#
# FALSE-POSITIVE awareness:
#   * ``map.get(key)`` shape: any chain ending in ``get`` matches.
#     Mitigation: tail-set excludes the most generic verbs that double
#     as Map/Set accessors (``set``, ``has``); registered HTTP verbs
#     (``get``/``post``/etc.) cannot be cleanly disambiguated without
#     receiver-type tracking. Accepted: a function passed as the 2nd
#     arg to a ``somethign.get(...)`` call would be promoted as
#     framework_registered — but in practice ``map.get`` takes 1
#     argument (the key), and 2-arg ``.get(key, default)`` calls
#     don't pass identifier-function arguments. False-positive
#     promotion costs accuracy on dead-code findings (the consumer
#     skips a demotion that might have been correct); silencing
#     real frameworks costs false negatives. Bias toward
#     admitting the framework case.
_FRAMEWORK_REGISTRATION_TAILS: FrozenSet[str] = frozenset({
    # Express / Fastify / Koa / Hono — lowercase HTTP verbs + use + route.
    "get", "post", "put", "patch", "delete", "head", "options",
    "all", "use", "route", "param",
    # Go gin / echo — capitalised HTTP verbs + Use + Group + Static.
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
    "Any", "Use", "Group", "Static",
    # Go chi — mixed-case verbs + Method/MethodFunc + Mount + Handle.
    "Get", "Post", "Put", "Patch", "Delete", "Head", "Options",
    "Method", "MethodFunc", "Mount",
    # Go net/http — Handle + HandleFunc on *http.ServeMux + http pkg.
    "Handle", "HandleFunc",
})


# Single-name decorators where the framework-dispatch interpretation
# is unambiguous enough to override the chain-length-2 gate. Entries
# here MUST be distinctive enough that collision with user-defined
# pass-through decorators is rare. Generic names (``task``,
# ``fixture``, ``register``, ``handler``) are deliberately excluded
# because a project's own ``@task`` / ``@fixture`` is more likely to
# be a pass-through than framework dispatch — false-positive
# promotion of pass-through-decorated dead code is the worse error
# (silences real findings) vs false-negative on framework code
# (caught by the chain-length-2 form which projects more commonly
# use via ``@pytest.fixture`` / ``@celery.task``).
#
# Conservative starter set covers the highest-value cases where the
# bare form is idiomatic AND the name is distinctive:
#   * Django signals: ``@receiver(post_save, sender=User)`` — bare
#     ``receiver`` is the standard import-pattern; chain-length-1
#     is the dominant usage.
#   * Celery shared tasks: ``@shared_task`` — the import-then-bare
#     form is the recommended Celery pattern for app-agnostic tasks.
#   * Celery periodic tasks: ``@periodic_task(...)`` — distinctive
#     enough not to collide.
#   * dramatiq: ``@actor`` — domain-specific term, unlikely to be a
#     user-defined pass-through.
_FRAMEWORK_DISPATCH_NAKED_NAMES: FrozenSet[str] = frozenset({
    "receiver",
    "shared_task",
    "periodic_task",
    "actor",
})


def _decorators_indicate_framework_dispatch(
    decorators: Iterable[Any],
) -> bool:
    """True iff any decorator on the function matches the
    framework-dispatch registration shape.

    Two acceptance shapes:

      * **Chain length >= 2**: decorator is a method on an imported
        object (e.g. ``app.route``, ``pytest.fixture``,
        ``celery_app.task``). Tail name must be in
        ``_FRAMEWORK_DISPATCH_TAILS``. This is the dominant form
        across the supported frameworks and the safer signal —
        pass-through decorators are typically single names.
      * **Chain length 1**: bare single-name decorator whose name is
        in the narrower ``_FRAMEWORK_DISPATCH_NAKED_NAMES`` set.
        Reserved for distinctive framework-only names (Django
        ``@receiver``, Celery ``@shared_task``, etc.) where the
        bare form is idiomatic. Generic names (``task``,
        ``fixture``, ``register``) deliberately NOT in this set —
        their bare form is more likely a user pass-through.

    The split keeps the resolver from over-promoting pass-through
    decorators (which would silence legitimate dead-code findings)
    while admitting the bare framework-decorator patterns that
    Django / Celery / dramatiq projects commonly use.
    """
    for chain in decorators:
        if not isinstance(chain, (list, tuple)):
            continue
        if not chain:
            continue
        tail = str(chain[-1])
        if len(chain) >= 2 and tail in _FRAMEWORK_DISPATCH_TAILS:
            return True
        if len(chain) == 1 and tail in _FRAMEWORK_DISPATCH_NAKED_NAMES:
            return True
    return False


def _resolved_ancestor_chain(
    file_path: str,
    class_name: str,
    idx: _AdjacencyIndex,
) -> Optional[FrozenSet[str]]:
    """Return the set of class names reachable from ``class_name``
    via base-class edges within ``file_path``, including
    ``class_name`` itself.

    Returns ``None`` if any base along the chain isn't defined in
    the same file — the resolver treats unresolvable bases as "we
    don't know the full hierarchy, don't narrow" rather than
    silently truncating. Cross-file inheritance is a follow-on
    project; today's narrowing only fires within a single file.
    """
    seen: Set[str] = {class_name}
    stack: List[str] = [class_name]
    # Guard against pathological recursive base claims (a class
    # listing itself in its own bases, etc.). The stack-based walk
    # already deduplicates via ``seen``; this is the loop bound.
    iterations = 0
    while stack:
        iterations += 1
        if iterations > 1000:
            return None
        current = stack.pop()
        bases = idx.class_bases.get((file_path, current))
        if bases is None:
            # ``current == class_name`` and no class_bases entry
            # means the class wasn't captured (perhaps a non-Python
            # extractor or the extractor didn't emit). Skip when
            # current is the receiver itself; for resolution of
            # ancestors we need bases.
            if current == class_name:
                continue
            # Mid-chain unresolved base — cross-file inheritance
            # most likely. Bail out: we can't be confident the
            # narrowing wouldn't drop a real caller.
            return None
        for b in bases:
            # Bases stored as raw chain strings (e.g. ``A``,
            # ``mixins.M``). For same-file narrowing we only handle
            # bare class names. Dotted bases mean "imported from
            # another module" — bail to over-inclusive.
            if "." in b:
                return None
            if (file_path, b) not in idx.class_bases:
                # Base name not defined in this file. Could be a
                # builtin (``object``, ``Exception``) or imported
                # class. For ``object`` and the common builtins
                # narrowing is still safe — they have no project
                # methods that ``self.foo()`` could resolve to.
                # For imported classes we'd risk dropping real
                # callers. Conservative path: bail out.
                if b in _SAFE_BUILTIN_BASES:
                    continue
                return None
            if b not in seen:
                seen.add(b)
                stack.append(b)
    return frozenset(seen)


# Builtins whose presence as a base doesn't add unknown methods to
# the receiver's potential dispatch set. Safe to ignore when
# computing the ancestor chain — they can't define a method that
# a ``self.foo()`` could legitimately resolve to as far as project
# code goes.
_SAFE_BUILTIN_BASES: FrozenSet[str] = frozenset({
    "object", "Exception", "BaseException", "ValueError", "TypeError",
    "KeyError", "IndexError", "RuntimeError", "OSError", "IOError",
    "FileNotFoundError", "NotImplementedError", "StopIteration",
    "AttributeError", "ImportError", "ModuleNotFoundError",
    "UnicodeError", "ZeroDivisionError", "ArithmeticError",
    "LookupError", "MemoryError", "OverflowError", "NameError",
    "ReferenceError", "SyntaxError", "SystemError", "GeneratorExit",
    "KeyboardInterrupt", "SystemExit", "Warning", "Enum", "IntEnum",
    "Flag", "IntFlag", "StrEnum", "NamedTuple", "Protocol",
    "ABCMeta", "ABC",
    # tuple/dict/list/set subclass bases for common patterns
    "tuple", "list", "dict", "set", "frozenset", "str", "bytes",
    "bytearray", "int", "float", "bool", "complex",
})


def _method_match_compatible(
    *,
    receiver_class: Optional[str],
    receiver_file: str,
    target_class: Optional[str],
    idx: _AdjacencyIndex,
) -> bool:
    """True iff a ``self.foo()`` / ``cls.foo()`` call site whose
    enclosing class is ``receiver_class`` could legitimately resolve
    to a method ``foo`` defined on ``target_class``.

    Returns True in any "we don't know enough to narrow" case — the
    substrate prefers over-reporting callers to dropping real ones.
    """
    if receiver_class is None:
        # Call site wasn't ``self.foo()`` / ``cls.foo()``; no
        # narrowing possible (could be anything).
        return True
    if target_class is None:
        # Target is module-level, not a method. But ``method_match``
        # was already populated when the call's chain head was
        # unresolved — receiver_class being set tells us the call
        # was ``self.foo()`` against a class instance, which can't
        # resolve to a module-level function named ``foo``. Drop.
        return False
    if receiver_class == target_class:
        # Same class — definitely possible.
        return True
    chain = _resolved_ancestor_chain(receiver_file, receiver_class, idx)
    if chain is None:
        # Couldn't resolve the receiver's hierarchy (cross-file
        # inheritance, dynamic bases). Stay over-inclusive.
        return True
    return target_class in chain


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
        if not isinstance(file_record, dict):
            continue
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


def _file_path_to_module(rel_path: str) -> Optional[str]:
    """Universal file-path → module conversion used by the same-file
    bare-name fast-path in ``function_called``.

    ``c/heartbeat.c`` → ``c.heartbeat``;
    ``packages/foo/bar.py`` → ``packages.foo.bar``;
    ``src/api/handler.rs`` → ``src.api.handler``.

    Matches the convention ``core.orchestration.reachability_enrichment.
    _path_to_module`` uses for the prepass — the prepass passes module-
    qualified names like ``c.heartbeat.read_u16_be`` to function_called,
    so the resolver needs to recognise the same module form to match
    same-file bare-name calls against them.

    Differs from ``_path_derived_module`` above: this helper is
    language-agnostic (strips ANY single suffix) and emits just the
    module, not a function-qualified candidate list. The two helpers
    serve different fast-paths and intentionally diverge in scope.

    Returns ``None`` for paths with no extension (extensionless
    scripts, Makefile-shaped artefacts) — those don't participate
    in module-style namespacing.
    """
    if not rel_path:
        return None
    from pathlib import PurePosixPath
    p = PurePosixPath(rel_path.replace("\\", "/"))
    if not p.suffix:
        return None
    parts = list(p.with_suffix("").parts)
    if not parts:
        return None
    return ".".join(parts)


def _path_derived_module(
    file_path: str, class_name: str, fn_name: str,
) -> List[str]:
    """Synthesise candidate ``<file_module>.<class_name>.<fn_name>``
    forms for languages where the file IS the module (Python / JS-TS
    / Ruby where no top-level module declaration sets
    ``package_name``).

    Returns one or two candidates — the raw path-derived form, plus
    a src-stripped form when the path starts with ``src/`` (the
    common Python src-layout / JS-TS monorepo convention). Empty
    list when the extension isn't recognised.
    """
    base = file_path
    suffix_match = None
    for suffix in (".pyi", ".py", ".tsx", ".jsx", ".mjs", ".cjs",
                    ".ts", ".js", ".rb"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            suffix_match = suffix
            break
    if suffix_match is None:
        return []
    if base.endswith("/__init__"):
        base = base[: -len("/__init__")]
    elif base.endswith("/index"):
        base = base[: -len("/index")]
    if not base:
        return []
    out: List[str] = [f"{base.replace('/', '.')}.{class_name}.{fn_name}"]
    if base.startswith("src/"):
        stripped = base[len("src/"):]
        if stripped:
            out.append(
                f"{stripped.replace('/', '.')}.{class_name}.{fn_name}",
            )
    return out


def _candidate_qualified_names(
    file_path: str,
    fn_name: str,
    *,
    package_name: Optional[str] = None,
    class_name: Optional[str] = None,
) -> List[str]:
    """Heuristic: derive plausible qualified names for an
    InternalFunction defined at ``(file_path, fn_name)``.

    Returns at most a handful of candidates (typically 1-2). Used by
    the index builder to canonicalise external callee edges that
    actually resolve to project-defined functions.

    Path-based heuristics (Python, JS/TS, Ruby): the file path
    encodes the module shape:
      * ``a/b/c.py`` → ``a.b.c``
      * ``a/b/__init__.py`` → ``a.b``
      * ``src/a/b/c.py`` → ``a.b.c`` (src-layout)
      * ``a/b/c.js`` → ``a.b.c`` / ``a/b/c``

    Declaration-based languages (Go, Java, Rust, C#, PHP) need
    the source's own package declaration to resolve correctly —
    the dir name is NOT authoritative. Those languages populate
    ``FileCallGraph.package_name`` from the extractor, and the
    resolver threads it in via ``package_name``.

    Returns an empty list when the file type isn't recognised and
    no package_name was supplied. Multiple candidates are returned
    in priority order; consumers do ``setdefault`` so the highest-
    confidence form wins.
    """
    candidates: List[str] = []

    # Declaration-based path: ``package_name`` from the extractor.
    # The qualified form depends on whether the language allows
    # module-level functions:
    #   * Java: every function lives inside a class. ONLY the
    #     class-qualified form ``<pkg>.<Class>.<method>`` is a
    #     valid resolution; the module-level form would falsely
    #     collide with another file declaring class ``<pkg>``.
    #   * C# / PHP: methods live inside classes, but module-level
    #     functions / global functions exist. Emit class-qualified
    #     first; fall through to module-level when no class.
    #   * Go / Rust: free functions are the norm; emit module-
    #     level. (Class-qualified is added too when present —
    #     Rust impl methods + Go method receivers benefit.)
    class_required = file_path.endswith(".java")
    if package_name and class_name:
        candidates.append(f"{package_name}.{class_name}.{fn_name}")
    if package_name and not (class_required and class_name is None):
        # In Java, a method with no class context shouldn't exist
        # — skip the module-level form to avoid colliding with
        # other files' class-qualified candidates that happen to
        # share the dotted prefix (e.g. ``com.example.Util.helper``
        # where one file's package is ``com.example.Util`` and
        # another's class is ``Util``).
        if not class_required:
            candidates.append(f"{package_name}.{fn_name}")

    # Python path-based heuristic.
    if file_path.endswith(".py") or file_path.endswith(".pyi"):
        base = file_path
        for suffix in (".pyi", ".py"):
            if base.endswith(suffix):
                base = base[: -len(suffix)]
                break
        if base.endswith("/__init__"):
            base = base[: -len("/__init__")]
        if base:
            candidates.append(f"{base.replace('/', '.')}.{fn_name}")
        # src-layout: ``src/mypkg/foo.py`` is imported as ``mypkg.foo``
        if base.startswith("src/"):
            stripped = base[len("src/"):]
            if stripped:
                candidates.append(
                    f"{stripped.replace('/', '.')}.{fn_name}",
                )

    # JS/TS / Ruby: file IS the module. Cross-package call sites
    # reference the file path (sans extension) or a stripped form.
    # Both shapes feed the import map.
    if file_path.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
                            ".rb")):
        base = file_path
        for suffix in (".tsx", ".mjs", ".cjs", ".jsx", ".js", ".ts", ".rb"):
            if base.endswith(suffix):
                base = base[: -len(suffix)]
                break
        if base.endswith("/index"):
            base = base[: -len("/index")]
        if base:
            module_form = base.replace("/", ".")
            # Class-qualified takes priority — JS / Ruby classes
            # exported from the file appear as ``<module>.<Class>.
            # <method>`` to importing callers that reference the
            # method via the class.
            if class_name:
                candidates.append(
                    f"{module_form}.{class_name}.{fn_name}",
                )
            # Dotted form (matches Ruby module nesting + JS's
            # canonical import-path-to-dotted transform).
            candidates.append(f"{module_form}.{fn_name}")

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
    #
    # Class-aware narrowing: each method_match entry carries the
    # receiver's class name (None when unknown). If the target is
    # a method of class T and the receiver's class R is known, we
    # can drop the entry when T isn't in R's ancestor chain — a
    # ``self.foo()`` inside ``class B`` can't possibly resolve to
    # ``class C.foo`` when B and C are unrelated. Entries with
    # ``receiver_class=None`` stay (the safe over-inclusive
    # default).
    method_match_set: Set[InternalFunction] = set()
    if isinstance(target, InternalFunction):
        candidates = idx.method_match.get(target.name, set())
        target_class = idx.class_of_method.get(target)
        narrowed: Set[InternalFunction] = set()
        for caller, receiver_class in candidates:
            if _method_match_compatible(
                    receiver_class=receiver_class,
                    receiver_file=caller.file_path,
                    target_class=target_class,
                    idx=idx):
                narrowed.add(caller)
        method_match_set = narrowed - definitive_set - uncertain_set

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


def is_framework_callable(
    inventory: Dict[str, Any],
    target: InternalFunction,
    *,
    exclude_test_files: bool = True,
) -> bool:
    """True iff ``target`` carries a framework-dispatch registration
    decorator (``@app.route``, ``@cli.command``, ``@task.fixture``,
    etc.). Such functions are reachable from outside the static call
    graph — the framework invokes them at runtime via internal
    dispatch — and consumers should treat them as live entry points
    even when ``callers_of`` returns an empty definitive set.

    See ``_FRAMEWORK_DISPATCH_TAILS`` for the heuristic.
    """
    idx = _get_or_build_index(inventory, exclude_test_files=exclude_test_files)
    return target in idx.framework_callable


def is_registered_via_call(
    inventory: Dict[str, Any],
    target: InternalFunction,
    *,
    exclude_test_files: bool = True,
) -> bool:
    """True iff ``target`` is passed as an identifier argument to a
    recognised framework registration call (``http.HandleFunc("/x",
    target)``, ``app.get("/users", target)``, ``router.use(target)``,
    etc.). Sister to :func:`is_framework_callable` but for the JS / Go
    pattern where the framework registers handlers via call arguments
    rather than decorators.

    Same-file matching only: ``target`` must be defined in the same
    file as the registration call. Cross-file resolution (handler in
    handlers.js, registration in routes.js) requires walking the
    file's import map and is a documented limitation — same as
    ``is_framework_callable``'s cross-file caveats for decorators.

    See ``_FRAMEWORK_REGISTRATION_TAILS`` for the registration-call
    pattern set.
    """
    idx = _get_or_build_index(inventory, exclude_test_files=exclude_test_files)
    return target in idx.framework_registered


def module_aborts_on_load(
    inventory: Dict[str, Any],
    file_path: str,
) -> Optional[Dict[str, Any]]:
    """Return the module-load-abort record for ``file_path`` if the
    inventory builder detected an unconditional top-of-module abort
    (``raise ImportError`` / ``throw new Error`` / ``init() panic`` /
    ``compile_error!``), else ``None``.

    When non-None, no function defined in the file (at or below the
    abort's line) is reachable through normal import / link: the
    file's top-level execution aborts before those bindings complete.
    Consumers treat this as a whole-file reachability gate that
    supersedes in-file call edges — a function called only by peers
    in the same aborting file is still dead, because the file never
    finishes loading.

    The returned dict carries ``line`` (1-indexed location of the
    abort) and ``summary`` (short label, e.g. ``"raise ImportError"``)
    — see :class:`core.inventory.module_load_abort.ModuleLoadAbort`.
    Detected at inventory-build time and stored on the file record;
    this accessor is a simple path-keyed lookup (no index build).
    """
    if not file_path:
        return None
    normalised = file_path.replace("\\", "/")
    for file_record in inventory.get("files", []):
        if not isinstance(file_record, dict):
            continue
        rec_path = file_record.get("path")
        if not isinstance(rec_path, str):
            continue
        if rec_path.replace("\\", "/") == normalised:
            abort = file_record.get("module_aborts_on_load")
            return abort if isinstance(abort, dict) else None
    return None


def build_excluded(
    inventory: Dict[str, Any],
    file_path: str,
) -> Optional[Dict[str, Any]]:
    """Return the build-exclusion record for ``file_path`` if the inventory
    builder detected that the file is never compiled (e.g. Go
    ``//go:build ignore``), else ``None``.

    When non-None, NO function in the file is reachable: the translation unit
    is excluded from the build, so nothing in it is compiled or linked —
    regardless of in-file call edges or external linkage. Unlike
    :func:`module_aborts_on_load` this is whole-file with no line threshold
    (a compile-time, not runtime, property). HEURISTIC, not sound: a build
    constraint is config-dependent (a forced build / alternate tag set could
    include the file), so consumers surface-only — demote / annotate, never
    hard-suppress.

    The returned dict carries ``line`` (constraint location, display-only)
    and ``summary`` (e.g. ``"//go:build ignore"``). Path-keyed lookup, no
    index build — mirrors :func:`module_aborts_on_load`.
    """
    if not file_path:
        return None
    normalised = file_path.replace("\\", "/")
    for file_record in inventory.get("files", []):
        if not isinstance(file_record, dict):
            continue
        rec_path = file_record.get("path")
        if not isinstance(rec_path, str):
            continue
        if rec_path.replace("\\", "/") == normalised:
            rec = file_record.get("build_excluded")
            return rec if isinstance(rec, dict) else None
    return None


def is_lexically_dead(
    inventory: Dict[str, Any],
    file_path: str,
    name: str,
    line: int = 0,
) -> bool:
    """True iff ``name`` (at ``line``, when given) is defined inside a
    lexically dead scope — an always-false guard (``if False:`` /
    ``if (false) {…}`` / ``#[cfg(any())]``) whose body never executes
    or compiles, so the function never binds (S3).

    Consumers treat this like a per-function reachability gate that
    supersedes in-scope call edges: two dead-scope functions calling
    each other read as mutually CALLED in the static graph, but the
    whole scope is dead. Detected at inventory-build time and stored
    as ``lexical_dead=True`` on the matching item; this accessor is a
    path/name-keyed lookup (no index build).

    Match is exact on ``(name, line)`` when ``line > 0`` — defensive
    against shadowed names / overloads. With ``line == 0`` it matches
    by name within the file (first hit wins). Returns ``False`` when
    the file or function isn't found (false-negative-safe: never
    claims dead when uncertain).
    """
    if not file_path or not name:
        return False
    normalised = file_path.replace("\\", "/")
    for file_record in inventory.get("files", []):
        if not isinstance(file_record, dict):
            continue
        rec_path = file_record.get("path")
        if not isinstance(rec_path, str):
            continue
        if rec_path.replace("\\", "/") != normalised:
            continue
        for item in file_record.get("items", []):
            if not isinstance(item, dict):
                continue
            if item.get("name") != name:
                continue
            if line and item.get("line_start") != line:
                continue
            return bool(item.get("lexical_dead"))
        return False
    return False


# ---------------------------------------------------------------------------
# Entry-point forward reachability (U7) — "is this reachable from a real
# entry, or only from an orphaned/dead chain?"
# ---------------------------------------------------------------------------
#
# ``function_called`` answers the 1-hop "does anything call this name?" — it
# reads CALLED for a function whose only caller is itself dead (a cluster of
# mutually-calling functions with no external entry: the dead-island). This
# adds the transitive answer: a function is reachable-from-entry iff it OR
# some function in its reverse-closure is an entry point. If none is, and
# the entry model is closeable for the language and no indirection could
# hide an entry edge, it's NO_PATH_FROM_ENTRY.
#
# Entry model per language (what can be invoked from outside the project's
# own call graph):
#   * any language: framework_callable / framework_registered (runtime
#     dispatch), and a function named ``main``.
#   * C/C++: non-``static`` functions (external linkage — another TU may
#     call them). SOUND + closeable: the static/extern split is total.
#   * Go: exported (Capitalized) functions.
#   * Rust: ``pub`` functions.
#   * JS/TS: exported functions.
#   * Java: ``public`` methods.
#   * Python: module-level public (non-``_``) functions.
#   * unknown language: treat every function as an entry → never flags
#     (false-negative-safe).
#
# Completeness: where the entry model isn't a closed signal, or an ancestor
# file uses call-masking indirection (getattr / reflection / func-like
# macros) that could hide an entry edge, return UNCERTAIN rather than claim
# NO_PATH_FROM_ENTRY. Surface-only consumers treat UNCERTAIN as "analyze".

# Per-language reachability profile — the declarative entry model. Adding a
# language's entry behaviour is one PROFILES entry; the entry accessors below
# derive from it instead of inline ``if language ==`` chains.
#
#   entry_model:
#     "sound"     — closed linkage/visibility signal; a NO_PATH_FROM_ENTRY
#                   verdict is trustworthy (C/C++ static-vs-extern, Go
#                   exported, Rust pub). entry_reachability may return NO_PATH.
#     "heuristic" — entries identifiable but the model isn't closed (dynamic
#                   dispatch / reflection); NO_PATH would be surface-only.
#                   (No language uses this yet — the Python/Java dead-island
#                   coverage units flip it on; today nothing is "heuristic".)
#     "none"      — no visibility-based entry signal; functions fall through
#                   to UNCERTAIN + the 1-hop NOT_CALLED logic (py/js/java/…).
#   visibility_entry: how a function's visibility marks it an external entry —
#     "non_static" (C/C++) | "go_exported" | "rust_pub" | "" (none).
#   has_go_init / has_java_web: language-specific framework-dispatch entries.
@dataclass(frozen=True)
class ReachabilityProfile:
    language: str
    entry_model: str = "none"
    visibility_entry: str = ""
    has_go_init: bool = False
    has_java_web: bool = False


PROFILES: Dict[str, ReachabilityProfile] = {
    "c":    ReachabilityProfile("c", "sound", "non_static"),
    "cpp":  ReachabilityProfile("cpp", "sound", "non_static"),
    "go":   ReachabilityProfile("go", "sound", "go_exported", has_go_init=True),
    "rust": ReachabilityProfile("rust", "sound", "rust_pub"),
    "java": ReachabilityProfile("java", "none", has_java_web=True),
    "python":     ReachabilityProfile("python", "none"),
    "javascript": ReachabilityProfile("javascript", "none"),
    "typescript": ReachabilityProfile("typescript", "none"),
    "ruby":       ReachabilityProfile("ruby", "none"),
    "csharp":     ReachabilityProfile("csharp", "none"),
    "php":        ReachabilityProfile("php", "none"),
}

_DEFAULT_PROFILE = ReachabilityProfile("")


def _profile(language: str) -> ReachabilityProfile:
    return PROFILES.get(language or "", _DEFAULT_PROFILE)


# Languages whose entry model is a closed, sound signal — DERIVED from the
# profiles (a NO_PATH verdict is trustworthy only for these). Kept as a
# frozenset for the entry_reachability soundness gate.
_CLOSEABLE_ENTRY_LANGS = frozenset(
    lang for lang, p in PROFILES.items() if p.entry_model == "sound"
)

# Java servlet / filter lifecycle methods — invoked by the container, no
# in-project caller. (init/destroy are generic names too; treating them as
# entries is the conservative, false-negative-safe direction.)
_JAVA_SERVLET_METHODS = frozenset({
    "doGet", "doPost", "doPut", "doDelete", "doHead", "doOptions",
    "doTrace", "service", "doFilter", "init", "destroy",
})
# Method-level annotation tail-names whose presence marks the method as
# framework-dispatched: the container / framework invokes it directly, so it
# needs no in-project caller to be reachable. Only annotations that denote a
# *no-caller* dispatch belong here — ``@Async`` / ``@Transactional`` are
# deliberately excluded because they merely wrap a normally-called method
# (it still has an in-project caller), so treating them as entries would
# wrongly shield a genuinely-dead async/transactional method from demotion.
_JAVA_METHOD_DISPATCH_ANNOTATIONS = frozenset({
    # JAX-RS / Spring MVC routing
    "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "Path",
    "RequestMapping", "GetMapping", "PostMapping", "PutMapping",
    "DeleteMapping", "PatchMapping",
    # Spring bean factory + container lifecycle callbacks
    "Bean", "PostConstruct", "PreDestroy",
    # Spring events + scheduling (container-invoked, no in-project caller)
    "EventListener", "Scheduled",
    # Message-driven listeners (Spring Messaging / Kafka / Rabbit / JMS / STOMP)
    "KafkaListener", "RabbitListener", "JmsListener",
    "MessageMapping", "SubscribeMapping", "StreamListener",
    # JPA / Hibernate entity lifecycle callbacks (persistence-provider-invoked)
    "PrePersist", "PostPersist", "PreUpdate", "PostUpdate",
    "PreRemove", "PostRemove", "PostLoad",
})
# Class-level stereotype annotation tail-names. The DI container instantiates
# the annotated class and dispatches into its PUBLIC methods (via injected
# references / proxies) with no in-project caller. Private / protected /
# package-private methods stay reachable only through the static closure from
# those public entries, so they are NOT promoted here.
_JAVA_CLASS_STEREOTYPES = frozenset({
    "Component", "Service", "Repository", "Controller", "RestController",
    "Configuration", "ControllerAdvice", "RestControllerAdvice",
})


def _annotation_tail(annotation: Any) -> str:
    """``@org.springframework...RequestMapping("/x")`` → ``RequestMapping``.

    Strips a fully-qualified prefix, any argument list, and a leading ``@``
    (the extractor stores attributes already ``@``-stripped, but be defensive).
    """
    return str(annotation).split("(")[0].strip().split(".")[-1].lstrip("@")


def _java_framework_entry(name: str, item: Dict[str, Any]) -> bool:
    """A Java method dispatched by a framework / DI container with no
    in-project caller — servlet lifecycle method, method-level dispatch
    annotation, or a public method of a stereotyped (container-managed) class.

    Adding an entry only ever *grows* the reachable set, so this can never
    suppress real code or demote live code; the worst case is failing to
    demote a genuinely-dead annotated method (under-claiming dead code).
    """
    if name in _JAVA_SERVLET_METHODS:
        return True
    meta = item.get("metadata") or {}
    for a in meta.get("attributes") or []:
        if _annotation_tail(a) in _JAVA_METHOD_DISPATCH_ANNOTATIONS:
            return True
    # Class stereotype → only the bean's PUBLIC methods are container-dispatched.
    if "public" in str(meta.get("visibility") or "").split():
        for a in meta.get("class_attributes") or []:
            if _annotation_tail(a) in _JAVA_CLASS_STEREOTYPES:
                return True
    return False


def _item_is_entry(item: Dict[str, Any], language: str) -> bool:
    """Is this inventory item an externally-invocable entry point under its
    language's linkage/visibility model? (Framework dispatch is handled
    separately off the adjacency index.)

    Visibility/linkage is only treated as an entry signal for the
    *closeable-entry* languages (C/C++ static-vs-extern, Go exported, Rust
    pub) — there it's total and sound. For fuzzy languages (Python / JS /
    Java) a public symbol is NOT reliably an entry (a public app function
    may be plain dead code, not a library API), so we don't treat it as
    one; those functions fall through to UNCERTAIN and the caller's
    existing 1-hop NOT_CALLED logic, leaving their behavior unchanged.
    ``main`` and framework dispatch are entries in every language.
    """
    name = item.get("name") or ""
    if name == "main":
        return True
    p = _profile(language)
    # Go runs every ``func init()`` automatically at package load — init
    # and its call tree are reachable even with no explicit caller.
    if p.has_go_init and name == "init":
        return True
    # Java framework-dispatched entries with no in-project caller: servlet
    # lifecycle methods, method-level dispatch annotations (routing, Spring
    # events/scheduling/messaging, bean factories, JPA callbacks), and public
    # methods of stereotyped (container-managed) classes. Without this, live
    # container-managed handlers (doPost, @EventListener, @Service methods)
    # read not_called and get surface-demoted.
    if p.has_java_web and _java_framework_entry(name, item):
        return True
    # Visibility/linkage entry signal (only for languages whose model is a
    # closed signal; "" ⇒ a public symbol is NOT reliably an entry, so those
    # fall through to UNCERTAIN + 1-hop NOT_CALLED, behaviour unchanged).
    if not p.visibility_entry:
        return False
    vis = (item.get("metadata") or {}).get("visibility")
    if p.visibility_entry == "non_static":
        # External linkage = potential entry from another TU. NOTE: a
        # ``static`` function whose ADDRESS is stored in a non-static /
        # exported object (an ops/vtable dispatch table) is externally
        # reachable too, but the call graph doesn't track address-taking —
        # such functions can read NO_PATH_FROM_ENTRY. Surface-only keeps this
        # from silencing them; tracking address-of is a substrate follow-up.
        return vis != "static"
    if p.visibility_entry == "go_exported":
        return vis == "exported" or name[:1].isupper()
    if p.visibility_entry == "rust_pub":
        return vis in ("public", "pub")
    return False


_ENTRY_SET_CACHE: Dict[int, Tuple[Dict[str, Any], "frozenset"]] = {}
_ENTRY_SET_CACHE_MAX = 8


def _entry_functions(inventory: Dict[str, Any]) -> "frozenset":
    """Set of InternalFunction entry points (visibility/linkage model +
    framework dispatch). Cached per-inventory by identity."""
    inv_id = id(inventory)
    cached = _ENTRY_SET_CACHE.get(inv_id)
    if cached is not None and cached[0] is inventory:
        return cached[1]
    entries: Set[InternalFunction] = set()
    for fr in inventory.get("files", []):
        if not isinstance(fr, dict):
            continue
        lang = fr.get("language") or ""
        path = fr.get("path") or ""
        for item in fr.get("items", []):
            if not isinstance(item, dict):
                continue
            if item.get("kind", "function") != "function":
                continue
            if _item_is_entry(item, lang):
                entries.add(InternalFunction(
                    file_path=path, name=item.get("name") or "",
                    line=int(item.get("line_start") or 0),
                ))
    idx = _get_or_build_index(inventory, exclude_test_files=True)
    entries |= idx.framework_callable
    entries |= idx.framework_registered
    frozen = frozenset(entries)
    _ENTRY_SET_CACHE[inv_id] = (inventory, frozen)
    if len(_ENTRY_SET_CACHE) > _ENTRY_SET_CACHE_MAX:
        _ENTRY_SET_CACHE.pop(next(iter(_ENTRY_SET_CACHE)), None)
    return frozen


# (reachable_set, closure_truncated) per inventory.
_ENTRY_REACHABLE_CACHE: Dict[int, Tuple[Dict[str, Any], "frozenset", bool]] = {}
# Closure depth for the entry set. Far above any realistic call-chain
# depth so reachability isn't lost to truncation (a truncated closure
# would falsely read deep-reachable functions as NO_PATH). It's a single
# cached BFS bounded by the graph size, so a high cap costs nothing extra.
_ENTRY_CLOSURE_MAX_DEPTH = 100_000


def _entry_reachable_set(
    inventory: Dict[str, Any],
) -> Tuple["frozenset", bool]:
    """``(reachable_set, truncated)``. ``reachable_set`` is every
    InternalFunction reachable from any entry (entries + their forward
    closure). ``truncated`` is True if the closure hit the depth cap — in
    which case the set may be incomplete and callers must not claim
    NO_PATH from a miss.

    One cached forward_closure (not a reverse walk per query), so
    membership is O(1) and the prepass can query every function cheaply.
    """
    inv_id = id(inventory)
    cached = _ENTRY_REACHABLE_CACHE.get(inv_id)
    if cached is not None and cached[0] is inventory:
        return cached[1], cached[2]
    entries = _entry_functions(inventory)
    fc = forward_closure(
        inventory, entries, max_depth=_ENTRY_CLOSURE_MAX_DEPTH,
    )
    reachable = set(entries)
    reachable.update(
        n for n in fc.nodes if isinstance(n, InternalFunction)
    )
    frozen = frozenset(reachable)
    _ENTRY_REACHABLE_CACHE[inv_id] = (inventory, frozen, fc.truncated)
    if len(_ENTRY_REACHABLE_CACHE) > _ENTRY_SET_CACHE_MAX:
        _ENTRY_REACHABLE_CACHE.pop(next(iter(_ENTRY_REACHABLE_CACHE)), None)
    return frozen, fc.truncated


def _file_language(inventory: Dict[str, Any], file_path: str) -> Optional[str]:
    norm = file_path.replace("\\", "/")
    for fr in inventory.get("files", []):
        if isinstance(fr, dict) and (fr.get("path") or "").replace("\\", "/") == norm:
            return fr.get("language")
    return None


def _file_has_masking(inventory: Dict[str, Any], file_path: str) -> bool:
    norm = file_path.replace("\\", "/")
    for fr in inventory.get("files", []):
        if not isinstance(fr, dict) or (fr.get("path") or "").replace("\\", "/") != norm:
            continue
        cg = fr.get("call_graph") or {}
        if set(cg.get("indirection") or []) & _MASKING_FLAGS:
            return True
        if cg.get("macro_call_targets"):
            return True
        return False
    return False


def entry_reachability(
    inventory: Dict[str, Any],
    target: InternalFunction,
    *,
    max_depth: int = 50,
) -> str:
    """``"reachable"`` | ``"no_path_from_entry"`` | ``"uncertain"``.

    Reachable iff ``target`` is in the entry-reachable set (entries + their
    forward closure). NO_PATH_FROM_ENTRY only when the language's entry
    model is closeable AND no file on a path that could reach the target
    carries call-masking indirection that might hide an entry edge;
    otherwise UNCERTAIN (the false-negative-safe default). Surface-only:
    consumers surface the verdict, they do not suppress on it.

    Perf: the reachable set is one cached forward-closure, so the common
    "reachable" answer is an O(1) membership test. The reverse-closure walk
    (for the masking check) runs ONLY for the non-reachable minority.
    """
    reachable, truncated = _entry_reachable_set(inventory)
    if target in reachable:
        return "reachable"
    if truncated:
        # The closure was depth-capped, so the reachable set may be
        # incomplete — a deep-reachable function could be missing. Don't
        # claim NO_PATH off an incomplete set.
        return "uncertain"
    # Not reachable from any entry. Decide confident-dead vs uncertain.
    lang = _file_language(inventory, target.file_path)
    if lang not in _CLOSEABLE_ENTRY_LANGS:
        return "uncertain"          # fuzzy entry model (py/js/...) → don't claim
    # Call-masking indirection (reflection / func-like macros) in the
    # target's file, or in any function that transitively calls it, could
    # hide an entry edge the static graph didn't capture → don't claim
    # dead. This reverse walk only runs for the not-reachable minority.
    if _file_has_masking(inventory, target.file_path):
        return "uncertain"
    rc = reverse_closure(inventory, target, max_depth=max_depth)
    for fn in rc.nodes:
        if isinstance(fn, InternalFunction) and _file_has_masking(
            inventory, fn.file_path,
        ):
            return "uncertain"
    return "no_path_from_entry"


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
        if not isinstance(file_record, dict):
            continue
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
    "is_framework_callable",
    "entry_reachability",
    "is_lexically_dead",
    "is_registered_via_call",
    "module_aborts_on_load",
    "parse_evidence_entry",
    "reverse_closure",
    "shortest_path",
]
