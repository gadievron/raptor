"""Package-scope Python call graph — cross-module resolution + assembly.

Lifts the call-graph view from single-file
(:mod:`core.analysis.python_module_callgraph`, whose docstring
declares cross-module resolution out of scope by design) to the whole
package tree. No parsing happens here: the raw material is the
per-file facts the inventory already extracts
(:mod:`core.inventory.call_graph` — import maps, relative-import
quads, call sites, class defs, decorated functions, dispatch tables,
getattr sites). This module's job is RESOLUTION (binding names across
module boundaries) and GRAPH ASSEMBLY (materialising nodes + edges
into a serialisable artifact).

## Consuming doctrine — originate and prioritize, never refute

This graph is an over- AND under-approximation at the same time:
dynamic dispatch it cannot see means real edges are missing; fan-out
across candidate definitions means some recorded edges never execute.
Consumers may use it to ORIGINATE work (seed candidate flows, find
callers to look at) and to PRIORITIZE (rank by proximity), and must
NEVER use it to refute or suppress — the absence of a path in an
incomplete graph is not evidence that no path exists. The API shape
enforces this: there is a :meth:`PackageCallGraph.paths_found` query
(positive evidence only) and deliberately NO ``no_path_exists`` /
``is_dead`` / not-called verdict surface. Reachability VERDICTS stay
with :mod:`core.analysis.reachability`, whose UNCERTAIN semantics are
built for suppression decisions.

That doctrine split is also why this module resolves more
aggressively than the sanitizer-cut substrate: the module-local graph
refuses shadowed / rebound names because its consumers certify
sanitizers (suppression-grade); an extra edge here can only add a
candidate to look at, so the local-rebind shadow guards are
deliberately not replicated.

## Resolution classes and confidence tiers

Every edge carries a ``tier``:

  * ``resolved_static`` — a single definition bound through an exact
    static route: same-file unique bare name, ``from x import y``
    (aliased or not, re-exported through ``__init__.py`` or not),
    ``import x`` + dotted call, ``Class.method`` where both class
    and method are statically defined.
  * ``resolved_convention`` — bound through a language convention
    that admits runtime variance: ``self.``/``cls.`` method calls
    (a subclass may override), inherited methods found by walking
    same-package bases, constructors (``Class()`` →
    ``Class.__init__``), and any resolution that fans out across
    multiple same-name definitions.
  * ``heuristic_dynamic`` — the two literal dynamic idioms turned
    into explicit low-confidence edges: dict-dispatch
    (``HANDLERS[k]()`` against a literal table of function refs)
    and ``getattr(obj, "literal")`` matched by bare name across the
    package.
  * ``unresolved`` — not an edge tier: call sites that resolve to
    nothing appear as explicit :class:`UnresolvedCall` records
    (never a silent drop), so a consumer can see exactly where the
    graph is blind.

Calls that leave the package (``requests.get(...)``) are not
"unresolved" — they resolve to an external name and are recorded in
``external_calls`` (the later config-driven consumers key off those
dotted names). Calls to Python builtins are counted in ``stats`` but
not recorded per-site: they would dominate every artifact while
carrying no cross-module information. The builtin name set is read
from the running interpreter (``dir(builtins)``), never hardcoded.

## Known silent gaps (missing edges with NO marker)

The unresolved-call records mark blind spots the resolver can SEE.
These it cannot — consumers ranking by absence of an edge must know
they exist (one more reason the doctrine forbids refutation):

  * Conditional imports: ``try: from a import f / except
    ImportError: from b import f`` — the extractor's import map is
    last-wins, so only the later provider gets the (confidently
    static) edge; the alternate provider vanishes unmarked. Rebinds
    that involve a relative-import quad are counted in
    ``stats.import_name_rebound``; absolute-vs-absolute rebinds are
    already collapsed at extraction time and are not countable here.
  * ``super()`` dispatch: ``super().m()`` has a call-result root —
    no name chain, no call-site record, no marker.
  * Method lookup order is an approximation (breadth-first over the
    declared bases), not C3 linearisation — a diamond whose MRO
    prefers a grandparent over a later direct base can bind to the
    wrong (same-name) override. The convention tier already flags
    the variance; the specific-node choice can still differ from
    runtime.
  * Module-level rebinds after a def (``f = wrapper(f)``) keep the
    def's edge — the graph resolves the written name, not the
    runtime slot.

## Bounds

Hostile / huge repos are the norm. Every accumulation is capped, and
hitting a cap degrades the artifact with an explicit ``caps_hit``
marker instead of failing. All walkers are iterative — a
pathological package layout must exhaust a budget, not the Python
stack. Record FIELDS are sanitised at the assembly boundary: the
artifact is loaded from disk across versions, so a malformed shape
(wrong container type, non-numeric line) degrades to a
``stats.malformed_facts`` count — :func:`build_package_callgraph`
never raises on record content.
"""
from __future__ import annotations

import builtins
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.json import load_json, save_json

SCHEMA_VERSION = 1

# Default artifact filename (written next to the other run artifacts).
PACKAGE_CALLGRAPH_FILENAME = "package-callgraph.json"

# The doctrine marker serialised into the artifact so downstream
# readers that never import this module still see the contract.
DOCTRINE = "originate_and_prioritize_only"

# --- confidence tiers -------------------------------------------------------

TIER_RESOLVED_STATIC = "resolved_static"
TIER_RESOLVED_CONVENTION = "resolved_convention"
TIER_HEURISTIC_DYNAMIC = "heuristic_dynamic"
TIER_UNRESOLVED = "unresolved"

# --- edge kinds -------------------------------------------------------------

KIND_CALL = "call"
KIND_METHOD_CALL = "method_call"
KIND_CONSTRUCTOR = "constructor"
KIND_DECORATOR = "decorator"
KIND_DICT_DISPATCH = "dict_dispatch"
KIND_GETATTR_DISPATCH = "getattr_dispatch"

# --- unresolved reasons -----------------------------------------------------

REASON_UNKNOWN_NAME = "unknown_name"
REASON_DYNAMIC_ATTRIBUTE = "dynamic_attribute"
REASON_UNMATCHED_METHOD = "unmatched_method"
REASON_CONSTRUCTOR_NO_INIT = "constructor_no_init"
REASON_DISPATCH_TABLE_UNKNOWN = "dispatch_table_unknown"
REASON_GETATTR_OPAQUE = "getattr_opaque"
REASON_GETATTR_UNMATCHED = "getattr_unmatched"
REASON_GETATTR_FANOUT_CAP = "getattr_fanout_cap"

# --- bounds -----------------------------------------------------------------
# Every cap trades completeness on pathological inputs against
# bounded memory / time on hostile ones. Hitting any of them appends
# a marker to ``caps_hit`` — a capped artifact is still valid for
# origination (its edges are real), it just covers less.

# Files admitted to the build. Higher covers monorepos in one
# artifact; lower protects the build from a planted tree of millions
# of tiny files. 20k files ≈ the largest single-package Python trees
# in the wild, and a repo past it should be built per-subtree.
_MAX_FILES = 20_000

# Node ceiling. Higher keeps every def of a machine-generated tree;
# lower bounds the artifact (and every consumer's load) — past the
# cap remaining files still parse but add no nodes, so edges into
# the retained set stay intact.
_MAX_NODES = 200_000

# Edge ceiling. Higher preserves complete fan-out on call-dense
# code; lower stops one hostile file (one caller, 500k call sites)
# from inflating the artifact unboundedly.
_MAX_EDGES = 500_000

# Unresolved-marker ceilings, total and per file. Higher keeps every
# blind spot addressable; lower stops obfuscated code (every call
# dynamic) from drowning the artifact in markers — past the cap the
# count still accumulates in ``stats`` so nothing is silent.
_MAX_UNRESOLVED_TOTAL = 20_000
_MAX_UNRESOLVED_PER_FILE = 200

# External-call ceiling. Higher gives the downstream consumers a
# complete out-of-package call census; lower bounds the artifact on
# import-heavy trees. External calls are one small record each, so
# this sits above the unresolved cap.
_MAX_EXTERNAL_TOTAL = 50_000

# getattr-by-literal fan-out per site. Higher catches dispatch onto
# very common method names; lower keeps one ``getattr(x, "run")`` in
# a 5000-runner package from minting 5000 heuristic edges (noise
# that would bury the tiers' signal). Over-cap sites degrade to an
# explicit fanout-cap marker instead of a partial edge set.
_MAX_GETATTR_FANOUT = 16

# Base-class walk ceiling per method lookup. Higher resolves deeper
# (or adversarially circular) inheritance lattices; lower bounds the
# per-call work. Real hierarchies are < 10 deep.
_MAX_BASE_WALK = 32

# Re-export alias discovery iterations (same fixed-point bound as
# reachability's pass 1.6) — real ``__init__`` re-export chains are
# 3-4 deep; the bound only exists so a crafted alias cycle can't
# spin the build.
_REEXPORT_FIXPOINT_ITERS = 8

# Wall-clock budget for the whole build, checked between files.
# Higher finishes giant trees in one artifact; lower keeps the build
# a predictable pipeline stage — past budget the graph ships with
# whatever was assembled plus the ``time_budget`` marker.
_BUILD_TIME_BUDGET_S = 120.0

# paths_found defaults. Path enumeration is exponential in the
# worst case; these bound one query. Higher finds more alternatives
# per query; lower keeps the query interactive.
_MAX_PATHS = 8
_MAX_PATH_DEPTH = 20
_MAX_PATH_EXPANSIONS = 50_000

# Python builtins, read from the interpreter — never a hardcoded
# vocabulary list. Calls to these carry no cross-module edge
# information (``len``, ``print``, ``staticmethod``, ...).
_BUILTIN_NAMES: frozenset[str] = frozenset(dir(builtins))

# Synthetic per-file module node name. Illegal as a Python
# identifier, so it can't collide with a real function — same
# convention as python_module_callgraph.MODULE_ENTRY_NAME.
MODULE_NODE_NAME = "<module>"

# Path prefixes stripped to form ALIAS module names (src-layout).
# Mirrors the convention in ``reachability._path_derived_module`` so
# both consumers of the same inventory agree on dotted forms.
_LAYOUT_PREFIXES = ("src/", "lib/")


# ---------------------------------------------------------------------------
# Artifact dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CallGraphNode:
    """One function (or synthetic per-file module entry) in the graph.

    ``node_id`` is deterministic and collision-free:
    ``<file_path>::<name>@<line>`` — file-path based, so two source
    roots mapping to the same dotted module can't merge. ``name`` is
    module-local (``"f"``, ``"Class.m"``, ``"<module>"``); ``module``
    is the file's dotted module path (``""`` when not derivable).
    """
    node_id: str
    kind: str                       # "function" | "module"
    file_path: str
    name: str
    module: str
    line: int
    end_line: int | None = None
    class_name: str | None = None

    @property
    def qual_name(self) -> str:
        """Dotted package-scope name (``pkg.mod.Class.m``)."""
        return f"{self.module}.{self.name}" if self.module else self.name


@dataclass(frozen=True)
class CallGraphEdge:
    """One resolved edge. ``lines`` lists every call line observed
    for this (src, dst, tier, kind) — multiplicity kept for evidence
    rendering, deduplicated as an edge."""
    src: str
    dst: str
    tier: str
    kind: str
    lines: tuple[int, ...] = ()


@dataclass(frozen=True)
class UnresolvedCall:
    """One call site the resolver could not bind — the explicit
    marker that replaces a silent drop. ``caller`` is the source
    node id (module node for module-level calls) or None when even
    the caller couldn't be attributed."""
    file_path: str
    line: int
    caller: str | None
    chain: tuple[str, ...]
    reason: str
    tier: str = TIER_UNRESOLVED


@dataclass(frozen=True)
class ExternalCall:
    """One call that resolves OUT of the package — a dotted name
    whose root is not part of the analysed tree. Not an edge (there
    is no in-package destination node) and not unresolved (the
    binding is known); downstream consumers key off ``target``."""
    file_path: str
    line: int
    caller: str | None
    target: str


@dataclass(frozen=True)
class PathsFound:
    """Positive path evidence between two nodes.

    ``paths`` holds up to ``max_paths`` simple paths as node-id
    sequences. An EMPTY ``paths`` means "none found within budget",
    never "no path exists" — and even ``budget_exhausted=False``
    proves nothing about absence: the graph itself is incomplete by
    construction (unresolved calls, invisible dynamic dispatch).
    There is deliberately no completeness claim on this result.
    """
    paths: tuple[tuple[str, ...], ...] = ()
    budget_exhausted: bool = False


# ---------------------------------------------------------------------------
# The graph
# ---------------------------------------------------------------------------


@dataclass
class PackageCallGraph:
    """Assembled package-scope call graph + assembly diagnostics.

    Query surface is positive-evidence only (see the module
    docstring): ``callees_of`` / ``callers_of`` / ``paths_found``.
    """
    nodes: tuple[CallGraphNode, ...] = ()
    edges: tuple[CallGraphEdge, ...] = ()
    unresolved_calls: tuple[UnresolvedCall, ...] = ()
    external_calls: tuple[ExternalCall, ...] = ()
    caps_hit: tuple[str, ...] = ()
    stats: dict[str, int] = field(default_factory=dict)
    language: str = "python"
    schema_version: int = SCHEMA_VERSION
    # Derived indices — built lazily, never serialised, and excluded
    # from equality (an indexed graph must compare equal to its
    # freshly-deserialised twin).
    _by_id: dict[str, CallGraphNode] = field(
        default_factory=dict, repr=False, compare=False)
    _out: dict[str, tuple[CallGraphEdge, ...]] = field(
        default_factory=dict, repr=False, compare=False)
    _in: dict[str, tuple[CallGraphEdge, ...]] = field(
        default_factory=dict, repr=False, compare=False)
    _indexed: bool = field(default=False, repr=False, compare=False)

    # -- indices ---------------------------------------------------------

    def _ensure_indices(self) -> None:
        if self._indexed:
            return
        self._by_id = {n.node_id: n for n in self.nodes}
        out: dict[str, list[CallGraphEdge]] = {}
        inn: dict[str, list[CallGraphEdge]] = {}
        for e in self.edges:
            out.setdefault(e.src, []).append(e)
            inn.setdefault(e.dst, []).append(e)
        # Deterministic successor order → deterministic path
        # enumeration and stable test snapshots.
        self._out = {
            k: tuple(sorted(v, key=lambda e: (e.dst, e.kind, e.tier)))
            for k, v in out.items()
        }
        self._in = {
            k: tuple(sorted(v, key=lambda e: (e.src, e.kind, e.tier)))
            for k, v in inn.items()
        }
        self._indexed = True

    # -- queries ---------------------------------------------------------

    def node(self, node_id: str) -> CallGraphNode | None:
        self._ensure_indices()
        return self._by_id.get(node_id)

    def nodes_by_name(self, bare_name: str) -> tuple[CallGraphNode, ...]:
        """Every function node whose module-local bare name matches
        (method names match without their class prefix)."""
        self._ensure_indices()
        return tuple(
            n for n in self.nodes
            if n.kind == "function"
            and n.name.rsplit(".", 1)[-1] == bare_name
        )

    def callees_of(self, node_id: str) -> tuple[CallGraphEdge, ...]:
        """Outgoing edges of ``node_id`` (empty tuple for unknown
        ids). An empty result is not absence evidence — unresolved
        and dynamic call sites are not in the edge set."""
        self._ensure_indices()
        return self._out.get(node_id, ())

    def callers_of(self, node_id: str) -> tuple[CallGraphEdge, ...]:
        """Incoming edges of ``node_id``. Same incompleteness caveat
        as :meth:`callees_of`."""
        self._ensure_indices()
        return self._in.get(node_id, ())

    def paths_found(
        self,
        src_id: str,
        dst_id: str,
        *,
        max_paths: int = _MAX_PATHS,
        max_depth: int = _MAX_PATH_DEPTH,
        max_expansions: int = _MAX_PATH_EXPANSIONS,
    ) -> PathsFound:
        """Enumerate up to ``max_paths`` simple paths src → dst.

        Positive evidence only — see :class:`PathsFound` for why an
        empty result never means "no path". There is deliberately no
        ``no_path_exists`` counterpart to this method.

        Iterative DFS with an explicit stack (a deep or crafted
        graph must exhaust the expansion budget, not the Python
        stack).
        """
        self._ensure_indices()
        if src_id not in self._by_id or dst_id not in self._by_id:
            return PathsFound()
        if src_id == dst_id:
            return PathsFound(paths=((src_id,),))
        paths: list[tuple[str, ...]] = []
        budget_exhausted = False
        expansions = 0
        path: list[str] = [src_id]
        on_path: set[str] = {src_id}
        stack: list[tuple[str, int]] = [(src_id, 0)]  # (node, next-succ idx)
        while stack:
            node_id, idx = stack[-1]
            succs = self._out.get(node_id, ())
            if idx >= len(succs):
                stack.pop()
                on_path.discard(node_id)
                path.pop()
                continue
            stack[-1] = (node_id, idx + 1)
            nxt = succs[idx].dst
            expansions += 1
            if expansions > max_expansions:
                budget_exhausted = True
                break
            if nxt == dst_id:
                paths.append(tuple(path) + (dst_id,))
                if len(paths) >= max_paths:
                    budget_exhausted = True
                    break
                continue
            if nxt in on_path:
                continue
            if len(path) >= max_depth:
                # Subtree pruned — deeper paths may exist.
                budget_exhausted = True
                continue
            stack.append((nxt, 0))
            on_path.add(nxt)
            path.append(nxt)
        return PathsFound(
            paths=tuple(paths), budget_exhausted=budget_exhausted,
        )

    # -- serialisation -----------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "language": self.language,
            "doctrine": DOCTRINE,
            "nodes": [
                {
                    "id": n.node_id,
                    "kind": n.kind,
                    "file_path": n.file_path,
                    "name": n.name,
                    "module": n.module,
                    "line": n.line,
                    "end_line": n.end_line,
                    "class_name": n.class_name,
                }
                for n in self.nodes
            ],
            "edges": [
                {
                    "src": e.src, "dst": e.dst,
                    "tier": e.tier, "kind": e.kind,
                    "lines": list(e.lines),
                }
                for e in self.edges
            ],
            "unresolved_calls": [
                {
                    "file_path": u.file_path, "line": u.line,
                    "caller": u.caller, "chain": list(u.chain),
                    "reason": u.reason, "tier": u.tier,
                }
                for u in self.unresolved_calls
            ],
            "external_calls": [
                {
                    "file_path": x.file_path, "line": x.line,
                    "caller": x.caller, "target": x.target,
                }
                for x in self.external_calls
            ],
            "caps_hit": list(self.caps_hit),
            "stats": dict(self.stats),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> PackageCallGraph:
        return cls(
            nodes=tuple(
                CallGraphNode(
                    node_id=str(n.get("id", "")),
                    kind=str(n.get("kind", "function")),
                    file_path=str(n.get("file_path", "")),
                    name=str(n.get("name", "")),
                    module=str(n.get("module", "")),
                    line=int(n.get("line") or 0),
                    end_line=n.get("end_line"),
                    class_name=n.get("class_name"),
                )
                for n in (d.get("nodes") or [])
            ),
            edges=tuple(
                CallGraphEdge(
                    src=str(e.get("src", "")),
                    dst=str(e.get("dst", "")),
                    tier=str(e.get("tier", "")),
                    kind=str(e.get("kind", "")),
                    lines=tuple(int(v) for v in (e.get("lines") or [])),
                )
                for e in (d.get("edges") or [])
            ),
            unresolved_calls=tuple(
                UnresolvedCall(
                    file_path=str(u.get("file_path", "")),
                    line=int(u.get("line") or 0),
                    caller=u.get("caller"),
                    chain=tuple(u.get("chain") or ()),
                    reason=str(u.get("reason", "")),
                )
                for u in (d.get("unresolved_calls") or [])
            ),
            external_calls=tuple(
                ExternalCall(
                    file_path=str(x.get("file_path", "")),
                    line=int(x.get("line") or 0),
                    caller=x.get("caller"),
                    target=str(x.get("target", "")),
                )
                for x in (d.get("external_calls") or [])
            ),
            caps_hit=tuple(d.get("caps_hit") or ()),
            stats={
                str(k): int(v)
                for k, v in (d.get("stats") or {}).items()
            },
            language=str(d.get("language", "python")),
            schema_version=int(d.get("schema_version") or SCHEMA_VERSION),
        )

    def save(self, path: str | Path) -> None:
        """Atomic JSON write via the shared artifact primitive."""
        save_json(path, self.to_dict())


def load_package_callgraph(path: str | Path) -> PackageCallGraph:
    """Load a saved artifact. Raises like :func:`core.json.load_json`
    on missing / malformed files — callers decide their degradation."""
    data = load_json(path)
    if not isinstance(data, dict):
        raise ValueError(f"package callgraph artifact is not an object: {path}")
    return PackageCallGraph.from_dict(data)


# ---------------------------------------------------------------------------
# Assembly — internal state
# ---------------------------------------------------------------------------


@dataclass
class _DefRecord:
    """One function definition from the inventory items."""
    bare_name: str
    class_name: str | None
    line: int
    end_line: int | None
    node: CallGraphNode
    nested_in_function: bool = False
    # Line span of the IMMEDIATE enclosing function when nested —
    # the only region where this def is a candidate runtime binding
    # for a bare-name call. None for non-nested defs.
    enclosing_span: tuple[int, int] | None = None


@dataclass
class _FileFacts:
    """Per-file resolution context.

    Every fact list is SANITISED at collection time (types coerced,
    malformed entries dropped with a ``stats.malformed_facts`` bump)
    — the artifact is loaded from disk across versions, so the
    assembly phases must never trust raw record shapes.
    """
    path: str
    module: str                      # raw dotted module ("" if underivable)
    is_init: bool
    module_node: CallGraphNode
    defs: list[_DefRecord] = field(default_factory=list)
    # (line, chain, caller, receiver_class) per static-name call site.
    calls: list[tuple[int, list[str], str | None, str | None]] = field(
        default_factory=list)
    # (def line, decorator chains) per decorated def.
    decorators: list[tuple[int, list[list[str]]]] = field(
        default_factory=list)
    # (line, root chain, caller) per subscript-callee call site.
    subscripts: list[tuple[int, list[str], str | None]] = field(
        default_factory=list)
    # (line, caller, attr_or_None) per getattr site.
    getattrs: list[tuple[int, str | None, str | None]] = field(
        default_factory=list)
    # table name → list of value chains.
    dispatch_tables: dict[str, list[list[str]]] = field(
        default_factory=dict)
    # local bound name → dotted target (absolute imports as written,
    # relative imports resolved against this file's package).
    import_table: dict[str, str] = field(default_factory=dict)
    # bare fn name (methods keyed by their bare method name too) →
    # def records; used for caller attribution.
    defs_by_bare: dict[str, list[_DefRecord]] = field(default_factory=dict)
    # bare fn name → module-level/nested (non-method) def records.
    fn_defs: dict[str, list[_DefRecord]] = field(default_factory=dict)
    # class name → (methods dict name→[def records], bases tuple)
    classes: dict[str, tuple[dict[str, list[_DefRecord]], tuple[str, ...]]] = (
        field(default_factory=dict)
    )


class _Assembler:
    """Build-time state. One instance per :func:`build_package_callgraph`
    call; never reused."""

    def __init__(self, *, time_budget_s: float, max_files: int,
                 max_nodes: int, max_edges: int) -> None:
        self.time_budget_s = time_budget_s
        self.max_files = max_files
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.started = time.monotonic()
        self.files: list[_FileFacts] = []
        self.node_count = 0
        # Package-scope resolution maps. Values:
        #   functions_q: dotted → tuple of function nodes
        #   classes_q:   dotted → (file_path, class_name)
        #   tables_q:    dotted → (file_path, table_name)
        #   modules_q:   dotted → file_path
        self.functions_q: dict[str, tuple[CallGraphNode, ...]] = {}
        self.classes_q: dict[str, tuple[str, str]] = {}
        self.tables_q: dict[str, tuple[str, str]] = {}
        self.modules_q: dict[str, str] = {}
        self.facts_by_path: dict[str, _FileFacts] = {}
        # Bare function name → nodes across the whole package
        # (functions AND methods) — the getattr-literal join.
        self.by_bare_name: dict[str, list[CallGraphNode]] = {}
        # Edge accumulator: (src, dst, tier, kind) → line set.
        self.edge_lines: dict[tuple[str, str, str, str], set[int]] = {}
        self.unresolved: list[UnresolvedCall] = []
        self.external: list[ExternalCall] = []
        self.caps_hit: list[str] = []
        self.stats: dict[str, int] = {}

    # -- small helpers ---------------------------------------------------

    def bump(self, key: str, n: int = 1) -> None:
        self.stats[key] = self.stats.get(key, 0) + n

    # Coercion helpers for disk-loaded record fields. A malformed
    # value degrades to the default and bumps ``malformed_facts`` —
    # the "never raises" contract of the entry point holds for
    # arbitrary artifact bytes, and the drop stays countable.

    def as_int(self, value: Any, default: int = 0) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, int):
            return value
        try:
            return int(value)
        except (TypeError, ValueError):
            if value is not None:
                self.bump("malformed_facts")
            return default

    def str_list(self, value: Any) -> list[str]:
        if isinstance(value, (list, tuple)):
            return [str(p) for p in value]
        if value:
            self.bump("malformed_facts")
        return []

    def as_dict(self, value: Any) -> dict:
        if isinstance(value, dict):
            return value
        if value:
            self.bump("malformed_facts")
        return {}

    def opt_str(self, value: Any) -> str | None:
        if value is None:
            return None
        return str(value)

    def mark_cap(self, name: str) -> None:
        if name not in self.caps_hit:
            self.caps_hit.append(name)

    def over_time_budget(self) -> bool:
        return time.monotonic() - self.started > self.time_budget_s

    # Frozen after the export/re-export phases (module tables no
    # longer change) — resolving every external call recomputing the
    # root set would be O(modules) per call site.
    roots: frozenset[str] = frozenset()

    def freeze_roots(self) -> None:
        self.roots = frozenset(
            alias.split(".", 1)[0] for alias in self.modules_q if alias
        )


def _module_for_path(path: str) -> tuple[str, bool]:
    """``a/b/c.py`` → (``"a.b.c"``, False); ``a/b/__init__.py`` →
    (``"a.b"``, True); root ``__init__.py`` → (``""``, True).
    Non-Python suffixes never reach here (caller filters)."""
    base = path.replace("\\", "/")
    for suffix in (".pyi", ".py"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    is_init = base.endswith("/__init__") or base == "__init__"
    if is_init:
        base = base[: -len("__init__")].rstrip("/")
    return base.replace("/", "."), is_init


def _module_aliases(module: str) -> list[str]:
    """The raw dotted module plus layout-stripped aliases
    (``src.pkg.mod`` → also ``pkg.mod``) — same convention as the
    reachability resolver, so both inventory consumers agree."""
    out = [module]
    for prefix in _LAYOUT_PREFIXES:
        dotted_prefix = prefix[:-1] + "."
        if module.startswith(dotted_prefix):
            stripped = module[len(dotted_prefix):]
            if stripped:
                out.append(stripped)
            break
    return out


def _qual(module: str, name: str) -> str:
    return f"{module}.{name}" if module else name


def _resolve_relative_target(
    package_parts: list[str], level: int, module: str, name: str,
) -> str | None:
    """Resolve one relative-import quad against the importing file's
    package. Level 1 = current package; each extra level ascends one.
    Returns the dotted target for ``name``, or None when the import
    ascends past the tree root."""
    ascend = level - 1
    if ascend > len(package_parts):
        return None
    parts = package_parts[: len(package_parts) - ascend] if ascend > 0 \
        else package_parts
    base = ".".join(parts)
    src_mod = f"{base}.{module}" if (base and module) else (module or base)
    return f"{src_mod}.{name}" if src_mod else name


# ---------------------------------------------------------------------------
# Assembly phases
# ---------------------------------------------------------------------------


def _collect_file(asm: _Assembler, record: dict[str, Any]) -> None:
    """Phase 1 per file: nodes + sanitised local fact tables."""
    path = str(record.get("path") or "")
    module, is_init = _module_for_path(path)
    cg = asm.as_dict(record.get("call_graph"))
    module_node = CallGraphNode(
        node_id=f"{path}::{MODULE_NODE_NAME}@0",
        kind="module", file_path=path, name=MODULE_NODE_NAME,
        module=module, line=0,
    )
    facts = _FileFacts(
        path=path, module=module, is_init=is_init,
        module_node=module_node,
    )
    asm.node_count += 1

    # Function defs from the inventory items (the builder normalises
    # 'functions' → 'items'; accept both for older artifacts).
    items = record.get("items", record.get("functions", [])) or []
    if not isinstance(items, list):
        asm.bump("malformed_facts")
        items = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if item.get("kind", "function") != "function":
            continue
        bare = str(item.get("name") or "")
        if not bare:
            continue
        if asm.node_count >= asm.max_nodes:
            asm.mark_cap("nodes")
            break
        meta = item.get("metadata") or {}
        cls_raw = meta.get("class_name") if isinstance(meta, dict) else None
        cls = asm.opt_str(cls_raw)
        line = asm.as_int(item.get("line_start"))
        end_line = asm.as_int(item.get("line_end")) or None
        name = f"{cls}.{bare}" if cls else bare
        node = CallGraphNode(
            node_id=f"{path}::{name}@{line}",
            kind="function", file_path=path, name=name,
            module=module, line=line,
            end_line=end_line,
            class_name=cls,
        )
        asm.node_count += 1
        rec = _DefRecord(
            bare_name=bare, class_name=cls, line=line,
            end_line=end_line, node=node,
        )
        facts.defs.append(rec)
        facts.defs_by_bare.setdefault(bare, []).append(rec)
        asm.by_bare_name.setdefault(bare, []).append(node)
        asm.bump("defs")

    # Nested-in-function sweep (iterative interval stack): a def
    # contained in another DEF's line range is not importable from
    # outside, so it's excluded from the exported qualified table —
    # and its IMMEDIATE enclosing span is recorded, because that span
    # is the only region where the nested name is a runtime binding
    # (the bare-name resolver scope-checks against it).
    # Methods live in class bodies, not function bodies — unaffected.
    stack: list[tuple[int, int]] = []          # (start, end) of open defs
    for rec in sorted(facts.defs,
                      key=lambda r: (r.line, -(r.end_line or r.line))):
        while stack and stack[-1][1] < rec.line:
            stack.pop()
        if stack:
            rec.nested_in_function = True
            rec.enclosing_span = stack[-1]
        stack.append((rec.line, rec.end_line or rec.line))

    for rec in facts.defs:
        if rec.class_name is None:
            facts.fn_defs.setdefault(rec.bare_name, []).append(rec)

    # Classes: method table + raw bases, from the call-graph facts
    # (nested classes stay resolvable same-file but are not exported).
    classes_raw = cg.get("classes")
    for cdef in classes_raw if isinstance(classes_raw, list) else []:
        if not isinstance(cdef, dict):
            continue
        cname = str(cdef.get("name") or "")
        if not cname:
            continue
        methods: dict[str, list[_DefRecord]] = {}
        for rec in facts.defs:
            if rec.class_name == cname:
                methods.setdefault(rec.bare_name, []).append(rec)
        facts.classes[cname] = (
            methods, tuple(asm.str_list(cdef.get("bases"))),
        )

    # Import table: absolute entries as written; relative quads
    # resolved against this file's package (the package IS the
    # module for __init__, the module minus its last segment else).
    # Rebind visibility is PARTIAL by extraction: the absolute-import
    # map is a dict (a later ``from b import f`` silently overwrote
    # an earlier ``from a import f`` at extraction time), so only
    # rebinds involving a relative quad are countable here — see the
    # module docstring's known-silent-gaps note.
    for local, dotted in asm.as_dict(cg.get("imports")).items():
        if local and dotted:
            facts.import_table[str(local)] = str(dotted)
    pkg_parts = (module.split(".") if module else [])
    if not is_init and pkg_parts:
        pkg_parts = pkg_parts[:-1]
    quads = cg.get("relative_imports")
    for quad in quads if isinstance(quads, list) else []:
        if not isinstance(quad, (list, tuple)) or len(quad) < 3:
            continue
        level = asm.as_int(quad[0])
        rel_module = str(quad[1] or "")
        name = str(quad[2] or "")
        asname = quad[3] if len(quad) > 3 else None
        if level <= 0 or not name:
            continue
        target = _resolve_relative_target(pkg_parts, level, rel_module, name)
        if target:
            bound = str(asname or name)
            if (bound in facts.import_table
                    and facts.import_table[bound] != target):
                asm.bump("import_name_rebound")
            facts.import_table[bound] = target

    # Sanitised dynamic-fact tables (see _FileFacts docstring).
    tables_raw = asm.as_dict(cg.get("dispatch_tables"))
    for tname, chains in tables_raw.items():
        if not isinstance(chains, (list, tuple)):
            asm.bump("malformed_facts")
            continue
        clean = [c for c in (asm.str_list(ch) for ch in chains) if c]
        if clean:
            facts.dispatch_tables[str(tname)] = clean

    calls_raw = cg.get("calls")
    for call in calls_raw if isinstance(calls_raw, list) else []:
        if not isinstance(call, dict):
            continue
        chain = asm.str_list(call.get("chain"))
        if not chain:
            continue
        facts.calls.append((
            asm.as_int(call.get("line")), chain,
            asm.opt_str(call.get("caller")),
            asm.opt_str(call.get("receiver_class")),
        ))

    deco_raw = cg.get("decorated_functions")
    for deco_fn in deco_raw if isinstance(deco_raw, list) else []:
        if not isinstance(deco_fn, dict):
            continue
        chains_raw = deco_fn.get("decorators")
        if not isinstance(chains_raw, (list, tuple)):
            continue
        chains = [c for c in (asm.str_list(ch) for ch in chains_raw) if c]
        if chains:
            facts.decorators.append(
                (asm.as_int(deco_fn.get("line")), chains))

    subs_raw = cg.get("subscript_calls")
    for site in subs_raw if isinstance(subs_raw, list) else []:
        if not isinstance(site, dict):
            continue
        chain = asm.str_list(site.get("chain"))
        if not chain:
            continue
        facts.subscripts.append((
            asm.as_int(site.get("line")), chain,
            asm.opt_str(site.get("caller")),
        ))

    ga_raw = cg.get("getattr_calls")
    for triple in ga_raw if isinstance(ga_raw, list) else []:
        if not isinstance(triple, (list, tuple)) or len(triple) < 3:
            continue
        facts.getattrs.append((
            asm.as_int(triple[0]),
            asm.opt_str(triple[1]),
            asm.opt_str(triple[2]),
        ))

    asm.files.append(facts)
    asm.facts_by_path[path] = facts


def _register_exports(asm: _Assembler) -> None:
    """Phase 2: package-scope qualified-name tables."""
    for facts in asm.files:
        aliases = _module_aliases(facts.module)
        for alias in aliases:
            if alias in asm.modules_q and asm.modules_q[alias] != facts.path:
                # Two files claiming one dotted module (e.g. both
                # ``src/pkg/m.py`` and ``pkg/m.py``): first wins,
                # counted — a collision can misdirect edges, so the
                # stat makes it visible.
                asm.bump("module_alias_collisions")
                continue
            asm.modules_q[alias] = facts.path
        for alias in aliases:
            for rec in facts.defs:
                if rec.nested_in_function:
                    continue
                q = _qual(alias, rec.node.name)
                existing = asm.functions_q.get(q, ())
                if rec.node not in existing:
                    asm.functions_q[q] = existing + (rec.node,)
            for cname, (_methods, _bases) in facts.classes.items():
                if "." in cname:
                    continue
                asm.classes_q.setdefault(_qual(alias, cname),
                                         (facts.path, cname))
            for tname in facts.dispatch_tables:
                asm.tables_q.setdefault(_qual(alias, tname),
                                        (facts.path, tname))


def _apply_reexports(asm: _Assembler) -> None:
    """Phase 3: ``__init__.py`` re-export aliasing to fixed point.

    ``pkg/__init__.py`` doing ``from .helpers import foo`` makes
    ``pkg.foo`` a package-level alias of ``pkg.helpers.foo`` — for
    functions, classes, dispatch tables, and modules alike (``from
    . import helpers`` re-exports the module). Same semantics as
    reachability's pass 1.6, applied to this module's four maps.
    Iteration count bounded — real chains are 3-4 deep.
    """
    for _ in range(_REEXPORT_FIXPOINT_ITERS):
        added = 0
        for facts in asm.files:
            if not facts.is_init:
                continue
            for alias_pkg in _module_aliases(facts.module):
                for local, dotted in facts.import_table.items():
                    alias_full = _qual(alias_pkg, local)
                    if alias_full == dotted:
                        continue
                    if (dotted in asm.functions_q
                            and alias_full not in asm.functions_q):
                        asm.functions_q[alias_full] = asm.functions_q[dotted]
                        added += 1
                    if (dotted in asm.classes_q
                            and alias_full not in asm.classes_q):
                        asm.classes_q[alias_full] = asm.classes_q[dotted]
                        added += 1
                    if (dotted in asm.tables_q
                            and alias_full not in asm.tables_q):
                        asm.tables_q[alias_full] = asm.tables_q[dotted]
                        added += 1
                    if (dotted in asm.modules_q
                            and alias_full not in asm.modules_q):
                        asm.modules_q[alias_full] = asm.modules_q[dotted]
                        added += 1
        asm.bump("reexport_aliases", added)
        if not added:
            break


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Resolution:
    """Outcome of resolving one call chain."""
    outcome: str            # "edges" | "external" | "builtin" | "unresolved"
    nodes: tuple[CallGraphNode, ...] = ()
    tier: str = ""
    kind: str = ""
    external_target: str = ""
    reason: str = ""


def _find_method(
    asm: _Assembler, facts: _FileFacts, class_name: str, method: str,
) -> tuple[tuple[CallGraphNode, ...], bool]:
    """Look up ``method`` on ``class_name`` (defined in ``facts``),
    walking same-package bases iteratively. Returns (nodes,
    inherited) — inherited=True when found on a base rather than the
    named class. Cycle-safe and bounded by _MAX_BASE_WALK."""
    worklist: list[tuple[str, str]] = [(facts.path, class_name)]
    seen: set[tuple[str, str]] = set()
    steps = 0
    first = True
    while worklist and steps < _MAX_BASE_WALK:
        steps += 1
        fpath, cname = worklist.pop(0)
        if (fpath, cname) in seen:
            continue
        seen.add((fpath, cname))
        cfacts = asm.facts_by_path.get(fpath)
        if cfacts is None:
            continue
        entry = cfacts.classes.get(cname)
        if entry is None:
            first = False
            continue
        methods, bases = entry
        recs = methods.get(method)
        if recs:
            return tuple(r.node for r in recs), not first
        first = False
        # Resolve each base in the DEFINING file's context: same-file
        # class name, or an imported / dotted name against the
        # package class table.
        for base in bases:
            if base in cfacts.classes:
                worklist.append((fpath, base))
                continue
            head, _, rest = base.partition(".")
            dotted: str | None = None
            if not rest and head in cfacts.import_table:
                dotted = cfacts.import_table[head]
            elif rest and head in cfacts.import_table:
                dotted = f"{cfacts.import_table[head]}.{rest}"
            elif rest:
                dotted = base
            if dotted and dotted in asm.classes_q:
                worklist.append(asm.classes_q[dotted])
    return (), False


def _constructor_nodes(
    asm: _Assembler, class_ref: tuple[str, str],
) -> tuple[CallGraphNode, ...]:
    fpath, cname = class_ref
    cfacts = asm.facts_by_path.get(fpath)
    if cfacts is None:
        return ()
    nodes, _inherited = _find_method(asm, cfacts, cname, "__init__")
    return nodes


def _resolve_dotted(
    asm: _Assembler, dotted: str,
) -> _Resolution:
    """Bind a fully-dotted name against the package tables."""
    fn_nodes = asm.functions_q.get(dotted)
    if fn_nodes:
        any_method = any(n.class_name for n in fn_nodes)
        tier = (TIER_RESOLVED_STATIC if len(fn_nodes) == 1
                else TIER_RESOLVED_CONVENTION)
        return _Resolution(
            outcome="edges", nodes=fn_nodes, tier=tier,
            kind=KIND_METHOD_CALL if any_method else KIND_CALL,
        )
    class_ref = asm.classes_q.get(dotted)
    if class_ref is not None:
        ctor = _constructor_nodes(asm, class_ref)
        if ctor:
            return _Resolution(
                outcome="edges", nodes=ctor,
                tier=TIER_RESOLVED_CONVENTION, kind=KIND_CONSTRUCTOR,
            )
        return _Resolution(outcome="unresolved",
                           reason=REASON_CONSTRUCTOR_NO_INIT)
    if dotted.split(".", 1)[0] in asm.roots:
        # In-package prefix but nothing bound — a dynamic module
        # attribute, generated code, or a name the inventory missed.
        return _Resolution(outcome="unresolved", reason=REASON_UNKNOWN_NAME)
    return _Resolution(outcome="external", external_target=dotted)


def _resolve_chain(
    asm: _Assembler, facts: _FileFacts,
    chain: list[str], receiver_class: str | None,
    caller_class: str | None, line: int = 0,
) -> _Resolution:
    """Bind one call chain in ``facts``'s namespace at call ``line``
    (0 = no position — e.g. a dispatch-table value reference, where
    only module-visible bindings apply). See the module docstring
    for the tier assignment rules."""
    root = chain[0]

    # self.m() / cls.m() — receiver is the enclosing class instance.
    if root in ("self", "cls"):
        if len(chain) != 2:
            # self.attr.m() routes through an attribute of unknown
            # type — a receiver this layer can't type.
            return _Resolution(outcome="unresolved",
                               reason=REASON_DYNAMIC_ATTRIBUTE)
        cls = receiver_class or caller_class
        if cls:
            nodes, _inherited = _find_method(asm, facts, cls, chain[1])
            if nodes:
                # Convention tier even for a direct hit: the runtime
                # receiver may be a subclass override.
                return _Resolution(
                    outcome="edges", nodes=nodes,
                    tier=TIER_RESOLVED_CONVENTION, kind=KIND_METHOD_CALL,
                )
        return _Resolution(outcome="unresolved",
                           reason=REASON_UNMATCHED_METHOD)

    if len(chain) == 1:
        # Bare name: same-file def(s) first, SCOPE-CHECKED. A def
        # nested inside another function is a runtime binding only
        # for call sites within its enclosing function's span —
        # without the check, one nested ``def helper`` anywhere in
        # the file hijacked every bare ``helper()`` call whose real
        # binding was a module-level def or an import. In-scope
        # nested defs win over module-level ones (Python scoping);
        # out-of-scope nested defs fall through to the import table.
        # (Module-level import shadowing of a module-level def stays
        # unmodelled — a wrong pick only misdirects an origination
        # edge, never a verdict.)
        candidates = facts.fn_defs.get(root)
        if candidates:
            in_scope_nested = [
                r for r in candidates
                if r.enclosing_span is not None
                and r.enclosing_span[0] <= line <= r.enclosing_span[1]
            ]
            visible = in_scope_nested or [
                r for r in candidates if not r.nested_in_function
            ]
            if visible:
                nodes = tuple(r.node for r in visible)
                return _Resolution(
                    outcome="edges", nodes=nodes,
                    tier=(TIER_RESOLVED_STATIC if len(nodes) == 1
                          else TIER_RESOLVED_CONVENTION),
                    kind=KIND_CALL,
                )
        if root in facts.import_table:
            return _resolve_dotted(asm, facts.import_table[root])
        if root in facts.classes:
            ctor = _constructor_nodes(asm, (facts.path, root))
            if ctor:
                return _Resolution(
                    outcome="edges", nodes=ctor,
                    tier=TIER_RESOLVED_CONVENTION, kind=KIND_CONSTRUCTOR,
                )
            return _Resolution(outcome="unresolved",
                               reason=REASON_CONSTRUCTOR_NO_INIT)
        if root in _BUILTIN_NAMES:
            return _Resolution(outcome="builtin")
        return _Resolution(outcome="unresolved", reason=REASON_UNKNOWN_NAME)

    # Dotted chain. Root bound by an import → join and bind.
    if root in facts.import_table:
        dotted = ".".join([facts.import_table[root], *chain[1:]])
        return _resolve_dotted(asm, dotted)

    # Class-qualified static-style call: Class.m(instance).
    if root in facts.classes and len(chain) == 2:
        nodes, inherited = _find_method(asm, facts, root, chain[1])
        if nodes:
            # A named class binds statically; only inheritance (or a
            # same-name fan-out) demotes to convention.
            tier = (TIER_RESOLVED_CONVENTION
                    if inherited or len(nodes) > 1
                    else TIER_RESOLVED_STATIC)
            return _Resolution(outcome="edges", nodes=nodes,
                               tier=tier, kind=KIND_METHOD_CALL)
        return _Resolution(outcome="unresolved",
                           reason=REASON_UNMATCHED_METHOD)

    if root in _BUILTIN_NAMES:
        # str.join / dict.fromkeys / ... — stdlib dispatch, no
        # cross-module information.
        return _Resolution(outcome="builtin")

    # Unknown object root (a local variable, a parameter, an
    # attribute) — dynamic attribute access this layer can't type.
    return _Resolution(outcome="unresolved",
                       reason=REASON_DYNAMIC_ATTRIBUTE)


# ---------------------------------------------------------------------------
# Edge emission
# ---------------------------------------------------------------------------


def _caller_node(
    facts: _FileFacts, caller_name: str | None, line: int,
) -> tuple[CallGraphNode, str | None]:
    """Attribute a call site to its enclosing function node. Returns
    (node, class_name_of_caller). Module-level → the module node.
    The extractor records the lexically-innermost function's BARE
    name; when several defs share it, prefer the one whose line span
    contains the call (smallest span wins), then the nearest def
    above."""
    if not caller_name:
        return facts.module_node, None
    candidates = facts.defs_by_bare.get(caller_name)
    if not candidates:
        return facts.module_node, None
    containing = [
        r for r in candidates
        if r.line <= line <= (r.end_line or r.line)
    ]
    if containing:
        best = min(containing,
                   key=lambda r: (r.end_line or r.line) - r.line)
        return best.node, best.class_name
    above = [r for r in candidates if r.line <= line]
    best = max(above, key=lambda r: r.line) if above \
        else min(candidates, key=lambda r: r.line)
    return best.node, best.class_name


class _EdgeSink:
    """Bounded accumulator for the three record kinds. All caps
    degrade with explicit markers (and stats) — nothing is silent."""

    def __init__(self, asm: _Assembler, max_edges: int) -> None:
        self.asm = asm
        self.max_edges = max_edges
        self.per_file_unresolved = 0

    def new_file(self) -> None:
        self.per_file_unresolved = 0

    def edge(self, src: CallGraphNode, dst: CallGraphNode,
             tier: str, kind: str, line: int) -> None:
        asm = self.asm
        key = (src.node_id, dst.node_id, tier, kind)
        lines = asm.edge_lines.get(key)
        if lines is not None:
            lines.add(line)
            return
        if len(asm.edge_lines) >= self.max_edges:
            asm.mark_cap("edges")
            asm.bump("edges_dropped_cap")
            return
        asm.edge_lines[key] = {line}

    def unresolved(self, facts: _FileFacts, line: int,
                   caller: CallGraphNode | None,
                   chain: tuple[str, ...], reason: str) -> None:
        asm = self.asm
        asm.bump("unresolved_total")
        if (self.per_file_unresolved >= _MAX_UNRESOLVED_PER_FILE
                or len(asm.unresolved) >= _MAX_UNRESOLVED_TOTAL):
            asm.mark_cap("unresolved")
            asm.bump("unresolved_dropped_cap")
            return
        self.per_file_unresolved += 1
        asm.unresolved.append(UnresolvedCall(
            file_path=facts.path, line=line,
            caller=caller.node_id if caller else None,
            chain=chain, reason=reason,
        ))

    def external(self, facts: _FileFacts, line: int,
                 caller: CallGraphNode | None, target: str) -> None:
        asm = self.asm
        asm.bump("external_total")
        if len(asm.external) >= _MAX_EXTERNAL_TOTAL:
            asm.mark_cap("external")
            asm.bump("external_dropped_cap")
            return
        asm.external.append(ExternalCall(
            file_path=facts.path, line=line,
            caller=caller.node_id if caller else None, target=target,
        ))

    def emit(self, facts: _FileFacts, line: int,
             caller: CallGraphNode, chain: tuple[str, ...],
             res: _Resolution, kind_override: str | None = None) -> None:
        """Route one resolution outcome to the right record."""
        if res.outcome == "edges":
            for node in res.nodes:
                self.edge(caller, node, res.tier,
                          kind_override or res.kind, line)
        elif res.outcome == "external":
            self.external(facts, line, caller, res.external_target)
        elif res.outcome == "builtin":
            self.asm.bump("builtin_calls_skipped")
        else:
            self.unresolved(facts, line, caller, chain, res.reason)


def _emit_file_edges(asm: _Assembler, facts: _FileFacts,
                     sink: _EdgeSink) -> None:
    """Phase 4 per file: resolve every sanitised call site."""
    sink.new_file()

    # Static-name call sites.
    for line, chain, caller_name, receiver_class in facts.calls:
        caller, caller_class = _caller_node(facts, caller_name, line)
        asm.bump("calls_total")
        res = _resolve_chain(
            asm, facts, chain,
            receiver_class=receiver_class,
            caller_class=caller_class,
            line=line,
        )
        sink.emit(facts, line, caller, tuple(chain), res)

    # Decorator applications: ``@deco`` runs when the def statement
    # executes. The def may be nested, but attributing the edge to
    # the module node (the import-time executor) is the honest
    # common case and always a valid origination source.
    for line, chains in facts.decorators:
        for chain in chains:
            res = _resolve_chain(asm, facts, chain,
                                 receiver_class=None, caller_class=None,
                                 line=line)
            sink.emit(facts, line, facts.module_node, tuple(chain), res,
                      kind_override=(KIND_DECORATOR
                                     if res.outcome == "edges" else None))

    # Dict-dispatch: HANDLERS[k]() against a literal table. Values
    # resolve in the TABLE's defining file's namespace (a bare name
    # in ``pkg/helpers.py``'s table means helpers' function, no
    # matter who imported the table).
    for line, chain, caller_name in facts.subscripts:
        caller, _cc = _caller_node(facts, caller_name, line)
        table_ref: tuple[str, str] | None = None
        root = chain[0]
        if len(chain) == 1:
            if root in facts.dispatch_tables:
                table_ref = (facts.path, root)
            elif root in facts.import_table:
                table_ref = asm.tables_q.get(facts.import_table[root])
        elif root in facts.import_table:
            dotted = ".".join([facts.import_table[root], *chain[1:]])
            table_ref = asm.tables_q.get(dotted)
        if table_ref is None:
            sink.unresolved(facts, line, caller, tuple(chain),
                            REASON_DISPATCH_TABLE_UNKNOWN)
            continue
        tfacts = asm.facts_by_path.get(table_ref[0])
        if tfacts is None:
            sink.unresolved(facts, line, caller, tuple(chain),
                            REASON_DISPATCH_TABLE_UNKNOWN)
            continue
        for vchain in tfacts.dispatch_tables.get(table_ref[1], []):
            # Table values are module-visible references — resolve
            # positionless (line 0: no nested-def scope applies).
            res = _resolve_chain(asm, tfacts, vchain,
                                 receiver_class=None, caller_class=None)
            if res.outcome == "edges":
                # Table membership, not the value's own binding
                # strength, decides confidence: which entry runs
                # depends on a runtime key.
                for node in res.nodes:
                    sink.edge(caller, node, TIER_HEURISTIC_DYNAMIC,
                              KIND_DICT_DISPATCH, line)
            else:
                asm.bump("dispatch_values_unresolved")

    # getattr dispatch: literal attr → every package function with
    # that bare name (methods included). Bounded fan-out; over-cap
    # and opaque sites degrade to explicit markers.
    for line, caller_name, attr in facts.getattrs:
        caller, _cc = _caller_node(facts, caller_name, line)
        if attr is None:
            sink.unresolved(facts, line, caller, ("getattr",),
                            REASON_GETATTR_OPAQUE)
            continue
        targets = asm.by_bare_name.get(attr, [])
        if not targets:
            sink.unresolved(facts, line, caller, ("getattr", attr),
                            REASON_GETATTR_UNMATCHED)
            continue
        if len(targets) > _MAX_GETATTR_FANOUT:
            # A partial edge set would look authoritative while
            # missing most candidates — the marker is more honest.
            sink.unresolved(facts, line, caller, ("getattr", attr),
                            REASON_GETATTR_FANOUT_CAP)
            asm.mark_cap("getattr_fanout")
            continue
        for node in targets:
            sink.edge(caller, node, TIER_HEURISTIC_DYNAMIC,
                      KIND_GETATTR_DISPATCH, line)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def _is_python_record(record: dict[str, Any]) -> bool:
    if record.get("language") == "python":
        return True
    path = str(record.get("path") or "")
    return path.endswith((".py", ".pyi"))


def build_package_callgraph(
    inventory: dict[str, Any],
    *,
    time_budget_s: float = _BUILD_TIME_BUDGET_S,
    max_files: int = _MAX_FILES,
    max_nodes: int = _MAX_NODES,
    max_edges: int = _MAX_EDGES,
) -> PackageCallGraph:
    """Assemble the package-scope Python call graph from an
    inventory artifact (the :func:`core.inventory.build_inventory`
    dict shape: ``files`` records carrying ``items`` +
    ``call_graph``).

    Never raises on malformed records — a file whose facts are
    missing or misshapen contributes nothing (the inventory layer
    already degraded it), and every bound hit is reported through
    ``caps_hit`` + ``stats``. See the module docstring for the
    consuming doctrine.
    """
    asm = _Assembler(
        time_budget_s=time_budget_s, max_files=max_files,
        max_nodes=max_nodes, max_edges=max_edges,
    )

    # Phase 1: per-file nodes + local tables.
    records = [r for r in (inventory.get("files") or [])
               if isinstance(r, dict)]
    asm.stats["files_seen"] = len(records)
    for record in records:
        if not _is_python_record(record):
            continue
        asm.bump("files_python")
        if asm.stats.get("files_processed", 0) >= max_files:
            asm.mark_cap("files")
            asm.bump("files_skipped_cap")
            continue
        if asm.node_count >= max_nodes:
            asm.mark_cap("nodes")
            asm.bump("files_skipped_cap")
            continue
        if asm.over_time_budget():
            asm.mark_cap("time_budget")
            asm.bump("files_skipped_cap")
            continue
        asm.bump("files_processed")
        _collect_file(asm, record)

    # Phases 2-3: exported names, then __init__ re-export aliases.
    _register_exports(asm)
    _apply_reexports(asm)
    asm.freeze_roots()

    # Phase 4: edges.
    sink = _EdgeSink(asm, max_edges)
    for facts in asm.files:
        if asm.over_time_budget():
            asm.mark_cap("time_budget")
            break
        _emit_file_edges(asm, facts, sink)

    # Materialise, deterministically ordered.
    nodes: list[CallGraphNode] = []
    for facts in asm.files:
        nodes.append(facts.module_node)
        nodes.extend(r.node for r in facts.defs)
    nodes.sort(key=lambda n: (n.file_path, n.line, n.name))
    edges = [
        CallGraphEdge(src=src, dst=dst, tier=tier, kind=kind,
                      lines=tuple(sorted(lines)))
        for (src, dst, tier, kind), lines in asm.edge_lines.items()
    ]
    edges.sort(key=lambda e: (e.src, e.dst, e.kind, e.tier))
    asm.stats["nodes"] = len(nodes)
    asm.stats["edges"] = len(edges)

    return PackageCallGraph(
        nodes=tuple(nodes),
        edges=tuple(edges),
        unresolved_calls=tuple(sorted(
            asm.unresolved, key=lambda u: (u.file_path, u.line))),
        external_calls=tuple(sorted(
            asm.external, key=lambda x: (x.file_path, x.line))),
        caps_hit=tuple(asm.caps_hit),
        stats=asm.stats,
    )


__all__ = [
    "DOCTRINE",
    "KIND_CALL",
    "KIND_CONSTRUCTOR",
    "KIND_DECORATOR",
    "KIND_DICT_DISPATCH",
    "KIND_GETATTR_DISPATCH",
    "KIND_METHOD_CALL",
    "MODULE_NODE_NAME",
    "PACKAGE_CALLGRAPH_FILENAME",
    "SCHEMA_VERSION",
    "TIER_HEURISTIC_DYNAMIC",
    "TIER_RESOLVED_CONVENTION",
    "TIER_RESOLVED_STATIC",
    "TIER_UNRESOLVED",
    "CallGraphEdge",
    "CallGraphNode",
    "ExternalCall",
    "PackageCallGraph",
    "PathsFound",
    "UnresolvedCall",
    "build_package_callgraph",
    "load_package_callgraph",
]
