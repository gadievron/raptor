"""Interprocedural taint propagation — the summary-level worklist.

The package callgraph knows WHO calls WHOM (with confidence tiers but
no argument positions); the per-function summaries know how taint
moves THROUGH one function (parameters → call-site arguments → sinks,
with sanitizer kill/tag semantics). This module joins the two: a
worklist fixpoint over facts ``(function node, parameter index, taint
class)`` seeded from the extracted route models and pack-declared
sources, producing in-memory CANDIDATE RECORDS (source → sink with a
function-level hop chain) for the downstream emission phase.

## Consuming doctrine — originate and prioritize, never refute

Inherited verbatim from the callgraph and route models: this engine
ORIGINATES candidates for a pipeline whose verdicts come from the
downstream classifier and validation stages. It has NO refutation,
suppression, or "no flow" surface — a run that finds nothing proves
nothing (the graph is incomplete by construction, the summaries are
bounded approximations, and every cap degrades coverage). The honest
signals of partial coverage are the FRONTIER records (taint reaching
a call the engine could not bind), ``caps_hit`` markers, and counted
stats — never silence, and never a clean claim.

## The lattice

Facts live in a finite lattice: for each key ``(node, param index,
taint class)`` the state is ``(confidence tier, killed sink-class
set)``. Joins are monotone in both coordinates:

* **tier** — the best (most confident) path tier seen so far; a
  path's tier is the MIN of its hop tiers (``resolved_static`` >
  ``resolved_convention`` > ``heuristic_dynamic``), and a later
  arrival over a more confident route re-propagates. Low-confidence
  edges are neither dropped nor silently trusted: they propagate
  carrying their tier, which rides every hop of the witness chain
  into the candidate record.
* **killed** — the set of sink classes transform sanitizers killed
  on EVERY discovered path to the key (intersection across paths,
  union along one path). A second, unsanitized route shrinks the
  set and re-propagates. A candidate whose sink class is killed on
  every known path is withheld with a counted stat
  (``candidates_killed``), mirroring the summary layer's
  ``sinks_suppressed_killed`` — visible, never silent. Because the
  consulted state is the JOIN, a sink reached by one killed and one
  live path emits (over-taint direction: the live path is real; the
  witness may then be the sanitized path, whose sanitizer hops
  remain visible on the record).

Both coordinates have small finite height (3 tiers; killed sets only
shrink, bounded by the pack sink-class vocabulary), so each key is
re-enqueued a bounded number of times and the fixpoint terminates
without cycle special-casing; the iteration cap below is a belt, not
the termination argument.

## Seeding

* **Route handlers**: every extracted route record seeds the WHOLE
  handler parameter surface (route ``params`` understate the
  attacker surface — query/body parameters arrive through the same
  signature), with the taint classes the loaded ``route_param``
  source specs declare. A leading ``self``/``cls`` on method-shaped
  handlers is not seeded (the receiver is not request data).
  Class-based-view handler ids are not graph nodes; they seed by
  the name-prefix join (nodes in the handler's file named
  ``<Class>.<http verb>``). Middleware chains are PRESENCE FACTS —
  they never gate or sanitize seeding.
* **Pack sources**: functions whose bodies fire a declared source
  are found by joining the graph's external-call census against the
  source specs (``call_return`` exact, ``module_attribute`` by
  dotted prefix, learned sources by function name); each match is
  visited and its in-body source flows enter the same worklist.
  Sources are not route-gated — a CLI tool's ``input()`` seeds too
  if a pack says so, provided a call record names it. (A function
  whose only source evidence is a bare attribute read — no call
  riding it — leaves no external-call record; builtin calls are
  census-counted, not recorded per site. If such a function is also
  unreachable from every other seed it is not discovered — a named
  miss, never a wrong claim; route-reachable ones are visited and
  fire regardless.)

## Honest blind spots (marked, counted, never silent)

* Taint reaching a call site the engine could not bind becomes a
  bounded FRONTIER record + ``stats.taint_at_unresolved`` — never a
  finding and never a "no flow past here" claim.
* Taint returned OUT of an internal callee into its caller does not
  flow back through the caller in this parameter-shaped lattice.
  BOTH sub-cases are counted under ``return_taint_unpropagated`` so
  the miss class is visible per run: a helper whose body fires a
  source and returns it (counted once per visited node at plan
  time) and a parameter that reaches its function's return value
  (counted per pop that observes it).
* Receiver taint entering a method through ``self`` is not seeded
  from tainted receivers (same parameter-shaped bound; the
  summaries record no receiver channel).

## Cost rails

The priced worst case is a PRODUCT over every dimension this engine
touches — each factor capped by a named rail:

    entry points (route seed facts ≤ MAX_SEED_FACTS;
      source-entry visits inside the visit cap)
    × edges reached (pre-bound successors ≤ MAX_PLAN_SUCCESSORS per
      node — the channels × flows × line-matched-edges product is
      target-shaped on every factor; upstream walls: graph ≤ 500k
      edges, summaries ≤ MAX_CALL_CHANNELS channels each)
    × lattice width (fact keys ≤ MAX_FACT_KEYS, itself the product
      functions visited (≤ MAX_FUNCTIONS_VISITED) × params per
      function (≤ MAX_PARAMS_PER_FUNCTION) × taint classes (closed
      pack vocabulary))
    × iterations (lattice height per key: 3 tiers + at most
      |sink-class vocabulary| killed-set shrinks; total pops belted
      by MAX_WORKLIST_ITERATIONS because dependency CYCLES let a
      hostile package multiply re-propagations — the fixpoint count
      is attacker-influenced, so it gets its own named cap+marker)
    × per-op cost — O(out-degree of the popped key) BY
      CONSTRUCTION: every per-node table (param → successors,
      param → sink hits, edge-line join, argument binding) is built
      ONCE when the node is first visited and looked up thereafter;
      a pop never re-scans summaries, the graph, or accumulated
      fact/candidate state (candidate eviction keeps a cached worst
      entry; witness reconstruction walks one predecessor chain of
      at most MAX_PATH_HOPS), and no per-fact step may cost
      O(functions) or O(candidates) — the once-per-file lesson,
      generalised to once-per-node.
    × RETAINED BYTES — time is not the only spend: memoized indexes,
      plans, binding signatures and the fact state all LIVE in RAM,
      and every one of those is target-shaped (one dense in-cap
      module retains two orders of magnitude more AST than its file
      size). The whole retention set is byte-accounted against
      MAX_RETAINED_BYTES: caches (plans, indexes) evict
      least-recently-used and rebuild on demand (counted — thrash
      burns the summary cap and the wall, never RAM), non-cache
      state (fact keys, binding signatures) refuses new entries
      counted. Host memory is never the enforcement mechanism.

Summary extraction and module indexing are the expensive per-node /
per-file steps; both are memoized (once per node / once per file),
demand-driven (only visited functions are ever summarised), and
independently capped (MAX_SUMMARIES, MAX_FILES_INDEXED) so the
binding cost is the visit cap × the summary layer's per-function
budgets. The plan keeps NO reference to the extracted summary or
its AST — everything a pop needs is copied into small pre-bound
tables at build time. Every cap → ``caps_hit`` marker + stat; a
capped run is valid for origination, it covers less.

All name-shaped output fields (function ids, callee names, route
patterns, file paths) are target-derived text — render chokepoints
must escape them before display, same contract as the callgraph and
route-model artifacts (``derived_from_target``). This module itself
never prints or logs target bytes.
"""

from __future__ import annotations

import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field, replace
from pathlib import Path
from collections.abc import Callable

from core.analysis.package_callgraph import (
    KIND_CONSTRUCTOR,
    KIND_DECORATOR,
    KIND_GETATTR_DISPATCH,
    KIND_METHOD_CALL,
    TIER_HEURISTIC_DYNAMIC,
    TIER_RESOLVED_CONVENTION,
    TIER_RESOLVED_STATIC,
    CallGraphEdge,
    CallGraphNode,
    PackageCallGraph,
)
from core.analysis.route_models import (
    HANDLER_KIND_CLASS,
    RouteModels,
    RouteRecord,
)
from core.taint.learned_intake import LearnedIntake
from core.taint.packs import (
    SOURCE_KIND_ROUTE_PARAM,
    TIER_LEARNED,
    TIER_PACK,
    PackSet,
)
from core.taint.summaries import (
    Flow,
    FunctionEntry,
    FunctionSummary,
    Limits,
    ModuleIndex,
    SpecIndex,
    build_spec_index,
    extract_summary,
    index_module,
)

#: Serialised into every result so downstream readers that never
#: import this module still see the contract (the callgraph idiom).
DOCTRINE = "originate_and_prioritize_only"

#: Bump when the candidate/result SHAPE or the propagation semantics
#: change in a way persisted results must not survive.
ENGINE_VERSION = 1

# ── named caps ───────────────────────────────────────────────────────
# Each cap names both directions; hitting any of them appends a
# marker to ``caps_hit`` plus a stat — a capped run is valid for
# origination, it covers less. Never a failure, never silent.

#: Worklist pops (the fixpoint iteration belt). The lattice is finite
#: so the fixpoint terminates without this cap — but dependency
#: CYCLES let a hostile package multiply re-propagations (tier and
#: killed-set improvements ripple around the cycle), so the
#: iteration count is attacker-influenced and gets its own wall.
#: Higher lets giant fact lattices converge completely; lower bounds
#: the time a crafted cyclic package can spend converging.
MAX_WORKLIST_ITERATIONS = 1_000_000

#: Fact keys tracked (the lattice-width wall: functions × params ×
#: classes is target-shaped on every factor). Higher converges huge
#: lattices completely; lower bounds state memory — over-cap
#: arrivals at NEW keys are dropped counted (existing keys still
#: join), so a capped run under-covers visibly, never corrupts.
MAX_FACT_KEYS = 2_000_000

#: Functions given a propagation plan (summary + successor tables).
#: Matches the callgraph's own file admission cap. Higher covers
#: monorepos completely; lower bounds the dominant cost (per-node
#: summary extraction) on a crafted many-function tree.
MAX_FUNCTIONS_VISITED = 20_000

#: Summary extractions (2× the visit cap: headroom so degraded or
#: re-entered extractions cannot grow unboundedly even if a future
#: caller decouples extraction from planning; today one plan = one
#: extraction, so the visit cap binds first by construction).
#: Higher keeps giant monorepos complete; lower bounds memory and
#: extraction time.
MAX_SUMMARIES = 40_000

#: Files indexed (one bounded parse each). Distinct from the visit
#: cap because argument BINDING peeks at callee files that may never
#: be visited themselves — a hostile tree fanning calls across many
#: tiny files must hit a wall of its own. Higher admits wide
#: monorepos; lower bounds parse work and index memory.
MAX_FILES_INDEXED = 20_000

#: Route seed facts. Higher seeds mega-APIs completely (route
#: records are already capped upstream at 10k); lower bounds the
#: entry-point dimension against a crafted registration flood.
MAX_SEED_FACTS = 50_000

#: Parameter indices considered per function (seeding and binding).
#: The width factor of the fact lattice is parameter count, and
#: parameter count is target-chosen — a generated 10k-parameter def
#: must not mint 10k facts per class. Higher keeps generated wide
#: signatures fully seeded; lower bounds the width factor. Over-cap
#: parameters are dropped counted (``params_capped``) — a recall
#: loss, marked, never a wrong claim.
MAX_PARAMS_PER_FUNCTION = 64

#: Pre-bound successor entries per node plan. Plan size is the
#: product channels × flows-per-channel × edges matched at one line,
#: and a crafted graph can put ANY number of edges on one call line
#: — the mega-fan-out shape that would otherwise turn one plan build
#: into an unbounded table. Higher preserves complete fan-out on
#: dispatch-heavy nodes; lower bounds plan memory and per-pop work.
#: Over-cap successors are dropped counted (``plan_succ_capped``) —
#: covered less, never silently mis-propagated.
MAX_PLAN_SUCCESSORS = 10_000

#: Candidate records kept (deterministic tier-ordered eviction, see
#: :class:`Candidate`). Higher keeps more of a flood for downstream
#: triage; lower bounds downstream spend — displacement is visible
#: in ``stats.candidates_evicted*``, never silent.
MAX_CANDIDATES = 500

#: Witness-chain hops per fact (path depth). Higher follows deeper
#: real call chains; lower bounds both propagation depth and the
#: per-candidate reconstruction walk. Deeper taint stops with a
#: counted marker (``path_hops_capped``) — covered less, not lied
#: about.
MAX_PATH_HOPS = 20

#: Frontier records retained (taint at unbindable call sites). The
#: FULL count always survives in ``stats.taint_at_unresolved``; this
#: bounds only the addressable record list. Higher keeps every blind
#: spot addressable; lower stops obfuscated code (every call
#: dynamic) from bloating the artifact.
MAX_FRONTIER_RECORDS = 5_000

#: Wall budget for one propagation run, checked between pops and at
#: every plan build. Higher finishes giant trees in one run; lower
#: keeps the engine a predictable pipeline stage — past budget the
#: run ships whatever was assembled plus the ``wall_budget`` marker.
ENGINE_WALL_BUDGET_S = 300.0

#: Estimated bytes RETAINED in RAM across module indexes, plans,
#: binding signatures and fact state — the memory analogue of the
#: wall budget. Retention is target-shaped on every component (a
#: dense in-cap module pins ~100x its file size in AST; a dispatch
#: hub's plan holds thousands of pre-bound successors; each fact key
#: holds witness state), so without this rail host memory would be
#: the only bound — an OOM kill is not a marked degrade. Over
#: budget, caches (plans, indexes) evict LRU and rebuild on demand
#: (counted; rebuild spend is bounded by MAX_SUMMARIES and the wall
#: budget); non-cache state (fact keys, binding signatures) refuses
#: new entries counted. Higher lets big-RAM hosts keep giant runs
#: fully memoized; lower keeps the engine inside a predictable
#: pipeline-stage footprint at the cost of cache-rebuild time.
MAX_RETAINED_BYTES = 1_073_741_824  # 1 GiB

# Byte estimators for the retention rail. Estimates lean HIGH
# (conservative direction: over-estimating retention evicts earlier,
# never later — a loose estimate costs rebuild time, a tight one
# costs RAM).
#
# Index calibration: a flat text ratio alone is NOT high-leaning —
# AST density per text byte is target-chosen, and an adversarial
# density search over 13 in-cap module variants measured retained
# ModuleIndex+AST between 88:1 and 199:1 (tuple-constant bodies
# 199:1, param-heavy tiny defs 189:1, dict displays 187:1,
# nested tuples 183:1, f-strings 161:1, ultra-tiny defs 151:1;
# the plain dense-def shape itself 103:1). The estimator therefore
# prices BOTH axes: a per-text-byte term (100:1 — marginal
# expression nodes cost ~50:1, so text covers them with margin) and
# a per-function term (4 KiB — def/arguments overhead is where the
# tiny-function variants blow past any flat ratio). This shape
# over-covers every measured variant (thinnest margin
# tuple-constant, ~12%; most others ≥ 35%).
#
# Plan calibration: a 2000-successor dispatch plan measures
# ~0.37 MiB (~190 B/entry, entry hops shared) — 384 B/entry (~2x)
# is the estimator. Fact state measures ~850 B/key — 896 B is the
# estimator.
_INDEX_BYTES_PER_TEXT_BYTE = 100
_INDEX_BYTES_PER_FUNCTION = 4_096
_INDEX_BYTES_BASE = 8_192
_PLAN_BYTES_PER_ENTRY = 384
_PLAN_BYTES_BASE = 4_096
_FACT_BYTES_EST = 896
_SIG_BYTES_BASE = 160
_SIG_BYTES_PER_PARAM = 64

# ── tiers / markers ─────────────────────────────────────────────────

#: Path-tier rank (lower = more confident). A path's tier is the MIN
#: of its hops; rank comparisons implement that MIN. Unknown edge
#: tier strings rank as heuristic (conservative: least confident).
_TIER_RANK: dict[str, int] = {
    TIER_RESOLVED_STATIC: 0,
    TIER_RESOLVED_CONVENTION: 1,
    TIER_HEURISTIC_DYNAMIC: 2,
}
_HEURISTIC_RANK = _TIER_RANK[TIER_HEURISTIC_DYNAMIC]
_TIER_BY_RANK = {v: k for k, v in _TIER_RANK.items()}

#: Tier label for the seed hop (taint entering its first function
#: crosses no graph edge, so nothing dilutes the path tier there).
SEED_HOP_TIER = TIER_RESOLVED_STATIC

#: Hop tag: argument binding degraded to taint-all-params (star
#: forms, arity/keyword mismatch) — the approximation is visible on
#: the hop, mirroring the summary layer's ``binding_approx``.
MARKER_BINDING_ALL_PARAMS = "binding_all_params"

#: HTTP verb names for the class-based-view name-prefix join —
#: protocol constants (RFC 9110 + PATCH), the one fixed vocabulary
#: besides the framework APIs themselves.
_HTTP_VERBS = frozenset(
    {"get", "post", "put", "delete", "patch", "options", "head", "trace"},
)

_PARAM_ORIGIN_PREFIX = "param:"
_SOURCE_ORIGIN_PREFIX = "source:"

#: Sentinel callee name the summary layer records when it cannot
#: name a callee at all (dispatch through values).
_UNRESOLVED_CALLEE = "unresolved"

_SPEC_TIER_RANK_CURATED = 0
_SPEC_TIER_RANK_LEARNED = 1


# ── limits (test-adjustable view over the module caps) ───────────────


@dataclass(frozen=True)
class EngineLimits:
    """Per-run budget set. Defaults are the module caps; tests shrink
    individual fields to pin the ±1 degradation boundaries."""

    max_iterations: int = MAX_WORKLIST_ITERATIONS
    max_fact_keys: int = MAX_FACT_KEYS
    max_functions_visited: int = MAX_FUNCTIONS_VISITED
    max_summaries: int = MAX_SUMMARIES
    max_files_indexed: int = MAX_FILES_INDEXED
    max_seed_facts: int = MAX_SEED_FACTS
    max_params_per_function: int = MAX_PARAMS_PER_FUNCTION
    max_plan_successors: int = MAX_PLAN_SUCCESSORS
    max_candidates: int = MAX_CANDIDATES
    max_path_hops: int = MAX_PATH_HOPS
    max_frontier_records: int = MAX_FRONTIER_RECORDS
    max_retained_bytes: int = MAX_RETAINED_BYTES
    wall_budget_s: float = ENGINE_WALL_BUDGET_S
    #: Per-function extraction budgets (the summary layer's own).
    summary_limits: Limits = field(default_factory=Limits)


# ── records ─────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Hop:
    """One function-level step of a candidate's witness chain.

    ``function`` is the callgraph node id entered at this hop;
    ``tier``/``kind``/``line`` describe the EDGE that entered it
    (``tier == SEED_HOP_TIER`` and ``kind == "seed"`` for the first
    hop). ``tags`` carries the honesty markers of the local flow
    that fed the hop (``assumed_propagation``, ``binding_approx``,
    ``sanitizer_demoted``, ``learned``, ``binding_all_params``);
    ``sanitizer_hops`` the sanitizer callees the flow passed
    through. All name fields are target-derived text — escape
    before rendering.
    """

    function: str
    tier: str
    kind: str
    line: int
    tags: tuple[str, ...] = ()
    sanitizer_hops: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "function": self.function, "tier": self.tier,
            "kind": self.kind, "line": self.line,
            "tags": list(self.tags),
            "sanitizer_hops": list(self.sanitizer_hops),
        }


@dataclass(frozen=True)
class Candidate:
    """One source → sink candidate flow (in-memory; the emission
    phase turns survivors into findings). NEVER a verdict: the
    downstream classifier and validation stages decide, and the
    engine writes no status beyond candidate.

    ``path_tier`` is the MIN tier over the hop chain. ``killed``
    lists sink classes transform-killed on EVERY discovered path to
    the sink's function (visible even when they did not silence this
    sink's class); it is recomputed from the FINAL lattice state
    when the run's results are assembled — the emission-time value
    is provisional, because a later live path can shrink the join
    after the witness stopped improving. The hop chain remains ONE
    real witness path; converging flows share a fact key, so both
    alternative PATHS and alternative SOURCES to the same sink
    collapse into that witness (deterministic under the FIFO order;
    the reconstruction phase widens). Eviction priority when the
    candidate cap binds is deterministic and documented: curated/
    pack sink specs survive learned sink specs; within a spec tier
    higher path tiers survive first, then shorter paths, then stable
    (function, line) order — displacement is counted per spec tier,
    never silent.
    """

    taint_class: str
    source: tuple[tuple[str, object], ...]
    sink_function: str
    sink_line: int
    sink_class: str
    sink_cwe: str
    sink_match: str
    sink_confidence: str
    spec_tier: str
    pack: str
    hops: tuple[Hop, ...]
    path_tier: str
    killed: tuple[str, ...] = ()

    def source_dict(self) -> dict[str, object]:
        return dict(self.source)

    def to_dict(self) -> dict[str, object]:
        return {
            "taint_class": self.taint_class,
            "source": self.source_dict(),
            "sink": {
                "function": self.sink_function,
                "line": self.sink_line,
                "sink_class": self.sink_class,
                "cwe": self.sink_cwe,
                "match": self.sink_match,
                "confidence": self.sink_confidence,
                "spec_tier": self.spec_tier,
                "pack": self.pack,
            },
            "hops": [h.to_dict() for h in self.hops],
            "path_tier": self.path_tier,
            "killed": list(self.killed),
            "derived_from_target": True,
        }


@dataclass(frozen=True)
class FrontierRecord:
    """Taint reached a call site the engine could not bind to any
    callee — the explicit blind-spot marker that replaces silence.
    NEVER a finding and never a "no flow past here" claim; the full
    occurrence count survives in ``stats.taint_at_unresolved`` even
    when this list is capped. Name fields are target-derived —
    escape before rendering."""

    function: str
    line: int
    callee: str
    resolution: str
    taint_class: str

    def to_dict(self) -> dict[str, object]:
        return {
            "function": self.function, "line": self.line,
            "callee": self.callee, "resolution": self.resolution,
            "taint_class": self.taint_class,
            "derived_from_target": True,
        }


@dataclass
class PropagationResult:
    """One propagation run's output: candidates plus the honest
    account of everything the run could NOT see (frontier records,
    caps, stats).

    Deliberately ABSENT from this surface: any refuted / clean /
    no-flow field. Zero candidates proves nothing — the frontier,
    ``caps_hit`` and the stats say what was not covered. Nothing may
    read the absence of a candidate as evidence of absence.
    """

    candidates: tuple[Candidate, ...] = ()
    frontier: tuple[FrontierRecord, ...] = ()
    caps_hit: tuple[str, ...] = ()
    stats: dict[str, int] = field(default_factory=dict)
    engine_version: int = ENGINE_VERSION

    def stat(self, name: str) -> int:
        return self.stats.get(name, 0)

    def to_dict(self) -> dict[str, object]:
        return {
            "engine_version": self.engine_version,
            "doctrine": DOCTRINE,
            "candidates": [c.to_dict() for c in self.candidates],
            "frontier": [f.to_dict() for f in self.frontier],
            "caps_hit": list(self.caps_hit),
            "stats": dict(sorted(self.stats.items())),
        }


# ── internal plumbing ────────────────────────────────────────────────


@dataclass(frozen=True)
class _Succ:
    """One pre-bound successor for one channel flow: built once at
    plan time, looked up per pop (per-op O(out-degree)). The entry
    hop is precomputed once and shared by every arrival through this
    successor."""

    dst: str
    tier_rank: int
    kind: str
    line: int
    params: tuple[int, ...]
    killed: frozenset[str]
    entry_hop: Hop


@dataclass(frozen=True)
class _SinkHit:
    """One pre-matched sink flow (for one parameter index or one
    in-body source flow)."""

    sink_class: str
    cwe: str
    match: str
    line: int
    confidence: str
    spec_tier: str
    pack: str
    killed: frozenset[str]
    tags: tuple[str, ...]
    sanitizer_hops: tuple[str, ...]


@dataclass
class _Plan:
    """Per-node propagation plan — every table a pop consults, built
    ONCE when the node is first visited. Deliberately keeps NO
    reference to the extracted :class:`FunctionSummary` or any AST:
    the plan is the only per-node retention, so everything a pop
    needs is copied into these small tables at build time (the
    retained-bytes rail accounts them; a summary reference would pin
    flow tuples — and through careless coupling, module ASTs — for
    the run's lifetime)."""

    node_id: str
    params: tuple[str, ...]
    qualname: str
    line_start: int
    opaque: bool
    succ_by_param: dict[int, list[_Succ]] = field(default_factory=dict)
    sinks_by_param: dict[int, list[_SinkHit]] = field(default_factory=dict)
    frontier_by_param: dict[int, list[tuple[str, str, int]]] = field(
        default_factory=dict)
    #: In-body source flows feeding bound successors: processed once
    #: at visit time (``(succ, taint classes, killed, markers,
    #: sanitizer hops, kind, match, line)``).
    source_tasks: list[tuple[_Succ, tuple[str, ...], frozenset[str],
                             tuple[str, ...], tuple[str, ...],
                             str, str, int]] = field(default_factory=list)
    #: In-body source flows feeding local sinks: same-function
    #: candidates, processed once at visit time.
    source_sinks: list[tuple[_SinkHit, tuple[str, ...],
                             str, str]] = field(default_factory=list)
    #: Source-event lines by match (for source descriptors).
    source_lines: dict[str, int] = field(default_factory=dict)
    #: Parameter indices with a flow into the return value (the
    #: lattice cannot carry them onward — counted per pop).
    param_returns: frozenset[int] = frozenset()
    #: An in-body SOURCE flow reaches the return value — the
    #: canonical helper-returns-tainted shape the lattice cannot
    #: carry to callers; counted once per visited node.
    source_return: bool = False
    #: Successor entries admitted so far (the plan-size rail).
    succ_count: int = 0

    def entry_count(self) -> int:
        """Table entries for the byte estimator."""
        return (self.succ_count
                + sum(len(v) for v in self.sinks_by_param.values())
                + sum(len(v) for v in self.frontier_by_param.values())
                + len(self.source_sinks))


@dataclass(frozen=True)
class _BindSig:
    """The binding-relevant slice of a callee's signature — kept
    INSTEAD of the FunctionEntry (whose ``.node`` would pin the def's
    whole AST subtree in the memo for the run's lifetime)."""

    params: tuple[str, ...]
    n_pos: int
    has_vararg: bool
    has_kwarg: bool

    def bytes_estimate(self) -> int:
        return _SIG_BYTES_BASE + _SIG_BYTES_PER_PARAM * len(self.params)


@dataclass
class _Seed:
    """One provenance root: the descriptor rendered into candidate
    ``source`` fields, plus the optional head hop prepended to
    witness chains that start one edge PAST the source function."""

    descriptor: tuple[tuple[str, object], ...]
    head_hop: Hop | None = None


@dataclass
class _FactState:
    """Joined lattice state for one key + its current witness."""

    tier_rank: int
    killed: frozenset[str]
    depth: int
    #: ("seed", seed index) or ("fact", parent key).
    pred: tuple[str, object]
    #: The hop that entered this key on the witness path.
    hop: Hop


_FactKey = tuple[str, int, str]  # (node_id, param_index, taint_class)


def _flow_param_index(flow: Flow) -> int | None:
    if flow.origin.startswith(_PARAM_ORIGIN_PREFIX):
        try:
            return int(flow.origin[len(_PARAM_ORIGIN_PREFIX):])
        except ValueError:  # pragma: no cover - extractor-formed
            return None
    return None


def _flow_source_origin(flow: Flow) -> tuple[str, str] | None:
    """``source:<kind>:<match>`` → ``(kind, match)``."""
    if not flow.origin.startswith(_SOURCE_ORIGIN_PREFIX):
        return None
    parts = flow.origin.split(":", 2)
    if len(parts) != 3:
        return None
    return parts[1], parts[2]


class _Engine:
    """One propagation run. Holds the bounded state; every budget
    check funnels through the named counters."""

    def __init__(
        self,
        graph: PackageCallGraph,
        routes: RouteModels,
        packs: PackSet,
        learned: LearnedIntake | None,
        *,
        target_root: str | Path,
        limits: EngineLimits,
        indexer: Callable[[Path, str], ModuleIndex] | None,
    ) -> None:
        self.graph = graph
        self.routes = routes
        self.limits = limits
        self.specs: SpecIndex = build_spec_index(packs, learned)
        self.packs = packs
        self.target_root = Path(target_root)
        self.indexer = indexer or self._default_indexer
        self.deadline = time.monotonic() + limits.wall_budget_s

        # Project-internal top-level module roots: dotted names
        # rooted here never match EXTERNAL pack specs (an in-package
        # module named like a sanitizer must not kill) — passed into
        # every extraction from the callgraph's package view.
        self.internal_roots = frozenset(
            n.module.split(".", 1)[0] for n in graph.nodes if n.module
        )

        self.state: dict[_FactKey, _FactState] = {}
        self.queue: deque[_FactKey] = deque()
        self.queued: set[_FactKey] = set()
        # Caches are LRU OrderedDicts so the retained-bytes rail can
        # evict; permanent refusals/failures live in side sets so a
        # blind spot is decided once, never retried into thrash.
        self.plans: OrderedDict[str, _Plan] = OrderedDict()
        self.plan_failures: set[str] = set()
        self.indexes: OrderedDict[str, ModuleIndex] = OrderedDict()
        self.index_refused: set[str] = set()
        self.bind_sigs: dict[str, _BindSig | None] = {}
        # Byte accounting for the retention rail.
        self.index_bytes: dict[str, int] = {}
        self.plan_bytes: dict[str, int] = {}
        self.retained_bytes = 0
        # Monotone identity sets: caps count DISTINCT work, thrash
        # counts separately (rebuild loops must burn their own
        # counters, not re-earn capacity).
        self.files_seen: set[str] = set()
        self.visited: set[str] = set()
        self.sources_fired: set[str] = set()
        self.seeds: list[_Seed] = []
        self.candidates: dict[tuple, Candidate] = {}
        self._cand_priority: dict[tuple, tuple] = {}
        #: identity -> (emitting fact key or None, the sink hit's own
        #: killed set): lets result() recompute each candidate's
        #: killed tuple from the FINAL lattice state.
        self._cand_state: dict[tuple, tuple[_FactKey | None,
                                            frozenset[str]]] = {}
        self._worst_key: tuple | None = None
        self._nodes_by_file: dict[str, list[CallGraphNode]] | None = None
        self.frontier: list[FrontierRecord] = []
        self._frontier_seen: set[tuple[str, int, str, str]] = set()
        self.caps_hit: list[str] = []
        self.stats: dict[str, int] = {}
        self.summaries_computed = 0
        self.pops = 0

    # -- bookkeeping ---------------------------------------------------

    def _count(self, name: str, n: int = 1) -> None:
        self.stats[name] = self.stats.get(name, 0) + n

    def _mark_cap(self, name: str) -> None:
        if name not in self.caps_hit:
            self.caps_hit.append(name)

    def _over_wall(self) -> bool:
        if time.monotonic() > self.deadline:
            self._mark_cap("wall_budget")
            return True
        return False

    def _default_indexer(self, path: Path, module_name: str) -> ModuleIndex:
        return index_module(path, module_name=module_name)

    # -- retained-bytes rail ------------------------------------------------

    def _evict_retained(self, need: int, keep: frozenset[str]) -> None:
        """Evict LRU caches until ``need`` more bytes fit the budget
        (or nothing evictable remains). Plans first (derived data),
        then indexes. Local references keep in-flight objects alive;
        eviction only drops the memo — rebuilds are deterministic and
        counted, and their spend is bounded by MAX_SUMMARIES plus the
        wall budget."""
        budget = self.limits.max_retained_bytes
        while self.retained_bytes + need > budget:
            victim = next((k for k in self.plans if k not in keep), None)
            if victim is not None:
                self.plans.pop(victim)
                self.retained_bytes -= self.plan_bytes.pop(victim, 0)
                self._mark_cap("retained_bytes")
                self._count("plans_evicted")
                continue
            victim = next((k for k in self.indexes if k not in keep),
                          None)
            if victim is not None:
                self.indexes.pop(victim)
                self.retained_bytes -= self.index_bytes.pop(victim, 0)
                self._mark_cap("retained_bytes")
                self._count("indexes_evicted")
                continue
            return

    def _reserve_retained(self, need: int, keep: frozenset[str]) -> bool:
        """Fit ``need`` bytes into the retention budget, evicting
        caches if required. False = refuse (caller counts + marks)."""
        self._evict_retained(need, keep)
        if self.retained_bytes + need > self.limits.max_retained_bytes:
            self._mark_cap("retained_bytes")
            return False
        self.retained_bytes += need
        return True

    # -- module index / signature memo ---------------------------------------

    @staticmethod
    def _index_bytes_estimate(idx: ModuleIndex) -> int:
        # Two axes, both target-chosen (see the estimator constants'
        # calibration note): per-text-byte AST density AND
        # per-function def overhead — a flat text ratio alone
        # under-counts tiny-function-flood shapes by ~2x. A degraded
        # index holds no tree.
        if idx.functions:
            return (_INDEX_BYTES_BASE
                    + _INDEX_BYTES_PER_TEXT_BYTE * len(idx.text)
                    + _INDEX_BYTES_PER_FUNCTION * len(idx.functions))
        return _INDEX_BYTES_BASE + 2 * len(idx.text)

    def _index_for(self, file_path: str,
                   module_name: str) -> ModuleIndex | None:
        cached = self.indexes.get(file_path)
        if cached is not None:
            self.indexes.move_to_end(file_path)
            return cached
        if file_path in self.index_refused:
            return None
        if file_path in self.files_seen:
            # Evicted by the retention rail; deterministic reload.
            self._count("index_reloads")
        elif len(self.files_seen) >= self.limits.max_files_indexed:
            self._mark_cap("files_indexed")
            self._count("files_indexed_capped")
            return None
        p = Path(file_path)
        if not p.is_absolute():
            p = self.target_root / p
        idx = self.indexer(p, module_name)
        est = self._index_bytes_estimate(idx)
        if not self._reserve_retained(est, keep=frozenset()):
            # Too big to retain even alone — a permanent, counted
            # blind spot (returning it unretained would let every
            # caller re-parse it unaccounted).
            self.index_refused.add(file_path)
            self.files_seen.add(file_path)
            self._count("index_refused_bytes")
            return None
        if file_path not in self.files_seen:
            self.files_seen.add(file_path)
            self._count("files_indexed")
        self.indexes[file_path] = idx
        self.index_bytes[file_path] = est
        return idx

    def _entry_from_index(self, node: CallGraphNode) -> FunctionEntry | None:
        """Look the node's def up in its (LRU-cached) module index.
        NOT memoized per node — a FunctionEntry pins its whole def
        AST, so callers copy what they need and drop it."""
        idx = self._index_for(node.file_path, node.module)
        if idx is None or not idx.ok:
            return None
        entry = idx.function_named(node.name) or idx.function_at(node.line)
        if entry is None:
            self._count("summary_join_failed")
        return entry

    def _bind_sig_for(self, node: CallGraphNode) -> _BindSig | None:
        cached = self.bind_sigs.get(node.node_id, "miss")
        if cached != "miss":
            return cached  # type: ignore[return-value]
        entry = self._entry_from_index(node)
        sig: _BindSig | None = None
        if entry is not None:
            args = entry.node.args
            sig = _BindSig(
                params=entry.params,
                n_pos=len(args.posonlyargs) + len(args.args),
                has_vararg=args.vararg is not None,
                has_kwarg=args.kwarg is not None,
            )
            if not self._reserve_retained(sig.bytes_estimate(),
                                          keep=frozenset()):
                # Signature memory refused: the channel becomes a
                # counted PERMANENT blind spot (memoized as None so
                # a hot call site cannot retry-thrash the evictor).
                self._count("bind_sig_refused_bytes")
                sig = None
        self.bind_sigs[node.node_id] = sig
        return sig

    # -- plans -----------------------------------------------------------

    def _plan_for(self, node_id: str) -> _Plan | None:
        """Build (once), rebuild (after a retention eviction — the
        rebuild is deterministic and counted) or fetch the node's
        propagation plan. A ``None`` plan means the node stays a
        blind spot — counted, never fabricated."""
        plan = self.plans.get(node_id)
        if plan is not None:
            self.plans.move_to_end(node_id)
            return plan
        if node_id in self.plan_failures:
            return None
        if self._over_wall():
            return None
        first_visit = node_id not in self.visited
        if first_visit and len(self.visited) >= \
                self.limits.max_functions_visited:
            self._mark_cap("functions_visited")
            self._count("functions_visited_capped")
            self.plan_failures.add(node_id)
            return None
        node = self.graph.node(node_id)
        if node is None or node.kind != "function":
            self._count("plan_unbuildable")
            self.plan_failures.add(node_id)
            return None
        idx = self._index_for(node.file_path, node.module)
        entry = self._entry_from_index(node) if idx is not None else None
        if idx is None or entry is None:
            self.plan_failures.add(node_id)
            return None
        if self.summaries_computed >= self.limits.max_summaries:
            self._mark_cap("summaries")
            self._count("summaries_capped")
            # NOT a permanent failure: the summary cap also bounds
            # rebuild thrash, and marking it permanent here would
            # turn a rebuild refusal into a lost node.
            return None
        summary = extract_summary(
            idx, entry, self.specs,
            limits=self.limits.summary_limits,
            internal_roots=self.internal_roots,
        )
        self.summaries_computed += 1
        self._count("summaries_computed")
        if summary.opaque:
            self._count("summaries_opaque")
        plan = self._build_plan(node, summary)
        est = _PLAN_BYTES_BASE + _PLAN_BYTES_PER_ENTRY * plan.entry_count()
        if self._reserve_retained(est, keep=frozenset({node.file_path})):
            self.plans[node_id] = plan
            self.plan_bytes[node_id] = est
        else:
            # Too big to retain even alone: the plan still serves
            # THIS caller (correctness), it is just never memoized —
            # counted, and rebuild spend stays inside the summary
            # cap + wall budget.
            self._count("plan_refused_bytes")
        if first_visit:
            self.visited.add(node_id)
            self._count("functions_visited")
        else:
            self._count("plan_rebuilds")
        if node_id not in self.sources_fired:
            self.sources_fired.add(node_id)
            if plan.source_return:
                # The canonical helper-returns-tainted shape: an
                # in-body source reaches the return value, which the
                # parameter-shaped lattice cannot carry to callers.
                # Counted once per node — the docstring's own
                # example must show up in the run's honest account.
                self._count("return_taint_unpropagated")
            # In-body sources fire ONCE per node ever, whatever
            # brought the visit about (rebuilds must not re-seed).
            self._process_local_sources(plan)
        return plan

    def _build_plan(self, node: CallGraphNode,
                    summary: FunctionSummary) -> _Plan:
        param_returns = frozenset(
            pi for f in summary.returns
            if (pi := _flow_param_index(f)) is not None
        )
        plan = _Plan(
            node_id=node.node_id,
            params=summary.params,
            qualname=summary.qualname,
            line_start=summary.line_start,
            opaque=summary.opaque,
            source_lines={ev.match: ev.line
                          for ev in reversed(summary.source_events)},
            param_returns=param_returns,
            source_return=any(_flow_source_origin(f) is not None
                              for f in summary.returns),
        )
        edges = [e for e in self.graph.callees_of(node.node_id)
                 if e.kind != KIND_DECORATOR]
        by_line: dict[int, list[CallGraphEdge]] = {}
        by_name: dict[str, list[CallGraphEdge]] = {}
        for e in edges:
            for ln in e.lines:
                by_line.setdefault(ln, []).append(e)
            dst = self.graph.node(e.dst)
            if dst is not None:
                by_name.setdefault(dst.qual_name, []).append(e)
                if dst.name != dst.qual_name:
                    by_name.setdefault(dst.name, []).append(e)

        for channel in summary.call_channels:
            param_flows: dict[int, list[Flow]] = {}
            source_flows: list[Flow] = []
            for flow in channel.flows:
                pi = _flow_param_index(flow)
                if pi is not None:
                    param_flows.setdefault(pi, []).append(flow)
                elif _flow_source_origin(flow) is not None:
                    source_flows.append(flow)
            if not param_flows and not source_flows:
                continue
            matched = self._join_channel(channel.callee, channel.line,
                                         by_line, by_name)
            if not matched:
                # External/builtin callees that match no edge were
                # fully handled in-summary (sink/sanitizer/
                # propagator specs); anything else is a blind spot.
                if channel.resolution in ("local", "relative",
                                          "unresolved"):
                    for pi in param_flows:
                        plan.frontier_by_param.setdefault(pi, []).append(
                            (channel.callee, channel.resolution,
                             channel.line))
                    for flow in source_flows:
                        for cls in flow.classes:
                            self._note_frontier(
                                plan.node_id, channel.line,
                                channel.callee, channel.resolution, cls)
                continue
            for edge in matched:
                binding = self._bind_channel(channel.arg, channel.kwarg,
                                             channel.star, edge)
                if binding is None:
                    continue
                bound_params, approx = binding
                for pi, flows in param_flows.items():
                    for flow in flows:
                        if not self._plan_succ_budget(plan):
                            break
                        plan.succ_by_param.setdefault(pi, []).append(
                            self._succ(edge, channel.line, bound_params,
                                       flow, approx))
                for flow in source_flows:
                    origin = _flow_source_origin(flow)
                    if origin is None:  # pragma: no cover - filtered
                        continue
                    if not self._plan_succ_budget(plan):
                        break
                    kind, match = origin
                    plan.source_tasks.append((
                        self._succ(edge, channel.line, bound_params,
                                   flow, approx),
                        flow.classes, frozenset(flow.killed),
                        flow.markers, flow.hops, kind, match,
                        channel.line,
                    ))

        for event in summary.sink_events:
            spec_tier = event.tier or TIER_PACK
            for flow in event.flows:
                hit = _SinkHit(
                    sink_class=event.sink_class, cwe=event.cwe,
                    match=event.match, line=event.line,
                    confidence=event.confidence, spec_tier=spec_tier,
                    pack=event.pack, killed=frozenset(flow.killed),
                    tags=flow.markers, sanitizer_hops=flow.hops,
                )
                pi = _flow_param_index(flow)
                if pi is not None:
                    plan.sinks_by_param.setdefault(pi, []).append(hit)
                    continue
                origin = _flow_source_origin(flow)
                if origin is not None:
                    kind, match = origin
                    plan.source_sinks.append(
                        (hit, flow.classes, kind, match))
        return plan

    def _plan_succ_budget(self, plan: _Plan) -> bool:
        """Admit one more successor entry into the plan, or refuse
        counted — the plan-size rail (channels × flows × matched
        edges is a target-shaped product)."""
        if plan.succ_count >= self.limits.max_plan_successors:
            self._mark_cap("plan_successors")
            self._count("plan_succ_capped")
            return False
        plan.succ_count += 1
        return True

    def _succ(self, edge: CallGraphEdge, line: int,
              params: tuple[int, ...], flow: Flow,
              approx: bool) -> _Succ:
        tags = set(flow.markers)
        if approx:
            tags.add(MARKER_BINDING_ALL_PARAMS)
        tier_rank = _TIER_RANK.get(edge.tier, _HEURISTIC_RANK)
        return _Succ(
            dst=edge.dst,
            tier_rank=tier_rank,
            kind=edge.kind,
            line=line,
            params=params,
            killed=frozenset(flow.killed),
            entry_hop=Hop(
                function=edge.dst, tier=_TIER_BY_RANK[tier_rank],
                kind=edge.kind, line=line, tags=tuple(sorted(tags)),
                sanitizer_hops=flow.hops,
            ),
        )

    def _join_channel(
        self, callee: str, line: int,
        by_line: dict[int, list[CallGraphEdge]],
        by_name: dict[str, list[CallGraphEdge]],
    ) -> list[CallGraphEdge]:
        """Join one summary call channel to graph edges: by line with
        a name-compatibility check first, then by resolved dotted
        name. An unjoinable channel is the caller's frontier
        decision."""
        out = [edge for edge in by_line.get(line, ())
               if self._name_compatible(callee, edge)]
        if out:
            return out
        if callee != _UNRESOLVED_CALLEE:
            return list(by_name.get(callee, ()))
        return []

    def _name_compatible(self, callee: str, edge: CallGraphEdge) -> bool:
        if callee == _UNRESOLVED_CALLEE:
            # The summary could not name the callee (dispatch through
            # values); the graph's edge at this line IS the binding
            # (dict-dispatch / getattr edges are exactly this shape).
            return True
        dst = self.graph.node(edge.dst)
        if dst is None:
            return False
        tail = callee.rsplit(".", 1)[-1]
        dst_bare = dst.name.rsplit(".", 1)[-1]
        if tail == dst_bare:
            return True
        if edge.kind == KIND_CONSTRUCTOR:
            # ``Cls(...)`` binds to ``Cls.__init__`` — compare the
            # class segment, not the synthetic method name.
            return tail == dst.name.split(".", 1)[0]
        return False

    # -- argument binding -------------------------------------------------

    def _bind_channel(
        self, arg: int, kwarg: str, star: str, edge: CallGraphEdge,
    ) -> tuple[tuple[int, ...], bool] | None:
        """Map one channel's argument slot to callee parameter
        indices ``(indices, approximated)``. Mismatch / star forms
        degrade to taint-all-params (bounded, flagged) — never a
        silent drop; ``None`` only when the callee's definition
        cannot be found at all (counted upstream)."""
        dst = self.graph.node(edge.dst)
        if dst is None:
            return None
        sig = self._bind_sig_for(dst)
        if sig is None:
            return None
        params = sig.params
        if not params:
            return (), False
        cap = self.limits.max_params_per_function
        if len(params) > cap:
            self._mark_cap("params_per_function")
            self._count("params_capped", len(params) - cap)
        shift = 0
        if params[0] in ("self", "cls") and edge.kind in (
            KIND_METHOD_CALL, KIND_CONSTRUCTOR, KIND_GETATTR_DISPATCH,
        ):
            # Bound-call forms: caller argument 0 lands on the first
            # non-receiver parameter.
            shift = 1
        if star:
            return self._all_params(params, cap), True
        if kwarg:
            for i, name in enumerate(params):
                if name == kwarg:
                    return ((i,), False) if i < cap else ((), False)
            if sig.has_kwarg:
                # Lands in **kwargs — a container, whole-value.
                i = len(params) - 1
                return ((i,), True) if i < cap else ((), True)
            return self._all_params(params, cap), True
        pos = arg + shift
        if 0 <= pos < sig.n_pos:
            if pos < cap:
                return (pos,), False
            return (), False
        if sig.has_vararg:
            i = sig.n_pos
            if i < len(params) and i < cap:
                return (i,), True
        return self._all_params(params, cap), True

    @staticmethod
    def _all_params(params: tuple[str, ...],
                    cap: int) -> tuple[int, ...]:
        return tuple(range(min(len(params), cap)))

    # -- frontier ---------------------------------------------------------

    def _note_frontier(self, function: str, line: int, callee: str,
                       resolution: str, taint_class: str) -> None:
        self._count("taint_at_unresolved")
        key = (function, line, callee, taint_class)
        if key in self._frontier_seen:
            return
        if len(self.frontier) >= self.limits.max_frontier_records:
            self._mark_cap("frontier_records")
            return
        self._frontier_seen.add(key)
        self.frontier.append(FrontierRecord(
            function=function, line=line, callee=callee,
            resolution=resolution, taint_class=taint_class,
        ))

    # -- seeding ------------------------------------------------------------

    def seed(self) -> None:
        self._seed_routes()
        self._seed_source_entries()

    def _route_param_classes(self, framework: str) -> tuple[str, ...]:
        exact = sorted({
            c for s in self.packs.sources
            if s.kind == SOURCE_KIND_ROUTE_PARAM
            and s.framework == framework
            for c in s.taint_classes
        })
        if exact:
            return tuple(exact)
        return tuple(sorted({
            c for s in self.packs.sources
            if s.kind == SOURCE_KIND_ROUTE_PARAM
            for c in s.taint_classes
        }))

    def _seed_routes(self) -> None:
        routes = sorted(
            self.routes.all_routes(),
            key=lambda r: (r.file_path, r.line, r.handler),
        )
        for route in routes:
            if self._over_wall():
                return
            classes = self._route_param_classes(route.framework)
            if not classes:
                # No loaded route_param spec covers this framework's
                # records: packs govern seeding, so nothing seeds —
                # counted, never silent.
                self._count("route_seeds_no_spec")
                continue
            for node_id in self._handler_nodes(route):
                self._seed_handler(node_id, route, classes)

    def _handler_nodes(self, route: RouteRecord) -> list[str]:
        if route.handler_kind == HANDLER_KIND_CLASS:
            # Class-based views: the record's handler id is a
            # fallback form, not a graph node — join by name prefix
            # over the handler's file, HTTP-verb methods only. The
            # per-file node index is built ONCE on first use (a
            # per-route scan over every graph node is routes × nodes
            # — the once-per-X lesson applies at the seed boundary
            # too).
            if self._nodes_by_file is None:
                by_file: dict[str, list[CallGraphNode]] = {}
                for n in self.graph.nodes:
                    if n.kind == "function":
                        by_file.setdefault(n.file_path, []).append(n)
                self._nodes_by_file = by_file
            file_path, _, rest = route.handler.partition("::")
            cls = rest.split("@", 1)[0]
            out = sorted(
                n.node_id
                for n in self._nodes_by_file.get(file_path, ())
                if n.name.startswith(f"{cls}.")
                and n.name.rsplit(".", 1)[-1] in _HTTP_VERBS
            )
            if not out:
                self._count("seed_handler_unbound")
            return out
        if self.graph.node(route.handler) is None:
            self._count("seed_handler_unbound")
            return []
        return [route.handler]

    def _seed_handler(self, node_id: str, route: RouteRecord,
                      classes: tuple[str, ...]) -> None:
        plan = self._plan_for(node_id)
        if plan is None:
            return
        seed_idx = len(self.seeds)
        self.seeds.append(_Seed(descriptor=(
            ("kind", "route_param"),
            ("framework", route.framework),
            ("route_pattern", route.route_pattern),
            ("handler", node_id),
            ("registration_file", route.file_path),
            ("registration_line", route.line),
        )))
        params = plan.params
        # Method-shaped handlers (CBV verb methods) receive the
        # instance first — the receiver is not request data.
        start = 1 if (params and params[0] in ("self", "cls")
                      and "." in plan.qualname) else 0
        cap = self.limits.max_params_per_function
        if len(params) - start > cap:
            self._mark_cap("params_per_function")
            self._count("params_capped", len(params) - start - cap)
        hop = Hop(function=node_id, tier=SEED_HOP_TIER, kind="seed",
                  line=plan.line_start)
        for i in range(start, min(len(params), start + cap)):
            for cls in classes:
                if self.stats.get("seed_facts", 0) >= \
                        self.limits.max_seed_facts:
                    self._mark_cap("seeds")
                    return
                self._count("seed_facts")
                self._arrive((node_id, i, cls), tier_rank=0,
                             killed=frozenset(), depth=0,
                             pred=("seed", seed_idx), hop=hop)

    def _seed_source_entries(self) -> None:
        """Visit functions whose bodies fire a declared source, found
        through the graph's external-call census (their in-body
        flows enter the worklist at plan-build time)."""
        call_names = set(self.specs.call_sources_by_name)
        attr_prefixes = tuple(self.specs.attr_sources_by_name)
        learned_names = set(self.specs.learned_sources_by_name)
        callers: set[str] = set()
        for ec in self.graph.external_calls:
            if ec.caller is None:
                continue
            t = ec.target
            if (t in call_names or t in learned_names
                    or any(t == p or t.startswith(p + ".")
                           for p in attr_prefixes)):
                callers.add(ec.caller)
        for caller in sorted(callers):
            if self._over_wall():
                return
            node = self.graph.node(caller)
            if node is None or node.kind != "function":
                # Module-level source reads have no function summary
                # to ride — a named miss, counted.
                self._count("source_entry_unplannable")
                continue
            self._count("source_entry_functions")
            self._plan_for(caller)

    # -- local (in-body) source processing ---------------------------------

    def _process_local_sources(self, plan: _Plan) -> None:
        """Flows born from in-body sources: same-function sink
        candidates plus outgoing facts, processed once per visited
        node."""
        for hit, classes, kind, match in plan.source_sinks:
            source = self._source_descriptor(plan, kind, match)
            hops = (Hop(function=plan.node_id, tier=SEED_HOP_TIER,
                        kind="seed", line=hit.line, tags=hit.tags,
                        sanitizer_hops=hit.sanitizer_hops),)
            for cls in classes:
                self._emit_candidate(
                    sink_function=plan.node_id, hit=hit,
                    taint_class=cls, joined_killed=hit.killed,
                    hops=hops, source=source,
                )
        seed_memo: dict[tuple[str, str, int], int] = {}
        for (succ, classes, killed, markers, san_hops,
             kind, match, line) in plan.source_tasks:
            memo_key = (kind, match, line)
            seed_idx = seed_memo.get(memo_key)
            if seed_idx is None:
                seed_idx = len(self.seeds)
                seed_memo[memo_key] = seed_idx
                self.seeds.append(_Seed(
                    descriptor=self._source_descriptor(plan, kind, match),
                    head_hop=Hop(function=plan.node_id,
                                 tier=SEED_HOP_TIER, kind="seed",
                                 line=line, tags=markers,
                                 sanitizer_hops=san_hops),
                ))
            for cls in classes:
                for pi in succ.params:
                    self._arrive(
                        (succ.dst, pi, cls),
                        tier_rank=succ.tier_rank,
                        killed=killed | succ.killed,
                        depth=1,
                        pred=("seed", seed_idx),
                        hop=succ.entry_hop,
                    )

    def _source_descriptor(
        self, plan: _Plan, kind: str, match: str,
    ) -> tuple[tuple[str, object], ...]:
        return (
            ("kind", kind), ("match", match),
            ("function", plan.node_id),
            ("line", plan.source_lines.get(match, 0)),
        )

    # -- the lattice ---------------------------------------------------------

    def _arrive(
        self, key: _FactKey, *, tier_rank: int, killed: frozenset[str],
        depth: int, pred: tuple[str, object], hop: Hop,
    ) -> None:
        """Join one arrival into the key's state; enqueue on
        improvement (monotone: the tier rank can only fall, the
        killed set can only shrink — finite height, so the fixpoint
        terminates without cycle special-casing)."""
        cur = self.state.get(key)
        if cur is None:
            if len(self.state) >= self.limits.max_fact_keys:
                self._mark_cap("fact_keys")
                self._count("fact_keys_capped")
                return
            if not self._reserve_retained(_FACT_BYTES_EST,
                                          keep=frozenset()):
                # Fact state is not evictable (it IS the fixpoint);
                # over the byte budget new keys refuse counted while
                # existing keys keep joining — partial, marked.
                self._count("fact_keys_refused_bytes")
                return
            self.state[key] = _FactState(
                tier_rank=tier_rank, killed=killed, depth=depth,
                pred=pred, hop=hop)
            self._count("facts_created")
            self._push(key)
            return
        new_rank = min(cur.tier_rank, tier_rank)
        new_killed = cur.killed & killed
        if new_rank == cur.tier_rank and new_killed == cur.killed:
            return
        if tier_rank < cur.tier_rank or killed < cur.killed:
            # The improving arrival becomes the witness (depth
            # included). An arrival that improves the JOIN without
            # strictly bettering the witness (e.g. an incomparable
            # killed set whose intersection shrinks the state)
            # leaves witness and depth untouched — the recorded
            # depth describes the WITNESS path, and the hop cap is
            # checked against it, so a stale witness can never
            # inflate the join's depth allowance.
            cur.pred = pred
            cur.hop = hop
            cur.depth = depth
        cur.tier_rank = new_rank
        cur.killed = new_killed
        self._count("fact_improvements")
        self._push(key)

    def _push(self, key: _FactKey) -> None:
        if key in self.queued:
            return
        self.queued.add(key)
        self.queue.append(key)

    # -- main loop -------------------------------------------------------------

    def run(self) -> None:
        self.seed()
        while self.queue:
            if self.pops >= self.limits.max_iterations:
                self._mark_cap("iterations")
                break
            if self.pops % 64 == 0 and self._over_wall():
                break
            key = self.queue.popleft()
            self.queued.discard(key)
            self.pops += 1
            self._process(key)
        self.stats["worklist_pops"] = self.pops

    def _process(self, key: _FactKey) -> None:
        node_id, pi, cls = key
        plan = self._plan_for(node_id)
        if plan is None:
            return
        if plan.opaque:
            # Taint reaching a capped/unparseable function dead-ends
            # in an opaque summary (all channels unknown) — counted,
            # never a silent no-flow.
            self._count("taint_at_opaque_summary")
        st = self.state[key]
        # Sinks in this function fed by this parameter.
        for hit in plan.sinks_by_param.get(pi, ()):
            combined = st.killed | hit.killed
            if hit.sink_class and hit.sink_class in combined:
                self._count("candidates_killed")
                continue
            self._emit_candidate(
                sink_function=node_id, hit=hit, taint_class=cls,
                joined_killed=combined,
                hops=self._witness_chain(key),
                source=self._source_of(key),
                fact_key=key,
            )
        # Frontier: this parameter feeds unbindable call sites.
        for callee, resolution, line in plan.frontier_by_param.get(pi, ()):
            self._note_frontier(node_id, line, callee, resolution, cls)
        # Successors.
        for succ in plan.succ_by_param.get(pi, ()):
            if st.depth + 1 > self.limits.max_path_hops:
                self._mark_cap("path_hops")
                self._count("path_hops_capped")
                continue
            new_rank = max(st.tier_rank, succ.tier_rank)
            new_killed = st.killed | succ.killed
            child_hop = succ.entry_hop
            for cpi in succ.params:
                self._arrive(
                    (succ.dst, cpi, cls),
                    tier_rank=new_rank,
                    killed=new_killed,
                    depth=st.depth + 1,
                    pred=("fact", key),
                    hop=child_hop,
                )
        # The parameter-shaped lattice cannot carry taint back out
        # through the return value — count the visible miss class
        # (the source-origin sub-case is counted once per node at
        # visit time; this is the param-origin sub-case, observed
        # per pop).
        if pi in plan.param_returns:
            self._count("return_taint_unpropagated")

    # -- witness / source reconstruction ---------------------------------------

    def _witness_chain(self, key: _FactKey) -> tuple[Hop, ...]:
        """Walk predecessor links back to the seed (bounded; a
        witness loop — possible after witness replacement inside a
        cycle — truncates with a counted marker rather than
        fabricating a chain)."""
        hops: list[Hop] = []
        seen: set[_FactKey] = set()
        cur: _FactKey | None = key
        while cur is not None:
            if cur in seen or len(hops) > self.limits.max_path_hops:
                self._count("witness_truncated")
                return tuple(reversed(hops))
            seen.add(cur)
            st = self.state.get(cur)
            if st is None:  # pragma: no cover - internal invariant
                self._count("witness_truncated")
                return tuple(reversed(hops))
            hops.append(st.hop)
            kind, parent = st.pred
            if kind == "seed":
                seed = self.seeds[parent]  # type: ignore[index]
                if seed.head_hop is not None:
                    hops.append(seed.head_hop)
                return tuple(reversed(hops))
            cur = parent  # type: ignore[assignment]
        return tuple(reversed(hops))  # pragma: no cover

    def _source_of(self, key: _FactKey) -> tuple[tuple[str, object], ...]:
        seen: set[_FactKey] = set()
        cur: _FactKey | None = key
        while cur is not None and cur not in seen:
            seen.add(cur)
            st = self.state.get(cur)
            if st is None:
                break
            kind, parent = st.pred
            if kind == "seed":
                return self.seeds[parent].descriptor  # type: ignore[index]
            cur = parent  # type: ignore[assignment]
        # Witness-loop truncation (counted above) can orphan the
        # root; the record stays honest about not knowing it.
        return (("kind", "unknown"),)

    # -- candidates --------------------------------------------------------------

    def _emit_candidate(
        self, *, sink_function: str, hit: _SinkHit, taint_class: str,
        joined_killed: frozenset[str], hops: tuple[Hop, ...],
        source: tuple[tuple[str, object], ...],
        fact_key: _FactKey | None = None,
    ) -> None:
        path_rank = max(
            (_TIER_RANK.get(h.tier, _HEURISTIC_RANK) for h in hops),
            default=0,
        )
        candidate = Candidate(
            taint_class=taint_class,
            source=source,
            sink_function=sink_function,
            sink_line=hit.line,
            sink_class=hit.sink_class,
            sink_cwe=hit.cwe,
            sink_match=hit.match,
            sink_confidence=hit.confidence,
            spec_tier=hit.spec_tier,
            pack=hit.pack,
            hops=hops,
            path_tier=_TIER_BY_RANK[path_rank],
            killed=tuple(sorted(joined_killed)),
        )
        identity = (source, sink_function, hit.line, hit.sink_class,
                    hit.match, taint_class)
        priority = self._priority(candidate)
        existing = self._cand_priority.get(identity)
        if existing is not None:
            if priority < existing:
                # Same flow, better witness (tier improved on
                # re-propagation): replace in place, no cap effect.
                self.candidates[identity] = candidate
                self._cand_priority[identity] = priority
                self._cand_state[identity] = (fact_key,
                                              frozenset(hit.killed))
                self._worst_key = None
            # An identity-equal re-emission with a no-better witness
            # still refreshed the LATTICE (that is why it re-popped);
            # the stored candidate's killed tuple is provisional and
            # result() recomputes it from final state, so nothing is
            # lost by keeping the existing witness here.
            return
        if len(self.candidates) >= self.limits.max_candidates:
            self._mark_cap("candidates")
            worst_key = self._find_worst()
            if (worst_key is None
                    or priority >= self._cand_priority[worst_key]):
                self._count("candidates_evicted")
                self._count_eviction(candidate.spec_tier)
                return
            evicted = self.candidates.pop(worst_key)
            del self._cand_priority[worst_key]
            self._cand_state.pop(worst_key, None)
            self._worst_key = None
            self._count("candidates_evicted")
            self._count_eviction(evicted.spec_tier)
        self.candidates[identity] = candidate
        self._cand_priority[identity] = priority
        self._cand_state[identity] = (fact_key, frozenset(hit.killed))
        if self._worst_key is not None:
            if priority > self._cand_priority[self._worst_key]:
                self._worst_key = identity
        self._count("candidates_emitted")

    def _count_eviction(self, spec_tier: str) -> None:
        self._count(f"candidates_evicted_spec_{spec_tier or TIER_PACK}")

    def _find_worst(self) -> tuple | None:
        """Current worst-priority candidate. The cache only survives
        consecutive at-cap REJECTIONS; any admit/replace invalidates
        it, so an eviction costs one O(max_candidates) rescan. Both
        directions: a heap would make this O(log n) but needs an
        invertible priority (the tuple mixes strings); the rescan is
        bounded by the candidate cap and only runs when the cap
        binds — measured noise next to plan builds. Revisit only if
        a profile ever shows eviction on top."""
        if self._worst_key is not None:
            return self._worst_key
        worst: tuple | None = None
        worst_p: tuple | None = None
        for k, p in self._cand_priority.items():
            if worst_p is None or p > worst_p:
                worst, worst_p = k, p
        self._worst_key = worst
        return worst

    @staticmethod
    def _priority(c: Candidate) -> tuple:
        """Deterministic eviction priority — LOWER survives longer.
        Curated/pack sink specs before learned; then better path
        tiers; then shorter paths; then stable (function, line)
        order."""
        spec_rank = (_SPEC_TIER_RANK_LEARNED
                     if c.spec_tier == TIER_LEARNED
                     else _SPEC_TIER_RANK_CURATED)
        return (
            spec_rank,
            _TIER_RANK.get(c.path_tier, _HEURISTIC_RANK),
            len(c.hops),
            c.sink_function,
            c.sink_line,
            c.sink_class,
            c.taint_class,
            c.sink_match,
            c.source,
        )

    # -- result ------------------------------------------------------------------

    def result(self) -> PropagationResult:
        # The killed tuple is AUTHORITATIVE only now: emission-time
        # values are provisional because a later live path can shrink
        # the join after the witness stopped improving (an
        # identity-equal re-emission with a longer witness is
        # discarded by priority, but the LATTICE kept improving) —
        # displaying the stale set would over-claim sanitization,
        # exactly the anti-documented direction. Suppression is
        # unaffected: killed sets only shrink, so a candidate emitted
        # live can never become killed here.
        final: list[Candidate] = []
        for identity, candidate in self.candidates.items():
            fact_key, hit_killed = self._cand_state[identity]
            joined = (self.state[fact_key].killed
                      if fact_key is not None and fact_key in self.state
                      else frozenset())
            killed = tuple(sorted(joined | hit_killed))
            if killed != candidate.killed:
                candidate = replace(candidate, killed=killed)
                self._count("candidates_killed_refreshed")
            final.append(candidate)
        ordered = sorted(final, key=self._priority)
        self.stats["candidates_kept"] = len(ordered)
        self.stats["fact_keys"] = len(self.state)
        self.stats["retained_bytes_estimate"] = self.retained_bytes
        return PropagationResult(
            candidates=tuple(ordered),
            frontier=tuple(self.frontier),
            caps_hit=tuple(self.caps_hit),
            stats=dict(self.stats),
        )


def propagate(
    graph: PackageCallGraph,
    routes: RouteModels,
    packs: PackSet,
    learned: LearnedIntake | None = None,
    *,
    target_root: str | Path,
    limits: EngineLimits | None = None,
    indexer: Callable[[Path, str], ModuleIndex] | None = None,
) -> PropagationResult:
    """Run one interprocedural propagation over ``graph`` seeded from
    ``routes`` and the pack-declared sources. Never raises on target
    content: hostile files degrade inside the summary layer, and
    every engine bound degrades to a marked partial result.

    ``indexer`` overrides how module files are read and indexed (the
    seam a later phase wires the summary cache through; tests feed
    in-memory trees). The default reads size-capped files from
    ``target_root``.
    """
    engine = _Engine(
        graph, routes, packs, learned,
        target_root=target_root,
        limits=limits or EngineLimits(),
        indexer=indexer,
    )
    engine.run()
    return engine.result()


__all__ = [
    "DOCTRINE",
    "ENGINE_VERSION",
    "ENGINE_WALL_BUDGET_S",
    "MARKER_BINDING_ALL_PARAMS",
    "MAX_CANDIDATES",
    "MAX_FACT_KEYS",
    "MAX_FILES_INDEXED",
    "MAX_FRONTIER_RECORDS",
    "MAX_FUNCTIONS_VISITED",
    "MAX_PARAMS_PER_FUNCTION",
    "MAX_PATH_HOPS",
    "MAX_PLAN_SUCCESSORS",
    "MAX_RETAINED_BYTES",
    "MAX_SEED_FACTS",
    "MAX_SUMMARIES",
    "MAX_WORKLIST_ITERATIONS",
    "SEED_HOP_TIER",
    "Candidate",
    "EngineLimits",
    "FrontierRecord",
    "Hop",
    "PropagationResult",
    "propagate",
]
