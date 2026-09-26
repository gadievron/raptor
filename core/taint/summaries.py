"""Per-function finite-lattice taint summaries (the P2 transfer pass).

The package callgraph carries WHO calls WHOM but no argument
positions, so taint cannot ride its edges alone. This module computes,
for ONE function at a time, the transfer facts an interprocedural
worklist needs:

* which parameters flow to the return value,
* which parameters (and locally-fired pack sources) flow into which
  CALL-SITE arguments — callee as a resolved dotted name or a local
  name, argument as a position or keyword,
* which parameters reach pack-declared sinks inside the body,
* where pack sanitizers kill or tag along those paths (with the kill
  census and the demote-on-shadow rule),
* which pack sources fire locally.

Everything is summary-level: taint state is a bounded set of
:class:`Flow` values per local name — a finite lattice, so one ordered
walk over the function's statements suffices and no path enumeration
happens here.

Soundness direction (stated, because the approximations below all
lean the same way): this pass ORIGINATES candidates for a pipeline
whose verdicts come from the downstream classifier and validation
stages. Approximations therefore degrade toward the sink firing
(over-taint, extra candidates) and away from suppression:

* Unknown callees propagate argument taint to their return value,
  tagged ``assumed_propagation`` — dropping taint at every unmodeled
  call is the classic cross-file recall killer.
* Assignments inside conditional bodies are WEAK updates (the old
  flows survive — the branch may not execute), so a sanitizer inside
  an ``if`` never silently certifies the fall-through path. Only
  statements in a dominating position (the function's top-level
  sequence, and ``with``/``try``-``finally`` bodies reached through
  it) strong-update, which is what makes a straight-line
  ``x = shlex.quote(x)`` kill real.
* Sanitizer KILLS never delete flows. A kill accumulates its sink
  classes into the flow's ``killed`` set; the flow keeps moving and
  is filtered per-class at each sink. Cross-function composition
  (C-phases) sees the killed set on the summary channels.
* A kill whose name binding is suspect — the file rebinds or shadows
  the sanitizer's bound root name (``import shlex`` then
  ``shlex = _noop``), the import table rebound it, or the module
  patches an attribute through it (``shlex.quote = str``) — DEMOTES
  to a tag: the flow stays alive, marked ``sanitizer_demoted``, and
  the demotion is counted. Rebind detection covers EVERY module-scope
  binding form (assignment, ``for`` targets, ``with ... as``, walrus,
  ``match`` captures, ``except ... as``), and a function-local
  rebind beside a function-local import demotes the same way.
  Written-name resolution is not runtime binding; a wrong kill would
  be an invisible false suppression.
* Builtin-name sinks/sanitizers (``eval``, ``open``, ``int`` …) match
  only while the name is NOT shadowed anywhere in the file or the
  function; a shadowed builtin is not the builtin, so the match is
  refused and counted (``builtin_shadowed``) rather than guessed.
* ``unless_kwargs`` suppression demands the literal token as written
  at the call site (``shell=False`` as an AST constant); a variable
  or computed value never suppresses.
* Name matching operates on the parser's identifiers, which CPython
  NFKC-normalises: NFKC-equivalent respellings (fullwidth,
  mathematical alphanumerics) of a sink name ARE the sink name — they
  match, and NFKC-equivalent shadows count as shadows. Cross-script
  homoglyphs (e.g. Cyrillic ``о``) are NOT NFKC-equivalent: they are
  genuinely different identifiers and fall to the dynamic-binding
  miss class like any other unknown name.

Explicitly NOT modelled (design non-goals, restated here because a
reader of a summary must know its miss classes; a miss is never a
"no flow" claim):

* Taint through module-global / class-attribute / request-context
  MUTATION. A function that writes a tainted value into a module
  name and another that reads it back are invisible to the
  param/return/call-arg summary model. ``global``/``nonlocal`` names
  are recorded on the summary (``global_names``) as an informational
  channel only — they are NOT taint channels in v1.
* Decorator wrapper-body flow. Decorator expressions on the function
  being summarised are skipped entirely: route binding was already
  resolved by the route models (a handler's decorator must not
  double-count as a call site), and wrapper bodies transforming
  request data are a named recall gap. Nested defs, their decorators,
  and lambda bodies are likewise skipped and counted.
* Field/index sensitivity and aliasing: whole-value granularity — a
  tainted element taints its container, an attribute read off a
  tainted object is tainted.
* Exception-object taint: ``except E as e`` binds ``e`` clean — an
  exception carrying attacker text (message, args) is not modelled
  as a taint carrier.
* CFG path sensitivity beyond the statement-order dominance split
  above.

Cost rails: every budget below is a named cap with both-direction
rationale. The worst case is a PRODUCT — functions per file × AST
nodes walked × flows per value × summary entries — so each factor is
capped independently and the per-node work is O(flows-per-value) by
construction: state lives in one dict updated as statements are
walked in order, never re-scanned per statement, and NO per-function
step may cost O(file) (the file is read, parsed, and line-split once
at index time; per-function hashing slices the pre-split list — a
crafted file of tens of thousands of one-line functions is the shape
that turns any per-function whole-file pass into minutes of work).
A function over ANY cap degrades to a conservative
OPAQUE summary (all params propagate to the return value, tagged
``summary_capped``) — never a silent partial answer. Source files are
attacker bytes: reads are size-capped, parse failures degrade to
opaque summaries for all the file's functions, nothing raises on
hostile input.
"""

from __future__ import annotations

import ast
import builtins
import time
import warnings
from dataclasses import dataclass, field, replace
from pathlib import Path
from collections.abc import Iterable, Sequence

from core.source.gated import read_text_gated
from core.source.lines import split_lines
# One body, not twinned (the packs.py _valid_access precedent): span
# hashes must byte-match the staleness convention, so the hashing
# helper is imported rather than re-implemented.
from core.staleness import _hash_from_lines
from core.taint.learned_intake import LearnedIntake, LearnedSpec
from core.taint.packs import (
    CONFIDENCE_HEURISTIC,
    SEMANTICS_KILL,
    SEMANTICS_TAG,
    SINK_KIND_METHOD_NAME,
    SOURCE_KIND_CALL_RETURN,
    SOURCE_KIND_MODULE_ATTRIBUTE,
    SOURCE_KIND_STORED_READ,
    PackSet,
    PropagatorSpec,
    SanitizerSpec,
    SinkSpec,
    SourceSpec,
)

#: Bump when the summary SHAPE or the transfer semantics change in a
#: way cached summaries must not survive. Part of every cache key.
SUMMARY_VERSION = 1

# ── named caps ───────────────────────────────────────────────────────
# Each cap names both directions. Over ANY of them the function
# degrades to an opaque summary with a counted reason — visible,
# conservative, never silent.

#: Byte budget for one source file, enforced by the gated reader
#: before parsing. Higher admits generated monoliths; lower bounds
#: what a planted blob can make the extractor parse. Over-cap files
#: degrade to opaque summaries for ALL their functions.
MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024

#: AST-node budget for the module-index scan (imports, module-scope
#: bindings, function spans). Higher keeps huge generated modules
#: indexable; lower bounds index time/memory on a hostile file.
MAX_MODULE_AST_NODES = 500_000

#: Total AST nodes walked per function. Higher keeps giant functions
#: summarised precisely; lower bounds the nodes factor of the cost
#: product on a crafted function.
MAX_NODES_PER_FUNCTION = 50_000

#: Statements walked per function. Higher admits long generated
#: bodies; lower bounds walk time independently of expression width.
MAX_STATEMENTS_PER_FUNCTION = 5_000

#: Expression nodes per STATEMENT — width, not just statement count,
#: is the hostile dimension (one statement fanning out thousands of
#: sub-expressions). Higher admits legitimately wide literals; lower
#: bounds the per-statement work unit.
MAX_EXPR_NODES_PER_STATEMENT = 2_000

#: Nesting depth for the recursive walkers (expressions and
#: statements share it). Higher admits deeply nested real code; lower
#: keeps the walker far from the interpreter's recursion limit on
#: parse-accepted pathological nesting.
MAX_WALK_DEPTH = 100

#: Access-path depth: attribute-chain segments resolved for callee /
#: source matching. Higher resolves deeper real chains; lower bounds
#: the per-chain resolution cost (resolution is O(depth^2) per chain,
#: constant once capped). Deeper chains degrade to unresolved —
#: toward the assumed-propagation floor, never toward a kill.
MAX_ACCESS_PATH_DEPTH = 12

#: Locals tracked in the taint state. Higher keeps huge functions
#: precise; lower bounds state memory (the locals factor).
MAX_LOCALS_TRACKED = 512

#: Flows (distinct origin records) per tracked value — the lattice
#: height factor. Higher preserves provenance in fan-in-heavy code;
#: lower bounds per-node union cost.
MAX_FLOWS_PER_VALUE = 64

#: Sanitizer hops recorded per flow. Higher keeps long real chains
#: readable; lower bounds flow size (over-cap appends one elision
#: marker and stops growing — the flow itself keeps moving).
MAX_HOPS_PER_FLOW = 8

#: Summary-entry caps — the entries factor of the cost product.
#: Higher keeps call-heavy functions complete; lower bounds summary
#: size against a crafted thousand-call body.
MAX_CALL_CHANNELS = 512
MAX_SINK_EVENTS = 128
MAX_SOURCE_EVENTS = 128
MAX_SANITIZER_EVENTS = 256

#: Informational ``global``/``nonlocal`` names recorded. Higher shows
#: more of the excluded-channel surface; lower bounds summary size.
MAX_GLOBAL_NAMES = 32

#: Wall budget per function. Generous — the node caps bind first on
#: every shape we could craft — but a belt against pathological
#: interpreter behaviour: higher tolerates slow hosts, lower bounds
#: the time one hostile function can consume.
PER_FUNCTION_WALL_BUDGET_S = 10.0

# ── markers (stable identifiers for tests, reports, consumers) ──────

MARKER_ASSUMED_PROPAGATION = "assumed_propagation"
MARKER_SANITIZER_DEMOTED = "sanitizer_demoted"
MARKER_BINDING_APPROX = "binding_approx"
MARKER_SUMMARY_CAPPED = "summary_capped"
MARKER_LEARNED = "learned"
MARKER_HOPS_ELIDED = "hops_elided"

_PARAM_ORIGIN_PREFIX = "param:"
_SOURCE_ORIGIN_PREFIX = "source:"

_BUILTIN_NAMES = frozenset(vars(builtins))

# f-string / t-string node families vary by interpreter version;
# resolve them once so the walker stays version-portable.
_JOINED_STR_TYPES = tuple(
    t for t in (getattr(ast, "JoinedStr", None),
                getattr(ast, "TemplateStr", None)) if t is not None
)
_FORMATTED_VALUE_TYPES = tuple(
    t for t in (getattr(ast, "FormattedValue", None),
                getattr(ast, "Interpolation", None)) if t is not None
)


class _Budget(Exception):
    """Internal: a cap bound mid-walk. Caught at the extraction
    boundary and converted to an opaque summary — never escapes."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# ── flow lattice ─────────────────────────────────────────────────────


@dataclass(frozen=True)
class Flow:
    """One taint origin as it rides through the function.

    ``origin`` is ``param:<index>`` (class dimension decided by the
    caller — the C-phase worklist supplies what taint actually
    arrives) or ``source:<kind>:<match>`` for pack sources fired
    in-body (``classes`` then carries the spec's taint classes).

    ``killed`` is the set of SINK classes transform sanitizers have
    killed along this flow's path; the flow itself never disappears —
    it is filtered per-class at each sink and the killed set rides
    into the summary channels so cross-function composition can see
    it. ``hops`` records sanitizer callees in path order (bounded;
    over-cap appends :data:`MARKER_HOPS_ELIDED` once).
    """

    origin: str
    classes: tuple[str, ...] = ()
    killed: tuple[str, ...] = ()
    hops: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()

    def with_marker(self, marker: str) -> Flow:
        if marker in self.markers:
            return self
        return replace(self, markers=tuple(sorted((*self.markers, marker))))

    def with_hop(self, hop: str) -> Flow:
        if len(self.hops) >= MAX_HOPS_PER_FLOW:
            if self.hops and self.hops[-1] == MARKER_HOPS_ELIDED:
                return self
            return replace(
                self, hops=(*self.hops[: MAX_HOPS_PER_FLOW - 1],
                            MARKER_HOPS_ELIDED),
            )
        return replace(self, hops=(*self.hops, hop))

    def with_killed(self, classes: Iterable[str]) -> Flow:
        merged = set(self.killed)
        merged.update(classes)
        return replace(self, killed=tuple(sorted(merged)))

    def to_dict(self) -> dict[str, object]:
        return {
            "origin": self.origin,
            "classes": list(self.classes),
            "killed": list(self.killed),
            "hops": list(self.hops),
            "markers": list(self.markers),
        }


Flows = frozenset[Flow]
_NO_FLOWS: Flows = frozenset()


def _flow_sort_key(f: Flow) -> tuple:
    return (f.origin, f.classes, f.killed, f.hops, f.markers)


# ── summary records ──────────────────────────────────────────────────


@dataclass(frozen=True)
class CallChannel:
    """Taint entering one argument of one call site — the record the
    worklist joins with the callee's own summary. ``callee`` is the
    resolved external dotted name, ``local:<qualname>`` for in-file
    bindings, or ``unresolved`` when this layer cannot bind the name
    (dispatch through values, over-depth chains)."""

    callee: str
    resolution: str  # external | builtin | local | relative | unresolved
    line: int
    arg: int = -1          # positional index, -1 when keyword/star
    kwarg: str = ""        # keyword name, "" when positional
    star: str = ""         # "*" / "**" for star-args (binding approx)
    flows: tuple[Flow, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "callee": self.callee, "resolution": self.resolution,
            "line": self.line, "arg": self.arg, "kwarg": self.kwarg,
            "star": self.star,
            "flows": [f.to_dict() for f in self.flows],
        }


@dataclass(frozen=True)
class SinkEvent:
    """A tainted value reached a declared sink argument in-body."""

    sink_class: str
    cwe: str
    match: str
    line: int
    confidence: str
    tier: str
    pack: str
    flows: tuple[Flow, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "sink_class": self.sink_class, "cwe": self.cwe,
            "match": self.match, "line": self.line,
            "confidence": self.confidence, "tier": self.tier,
            "pack": self.pack,
            "flows": [f.to_dict() for f in self.flows],
        }


@dataclass(frozen=True)
class SourceEvent:
    """A pack source fired inside the body."""

    kind: str
    match: str
    line: int
    classes: tuple[str, ...] = ()
    tier: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind, "match": self.match, "line": self.line,
            "classes": list(self.classes), "tier": self.tier,
        }


@dataclass(frozen=True)
class SanitizerEvent:
    """A sanitizer transformed a TAINTED value (clean inputs are not
    events). ``applied`` records what actually happened — ``kill`` or
    ``tag`` — which differs from the spec's ``semantics`` exactly when
    the demote-on-shadow rule fired (``demoted=True``, counted)."""

    match: str
    semantics: str
    applied: str
    demoted: bool
    demotion_reason: str
    line: int
    classes: tuple[str, ...] = ()
    tier: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "match": self.match, "semantics": self.semantics,
            "applied": self.applied, "demoted": self.demoted,
            "demotion_reason": self.demotion_reason, "line": self.line,
            "classes": list(self.classes), "tier": self.tier,
        }


@dataclass(frozen=True)
class FunctionSummary:
    """The finite-lattice transfer summary for one function.

    ``returns`` carries every flow reaching a ``return``/``yield``
    value; a parameter flows to the return value exactly when a
    ``param:<i>`` origin appears there. ``opaque=True`` marks the
    conservative degradation (all params → return, tagged
    ``summary_capped``); ``markers`` then names the reason. All
    name-shaped fields are parse-derived identifiers (bounded by
    Python's grammar) — still target-derived text, so render
    chokepoints escape them like every producer's output.
    """

    function_id: str        # <file>::<qualname>@<line> (the I1 node form)
    qualname: str
    file: str
    line_start: int
    line_end: int
    content_hash: str       # core.staleness convention: SHA-256[:12] of the span
    params: tuple[str, ...] = ()
    returns: tuple[Flow, ...] = ()
    call_channels: tuple[CallChannel, ...] = ()
    sink_events: tuple[SinkEvent, ...] = ()
    source_events: tuple[SourceEvent, ...] = ()
    sanitizer_events: tuple[SanitizerEvent, ...] = ()
    #: ``global``/``nonlocal`` names — an INFORMATIONAL record of the
    #: mutation channel v1 does NOT model (see the module docstring's
    #: non-goals). Never a taint channel.
    global_names: tuple[str, ...] = ()
    markers: tuple[str, ...] = ()
    opaque: bool = False
    stats: tuple[tuple[str, int], ...] = ()

    def stat(self, name: str) -> int:
        return dict(self.stats).get(name, 0)

    def params_to_return(self) -> tuple[int, ...]:
        """Parameter indices with a flow into the return value."""
        out: set[int] = set()
        for f in self.returns:
            if f.origin.startswith(_PARAM_ORIGIN_PREFIX):
                out.add(int(f.origin[len(_PARAM_ORIGIN_PREFIX):]))
        return tuple(sorted(out))

    def to_dict(self) -> dict[str, object]:
        return {
            "version": SUMMARY_VERSION,
            "function_id": self.function_id,
            "qualname": self.qualname,
            "file": self.file,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "content_hash": self.content_hash,
            "params": list(self.params),
            "returns": [f.to_dict() for f in self.returns],
            "call_channels": [c.to_dict() for c in self.call_channels],
            "sink_events": [s.to_dict() for s in self.sink_events],
            "source_events": [s.to_dict() for s in self.source_events],
            "sanitizer_events": [s.to_dict() for s in self.sanitizer_events],
            "global_names": list(self.global_names),
            "markers": list(self.markers),
            "opaque": self.opaque,
            "stats": {k: v for k, v in self.stats},
        }


def kill_census(
    summaries: Iterable[FunctionSummary],
) -> dict[tuple[str, str], int]:
    """Run-level sanitizer-kill census: ``(callee, file) -> kills``.

    Aggregates the per-function :class:`SanitizerEvent` records so a
    run summary can print its top killers — an operator can SEE what
    silenced flows. Demoted kills are not kills (they tagged)."""
    out: dict[tuple[str, str], int] = {}
    for s in summaries:
        for ev in s.sanitizer_events:
            if ev.applied == SEMANTICS_KILL:
                key = (ev.match, s.file)
                out[key] = out.get(key, 0) + 1
    return out


# ── spec index (matching tables built once per pack/learned set) ─────


@dataclass(frozen=True)
class SpecIndex:
    """Exact-name matching tables over one pack set (+ optional
    learned intake). Built once, consulted per call site — dict
    lookups, never scans."""

    sinks_by_name: dict[str, tuple[SinkSpec, ...]]
    method_sinks: tuple[SinkSpec, ...]
    sanitizers_by_name: dict[str, tuple[SanitizerSpec, ...]]
    propagators_by_name: dict[str, tuple[PropagatorSpec, ...]]
    call_sources_by_name: dict[str, tuple[SourceSpec, ...]]
    attr_sources_by_name: dict[str, tuple[SourceSpec, ...]]
    learned_sinks_by_name: dict[str, tuple[LearnedSpec, ...]]
    learned_sources_by_name: dict[str, tuple[LearnedSpec, ...]]
    learned_sanitizers_by_name: dict[str, tuple[LearnedSpec, ...]]
    learned_propagators_by_name: dict[str, tuple[LearnedSpec, ...]]
    #: Bare builtin names the packs declare specs on — the only names
    #: matched WITHOUT an import binding (shadowing-aware, see
    #: :meth:`_Extraction._resolve_callee`).
    builtin_spec_names: frozenset[str]


def _by_name(specs: Iterable, key: str) -> dict[str, tuple]:
    out: dict[str, list] = {}
    for spec in specs:
        out.setdefault(getattr(spec, key), []).append(spec)
    return {k: tuple(v) for k, v in out.items()}


def build_spec_index(
    packs: PackSet, learned: LearnedIntake | None = None,
) -> SpecIndex:
    """Build the matching tables for :func:`extract_summary`.

    Reserved stored-taint kinds ride their dotted analogues:
    ``stored_read`` sources match like ``call_return`` (the read API's
    return carries the stored taint), ``stored_write`` sinks match
    like ``dotted_callee`` (v1 treats a hit as a finding of the
    spec's class); the cross-request pairing is a later phase's job.
    ``route_param`` sources never match in-body — the engine seeds
    handler parameters from route records directly.
    """
    method_sinks = tuple(
        s for s in packs.sinks if s.kind == SINK_KIND_METHOD_NAME
    )
    dotted_sinks = [
        s for s in packs.sinks if s.kind != SINK_KIND_METHOD_NAME
    ]
    call_sources = [
        s for s in packs.sources
        if s.kind in (SOURCE_KIND_CALL_RETURN, SOURCE_KIND_STORED_READ)
    ]
    attr_sources = [
        s for s in packs.sources if s.kind == SOURCE_KIND_MODULE_ATTRIBUTE
    ]
    builtin_names = {
        s.match for s in dotted_sinks if s.match in _BUILTIN_NAMES
    }
    builtin_names.update(
        s.match for s in packs.sanitizers if s.match in _BUILTIN_NAMES
    )
    builtin_names.update(
        s.match for s in packs.propagators if s.match in _BUILTIN_NAMES
    )
    builtin_names.update(
        s.match for s in call_sources if s.match in _BUILTIN_NAMES
    )
    learned = learned or LearnedIntake()
    return SpecIndex(
        sinks_by_name=_by_name(dotted_sinks, "match"),
        method_sinks=method_sinks,
        sanitizers_by_name=_by_name(packs.sanitizers, "match"),
        propagators_by_name=_by_name(packs.propagators, "match"),
        call_sources_by_name=_by_name(call_sources, "match"),
        attr_sources_by_name=_by_name(attr_sources, "match"),
        learned_sinks_by_name=_by_name(learned.sinks, "function"),
        learned_sources_by_name=_by_name(learned.sources, "function"),
        learned_sanitizers_by_name=_by_name(learned.sanitizers, "function"),
        learned_propagators_by_name=_by_name(learned.propagators, "function"),
        builtin_spec_names=frozenset(builtin_names),
    )


# ── limits (test-adjustable view over the module caps) ───────────────


@dataclass(frozen=True)
class Limits:
    """Per-extraction budget set. Defaults are the module caps; tests
    shrink individual fields to pin the ±1 degradation boundaries."""

    max_nodes: int = MAX_NODES_PER_FUNCTION
    max_statements: int = MAX_STATEMENTS_PER_FUNCTION
    max_expr_nodes_per_statement: int = MAX_EXPR_NODES_PER_STATEMENT
    max_walk_depth: int = MAX_WALK_DEPTH
    max_access_path_depth: int = MAX_ACCESS_PATH_DEPTH
    max_locals: int = MAX_LOCALS_TRACKED
    max_flows_per_value: int = MAX_FLOWS_PER_VALUE
    max_call_channels: int = MAX_CALL_CHANNELS
    max_sink_events: int = MAX_SINK_EVENTS
    max_source_events: int = MAX_SOURCE_EVENTS
    max_sanitizer_events: int = MAX_SANITIZER_EVENTS
    wall_budget_s: float = PER_FUNCTION_WALL_BUDGET_S


# ── module index (one bounded parse per file, shared by functions) ──


@dataclass(frozen=True)
class FunctionEntry:
    """One function found by the module scan."""

    qualname: str
    line_start: int
    line_end: int
    node: ast.FunctionDef | ast.AsyncFunctionDef
    params: tuple[str, ...]


@dataclass
class ModuleIndex:
    """Bounded per-file context the per-function pass reads.

    ``ok=False`` (with ``degrade_reason``) means every function in
    the file degrades to an opaque summary — the file was over the
    read cap, unparseable, or over the index node budget. The index
    itself never raises on hostile bytes.
    """

    path: str
    module_name: str = ""
    ok: bool = True
    degrade_reason: str = ""
    #: newline-NORMALISED source (``\r\n``/lone ``\r`` -> ``\n``): the
    #: CPython tokenizer counts a lone ``\r`` as a line break but the
    #: ``\n``-only line chokepoint does not, so un-normalised text
    #: desyncs every AST line number from the split list — span
    #: hashes then cover the wrong window or collapse to ``""`` and a
    #: content-keyed cache serves STALE summaries across edits.
    text: str = ""
    #: ``text`` split once at index time: hashing per function from
    #: the pre-split list keeps the cost linear in file size —
    #: re-splitting the whole module per function is a
    #: functions-times-bytes quadratic a crafted many-tiny-function
    #: file weaponises.
    lines: list[str] = field(default_factory=list)
    #: local binding -> external dotted name (absolute imports; and
    #: relative imports when ``module_name`` allowed absolutising).
    import_table: dict[str, str] = field(default_factory=dict)
    #: names bound by relative imports we could NOT absolutise —
    #: resolvable as project-internal, never as an external spec name.
    relative_bindings: set[str] = field(default_factory=set)
    #: module-scope non-import assignment targets.
    module_assigned: set[str] = field(default_factory=set)
    #: module-scope def/class names.
    module_defs: set[str] = field(default_factory=set)
    #: import bindings later rebound (second import or module-scope
    #: assignment of the same name) — the kill-demotion suspect signal.
    import_rebound: set[str] = field(default_factory=set)
    #: names written under a ``global`` declaration ANYWHERE in the
    #: file — a runtime rebind channel written-name resolution
    #: cannot see, so it feeds the suspect signal too.
    global_written: set[str] = field(default_factory=set)
    #: import-bound roots whose ATTRIBUTES are assigned at module
    #: scope (``shlex.quote = str``) — the object survives but its
    #: member may be anything now, so kills through the root demote.
    module_attr_patched: set[str] = field(default_factory=set)
    functions: list[FunctionEntry] = field(default_factory=list)

    def function_at(self, line: int) -> FunctionEntry | None:
        best: FunctionEntry | None = None
        for entry in self.functions:
            if entry.line_start <= line <= entry.line_end and (
                best is None or entry.line_start >= best.line_start
            ):
                best = entry
        return best

    def function_named(self, qualname: str) -> FunctionEntry | None:
        for entry in self.functions:
            if entry.qualname == qualname:
                return entry
        return None

    def suspect_binding(self, root: str) -> bool:
        """Shadow/rebind signal for an import-bound *root* — kills
        through a suspect binding demote to tags."""
        return (root in self.import_rebound
                or root in self.module_assigned
                or root in self.global_written
                or root in self.module_attr_patched)

    def shadowed_builtin(self, root: str) -> bool:
        """A builtin name bound ANYWHERE in the file is not the
        builtin (conservative: module scope, import, or def)."""
        return (root in self.module_assigned
                or root in self.module_defs
                or root in self.import_table
                or root in self.relative_bindings
                or root in self.global_written)


def _assigned_names(target: ast.AST) -> Iterable[str]:
    """Bare names bound by an assignment target (tuple/list unpack
    walked; attribute/subscript targets bind no NAME)."""
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for elt in target.elts:
            yield from _assigned_names(elt)
    elif isinstance(target, ast.Starred):
        yield from _assigned_names(target.value)


def _resolve_relative(
    module_name: str, level: int, rel_module: str, name: str,
) -> str:
    """Absolutise one relative-import binding against *module_name*
    (the file's dotted module path). Empty result = unresolvable."""
    if not module_name or level <= 0:
        return ""
    pkg_parts = module_name.split(".")[:-1]
    if level - 1 > len(pkg_parts):
        return ""
    base = pkg_parts[: len(pkg_parts) - (level - 1)]
    if rel_module:
        base = [*base, *rel_module.split(".")]
    return ".".join([*base, name]) if base else name


def _function_params(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, ...]:
    a = node.args
    names = [p.arg for p in (*a.posonlyargs, *a.args)]
    if a.vararg:
        names.append(a.vararg.arg)
    names.extend(p.arg for p in a.kwonlyargs)
    if a.kwarg:
        names.append(a.kwarg.arg)
    return tuple(names)


def _module_binding_names(tree: ast.Module) -> Iterable[tuple[str, bool]]:
    """Every name a module binds at module/class scope, through ANY
    binding form: assignments (plain/annotated/augmented/chained),
    ``for``/``async for`` targets, ``with ... as``, walrus targets,
    ``match`` capture names, ``except ... as``. Yields ``(name,
    is_attr_patch)`` — attr-patch entries are the ROOT names of
    attribute-target assignments (``shlex.quote = str``), which do
    not rebind the name but patch the bound object's member.

    Function and lambda BODIES are skipped (their bindings are local;
    module writes from inside ride ``global``, collected separately)
    — but a def's decorator list, default-argument expressions, and
    annotations EXECUTE at the enclosing scope when the module
    imports, so ``def g(a=(shlex := object())): ...`` and
    ``@(shlex := deco)`` rebind module names and are scanned.
    Class bodies are included — a class-scope rebind of an imported
    name is the same review-evading shape at one remove. Iterative,
    linear, bounded by the caller's module node budget.
    """
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.Lambda)):
            # Skip the BODY only: decorators, defaults, and
            # annotations run at def time in THIS scope. Annotations
            # are included even where a __future__ import would defer
            # them — over-scanning there only over-demotes (recall-
            # neutral); missing an eager one would false-suppress.
            args = node.args
            stack.extend(d for d in args.defaults if d is not None)
            stack.extend(d for d in args.kw_defaults if d is not None)
            if not isinstance(node, ast.Lambda):
                stack.extend(node.decorator_list)
                if node.returns is not None:
                    stack.append(node.returns)
                for arg in (*args.posonlyargs, *args.args,
                            *args.kwonlyargs, args.vararg, args.kwarg):
                    if arg is not None and arg.annotation is not None:
                        stack.append(arg.annotation)
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            targets = (node.targets if isinstance(node, ast.Assign)
                       else [node.target])
            for target in targets:
                yield from ((n, False) for n in _assigned_names(target))
                base = target
                while isinstance(base, (ast.Attribute, ast.Subscript)):
                    base = base.value
                if isinstance(base, ast.Name) and base is not target:
                    yield base.id, True
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            yield from ((n, False) for n in _assigned_names(node.target))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                if item.optional_vars is not None:
                    yield from ((n, False)
                                for n in _assigned_names(item.optional_vars))
        elif isinstance(node, ast.NamedExpr):
            if isinstance(node.target, ast.Name):
                yield node.target.id, False
        elif isinstance(node, ast.ExceptHandler):
            if node.name:
                yield node.name, False
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name:
                yield node.name, False
        elif isinstance(node, ast.MatchMapping):
            if node.rest:
                yield node.rest, False
        stack.extend(ast.iter_child_nodes(node))


def index_module_text(
    text: str,
    path: str,
    *,
    module_name: str = "",
    max_nodes: int = MAX_MODULE_AST_NODES,
) -> ModuleIndex:
    """Build the per-file context from already-read source text.

    Never raises on hostile input: parse failures and the node budget
    degrade the whole index (``ok=False`` + reason), which downstream
    turns into opaque summaries for every function in the file.
    """
    # Normalise line endings BEFORE parsing: the tokenizer treats a
    # lone ``\r`` as a line break, the ``\n``-only split chokepoint
    # does not — parse-vs-split disagreement desyncs every AST line
    # number from the hashed line list (stale-cache surface). After
    # this, AST linenos and ``lines`` share one line model.
    if "\r" in text:
        text = text.replace("\r\n", "\n").replace("\r", "\n")
    idx = ModuleIndex(path=path, module_name=module_name, text=text)
    idx.lines = split_lines(text)
    try:
        with warnings.catch_warnings():
            # Target bytes must not spill compiler warnings (invalid
            # escapes etc.) into operator streams.
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        idx.ok = False
        idx.degrade_reason = "parse_failed"
        return idx

    nodes_seen = 0
    for node in ast.walk(tree):
        nodes_seen += 1
        if nodes_seen > max_nodes:
            idx.ok = False
            idx.degrade_reason = "module_nodes_capped"
            return idx
        if isinstance(node, ast.Global):
            idx.global_written.update(node.names)

    # Function spans + qualnames, at any nesting. Iterative scope
    # walk (parse-accepted nesting must not blow OUR stack).
    stack: list[tuple[ast.AST, str]] = [(tree, "")]
    while stack:
        scope_node, prefix = stack.pop()
        for child in ast.iter_child_nodes(scope_node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                qual = f"{prefix}{child.name}"
                idx.functions.append(FunctionEntry(
                    qualname=qual,
                    line_start=child.lineno,
                    line_end=getattr(child, "end_lineno", child.lineno)
                    or child.lineno,
                    node=child,
                    params=_function_params(child),
                ))
                stack.append((child, f"{qual}."))
            elif isinstance(child, ast.ClassDef):
                stack.append((child, f"{prefix}{child.name}."))
            elif isinstance(child, (ast.If, ast.Try, ast.With,
                                    ast.AsyncWith, ast.For, ast.AsyncFor,
                                    ast.While)):
                stack.append((child, prefix))
            elif hasattr(ast, "TryStar") and isinstance(
                child, ast.TryStar,
            ):
                stack.append((child, prefix))
    idx.functions.sort(key=lambda e: (e.line_start, e.qualname))

    # Module-scope bindings: walk statements OUTSIDE function bodies
    # (class bodies and module-level compound statements included —
    # conditional module-level rebinds are exactly the suspect shape).
    #
    # Binding collection runs FIRST and covers EVERY module-scope
    # binding form, not just plain assignment: ``for shlex in ...``,
    # ``with ... as shlex``, ``(shlex := ...)``, ``case ... as
    # shlex``/capture names, ``except ... as shlex`` all rebind the
    # written name just as effectively — a rebind detector that only
    # sees Assign hands the kill-demotion rule an evasion catalogue.
    # Attribute-target assigns (``shlex.quote = str``) do not rebind
    # the NAME, but they patch the imported object's member — the
    # root name is marked rebind-suspect so kills through it demote
    # (fail toward the sink firing, never toward suppression).
    for name, is_attr_patch in _module_binding_names(tree):
        if is_attr_patch:
            idx.module_attr_patched.add(name)
        else:
            idx.module_assigned.add(name)

    def bind_import(bound: str, target: str) -> None:
        if bound in idx.import_table and idx.import_table[bound] != target:
            idx.import_rebound.add(bound)
        if bound in idx.module_assigned:
            idx.import_rebound.add(bound)
        idx.import_table[bound] = target

    stmt_stack: list[ast.stmt] = [
        s for s in reversed(tree.body)
    ]
    while stmt_stack:
        stmt = stmt_stack.pop()
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            idx.module_defs.add(stmt.name)
            continue  # function bodies are not module scope
        if isinstance(stmt, ast.ClassDef):
            idx.module_defs.add(stmt.name)
            stmt_stack.extend(reversed(stmt.body))
            continue
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                bound = alias.asname or alias.name.split(".")[0]
                target = alias.name if alias.asname else bound
                bind_import(bound, target)
            continue
        if isinstance(stmt, ast.ImportFrom):
            for alias in stmt.names:
                if alias.name == "*":
                    continue
                bound = alias.asname or alias.name
                if stmt.level and stmt.level > 0:
                    resolved = _resolve_relative(
                        module_name, stmt.level, stmt.module or "",
                        alias.name,
                    )
                    if resolved:
                        bind_import(bound, resolved)
                    else:
                        idx.relative_bindings.add(bound)
                else:
                    bind_import(bound, f"{stmt.module}.{alias.name}"
                                if stmt.module else alias.name)
            continue
        for attr in ("body", "orelse", "finalbody"):
            stmt_stack.extend(reversed(getattr(stmt, attr, []) or []))
        for handler in getattr(stmt, "handlers", []) or []:
            stmt_stack.extend(reversed(handler.body))
        for case in getattr(stmt, "cases", []) or []:
            stmt_stack.extend(reversed(case.body))
    # Rebinds of import-bound names via ANY collected form.
    idx.import_rebound.update(idx.module_assigned & set(idx.import_table))
    return idx


def index_module(
    path: str | Path,
    *,
    module_name: str = "",
    max_bytes: int = MAX_SOURCE_FILE_BYTES,
) -> ModuleIndex:
    """Read (size-capped, FIFO-proof) and index one source file.

    Over-cap / unreadable files degrade to ``ok=False`` — every
    function in them summarises opaque, counted, never raised."""
    try:
        text = read_text_gated(path, max_bytes)
    except (ValueError, OSError):
        idx = ModuleIndex(path=str(path), module_name=module_name)
        idx.ok = False
        idx.degrade_reason = "file_unreadable_or_over_cap"
        return idx
    return index_module_text(text, str(path), module_name=module_name)


# ── extraction ───────────────────────────────────────────────────────


def _opaque_summary(
    idx: ModuleIndex,
    entry: FunctionEntry | None,
    reason: str,
    *,
    file: str,
    qualname: str = "",
    line_start: int = 0,
    line_end: int = 0,
    params: tuple[str, ...] = (),
    content_hash: str = "",
    stats: dict[str, int] | None = None,
) -> FunctionSummary:
    """The conservative degradation: all params propagate to the
    return value, tagged — a capped function covers less, never lies."""
    if entry is not None:
        qualname = entry.qualname
        line_start, line_end = entry.line_start, entry.line_end
        params = entry.params
        if not content_hash and idx.lines:
            # Hash from the pre-split line list — per-function
            # re-splitting of the whole module is the
            # functions-times-bytes quadratic (see ModuleIndex.lines).
            content_hash = _hash_from_lines(idx.lines, line_start, line_end)
    returns = tuple(
        Flow(
            origin=f"{_PARAM_ORIGIN_PREFIX}{i}",
            markers=tuple(sorted((MARKER_ASSUMED_PROPAGATION,
                                  MARKER_SUMMARY_CAPPED))),
        )
        for i in range(len(params))
    )
    all_stats = dict(stats or {})
    all_stats[f"opaque_{reason}"] = all_stats.get(f"opaque_{reason}", 0) + 1
    return FunctionSummary(
        function_id=f"{file}::{qualname}@{line_start}",
        qualname=qualname,
        file=file,
        line_start=line_start,
        line_end=line_end,
        content_hash=content_hash,
        params=params,
        returns=returns,
        markers=(f"{MARKER_SUMMARY_CAPPED}:{reason}",),
        opaque=True,
        stats=tuple(sorted(all_stats.items())),
    )


class _Extraction:
    """One function's walk. Holds the bounded state; every budget
    check funnels through :meth:`_spend`."""

    def __init__(
        self,
        idx: ModuleIndex,
        entry: FunctionEntry,
        specs: SpecIndex,
        limits: Limits,
        internal_roots: frozenset[str],
    ) -> None:
        self.idx = idx
        self.entry = entry
        self.specs = specs
        self.limits = limits
        self.internal_roots = internal_roots
        self.state: dict[str, Flows] = {}
        self.returns: set[Flow] = set()
        self.channels: list[CallChannel] = []
        self.sink_events: list[SinkEvent] = []
        self.source_events: list[SourceEvent] = []
        self.sanitizer_events: list[SanitizerEvent] = []
        self._seen_sources: set[tuple[str, str]] = set()
        self.global_names: list[str] = []
        self.markers: set[str] = set()
        self.stats: dict[str, int] = {}
        self.nodes = 0
        self.stmts = 0
        self.stmt_expr_nodes = 0
        self.deadline = time.monotonic() + limits.wall_budget_s
        # Function-local bindings, pre-scanned (flow-insensitive):
        # feeds builtin shadowing and the local-shadow demotion signal.
        self.local_bindings: set[str] = set(entry.params)
        self.local_nonimport: set[str] = set(entry.params)
        self.local_import_table: dict[str, str] = {}
        self._prescan_locals(entry.node)

    # -- budgets ------------------------------------------------------

    def _spend(self, nodes: int = 1) -> None:
        self.nodes += nodes
        self.stmt_expr_nodes += nodes
        if self.nodes > self.limits.max_nodes:
            raise _Budget("node_budget")
        if self.stmt_expr_nodes > self.limits.max_expr_nodes_per_statement:
            raise _Budget("statement_width")
        if self.nodes % 256 == 0 and time.monotonic() > self.deadline:
            raise _Budget("wall_budget")

    def _count(self, name: str, n: int = 1) -> None:
        self.stats[name] = self.stats.get(name, 0) + n

    # -- local pre-scan -----------------------------------------------

    def _prescan_locals(self, fn: ast.AST) -> None:
        """Names the function binds ANYWHERE (assignments, defs, for
        targets, with-vars, except names, match captures, local
        imports). Iterative; nested function bodies excluded (their
        own scopes).

        Two layers: ``local_bindings`` is every locally bound name;
        ``local_nonimport`` is the subset bound by anything OTHER
        than an import statement. A name that is BOTH import-bound
        and non-import-bound in the same body (``import shlex;
        shlex = object()``) has a suspect written-name resolution —
        the resolver demotes kills through it exactly like a
        module-scope rebind."""
        stack: list[ast.AST] = list(ast.iter_child_nodes(fn))
        budget = self.limits.max_nodes
        seen = 0
        globals_declared: set[str] = set()

        def bind(name: str) -> None:
            self.local_bindings.add(name)
            self.local_nonimport.add(name)

        while stack:
            node = stack.pop()
            seen += 1
            if seen > budget:
                raise _Budget("node_budget")
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.Lambda)):
                if isinstance(node, (ast.FunctionDef,
                                     ast.AsyncFunctionDef)):
                    bind(node.name)
                continue  # separate scope
            if isinstance(node, ast.ClassDef):
                bind(node.name)
                continue
            if isinstance(node, (ast.Global, ast.Nonlocal)):
                globals_declared.update(node.names)
            elif isinstance(node, ast.Name) and isinstance(
                node.ctx, (ast.Store, ast.Del),
            ):
                bind(node.id)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    bound = alias.asname or alias.name.split(".")[0]
                    target = alias.name if alias.asname else bound
                    self.local_import_table[bound] = target
                    self.local_bindings.add(bound)
            elif isinstance(node, ast.ImportFrom):
                for alias in node.names:
                    if alias.name == "*":
                        continue
                    bound = alias.asname or alias.name
                    self.local_bindings.add(bound)
                    if not node.level and node.module:
                        self.local_import_table[bound] = (
                            f"{node.module}.{alias.name}"
                        )
            elif isinstance(node, ast.ExceptHandler) and node.name:
                bind(node.name)
            elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
                if node.name:
                    bind(node.name)
            elif isinstance(node, ast.MatchMapping) and node.rest:
                bind(node.rest)
            stack.extend(ast.iter_child_nodes(node))
        # A ``global x`` declaration means writes to x are NOT local
        # bindings (they rebind the module name — recorded there).
        self.local_bindings -= globals_declared
        self.local_nonimport -= globals_declared

    # -- state --------------------------------------------------------

    def _bind(self, name: str, flows: Flows, *, strong: bool) -> None:
        if not flows and strong:
            if name in self.state:
                self.state[name] = _NO_FLOWS
            return
        if not flows:
            return
        old = self.state.get(name, _NO_FLOWS)
        new = flows if strong else (old | flows)
        if len(new) > self.limits.max_flows_per_value:
            raise _Budget("flows_per_value")
        if name not in self.state and len(self.state) >= self.limits.max_locals:
            raise _Budget("locals_tracked")
        self.state[name] = new

    def _lookup(self, name: str) -> Flows:
        return self.state.get(name, _NO_FLOWS)

    # -- chain building / resolution ----------------------------------

    def _chain_of(self, node: ast.AST) -> tuple[str, ...] | None:
        """``a.b.c`` as ``("a","b","c")``; None when the expression is
        not a plain name chain or exceeds the access-path depth (a
        counted degrade toward unresolved, never toward a match)."""
        parts: list[str] = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            if len(parts) > self.limits.max_access_path_depth:
                self._count("access_path_depth_capped")
                return None
            cur = cur.value
        if not isinstance(cur, ast.Name):
            return None
        parts.append(cur.id)
        parts.reverse()
        return tuple(parts)

    def _resolve_chain(self, chain: tuple[str, ...]) -> tuple[str, str, bool]:
        """Resolve *chain* to ``(name, resolution, suspect)``.

        resolution: ``external`` (dotted name joinable to specs),
        ``builtin`` (unshadowed builtin, matched by bare name),
        ``local`` (in-file binding — never matches external specs;
        may match learned specs via the module-qualified name),
        ``relative`` (project-internal via relative import),
        ``unresolved``. ``suspect`` carries the rebind/shadow
        signal for external bindings.
        """
        root = chain[0]
        rest = chain[1:]
        if root in ("self", "cls"):
            return ".".join(chain), "unresolved", False

        def builtin_shadowed() -> tuple[str, str, bool] | None:
            # The I1 written-name lesson, pinned for builtins: a
            # shadowed builtin (local def/assign, module rebind,
            # global write) is NOT the builtin. Conservative both
            # ways — no sink match to overclaim, no sanitizer kill
            # to trust — and counted.
            if (root in self.specs.builtin_spec_names
                    and (root in self.local_bindings
                         or self.idx.shadowed_builtin(root))):
                self._count("builtin_shadowed")
                return ".".join(chain), "unresolved", False
            return None

        local_import = self.local_import_table.get(root)
        if local_import is not None:
            # A function-local import binds the name — but if the
            # SAME body also rebinds it any other way (``import
            # shlex; shlex = object()``), the written-name
            # resolution is suspect exactly like a module-scope
            # rebind: kills through it demote.
            dotted = ".".join([local_import, *rest])
            suspect = root in self.local_nonimport
            return dotted, self._external_or_internal(dotted), suspect
        if root in self.local_bindings:
            if root in self.idx.import_table:
                # A function-local def/assignment shadows a
                # module-scope import binding SOMEWHERE in this body
                # (flow-insensitive): written-name resolution still
                # points at the import, but the binding is suspect —
                # external + suspect, so a curated kill demotes to a
                # tag instead of firing (the local-shadow arm).
                dotted = ".".join([self.idx.import_table[root], *rest])
                return dotted, self._external_or_internal(dotted), True
            shadowed = builtin_shadowed()
            if shadowed is not None:
                return shadowed
            # Function-local value: a call through it is dynamic. A
            # bare local def is still joinable for LEARNED specs via
            # the module-qualified spelling.
            if not rest and self.idx.module_name:
                return f"{self.idx.module_name}.{root}", "local", False
            return ".".join(chain), "local", False
        if root in self.idx.import_table:
            dotted = ".".join([self.idx.import_table[root], *rest])
            suspect = self.idx.suspect_binding(root)
            return dotted, self._external_or_internal(dotted), suspect
        if root in self.idx.relative_bindings:
            return ".".join(chain), "relative", False
        shadowed = builtin_shadowed()
        if shadowed is not None:
            return shadowed
        if root in self.idx.module_defs:
            qual = ".".join(chain)
            if self.idx.module_name:
                qual = f"{self.idx.module_name}.{qual}"
            return qual, "local", False
        if root in self.idx.module_assigned:
            return ".".join(chain), "local", False
        if root in _BUILTIN_NAMES:
            return ".".join(chain), "builtin", False
        return ".".join(chain), "unresolved", False

    def _external_or_internal(self, dotted: str) -> str:
        if dotted.split(".", 1)[0] in self.internal_roots:
            return "local"
        return "external"

    # -- source matching ----------------------------------------------

    def _attr_source_flows(self, node: ast.AST) -> Flows:
        """``module_attribute`` sources: expressions rooted at an
        import binding of the declared dotted name (``request.args``
        under ``from flask import request``)."""
        if not self.specs.attr_sources_by_name:
            return _NO_FLOWS
        chain = self._chain_of(node)
        if chain is None:
            return _NO_FLOWS
        name, resolution, _suspect = self._resolve_chain(chain)
        if resolution != "external":
            return _NO_FLOWS
        out: set[Flow] = set()
        prefix = name
        while prefix:
            for spec in self.specs.attr_sources_by_name.get(prefix, ()):
                out.add(Flow(
                    origin=(f"{_SOURCE_ORIGIN_PREFIX}"
                            f"{spec.kind}:{spec.match}"),
                    classes=spec.taint_classes,
                ))
                self._record_source(spec, getattr(node, "lineno", 0))
            prefix = prefix.rsplit(".", 1)[0] if "." in prefix else ""
        return frozenset(out)

    def _record_source(self, spec: SourceSpec | LearnedSpec,
                       line: int) -> None:
        # One event per (kind, match): the worklist needs "this
        # source fires in this function", not every read site — and
        # a handler reading ``request`` on hundreds of lines must
        # not burn the event budget into an opaque degrade.
        if isinstance(spec, SourceSpec):
            kind, match = spec.kind, spec.match
        else:
            kind, match = "learned", spec.function
        if (kind, match) in self._seen_sources:
            return
        if len(self.source_events) >= self.limits.max_source_events:
            raise _Budget("source_events")
        self._seen_sources.add((kind, match))
        self.source_events.append(SourceEvent(
            kind=kind, match=match, line=line,
            classes=spec.taint_classes, tier=spec.tier,
        ))

    # -- statement walk ------------------------------------------------

    def run(self) -> None:
        params = self.entry.params
        for i, name in enumerate(params):
            self.state[name] = frozenset(
                {Flow(origin=f"{_PARAM_ORIGIN_PREFIX}{i}")},
            )
        # Decorators on the summarised function are SKIPPED: route
        # binding is already resolved upstream and wrapper-body flow
        # is a named non-goal — a decorator call must not
        # double-count as a call site of this function.
        if self.entry.node.decorator_list:
            self._count("decorators_skipped",
                        len(self.entry.node.decorator_list))
        self._exec_block(self.entry.node.body, strong=True, depth=0)

    def _exec_block(self, stmts: Sequence[ast.stmt], *, strong: bool,
                    depth: int) -> None:
        if depth > self.limits.max_walk_depth:
            raise _Budget("walk_depth")
        for stmt in stmts:
            self.stmts += 1
            if self.stmts > self.limits.max_statements:
                raise _Budget("statement_budget")
            self.stmt_expr_nodes = 0
            self._exec_stmt(stmt, strong=strong, depth=depth)

    def _exec_stmt(self, stmt: ast.stmt, *, strong: bool,
                   depth: int) -> None:
        self._spend()
        d = depth + 1
        if isinstance(stmt, ast.Assign):
            # Element-wise refinement for the syntactic pairwise case
            # (``x, y = a, b``): bind each element to its own value.
            # Everything else falls back to whole-value unpack (a
            # tainted pair taints both halves — the design's stated
            # approximation).
            first = stmt.targets[0]
            if (len(stmt.targets) == 1
                    and isinstance(first, (ast.Tuple, ast.List))
                    and isinstance(stmt.value, (ast.Tuple, ast.List))
                    and len(first.elts) == len(stmt.value.elts)
                    and not any(isinstance(e, ast.Starred)
                                for e in (*first.elts,
                                          *stmt.value.elts))):
                # Python evaluates the WHOLE right side before any
                # target binds, so the walk must too: binding
                # pairwise-as-evaluated turns ``x, y = y, x`` into a
                # strong-position taint erasure (y's new flows read
                # x AFTER x was already overwritten).
                values = [self._eval(value, d) for value in stmt.value.elts]
                for target, flows in zip(first.elts, values):
                    self._assign_target(target, flows,
                                        strong=strong, depth=d)
            else:
                flows = self._eval(stmt.value, d)
                for target in stmt.targets:
                    self._assign_target(target, flows, strong=strong,
                                        depth=d)
        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                flows = self._eval(stmt.value, d)
                self._assign_target(stmt.target, flows, strong=strong,
                                    depth=d)
        elif isinstance(stmt, ast.AugAssign):
            flows = self._eval(stmt.value, d)
            # Augmented assignment reads the old value: always weak.
            self._assign_target(stmt.target, flows, strong=False, depth=d)
        elif isinstance(stmt, ast.Expr):
            self._eval(stmt.value, d)
        elif isinstance(stmt, ast.Return):
            if stmt.value is not None:
                self._add_returns(self._eval(stmt.value, d))
        elif isinstance(stmt, ast.If):
            self._eval(stmt.test, d)
            self._exec_block(stmt.body, strong=False, depth=d)
            self._exec_block(stmt.orelse, strong=False, depth=d)
        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            iter_flows = self._eval(stmt.iter, d)
            # Whole-value: iterating a tainted container taints the
            # loop variable. Loop bodies may run zero times: weak.
            self._assign_target(stmt.target, iter_flows, strong=False,
                                depth=d)
            self._exec_block(stmt.body, strong=False, depth=d)
            self._exec_block(stmt.orelse, strong=False, depth=d)
        elif isinstance(stmt, ast.While):
            self._eval(stmt.test, d)
            self._exec_block(stmt.body, strong=False, depth=d)
            self._exec_block(stmt.orelse, strong=False, depth=d)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                ctx_flows = self._eval(item.context_expr, d)
                if item.optional_vars is not None:
                    self._assign_target(item.optional_vars, ctx_flows,
                                        strong=strong, depth=d)
            # A with-body reached through a dominating position still
            # dominates the statements after it (an escaping
            # exception skips those statements entirely).
            self._exec_block(stmt.body, strong=strong, depth=d)
        elif isinstance(stmt, ast.Try) or (
            hasattr(ast, "TryStar") and isinstance(stmt, ast.TryStar)
        ):
            # A try body can raise partway: statements after the try
            # still run via the handler, so nothing inside the body
            # or handlers dominates what follows — weak. finally
            # always runs: inherits strength.
            self._exec_block(stmt.body, strong=False, depth=d)
            for handler in stmt.handlers:
                if handler.name:
                    self._bind(handler.name, _NO_FLOWS, strong=False)
                self._exec_block(handler.body, strong=False, depth=d)
            self._exec_block(stmt.orelse, strong=False, depth=d)
            self._exec_block(stmt.finalbody, strong=strong, depth=d)
        elif isinstance(stmt, ast.Match):
            subject = self._eval(stmt.subject, d)
            for case in stmt.cases:
                # Whole-value: every captured name gets the subject's
                # flows; case bodies are branches — weak.
                for name in self._match_captures(case.pattern):
                    self._bind(name, subject, strong=False)
                if case.guard is not None:
                    self._eval(case.guard, d)
                self._exec_block(case.body, strong=False, depth=d)
        elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            # Nested defs are their OWN summary subjects; walking
            # their bodies here would double-count. Their decorators
            # and defaults do execute in this scope — evaluated for
            # taint movement, bodies skipped and counted.
            self._count("nested_defs_skipped")
            for deco in stmt.decorator_list:
                self._eval(deco, d)
            for default in (*stmt.args.defaults, *stmt.args.kw_defaults):
                if default is not None:
                    self._eval(default, d)
        elif isinstance(stmt, ast.ClassDef):
            self._count("nested_defs_skipped")
            for deco in stmt.decorator_list:
                self._eval(deco, d)
            for base in stmt.bases:
                self._eval(base, d)
        elif isinstance(stmt, (ast.Global, ast.Nonlocal)):
            # Recorded, informational ONLY: mutation through module
            # globals is a named v1 non-goal, not a taint channel.
            for name in stmt.names:
                if (len(self.global_names) < MAX_GLOBAL_NAMES
                        and name not in self.global_names):
                    self.global_names.append(name)
        elif isinstance(stmt, ast.Delete):
            # ``del`` erases taint state — a strong effect, legal
            # only in dominating positions like any other strong
            # update. A branch-local ``del x`` may never execute, so
            # the weak form is a no-op (the old flow survives —
            # over-taint, the same direction as weak assignment).
            if strong:
                for target in stmt.targets:
                    for name in _assigned_names(target):
                        self.state.pop(name, None)
        elif isinstance(stmt, ast.Raise):
            if stmt.exc is not None:
                self._eval(stmt.exc, d)
            if stmt.cause is not None:
                self._eval(stmt.cause, d)
        elif isinstance(stmt, ast.Assert):
            self._eval(stmt.test, d)
            if stmt.msg is not None:
                self._eval(stmt.msg, d)
        elif isinstance(stmt, (ast.Import, ast.ImportFrom)):
            pass  # bindings pre-scanned into the local import table
        # Pass / Break / Continue: nothing.

    def _match_captures(self, pattern: ast.AST) -> Iterable[str]:
        stack = [pattern]
        while stack:
            p = stack.pop()
            self._spend()
            name = getattr(p, "name", None)
            if isinstance(p, (ast.MatchAs, ast.MatchStar)) and name:
                yield name
            rest = getattr(p, "rest", None)
            if rest:
                yield rest
            stack.extend(ast.iter_child_nodes(p))

    def _assign_target(self, target: ast.AST, flows: Flows, *,
                       strong: bool, depth: int) -> None:
        self._spend()
        if isinstance(target, ast.Name):
            self._bind(target.id, flows, strong=strong)
        elif isinstance(target, (ast.Tuple, ast.List)):
            # Whole-value tuple unpack: every element gets the
            # value's flows (a tainted pair taints both halves).
            for elt in target.elts:
                self._assign_target(elt, flows, strong=strong,
                                    depth=depth + 1)
        elif isinstance(target, ast.Starred):
            self._assign_target(target.value, flows, strong=strong,
                                depth=depth + 1)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            # Whole-value: writing a tainted value INTO a container
            # taints the container's base name (weak — the rest of
            # the container keeps its history).
            base = target
            hops = 0
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                if isinstance(base, ast.Subscript):
                    self._eval(base.slice, depth + 1)
                base = base.value
                hops += 1
                if hops > self.limits.max_access_path_depth:
                    self._count("access_path_depth_capped")
                    return
            if isinstance(base, ast.Name):
                self._bind(base.id, flows, strong=False)
            else:
                self._eval(base, depth + 1)

    def _add_returns(self, flows: Flows) -> None:
        self.returns.update(flows)
        if len(self.returns) > self.limits.max_flows_per_value:
            raise _Budget("flows_per_value")

    # -- expression walk -----------------------------------------------

    def _eval(self, node: ast.expr, depth: int) -> Flows:
        self._spend()
        if depth > self.limits.max_walk_depth:
            raise _Budget("walk_depth")
        d = depth + 1
        if isinstance(node, ast.Name):
            return self._union(self._lookup(node.id),
                               self._attr_source_flows(node))
        if isinstance(node, ast.Constant):
            return _NO_FLOWS
        if isinstance(node, ast.Attribute):
            base = self._eval(node.value, d)
            # Whole-value: attribute read off a tainted object is
            # tainted; plus the module_attribute source check on the
            # full chain.
            return self._union(base, self._attr_source_flows(node))
        if isinstance(node, ast.Subscript):
            base = self._eval(node.value, d)
            self._eval(node.slice, d)
            return base
        if isinstance(node, ast.Call):
            return self._eval_call(node, d)
        if isinstance(node, ast.BoolOp):
            out: Flows = _NO_FLOWS
            for value in node.values:
                out = self._union(out, self._eval(value, d))
            return out
        if isinstance(node, ast.BinOp):
            return self._union(self._eval(node.left, d),
                               self._eval(node.right, d))
        if isinstance(node, ast.UnaryOp):
            return self._eval(node.operand, d)
        if isinstance(node, ast.Compare):
            self._eval(node.left, d)
            for comp in node.comparators:
                self._eval(comp, d)
            return _NO_FLOWS  # a boolean is not the tainted value
        if isinstance(node, _JOINED_STR_TYPES):
            out = _NO_FLOWS
            for value in node.values:
                out = self._union(out, self._eval(value, d))
            return out
        if isinstance(node, _FORMATTED_VALUE_TYPES):
            return self._eval(node.value, d)
        if isinstance(node, ast.IfExp):
            self._eval(node.test, d)
            return self._union(self._eval(node.body, d),
                               self._eval(node.orelse, d))
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            out = _NO_FLOWS
            for elt in node.elts:
                out = self._union(out, self._eval(elt, d))
            return out
        if isinstance(node, ast.Dict):
            out = _NO_FLOWS
            for key in node.keys:
                if key is not None:
                    out = self._union(out, self._eval(key, d))
            for value in node.values:
                out = self._union(out, self._eval(value, d))
            return out
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp,
                             ast.DictComp)):
            return self._eval_comprehension(node, d)
        if isinstance(node, ast.Starred):
            return self._eval(node.value, d)
        if isinstance(node, ast.Await):
            return self._eval(node.value, d)  # await is transparent
        if isinstance(node, (ast.Yield, ast.YieldFrom)):
            if node.value is not None:
                self._add_returns(self._eval(node.value, d))
            return _NO_FLOWS  # sent-in values are not modelled
        if isinstance(node, ast.NamedExpr):
            flows = self._eval(node.value, d)
            # Walrus targets bind mid-expression — conditionally
            # reached, so weak.
            if isinstance(node.target, ast.Name):
                self._bind(node.target.id, flows, strong=False)
            return flows
        if isinstance(node, ast.Lambda):
            # Lambda bodies are separate scopes; skipped + counted
            # (a returned closure over tainted locals is a named
            # miss class, not a wrong claim).
            self._count("lambdas_skipped")
            return _NO_FLOWS
        if isinstance(node, ast.Slice):
            for part in (node.lower, node.upper, node.step):
                if part is not None:
                    self._eval(part, d)
            return _NO_FLOWS
        # Unknown/rare expression node: evaluate children for taint
        # movement, propagate their union (conservative).
        out = _NO_FLOWS
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                out = self._union(out, self._eval(child, d))
        return out

    def _union(self, a: Flows, b: Flows) -> Flows:
        if not b:
            return a
        if not a:
            return b
        merged = a | b
        if len(merged) > self.limits.max_flows_per_value:
            raise _Budget("flows_per_value")
        return merged

    def _eval_comprehension(self, node: ast.expr, depth: int) -> Flows:
        # Generators first (they bind the loop variables), then the
        # element expressions — the design's stated approximation:
        # comprehensions propagate, whole-value.
        for gen in node.generators:
            iter_flows = self._eval(gen.iter, depth)
            self._assign_target(gen.target, iter_flows, strong=False,
                                depth=depth)
            for cond in gen.ifs:
                self._eval(cond, depth)
        out = _NO_FLOWS
        if isinstance(node, ast.DictComp):
            out = self._union(self._eval(node.key, depth),
                              self._eval(node.value, depth))
        else:
            out = self._eval(node.elt, depth)
        return out

    # -- calls ----------------------------------------------------------

    def _eval_call(self, node: ast.Call, depth: int) -> Flows:
        line = node.lineno
        chain = self._chain_of(node.func)
        if chain is None:
            # Dynamic callee (call on a call result, subscripted
            # callable, over-depth chain): evaluate the callee
            # expression itself; the call is unresolvable.
            callee_flows = self._eval(node.func, depth)
            name, resolution = "unresolved", "unresolved"
        else:
            callee_flows = _NO_FLOWS
            if isinstance(node.func, (ast.Attribute, ast.Name)):
                # Receiver taint rides through method-call results
                # (whole-value): evaluate the ROOT object only —
                # attribute hops add nothing under whole-value.
                root_node: ast.AST = node.func
                while isinstance(root_node, ast.Attribute):
                    root_node = root_node.value
                if isinstance(root_node, ast.Name):
                    callee_flows = self._lookup(root_node.id)
            # A method call ON a source attribute (request.args.get)
            # taints through the receiver: the module_attribute
            # check runs on the callee chain's prefixes too.
            callee_flows = self._union(
                callee_flows, self._attr_source_flows(node.func),
            )
            name, resolution, suspect = self._resolve_chain(chain)

        # Arguments: positions, keywords, stars — each evaluated once.
        pos_flows: list[Flows] = []
        star_flows: Flows = _NO_FLOWS
        kw_flows: dict[str, Flows] = {}
        dstar_flows: Flows = _NO_FLOWS
        for arg in node.args:
            if isinstance(arg, ast.Starred):
                star_flows = self._union(star_flows,
                                         self._eval(arg.value, depth))
            else:
                pos_flows.append(self._eval(arg, depth))
        for kw in node.keywords:
            if kw.arg is None:
                dstar_flows = self._union(dstar_flows,
                                          self._eval(kw.value, depth))
            else:
                kw_flows[kw.arg] = self._eval(kw.value, depth)

        all_arg_flows: Flows = callee_flows
        for f in pos_flows:
            all_arg_flows = self._union(all_arg_flows, f)
        for f in kw_flows.values():
            all_arg_flows = self._union(all_arg_flows, f)
        all_arg_flows = self._union(all_arg_flows, star_flows)
        all_arg_flows = self._union(all_arg_flows, dstar_flows)

        if chain is None:
            self._record_channels("unresolved", "unresolved", line,
                                  pos_flows, kw_flows, star_flows,
                                  dstar_flows)
            return self._assume_propagation(all_arg_flows)

        self._record_channels(name, resolution, line, pos_flows,
                              kw_flows, star_flows, dstar_flows)

        matchable = resolution in ("external", "builtin")
        # Sinks fire on the resolved external/builtin name; learned
        # sinks additionally on local module-qualified names.
        if matchable:
            for spec in self.specs.sinks_by_name.get(name, ()):
                self._match_sink(spec, node, line, pos_flows, kw_flows,
                                 star_flows, dstar_flows)
        for spec in self.specs.learned_sinks_by_name.get(name, ()):
            self._match_learned_sink(spec, line, pos_flows, kw_flows,
                                     star_flows, dstar_flows)
        # method_name sinks: bare-name equality on attribute calls,
        # heuristic by construction, resolution-independent (that is
        # their point — cursor.execute has no import binding).
        if len(chain) >= 2:
            for spec in self.specs.method_sinks:
                if spec.match != chain[-1]:
                    continue
                if spec.receiver_hint and spec.receiver_hint not in chain[:-1]:
                    continue
                self._match_sink(spec, node, line, pos_flows, kw_flows,
                                 star_flows, dstar_flows)

        # Return-flow precedence (the callee-summary rule (1) is the
        # worklist's job — P2 records the channels above for it):
        # propagator > sanitizer > assumed propagation.
        if matchable:
            props = self.specs.propagators_by_name.get(name, ())
            if props:
                return self._apply_propagators(props, pos_flows, kw_flows,
                                               star_flows, dstar_flows,
                                               node, depth)
            sans = self.specs.sanitizers_by_name.get(name, ())
            if sans:
                return self._apply_sanitizers(sans, all_arg_flows, line,
                                              suspect=suspect)
            srcs = self.specs.call_sources_by_name.get(name, ())
            if srcs:
                out = self._assume_propagation(all_arg_flows)
                for spec in srcs:
                    self._record_source(spec, line)
                    out = self._union(out, frozenset({Flow(
                        origin=(f"{_SOURCE_ORIGIN_PREFIX}"
                                f"{spec.kind}:{spec.match}"),
                        classes=spec.taint_classes,
                    )}))
                return out
        lprops = self.specs.learned_propagators_by_name.get(name, ())
        if lprops:
            return self._apply_learned_propagators(lprops, pos_flows,
                                                   all_arg_flows)
        lsans = self.specs.learned_sanitizers_by_name.get(name, ())
        if lsans:
            # Learned sanitizers are tag-only BY CONSTRUCTION (the
            # intake demotes kill claims before they get here).
            return self._apply_learned_sanitizers(lsans, all_arg_flows,
                                                  line)
        lsrcs = self.specs.learned_sources_by_name.get(name, ())
        if lsrcs:
            out = self._assume_propagation(all_arg_flows)
            for lspec in lsrcs:
                self._record_source(lspec, line)
                out = self._union(out, frozenset({Flow(
                    origin=f"{_SOURCE_ORIGIN_PREFIX}learned:{lspec.function}",
                    classes=lspec.taint_classes,
                    markers=(MARKER_LEARNED,),
                )}))
            return out
        return self._assume_propagation(all_arg_flows)

    def _assume_propagation(self, flows: Flows) -> Flows:
        """Rule (4): unknown callees propagate argument taint to the
        return value, tagged. Dropping instead is the classic
        cross-file recall killer; the tag keeps the approximation
        visible to every downstream consumer."""
        return frozenset(
            f.with_marker(MARKER_ASSUMED_PROPAGATION) for f in flows
        )

    def _record_channels(
        self, callee: str, resolution: str, line: int,
        pos_flows: list[Flows], kw_flows: dict[str, Flows],
        star_flows: Flows, dstar_flows: Flows,
    ) -> None:
        def push(channel: CallChannel) -> None:
            if len(self.channels) >= self.limits.max_call_channels:
                raise _Budget("call_channels")
            self.channels.append(channel)

        for i, flows in enumerate(pos_flows):
            if flows:
                push(CallChannel(
                    callee=callee, resolution=resolution, line=line,
                    arg=i, flows=tuple(sorted(flows, key=_flow_sort_key)),
                ))
        for kwarg, flows in kw_flows.items():
            if flows:
                push(CallChannel(
                    callee=callee, resolution=resolution, line=line,
                    kwarg=kwarg,
                    flows=tuple(sorted(flows, key=_flow_sort_key)),
                ))
        if star_flows:
            push(CallChannel(
                callee=callee, resolution=resolution, line=line, star="*",
                flows=tuple(
                    sorted((f.with_marker(MARKER_BINDING_APPROX)
                            for f in star_flows), key=_flow_sort_key),
                ),
            ))
        if dstar_flows:
            push(CallChannel(
                callee=callee, resolution=resolution, line=line, star="**",
                flows=tuple(
                    sorted((f.with_marker(MARKER_BINDING_APPROX)
                            for f in dstar_flows), key=_flow_sort_key),
                ),
            ))

    # -- sinks -----------------------------------------------------------

    def _unless_suppressed(self, spec: SinkSpec, node: ast.Call) -> bool:
        """``unless_kwargs``: every declared pair must appear at the
        call site as EXACTLY that literal token (an AST constant whose
        source spelling equals the pack literal). Variables and
        expressions never satisfy a pair — degradation is toward the
        sink firing."""
        if not spec.unless_kwargs:
            return False
        present: dict[str, ast.expr] = {
            kw.arg: kw.value for kw in node.keywords if kw.arg
        }
        for key, literal in spec.unless_kwargs:
            value = present.get(key)
            if value is None or not isinstance(value, ast.Constant):
                return False
            try:
                token = ast.unparse(value)
            except (ValueError, RecursionError):  # pragma: no cover
                return False
            if token != literal:
                return False
        return True

    def _declared_arg_flows(
        self, args: tuple[int, ...], kwargs: tuple[str, ...],
        pos_flows: list[Flows], kw_flows: dict[str, Flows],
        star_flows: Flows, dstar_flows: Flows,
    ) -> Flows:
        hit: Flows = _NO_FLOWS
        for pos in args:
            if pos < len(pos_flows):
                hit = self._union(hit, pos_flows[pos])
        for kwarg in kwargs:
            hit = self._union(hit, kw_flows.get(kwarg, _NO_FLOWS))
        # Star-args can land in any declared position — INCLUDING a
        # pos-or-keyword parameter the sink declared by keyword name
        # (``launch(*args)`` binding ``cmd`` positionally), so the
        # gate is args-or-kwargs. The forwarding approximation is
        # counted via the marker the channel already carries.
        if star_flows and (args or kwargs):
            hit = self._union(hit, frozenset(
                f.with_marker(MARKER_BINDING_APPROX) for f in star_flows
            ))
        if dstar_flows and (kwargs or args):
            hit = self._union(hit, frozenset(
                f.with_marker(MARKER_BINDING_APPROX) for f in dstar_flows
            ))
        return hit

    def _match_sink(
        self, spec: SinkSpec, node: ast.Call, line: int,
        pos_flows: list[Flows], kw_flows: dict[str, Flows],
        star_flows: Flows, dstar_flows: Flows,
    ) -> None:
        hit = self._declared_arg_flows(spec.args, spec.kwargs, pos_flows,
                                       kw_flows, star_flows, dstar_flows)
        if not hit:
            return
        if self._unless_suppressed(spec, node):
            self._count("sinks_suppressed_unless_kwargs")
            return
        live = frozenset(f for f in hit if spec.sink_class not in f.killed)
        if not live:
            # Every flow into this sink was transform-killed for this
            # class upstream — counted, so a kill is never invisible.
            self._count("sinks_suppressed_killed")
            return
        if len(self.sink_events) >= self.limits.max_sink_events:
            raise _Budget("sink_events")
        self.sink_events.append(SinkEvent(
            sink_class=spec.sink_class, cwe=spec.cwe, match=spec.match,
            line=line, confidence=spec.confidence, tier=spec.tier,
            pack=spec.pack,
            flows=tuple(sorted(live, key=_flow_sort_key)),
        ))

    def _match_learned_sink(
        self, spec: LearnedSpec, line: int,
        pos_flows: list[Flows], kw_flows: dict[str, Flows],
        star_flows: Flows, dstar_flows: Flows,
    ) -> None:
        args = spec.params_affected or tuple(range(len(pos_flows)))
        hit = self._declared_arg_flows(args, (), pos_flows, kw_flows,
                                       star_flows, dstar_flows)
        for flows in kw_flows.values():
            hit = self._union(hit, flows)
        if not hit:
            return
        classes = spec.taint_classes
        live = frozenset(
            f for f in hit if not all(c in f.killed for c in classes)
        )
        if not live:
            self._count("sinks_suppressed_killed")
            return
        if len(self.sink_events) >= self.limits.max_sink_events:
            raise _Budget("sink_events")
        self.sink_events.append(SinkEvent(
            sink_class=classes[0] if classes else "",
            cwe="", match=spec.function, line=line,
            confidence=CONFIDENCE_HEURISTIC, tier=spec.tier, pack="",
            flows=tuple(sorted(
                (f.with_marker(MARKER_LEARNED) for f in live),
                key=_flow_sort_key,
            )),
        ))

    # -- sanitizers / propagators ------------------------------------------

    def _record_sanitizer(self, event: SanitizerEvent) -> None:
        if len(self.sanitizer_events) >= self.limits.max_sanitizer_events:
            raise _Budget("sanitizer_events")
        self.sanitizer_events.append(event)

    def _apply_sanitizers(
        self, specs: tuple[SanitizerSpec, ...], flows: Flows, line: int,
        *, suspect: bool,
    ) -> Flows:
        if not flows:
            return _NO_FLOWS  # sanitizing a clean value is not an event
        out = flows
        for spec in specs:
            if spec.semantics == SEMANTICS_KILL and not suspect:
                self._count("sanitizer_kills")
                self._record_sanitizer(SanitizerEvent(
                    match=spec.match, semantics=spec.semantics,
                    applied=SEMANTICS_KILL, demoted=False,
                    demotion_reason="", line=line,
                    classes=spec.sink_classes, tier=spec.tier,
                ))
                out = frozenset(
                    f.with_killed(spec.sink_classes).with_hop(spec.match)
                    for f in out
                )
            elif spec.semantics == SEMANTICS_KILL:
                # The binding is suspect (rebound / shadowed
                # written name) — the kill demotes to a tag: the flow
                # stays alive, marked, and the demotion is counted.
                self._count("sanitizer_kill_demotions")
                self._record_sanitizer(SanitizerEvent(
                    match=spec.match, semantics=spec.semantics,
                    applied=SEMANTICS_TAG, demoted=True,
                    demotion_reason="binding_suspect", line=line,
                    classes=spec.sink_classes, tier=spec.tier,
                ))
                out = frozenset(
                    f.with_hop(spec.match)
                    .with_marker(MARKER_SANITIZER_DEMOTED)
                    for f in out
                )
            else:
                self._record_sanitizer(SanitizerEvent(
                    match=spec.match, semantics=spec.semantics,
                    applied=SEMANTICS_TAG, demoted=False,
                    demotion_reason="", line=line,
                    classes=spec.sink_classes, tier=spec.tier,
                ))
                out = frozenset(f.with_hop(spec.match) for f in out)
        return out

    def _apply_learned_sanitizers(
        self, specs: tuple[LearnedSpec, ...], flows: Flows, line: int,
    ) -> Flows:
        if not flows:
            return _NO_FLOWS
        out = flows
        for spec in specs:
            self._record_sanitizer(SanitizerEvent(
                match=spec.function, semantics=spec.semantics or SEMANTICS_TAG,
                applied=SEMANTICS_TAG, demoted=False, demotion_reason="",
                line=line, classes=spec.taint_classes, tier=spec.tier,
            ))
            out = frozenset(
                f.with_hop(spec.function).with_marker(MARKER_LEARNED)
                for f in out
            )
        return out

    def _apply_propagators(
        self, specs: tuple[PropagatorSpec, ...],
        pos_flows: list[Flows], kw_flows: dict[str, Flows],
        star_flows: Flows, dstar_flows: Flows,
        node: ast.Call, depth: int,
    ) -> Flows:
        """Curated/pack propagators apply AS DECLARED (only in-tree
        rows may narrow below the all-args floor — the loader enforced
        that). ``Argument[*]`` covers keywords and stars too;
        ``Argument[n]`` is that position only. ``to`` cells other than
        ReturnValue taint the named positional argument's base name
        (out-param modelling, weak)."""
        out: Flows = _NO_FLOWS
        for spec in specs:
            for edge in spec.flows:
                src = self._cell_flows(edge.src, pos_flows, kw_flows,
                                       star_flows, dstar_flows)
                if not src:
                    continue
                if edge.dst == "ReturnValue":
                    out = self._union(out, src)
                else:
                    pos = _argument_cell_index(edge.dst)
                    if pos is not None and pos < len(node.args):
                        target = node.args[pos]
                        if isinstance(target, ast.Name):
                            self._bind(target.id, src, strong=False)
        return out

    def _cell_flows(
        self, cell: str, pos_flows: list[Flows],
        kw_flows: dict[str, Flows], star_flows: Flows, dstar_flows: Flows,
    ) -> Flows:
        if cell == "Argument[*]":
            out: Flows = _NO_FLOWS
            for f in pos_flows:
                out = self._union(out, f)
            for f in kw_flows.values():
                out = self._union(out, f)
            out = self._union(out, star_flows)
            return self._union(out, dstar_flows)
        pos = _argument_cell_index(cell)
        if pos is None:
            return _NO_FLOWS
        got = pos_flows[pos] if pos < len(pos_flows) else _NO_FLOWS
        if star_flows:
            got = self._union(got, frozenset(
                f.with_marker(MARKER_BINDING_APPROX) for f in star_flows
            ))
        return got

    def _apply_learned_propagators(
        self, specs: tuple[LearnedSpec, ...],
        pos_flows: list[Flows], all_arg_flows: Flows,
    ) -> Flows:
        """Additive-only rule: a learned propagator UNIONS with the
        assumed-propagation floor — it may add flows, it can never
        remove an argument from propagation."""
        out = self._assume_propagation(all_arg_flows)
        for spec in specs:
            for edge in spec.added_flows:
                src = self._cell_flows(edge.src, pos_flows, {}, _NO_FLOWS,
                                       _NO_FLOWS)
                if src and edge.dst == "ReturnValue":
                    out = self._union(out, frozenset(
                        f.with_marker(MARKER_LEARNED) for f in src
                    ))
        return out

    # -- finish ---------------------------------------------------------

    def summary(self) -> FunctionSummary:
        entry = self.entry
        # Pre-split list: O(span) per function, not O(file) — the
        # cross-function cost dimension (see ModuleIndex.lines).
        content_hash = _hash_from_lines(
            self.idx.lines, entry.line_start, entry.line_end,
        )
        self.stats["nodes_walked"] = self.nodes
        self.stats["statements_walked"] = self.stmts
        return FunctionSummary(
            function_id=(f"{self.idx.path}::{entry.qualname}"
                         f"@{entry.line_start}"),
            qualname=entry.qualname,
            file=self.idx.path,
            line_start=entry.line_start,
            line_end=entry.line_end,
            content_hash=content_hash,
            params=entry.params,
            returns=tuple(sorted(self.returns, key=_flow_sort_key)),
            call_channels=tuple(self.channels),
            sink_events=tuple(self.sink_events),
            source_events=tuple(self.source_events),
            sanitizer_events=tuple(self.sanitizer_events),
            global_names=tuple(self.global_names),
            markers=tuple(sorted(self.markers)),
            opaque=False,
            stats=tuple(sorted(self.stats.items())),
        )


def _argument_cell_index(cell: str) -> int | None:
    if cell.startswith("Argument[") and cell.endswith("]"):
        inner = cell[len("Argument["):-1]
        if inner.isdigit():
            return int(inner)
    return None


def extract_summary(
    idx: ModuleIndex,
    entry: FunctionEntry,
    specs: SpecIndex,
    *,
    limits: Limits | None = None,
    internal_roots: frozenset[str] = frozenset(),
) -> FunctionSummary:
    """Compute one function's summary (never raises on target input).

    ``internal_roots`` names the analysed package's own top-level
    module roots: dotted names rooted there are project-internal, so
    they never match EXTERNAL pack specs (an in-package module named
    like a sanitizer must not kill) — the worklist passes them from
    the callgraph's package view.
    """
    limits = limits or Limits()
    if not idx.ok:
        return _opaque_summary(idx, entry, idx.degrade_reason or "module",
                               file=idx.path)
    try:
        run = _Extraction(idx, entry, specs, limits, internal_roots)
        run.run()
        return run.summary()
    except _Budget as capped:
        return _opaque_summary(idx, entry, capped.reason, file=idx.path)
    except RecursionError:  # belt: the walkers are depth-guarded
        return _opaque_summary(idx, entry, "walk_depth", file=idx.path)


def summarize_module(
    idx: ModuleIndex,
    specs: SpecIndex,
    *,
    limits: Limits | None = None,
    internal_roots: frozenset[str] = frozenset(),
) -> list[FunctionSummary]:
    """Summaries for every function the index found (test/CLI
    convenience; the worklist calls :func:`extract_summary` per
    visited function instead — demand-driven)."""
    return [
        extract_summary(idx, entry, specs, limits=limits,
                        internal_roots=internal_roots)
        for entry in idx.functions
    ]


__all__ = [
    "MAX_ACCESS_PATH_DEPTH",
    "MAX_CALL_CHANNELS",
    "MAX_FLOWS_PER_VALUE",
    "MAX_MODULE_AST_NODES",
    "MAX_NODES_PER_FUNCTION",
    "MAX_SINK_EVENTS",
    "MAX_SOURCE_FILE_BYTES",
    "MAX_STATEMENTS_PER_FUNCTION",
    "MARKER_ASSUMED_PROPAGATION",
    "MARKER_BINDING_APPROX",
    "MARKER_LEARNED",
    "MARKER_SANITIZER_DEMOTED",
    "MARKER_SUMMARY_CAPPED",
    "PER_FUNCTION_WALL_BUDGET_S",
    "SUMMARY_VERSION",
    "CallChannel",
    "Flow",
    "FunctionEntry",
    "FunctionSummary",
    "Limits",
    "ModuleIndex",
    "SanitizerEvent",
    "SinkEvent",
    "SourceEvent",
    "SpecIndex",
    "build_spec_index",
    "extract_summary",
    "index_module",
    "index_module_text",
    "kill_census",
    "summarize_module",
]
