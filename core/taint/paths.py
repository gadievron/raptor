"""Path reconstruction — renderable step records for taint candidates.

The propagation engine's candidates carry a function-level hop chain
(node id, edge tier/kind/line, honesty tags, sanitizer hops per hop).
This module turns those chains into STEP RECORDS: per-step file:line
spans resolved against the real inventory, bounded+escaped source
excerpts, tainted-parameter names where the summaries know them, and
per-step tier/tag/sanitizer/killed visibility. The emission phase
serializes these steps as SARIF ``codeFlows`` locations — the step
record defined here IS that contract.

## The step record contract (consumed by the emission phase)

One :class:`Step` per hop of a path, seed → sink order, plus a
terminal ``kind="sink"`` step for the sink call site itself:

* ``function`` — the callgraph node id entered at this step
  (verbatim target-derived text; see the escaping split below).
* ``file`` / ``function_line`` — where that function is defined,
  resolved from the callgraph node. ``""``/``0`` when the node is
  unknown (dangling edge) — NEVER fabricated.
* ``call_file`` / ``call_line`` — the TAINT-CROSSING SITE of this
  step, uniform across kinds: for a graph-edge step the PREVIOUS
  step's file plus the edge's recorded call line; for a seed step
  the entry site in the function's own file (the joined def line
  for route seeds, the source call line for in-body sources); for
  the sink step the sink call's own file:line. The excerpt, when
  present, is always the text AT this span — the record never
  attributes an excerpt to a line it does not name.
* ``tier`` / ``kind`` / ``tags`` / ``sanitizers`` /
  ``killed_classes`` — the edge tier, edge kind (``seed`` / ``sink``
  / graph edge kind), honesty markers, sanitizer callees the local
  flow passed through (TAG semantics stay visible as annotations,
  never suppressing), and the sink classes transform-killed on the
  flow that fed this step.
* ``tainted_param`` — the parameter name receiving taint at this
  step, when the extraction memos still know the signature (``""``
  otherwise — honest omission, counted).
* ``excerpt`` / ``excerpt_truncated`` — the source line at the
  step's taint-crossing site, whitespace-stripped, ESCAPED
  (non-printables become ``\\xHH``/``\\uHHHH`` per the
  ``core.security.log_sanitisation`` contract) and BOUNDED: the cap
  bounds the kept escaped text, the explicit elision marker rides
  on top and reports the elided length in raw characters. Omitted
  (``""``) when the line cannot be read back from the inventory —
  an excerpt is never synthesized.

Escaping split, deliberate: ``excerpt`` is prose destined for
human-facing renderers, so THIS layer escapes it. Name-shaped fields
(``function``, ``file``, ``call_file``) stay verbatim because
downstream consumers join them against the inventory (escaping would
break the join); they remain ``derived_from_target`` text that
render chokepoints must escape at display time — the engine's
standing contract.

No fabricated spans: every ``file``/``line`` pair a step renders
comes from the callgraph node table, the edge's recorded call line,
or the sink event's recorded line — reconstruction resolves and
bounds, it never invents. A lookup that fails leaves the field
empty/zero and is counted.

## Cost shape

Reconstruction is post-fixpoint and bounded by the product
candidates × path hops × alternatives — every factor already
carries an engine rail (MAX_CANDIDATES, MAX_PATH_HOPS, and the two
caps below). Excerpt reads go through the engine's LRU module-index
cache (reloads counted, files capped); this module holds no state
beyond its counters.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from core.analysis.package_callgraph import TIER_RESOLVED_STATIC
from core.security.log_sanitisation import escape_nonprintable

# ── named caps (both directions; hitting one is counted, never silent) ──

#: Alternative arrivals RETAINED per fact key during propagation —
#: the converging routes (and the alternative SOURCES) the witness
#: collapse would otherwise hide. Higher preserves more distinct
#: routes per key for reconstruction at fact-state RAM cost (the
#: retention is keys × alts × ~record size and JOINS the engine's
#: retained-bytes accounting); lower hides genuinely distinct
#: alternative sources behind the cap (over-cap arrivals are dropped
#: counted, marked ``alt_arrivals``).
MAX_ALT_ARRIVALS_PER_KEY = 4

#: Alternative paths RENDERED per candidate. Higher gives reviewers
#: more converging evidence per finding at artifact-size cost
#: (candidates × alternatives × steps); lower collapses back toward
#: the witness-only view (truncation counted, marked
#: ``alternatives``).
MAX_ALTERNATIVES_PER_CANDIDATE = 3

#: Per-step excerpt bound: it bounds the KEPT (escaped) text — the
#: explicit elision marker rides ON TOP of the bound, and the marker
#: reports the elided length in RAW characters. Escaping is applied
#: to a raw window sliced generously past the bound (4x) so a
#: crafted megabyte line cannot buy a full-line escape scan, and the
#: kept text is assembled piece-wise so no escape sequence is ever
#: severed. Higher shows more context per step but every character
#: is attacker bytes riding into every downstream render egress;
#: lower elides context reviewers may need. Truncation carries the
#: marker plus a flag, never silent.
MAX_EXCERPT_CHARS = 160

#: Step kind for the terminal sink step. Like the seed hop, the sink
#: step crosses no graph edge — it is intra-function detail from the
#: summary layer, so its tier is the non-diluting constant and it
#: never changes a path's tier.
STEP_KIND_SINK = "sink"
SINK_STEP_TIER = TIER_RESOLVED_STATIC

# Serialized-artifact byte estimators (the sixth cost dimension:
# name-shaped fields ride VERBATIM into every step and alternative,
# so the serialized result is target-shaped in name length ×
# candidates × steps — hostile-length node ids amplify it into the
# hundreds of MB). This layer only MEASURES (a cheap sum over the
# already-built records, surfaced as ``artifact_bytes_estimate`` +
# a threshold marker); the enforcing rail belongs at the emission
# boundary where serialization actually happens. Scaffolding
# constants lean high (JSON keys, quotes, delimiters per record).
_STEP_SCAFFOLD_BYTES = 224
_ALT_SCAFFOLD_BYTES = 96


class HopLike(Protocol):
    """The slice of the engine's ``Hop`` record this module reads
    (structural, so the engine can import this module without a
    cycle)."""

    function: str
    tier: str
    kind: str
    line: int
    tags: tuple[str, ...]
    sanitizer_hops: tuple[str, ...]
    killed: tuple[str, ...]


@dataclass(frozen=True)
class Step:
    """One renderable step of a candidate path (contract above)."""

    function: str
    file: str
    function_line: int
    tier: str
    kind: str
    call_file: str = ""
    call_line: int = 0
    tainted_param: str = ""
    tags: tuple[str, ...] = ()
    sanitizers: tuple[str, ...] = ()
    killed_classes: tuple[str, ...] = ()
    excerpt: str = ""
    excerpt_truncated: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "function": self.function,
            "file": self.file,
            "function_line": self.function_line,
            "tier": self.tier,
            "kind": self.kind,
            "call_file": self.call_file,
            "call_line": self.call_line,
            "tainted_param": self.tainted_param,
            "tags": list(self.tags),
            "sanitizers": list(self.sanitizers),
            "killed_classes": list(self.killed_classes),
            "excerpt": self.excerpt,
            "excerpt_truncated": self.excerpt_truncated,
            "derived_from_target": True,
        }

    def bytes_estimate(self) -> int:
        """Serialized-size estimate (see the artifact-bytes note at
        the module constants)."""
        return (_STEP_SCAFFOLD_BYTES
                + len(self.function) + len(self.file)
                + len(self.call_file) + len(self.tainted_param)
                + len(self.excerpt) + len(self.tier) + len(self.kind)
                + sum(len(t) + 4 for t in self.tags)
                + sum(len(s) + 4 for s in self.sanitizers)
                + sum(len(k) + 4 for k in self.killed_classes))


@dataclass(frozen=True)
class SinkSite:
    """The sink call's own location + local-flow annotations — the
    input for the terminal sink step."""

    function: str
    line: int
    tags: tuple[str, ...] = ()
    sanitizers: tuple[str, ...] = ()
    killed: tuple[str, ...] = ()


@dataclass(frozen=True)
class AlternativePath:
    """One alternative route to a candidate's sink that the witness
    collapse folded away — a different path, a different source, or
    both. Steps carry no excerpts (the witness path renders the
    excerpts once per candidate; alternatives are navigation aids —
    a documented artifact-size choice, not a capability limit)."""

    source: tuple[tuple[str, object], ...]
    steps: tuple[Step, ...]
    path_tier: str

    def to_dict(self) -> dict[str, object]:
        return {
            "source": dict(self.source),
            "steps": [s.to_dict() for s in self.steps],
            "path_tier": self.path_tier,
            "derived_from_target": True,
        }

    def bytes_estimate(self) -> int:
        """Serialized-size estimate (see the artifact-bytes note at
        the module constants)."""
        return (_ALT_SCAFFOLD_BYTES
                + descriptor_bytes_estimate(self.source)
                + len(self.path_tier)
                + sum(s.bytes_estimate() for s in self.steps))


@dataclass(frozen=True)
class KilledOrigin:
    """Which step killed a candidate's ``killed`` class — the
    provenance behind the withheld-count story. ``step`` indexes the
    candidate's witness steps; ``None`` means the kill was observed
    only on non-witness paths (the killed set is an intersection
    ACROSS paths, the witness is ONE path — honesty over guessing)."""

    sink_class: str
    step: int | None
    sanitizers: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {
            "sink_class": self.sink_class,
            "step": self.step,
            "sanitizers": list(self.sanitizers),
        }


def descriptor_bytes_estimate(
    descriptor: tuple[tuple[str, object], ...],
) -> int:
    """Serialized-size estimate for a source descriptor."""
    return sum(len(k) + len(v if isinstance(v, str) else str(v)) + 12
               for k, v in descriptor)


def killed_origins(
    killed: tuple[str, ...], steps: tuple[Step, ...],
) -> tuple[KilledOrigin, ...]:
    """Attribute each killed class to the first witness step whose
    entering flow carried the kill (sink step included)."""
    out: list[KilledOrigin] = []
    for cls in killed:
        origin = KilledOrigin(sink_class=cls, step=None)
        for i, step in enumerate(steps):
            if cls in step.killed_classes:
                origin = KilledOrigin(sink_class=cls, step=i,
                                      sanitizers=step.sanitizers)
                break
        out.append(origin)
    return tuple(out)


class StepRenderer:
    """Resolves hop chains to step records through injected lookups
    (the engine wires its graph, module-index cache, and signature
    memos in). Never raises on lookup failure — a step degrades to
    empty span fields, counted.

    Lookups:

    * ``node_lookup(node_id) -> (file_path, def_line) | None``
    * ``line_lookup(file_path, line) -> str | None`` — the raw source
      line, or ``None`` when the file/line cannot be read back.
    * ``param_lookup(node_id, index) -> str`` — parameter name, ``""``
      when unknown.
    """

    def __init__(
        self,
        *,
        node_lookup,
        line_lookup,
        param_lookup,
        max_excerpt_chars: int = MAX_EXCERPT_CHARS,
    ) -> None:
        self._node = node_lookup
        self._line = line_lookup
        self._param = param_lookup
        self.max_excerpt_chars = max_excerpt_chars
        self.stats: dict[str, int] = {}

    def _count(self, name: str, n: int = 1) -> None:
        self.stats[name] = self.stats.get(name, 0) + n

    def _excerpt(self, file_path: str, line: int) -> tuple[str, bool]:
        if not file_path or line < 1:
            self._count("excerpts_unavailable")
            return "", False
        raw = self._line(file_path, line)
        if raw is None:
            self._count("excerpts_unavailable")
            return "", False
        stripped = raw.strip()
        cap = self.max_excerpt_chars
        # Slice the RAW text to a generous window (4x the bound —
        # escaping expands, never shrinks, so anything past the
        # window can never reach the kept text) BEFORE escaping: a
        # megabyte-long crafted line must not buy a full-line
        # per-char escape scan per step. Escape-then-bound semantics
        # survive inside the window.
        window = stripped[: cap * 4]
        escaped = escape_nonprintable(window)
        self._count("excerpts_rendered")
        if len(window) == len(stripped) and len(escaped) <= cap:
            return escaped, False
        # Bound the kept text piece-wise so an escape sequence is
        # never severed mid-way, and report the elision in RAW
        # characters (the only count that does not depend on the
        # unescaped tail).
        self._count("excerpts_truncated")
        out: list[str] = []
        length = 0
        used = 0
        for ch in window:
            piece = ch if ch.isprintable() else escape_nonprintable(ch)
            if length + len(piece) > cap:
                break
            out.append(piece)
            length += len(piece)
            used += 1
        over = len(stripped) - used
        return f"{''.join(out)}...[+{over} chars]", True

    def render(
        self,
        entries: list[tuple[int | None, HopLike]],
        *,
        sink: SinkSite | None = None,
        with_excerpts: bool = True,
    ) -> tuple[Step, ...]:
        """Render one path (seed → sink order) to step records.
        ``entries`` pairs each hop with the parameter index receiving
        taint at that hop (``None`` when the step is not
        parameter-shaped, e.g. an in-body source's head hop)."""
        steps: list[Step] = []
        prev_file = ""
        for pi, hop in entries:
            located = self._node(hop.function)
            file_path, def_line = located if located else ("", 0)
            if hop.kind == "seed":
                # The entry site lives in the function's own file;
                # the joined summary line (not the graph node's) is
                # where the excerpt comes from, so the record names
                # exactly that span.
                call_file, call_line = file_path, hop.line
            else:
                call_file, call_line = prev_file, hop.line
            ex_file, ex_line = call_file, call_line
            param = ""
            if pi is not None:
                param = self._param(hop.function, pi)
                if not param:
                    self._count("param_names_unknown")
            excerpt, truncated = (
                self._excerpt(ex_file, ex_line) if with_excerpts
                else ("", False))
            steps.append(Step(
                function=hop.function,
                file=file_path,
                function_line=def_line,
                tier=hop.tier,
                kind=hop.kind,
                call_file=call_file,
                call_line=call_line,
                tainted_param=param,
                tags=hop.tags,
                sanitizers=hop.sanitizer_hops,
                killed_classes=hop.killed,
                excerpt=excerpt,
                excerpt_truncated=truncated,
            ))
            prev_file = file_path
        if sink is not None:
            located = self._node(sink.function)
            file_path, def_line = located if located else ("", 0)
            excerpt, truncated = (
                self._excerpt(file_path, sink.line) if with_excerpts
                else ("", False))
            steps.append(Step(
                function=sink.function,
                file=file_path,
                function_line=def_line,
                tier=SINK_STEP_TIER,
                kind=STEP_KIND_SINK,
                call_file=file_path,
                call_line=sink.line,
                tags=sink.tags,
                sanitizers=sink.sanitizers,
                killed_classes=sink.killed,
                excerpt=excerpt,
                excerpt_truncated=truncated,
            ))
        self._count("steps_rendered", len(steps))
        return tuple(steps)


__all__ = [
    "MAX_ALTERNATIVES_PER_CANDIDATE",
    "MAX_ALT_ARRIVALS_PER_KEY",
    "MAX_EXCERPT_CHARS",
    "SINK_STEP_TIER",
    "STEP_KIND_SINK",
    "AlternativePath",
    "KilledOrigin",
    "SinkSite",
    "Step",
    "StepRenderer",
    "descriptor_bytes_estimate",
    "killed_origins",
]
