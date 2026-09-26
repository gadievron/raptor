"""Bounded intake for project-learned taint specs.

The one target-derived channel into the pack model: specs learned
from the analysed project (:mod:`core.iris` — LLM-synthesised,
tool-refined, sometimes operator-promoted) map into the same
in-memory vocabulary as the in-tree packs, tier-tagged ``learned``.
Because the store contents are derived from a possibly hostile
repository, the intake is a pure, bounded filter — it enforces every
rule structurally, so a flooded or steering store degrades to counted
refusals rather than shifted verdicts:

* **Closed taint-class vocabulary.** A learned spec naming ANY class
  outside the pack-declared vocabulary is dropped with a counted
  refusal — a hostile store cannot mint classes that bypass sink
  pairing (and cannot smuggle one in beside a valid class). Store
  spellings are ALIASED first, not just normalized: the synthesis
  prompt's short labels (``sql``, ``cmd``, ``path``, ``template`` …)
  map to the packs' class vocabulary through the scorecard bridge's
  class→CWE table composed with the sanitizer catalog's CWE→class
  mapping, so real store output joins. An alias whose class no loaded
  pack declares still refuses — the alias map widens spelling, never
  membership. Specs with NO classes on classed roles drop as intended
  (classless = unroutable: nothing to pair against a sink class);
  heuristic-fallback store rows are the known member of that class.
* **Per-role count caps** with ``caps_hit`` markers and
  **tier-ordered truncation**: operator-promoted specs survive first,
  then by confidence, then stable input order. Higher caps admit big
  genuinely-learned vocabularies; lower caps bound a flooded store's
  reach — both directions are one constant edit below.
* **Learned sanitizers are tag-only.** Kill semantics (dropping taint
  outright) come only from the in-tree curated/pack channel; every
  sanitizer emitted here carries ``semantics="tag"`` by construction,
  and an input that CLAIMS kill is demoted with a counted marker
  (``learned_sanitizer_kill_demoted``) so a steering store's attempt
  is visible, not silent. A learned entry naming a curated callee is
  additive and deterministic: it rides beside the curated entry as a
  tag hop at ``learned`` tier and can never weaken the curated kill
  (the channels merge, they do not collide).
* **Learned propagators are additive-only.** A learned spec may ADD
  flows over the assumed-propagation floor but can never remove an
  argument from propagation — the output field is ``added_flows`` and
  the model has NO narrowing field at all. A spec-shaped input that
  claims narrowing is dropped with a counted refusal; only in-tree
  pack entries may narrow (``PropagatorSpec.narrowing``). Without
  this rule, a heuristic spec listing one affected parameter of a
  two-parameter function would silently kill taint on the other —
  kill-by-omission through a channel whose sanitizer rule only covers
  explicit sanitizers.
* **Hostile-text bounds.** Function names are charset- and
  length-validated (they are target-derived bytes headed for prompts
  and logs); anything outside the dotted-name grammar is refused.

The intake is a pure function over spec lists — it holds no state and
performs no IO, so its rules are pinned independently of any engine
that later consumes the result.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from collections.abc import Iterable, Mapping

from core.dataflow.sanitizer_catalog import sink_classes_for_cwe
from core.iris.scorecard_bridge import TAINT_CLASS_TO_CWE
from core.security.log_sanitisation import escape_nonprintable
from core.taint.packs import (
    SEMANTICS_TAG,
    TIER_LEARNED,
    FlowEdge,
    # Grammar constants and the curated class-spelling table shared
    # with the pack loader — learned names and classes must satisfy
    # exactly the grammars and spellings pack fields do, so they are
    # imported rather than twinned.
    _CLASS_RE,
    _CURATED_SINK_CLASS,
    _DOTTED_RE,
)

# ── named caps (both directions matter — see the module docstring) ───

MAX_LEARNED_SOURCES = 200
MAX_LEARNED_SINKS = 200
MAX_LEARNED_SANITIZERS = 100
MAX_LEARNED_PROPAGATORS = 100

#: Function-name bound. Learned names are target-derived; a
#: megabyte "name" is hostile by construction. Higher admits deeply
#: qualified names, lower tightens what can ride into prompts/logs.
MAX_LEARNED_NAME_LEN = 300

#: Store-spec ``source`` value stamped by an interactive operator
#: promotion — the only marker that earns first-survivor ordering.
OPERATOR_CONFIRMED_SOURCE = "operator_confirmed"

_ROLE_SOURCE = "source"
_ROLE_SINK = "sink"
_ROLE_SANITIZER = "sanitiser"
_ROLE_PROPAGATOR = "propagator"
#: Both spellings accepted on input; output roles use the store's.
_ROLE_ALIASES = {
    "source": _ROLE_SOURCE,
    "sink": _ROLE_SINK,
    "sanitiser": _ROLE_SANITIZER,
    "sanitizer": _ROLE_SANITIZER,
    "propagator": _ROLE_PROPAGATOR,
}

# Refusal reason keys (counted; stable identifiers for tests/reports).
REFUSED_UNKNOWN_ROLE = "unknown_role"
REFUSED_INVALID_FUNCTION_NAME = "invalid_function_name"
REFUSED_NO_TAINT_CLASSES = "no_taint_classes"
REFUSED_CLASS_OUTSIDE_VOCABULARY = "taint_class_outside_vocabulary"
REFUSED_TOO_MANY_CLASSES = "taint_classes_overflow"
REFUSED_PROPAGATOR_NARROWING = "learned_propagator_narrowing"
REFUSED_CAPPED = "capped_{role}"

# Demotion marker keys (counted; the spec is still admitted).
DEMOTED_SANITIZER_KILL = "learned_sanitizer_kill_demoted"

#: Class-count bound per spec. Real specs name a handful of classes;
#: past this the row is spam-shaped and drops whole (truncating and
#: admitting would let a flooded row smuggle its head through).
MAX_CLASSES_PER_SPEC = 32


def _build_class_aliases() -> dict[str, str]:
    """Store spelling → pack class-vocabulary spelling.

    The synthesis prompt asks for short labels (``sql``, ``cmd``,
    ``path``, ``deserialize`` …). Composed here: the scorecard
    bridge's class→CWE table joined through the sanitizer catalog's
    CWE→sink-class mapping (translated to pack spellings), extended
    with the bridge CWEs the catalog deliberately leaves unmapped but
    the seed packs declare classes for. Membership still gates on the
    LOADED vocabulary — an alias for a class no pack declares remains
    a counted refusal, so this table widens spelling, never reach.
    """
    # Bridge CWEs with no curated sanitizer class; pack spellings.
    cwe_fallback = {
        "CWE-94": "code-injection",
        "CWE-95": "code-injection",
        "CWE-1336": "template-injection",
        "CWE-601": "url-redirection",
    }
    # Prompt-vocabulary synonyms for bridge keys.
    synonyms = {"cmd": "command", "ssti": "template", "code": "eval"}
    out: dict[str, str] = {}
    for alias, cwe in TAINT_CLASS_TO_CWE.items():
        curated = sorted(sink_classes_for_cwe(cwe))
        if curated:
            out[alias] = _CURATED_SINK_CLASS.get(curated[0], curated[0])
        elif cwe in cwe_fallback:
            out[alias] = cwe_fallback[cwe]
        # else: no pack-expressible class (deserialize, ssrf, ldap,
        # xpath, log, crypto, xml, nosql today) — the raw spelling
        # rides through to the vocabulary gate and refuses counted.
    for syn, bridge_key in synonyms.items():
        if bridge_key in out:
            out[syn] = out[bridge_key]
    return out


_CLASS_ALIASES = _build_class_aliases()


@dataclass(frozen=True)
class LearnedSpec:
    """One learned spec admitted through the intake bounds.

    Sanitizer specs always carry ``semantics="tag"``; propagator
    specs carry ``added_flows`` (unioned with the propagation floor —
    never replacing it). There is deliberately no narrowing field.
    """

    role: str
    function: str
    file: str = ""
    taint_classes: tuple[str, ...] = ()
    params_affected: tuple[int, ...] = ()
    return_tainted: bool = False
    confidence: float = 0.0
    evidence_tier: str = ""
    human_promoted: bool = False
    tier: str = TIER_LEARNED
    semantics: str = ""
    added_flows: tuple[FlowEdge, ...] = ()


@dataclass(frozen=True)
class LearnedIntake:
    """Result of one intake pass — admitted specs plus the honest
    account of everything that was not admitted."""

    sources: tuple[LearnedSpec, ...] = ()
    sinks: tuple[LearnedSpec, ...] = ()
    sanitizers: tuple[LearnedSpec, ...] = ()
    propagators: tuple[LearnedSpec, ...] = ()
    caps_hit: tuple[str, ...] = ()
    refusals: tuple[tuple[str, int], ...] = ()
    #: Counted markers for specs ADMITTED in a weakened form (e.g. a
    #: claimed kill sanitizer demoted to tag) — distinct from
    #: refusals so "what did we drop" and "what did we weaken" read
    #: separately.
    demotions: tuple[tuple[str, int], ...] = ()

    def refusal_count(self, reason: str) -> int:
        return dict(self.refusals).get(reason, 0)

    def demotion_count(self, marker: str) -> int:
        return dict(self.demotions).get(marker, 0)

    @property
    def admitted(self) -> int:
        return (len(self.sources) + len(self.sinks)
                + len(self.sanitizers) + len(self.propagators))

    def to_dict(self) -> dict[str, Any]:
        return {
            "admitted": {
                "sources": len(self.sources),
                "sinks": len(self.sinks),
                "sanitizers": len(self.sanitizers),
                "propagators": len(self.propagators),
            },
            "caps_hit": list(self.caps_hit),
            "refusals": {reason: count for reason, count in self.refusals},
            "demotions": {marker: count for marker, count in self.demotions},
        }


def _get(spec: Any, name: str, default: Any = None) -> Any:
    """Duck-typed field access: object attributes (TaintSpec) or dict
    keys (serialized store rows) both work."""
    if isinstance(spec, Mapping):
        return spec.get(name, default)
    return getattr(spec, name, default)


def _normalize_class(raw: Any) -> str | None:
    """Store taint classes use underscore spellings and the synthesis
    prompt's short labels; the pack vocabulary uses dashed class
    names. Normalize, then alias, before the membership check so the
    closed-vocabulary rule tests semantics, not spelling."""
    if not isinstance(raw, str) or not raw or len(raw) > 100:
        return None
    candidate = raw.strip().lower().replace("_", "-")
    if not _CLASS_RE.match(candidate):
        return None
    return _CLASS_ALIASES.get(candidate, candidate)


def _confidence(spec: Any) -> float:
    raw = _get(spec, "confidence", 0.0)
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return 0.0
    if raw != raw or raw in (float("inf"), float("-inf")):
        return 0.0
    return min(1.0, max(0.0, float(raw)))


def _params_affected(spec: Any) -> tuple[int, ...]:
    raw = _get(spec, "params_affected", ()) or ()
    out: list[int] = []
    if isinstance(raw, (list, tuple)):
        for p in raw[:16]:
            if isinstance(p, int) and not isinstance(p, bool) and 0 <= p <= 63:
                out.append(p)
    return tuple(out)


_TIER_TOKEN_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}\Z")


def _evidence_tier(spec: Any) -> str:
    """Tier values are enum tokens (``xref_backed`` …). The store is
    target-derived, so anything outside the token charset — control
    bytes included — floors to "" rather than riding into prompts."""
    raw = _get(spec, "evidence_tier", "")
    value = getattr(raw, "value", raw)
    if isinstance(value, str) and _TIER_TOKEN_RE.match(value):
        return value
    return ""


def _added_flows(params: tuple[int, ...], return_tainted: bool) -> tuple[FlowEdge, ...]:
    """Learned propagation as flow ADDITIONS. With no parameter facts
    the addition is the conservative all-args-to-return edge; either
    way the result is unioned with the propagation floor downstream —
    a learned spec can widen flow, never shrink it."""
    del return_tainted  # a propagator's declared output is its return
    if not params:
        return (FlowEdge(src="Argument[*]", dst="ReturnValue"),)
    return tuple(FlowEdge(src=f"Argument[{p}]", dst="ReturnValue") for p in params)


def intake_learned_specs(
    specs: Iterable[Any],
    *,
    vocabulary: frozenset[str],
    max_sources: int = MAX_LEARNED_SOURCES,
    max_sinks: int = MAX_LEARNED_SINKS,
    max_sanitizers: int = MAX_LEARNED_SANITIZERS,
    max_propagators: int = MAX_LEARNED_PROPAGATORS,
) -> LearnedIntake:
    """Filter learned specs through the intake bounds (pure function).

    ``vocabulary`` is the closed taint-class set the loaded packs
    declare (:meth:`core.taint.packs.PackSet.taint_class_vocabulary`).
    Everything refused is counted in ``refusals``; every cap that
    binds lands in ``caps_hit``. Nothing raises: a hostile store's
    worst case is an empty admitted set with loud counters.
    """
    refusals: dict[str, int] = {}
    demotions: dict[str, int] = {}

    def refuse(reason: str) -> None:
        refusals[reason] = refusals.get(reason, 0) + 1

    def demote(marker: str) -> None:
        demotions[marker] = demotions.get(marker, 0) + 1

    # (sort_key, spec) per role; sort key = operator-promoted first,
    # then confidence descending, then stable input order.
    buckets: dict[str, list[tuple[tuple[int, float, int], LearnedSpec]]] = {
        _ROLE_SOURCE: [], _ROLE_SINK: [],
        _ROLE_SANITIZER: [], _ROLE_PROPAGATOR: [],
    }

    for index, spec in enumerate(specs):
        role_raw = _get(spec, "role", "")
        role = _ROLE_ALIASES.get(role_raw if isinstance(role_raw, str) else "")
        if role is None:
            refuse(REFUSED_UNKNOWN_ROLE)
            continue

        function = _get(spec, "function", "")
        if (not isinstance(function, str)
                or not 0 < len(function) <= MAX_LEARNED_NAME_LEN
                or not _DOTTED_RE.match(function)):
            refuse(REFUSED_INVALID_FUNCTION_NAME)
            continue

        # Additive-only pin: a learned spec has no legal way to narrow
        # propagation. Anything claiming to is refused outright rather
        # than admitted with the claim stripped — stripping would let a
        # steering store discover which of its rows got through.
        if role == _ROLE_PROPAGATOR and bool(_get(spec, "narrowing", False)):
            refuse(REFUSED_PROPAGATOR_NARROWING)
            continue

        classes_raw = _get(spec, "taint_classes", ()) or ()
        classes: list[str] = []
        outside = False
        if isinstance(classes_raw, (list, tuple)):
            if len(classes_raw) > MAX_CLASSES_PER_SPEC:
                # Drop-whole, no truncate-and-admit: slicing would let
                # a flooded row smuggle its head through the gate.
                refuse(REFUSED_TOO_MANY_CLASSES)
                continue
            for c in classes_raw:
                normalized = _normalize_class(c)
                if normalized is None or normalized not in vocabulary:
                    outside = True
                    break
                classes.append(normalized)
        if outside:
            refuse(REFUSED_CLASS_OUTSIDE_VOCABULARY)
            continue
        if role != _ROLE_PROPAGATOR and not classes:
            # Sources/sinks/sanitizers pair by class; an unclassed spec
            # has nothing to pair with. Propagators are class-agnostic.
            refuse(REFUSED_NO_TAINT_CLASSES)
            continue

        file_raw = _get(spec, "file", "")
        # Informational field, but target-derived bytes headed for
        # reports/prompts: escape at admit (bounded below) rather
        # than dropping an otherwise-sound spec over a weird path.
        file_str = (escape_nonprintable(file_raw)
                    if isinstance(file_raw, str) else "")
        confidence = _confidence(spec)
        params = _params_affected(spec)
        return_tainted = bool(_get(spec, "return_tainted", False))
        human = _get(spec, "source", "") == OPERATOR_CONFIRMED_SOURCE

        if role == _ROLE_SANITIZER:
            claimed = _get(spec, "semantics", "")
            if isinstance(claimed, str) and claimed.strip().lower() == "kill":
                # Admitted anyway (as tag) — but a kill CLAIM from the
                # learned channel is exactly the steering shape the
                # tag-only rule exists for, so the demotion is counted.
                demote(DEMOTED_SANITIZER_KILL)

        admitted = LearnedSpec(
            role=role,
            function=function,
            file=file_str[:1024],
            taint_classes=tuple(classes),
            params_affected=params,
            return_tainted=return_tainted,
            confidence=confidence,
            evidence_tier=_evidence_tier(spec),
            human_promoted=human,
            tier=TIER_LEARNED,
            semantics=SEMANTICS_TAG if role == _ROLE_SANITIZER else "",
            added_flows=(
                _added_flows(params, return_tainted)
                if role == _ROLE_PROPAGATOR else ()
            ),
        )
        sort_key = (0 if human else 1, -confidence, index)
        buckets[role].append((sort_key, admitted))

    caps = {
        _ROLE_SOURCE: ("learned_sources", max_sources),
        _ROLE_SINK: ("learned_sinks", max_sinks),
        _ROLE_SANITIZER: ("learned_sanitizers", max_sanitizers),
        _ROLE_PROPAGATOR: ("learned_propagators", max_propagators),
    }
    kept: dict[str, tuple[LearnedSpec, ...]] = {}
    caps_hit: list[str] = []
    for role, entries in buckets.items():
        marker, cap = caps[role]
        entries.sort(key=lambda pair: pair[0])
        if len(entries) > cap:
            caps_hit.append(marker)
            reason = REFUSED_CAPPED.format(role=marker.removeprefix("learned_"))
            refusals[reason] = refusals.get(reason, 0) + (len(entries) - cap)
            entries = entries[:cap]
        kept[role] = tuple(s for _, s in entries)

    return LearnedIntake(
        sources=kept[_ROLE_SOURCE],
        sinks=kept[_ROLE_SINK],
        sanitizers=kept[_ROLE_SANITIZER],
        propagators=kept[_ROLE_PROPAGATOR],
        caps_hit=tuple(sorted(caps_hit)),
        refusals=tuple(sorted(refusals.items())),
        demotions=tuple(sorted(demotions.items())),
    )


__all__ = [
    "DEMOTED_SANITIZER_KILL",
    "MAX_CLASSES_PER_SPEC",
    "MAX_LEARNED_NAME_LEN",
    "MAX_LEARNED_PROPAGATORS",
    "MAX_LEARNED_SANITIZERS",
    "MAX_LEARNED_SINKS",
    "MAX_LEARNED_SOURCES",
    "OPERATOR_CONFIRMED_SOURCE",
    "REFUSED_CAPPED",
    "REFUSED_CLASS_OUTSIDE_VOCABULARY",
    "REFUSED_INVALID_FUNCTION_NAME",
    "REFUSED_NO_TAINT_CLASSES",
    "REFUSED_PROPAGATOR_NARROWING",
    "REFUSED_TOO_MANY_CLASSES",
    "REFUSED_UNKNOWN_ROLE",
    "LearnedIntake",
    "LearnedSpec",
    "intake_learned_specs",
]
