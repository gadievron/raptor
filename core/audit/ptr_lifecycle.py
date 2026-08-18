"""ptr_lifecycle channel — stale-pointer / field-parity lifecycle census.

Target class (CWE-825/672/416, the peeloff shape): a lifecycle event
on an object (free, release, re-target) leaves a previously-taken
alias — a cached pointer in another struct field or a long-lived
local — pointing at the old referent; a later read through the alias
is a UAF/stale-use that flow tools miss because the alias hop breaks
the dataflow. Substrate: the field-access census
(:mod:`core.audit.field_census`).

Two legs, two epistemologies:

* **Leg A — field-assignment-parity** (statistical): "N sibling
  fields of the same object graph are re-targeted from the same
  source; one field that is read elsewhere is not re-assigned."
  Emits a :class:`~core.audit.peer_evidence.PeerEvidence` (dimension
  ``field-parity``) — which lands under the **consistency namespace**
  by construction (``consistency:field-parity-majority``),
  detection-grade, aggregation-eligible. Deliberate: parity alone is
  a majority statistic, so the single-namespace self-corroboration
  firewall must apply to it. ``peer_evidence.py`` is imported, never
  changed.
* **Leg B — stale-alias census** (structural, own ``ptr_lifecycle``
  namespace, promote-capable): alias edge + lifecycle event + live
  alias + post-event read, all four receipts present.

Escalators: entry-reachability (standard, escalator-not-gate);
dark_verify — CWE-416 is dark-verify-eligible (``cwe_dispatch``), so
a confirmed stale-alias claiming CWE-416 can earn a dynamic receipt
through the existing witness pipeline; typestate corroborates as an
independent namespace.

Boundary declarations: single-binding intra-function UAF stays with
the existing CWE-416 chain (smt check-early-release, cocci
use_after_free, CodeQL); ``cross_function_verify.incomplete_cleanup``
stays the adjudicator for LLM cleanup hypotheses; this channel owns
only the alias-hop class neither covers.

Verdict discipline follows ``fail_open`` / ``consistency``: confirmed
/ refuted / inconclusive-with-reason, never a guess. No LLM calls, no
subprocesses.
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .field_census import (
    RHS_FROM_FIELD,
    RHS_LITERAL_NULL,
    FieldCensus,
    build_field_census,
)
from .peer_evidence import PeerEvidence, PeerExhibit

logger = logging.getLogger(__name__)

# Rule-id namespace (own, structural — leg B).
RULE_STALE_ALIAS = "ptr_lifecycle:stale-alias"

# Detection-grade variant (naming-stem-only event vocabulary or a
# degraded census) — may not promote alone; participates in
# _aggregate_channel_confirmations.
DETECTION_VARIANT_SUFFIX = "-naming"

# Leg A emits under the consistency namespace by construction.
DIMENSION_FIELD_PARITY = "field-parity"

# CWE families the channel joins via the fallback chain. CWE-825 /
# CWE-672 are channel-owned (no other dispatch entry); the CWE-416
# membership is additive to the existing rich entry. CWE-416 is the
# dark-verify escalator carrier: confirmed stale-alias hypotheses in
# that family are witness-eligible through the existing pipeline.
PTR_LIFECYCLE_CWES = frozenset({"CWE-825", "CWE-672", "CWE-416"})
DARK_VERIFY_CWE = "CWE-416"

# Enumerated inconclusive reasons (each a distinct tested string).
REASON_CENSUS_INCOMPLETE = "census-incomplete"
REASON_ALIAS_ESCAPES = "alias-escapes"
REASON_EVENT_VOCAB_UNBOUND = "event-vocab-unbound"
REASON_LANGUAGE_UNSUPPORTED = "language-unsupported"
REASON_HYPOTHESIS_UNBINDABLE = "hypothesis-unbindable"

INCONCLUSIVE_REASONS = frozenset({
    REASON_CENSUS_INCOMPLETE,
    REASON_ALIAS_ESCAPES,
    REASON_EVENT_VOCAB_UNBOUND,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_HYPOTHESIS_UNBINDABLE,
})

# SEED SET — universal deallocator exemplars (libc + kernel), the
# registry-grade Tier-A-style vocabulary. Project/library free verbs
# (BIO_free, X_destroy, ...) arrive via the learned DomainVocabulary
# (deallocators / refcount_puts) or match the naming stem at
# detection grade only. Do not grow this tuple — teach the study
# loop / pack instead (SEED_SET_CAP discipline).
_SEED_DEALLOCATORS = (
    "free", "kfree", "vfree", "kvfree", "kfree_rcu",
    "kfree_sensitive", "g_free",
)

# Naming-stem fallback: recognisably free-shaped project names.
# Matches select the -naming detection variant, never registry grade.
_NAMING_STEM_RE = re.compile(
    r"\A\w+_(?:free|destroy|release|put|teardown)\w*\Z",
)

_RCU_SAFE_EVENT_RE = re.compile(r"_rcu\Z")
_RCU_DEREF_RE = re.compile(r"\brcu_dereference\w*\s*\(")

# Hypothesis shapes asserting the alias-hop class. Plain
# "use-after-free" phrasing deliberately does NOT dispatch here — the
# existing CWE-416 chain owns the single-binding class.
_PTR_LIFECYCLE_HYPOTHESIS_RE = re.compile(
    r"(?:(?:stale|dangling|cached)\W{0,20}(?:pointer|reference|handle|alias)"
    r"|outliv\w+"
    r"|freed.{0,40}(?:still|later).{0,20}(?:read|used|deref)"
    r"|not\s+(?:re)?assigned.{0,40}(?:sibling|other\s+field)"
    r"|peel.?off"
    r"|alias.{0,40}(?:freed|released|old\s+referent))",
    re.IGNORECASE | re.DOTALL,
)

_BACKTICK_IDENT_RE = re.compile(r"`([A-Za-z_][\w.>-]*)\s*(?:\(\s*\))?`")
_IDENT_RE = re.compile(r"\b([A-Za-z_]\w{2,})\b")

_HYPOTHESIS_STOPWORDS = frozenset({
    "the", "and", "for", "not", "with", "when", "after", "stale",
    "dangling", "cached", "pointer", "reference", "handle", "alias",
    "freed", "free", "released", "release", "still", "later", "read",
    "used", "deref", "sibling", "other", "field", "assigned",
    "reassigned", "this", "that", "struct", "error", "path", "left",
    "old", "referent", "outlives", "peeloff", "function", "int",
    "void", "char",
})

# Invalidation search bounds (leg B step 3).
_INVALIDATION_CALLEE_DEPTH = 2
_MAX_INVALIDATION_FUNCTIONS = 50

# Standing pre-pass caps.
PREPASS_BUDGET_S = 20.0
MAX_PARITY_DEVIATIONS = 20
MAX_ALIAS_CANDIDATES = 50
MAX_LEADS = 20

# Leg A cluster threshold (§3.1).
PARITY_MIN_CLUSTER = 3


def is_ptr_lifecycle_hypothesis(text: str) -> bool:
    """True when the hypothesis asserts the alias-hop stale-pointer
    shape (stale/dangling/cached pointer, sibling field not
    re-assigned, peeloff)."""
    return bool(text) and bool(_PTR_LIFECYCLE_HYPOTHESIS_RE.search(text))


def ptr_lifecycle_applicable(cwe: str) -> bool:
    """True when the CWE belongs to the alias-hop lifecycle family."""
    norm = (cwe or "").upper().strip()
    if norm and not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return norm in PTR_LIFECYCLE_CWES


def is_detection_rule_id(rule_id: str) -> bool:
    """True for the detection-grade ``-naming`` variants — they may
    not promote alone but participate in channel aggregation."""
    return rule_id.startswith("ptr_lifecycle:") and rule_id.endswith(
        DETECTION_VARIANT_SUFFIX,
    )


# ── event vocabulary (seeds < pack < learned; graded) ───────────────


@lru_cache(maxsize=8)
def _seed_set() -> frozenset[str]:
    return frozenset(_SEED_DEALLOCATORS)


def _event_vocab_source(verb: str, vocab: Any = None) -> str | None:
    """Grade the lifecycle-event verb: ``learned`` (DomainVocabulary
    deallocators / refcount_puts — registry), ``seed`` (universal
    exemplar — registry), ``naming`` (stem match — detection), or
    None (not a recognised lifecycle verb)."""
    learned = (
        set(getattr(vocab, "deallocators", None) or ())
        | set(getattr(vocab, "refcount_puts", None) or ())
    )
    if verb in learned:
        return "learned"
    if verb in _seed_set():
        return "seed"
    if _NAMING_STEM_RE.match(verb):
        return "naming"
    return None


@lru_cache(maxsize=32)
def _event_call_re(names: tuple[str, ...]) -> re.Pattern:
    alts = "|".join(
        re.escape(n) for n in sorted(names, key=len, reverse=True)
    )
    return re.compile(
        r"\b(" + alts + r"|\w+_(?:free|destroy|release|put|teardown)\w*"
        r")\s*\(\s*&?\s*([A-Za-z_]\w*)"
    )


# ── receipts ────────────────────────────────────────────────────────


@dataclass
class AliasEvidence:
    """Aggregate leg-B verdict for one stale-alias claim: the four
    structural receipts (alias edge, lifecycle event, live-alias
    invalidation search, post-event reads)."""

    outcome: str                    # confirmed | refuted | inconclusive
    reason: str
    rule_id: str = RULE_STALE_ALIAS
    cwe: str = DARK_VERIFY_CWE
    owner: dict[str, Any] | None = None
    alias: dict[str, Any] | None = None
    event: dict[str, Any] | None = None
    post_event_reads: list[dict[str, Any]] = field(default_factory=list)
    invalidation_search: dict[str, Any] | None = None
    census_tier: str = ""
    reachability: dict[str, Any] | None = None
    corroboration: list[Any] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "outcome": self.outcome,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "cwe": self.cwe,
            "census_tier": self.census_tier,
        }
        if self.owner is not None:
            d["owner"] = self.owner
        if self.alias is not None:
            d["alias"] = self.alias
        if self.event is not None:
            d["event"] = self.event
        if self.post_event_reads:
            d["post_event_reads"] = self.post_event_reads[:3]
        if self.invalidation_search is not None:
            d["invalidation_search"] = self.invalidation_search
        if self.reachability is not None:
            d["reachability"] = self.reachability
        if self.corroboration:
            d["corroboration"] = [
                c.to_dict() if hasattr(c, "to_dict") else c
                for c in self.corroboration
            ]
        return d


def _inconclusive(reason: str, detail: str = "",
                  census_tier: str = "") -> AliasEvidence:
    return AliasEvidence(
        outcome="inconclusive",
        reason=f"{reason}: {detail}" if detail else reason,
        census_tier=census_tier,
    )


@dataclass
class FieldParityDeviation:
    """One leg-A deviation: a same-source re-target cluster missing a
    provenance-linked, read-elsewhere sibling field."""

    file: str
    function: str
    line: int
    field: str
    cluster_fields: tuple[str, ...]
    src_owner: str
    dst_owner: str
    description: str
    peer_evidence: PeerEvidence


# ── leg A: field-assignment parity ──────────────────────────────────


def detect_field_parity_deviations(
    census: FieldCensus,
    *,
    min_cluster: int = PARITY_MIN_CLUSTER,
    max_deviations: int = MAX_PARITY_DEVIATIONS,
) -> list[FieldParityDeviation]:
    """Cluster same-function writes whose rhs-provenance shares a
    source object; report graph fields that are read elsewhere but
    absent from the cluster.

    Owner linkage is by base-identifier name (the census does not
    resolve types) — a deliberate approximation for a detection-grade
    majority statistic; every receipt names the exact sites.
    """
    # (file, function, dst_owner, src_owner) → {field: FieldWrite}
    clusters: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    for rec in census.fields.values():
        for w in rec.writes:
            if not w.rhs_class.startswith(f"{RHS_FROM_FIELD}:"):
                continue
            src_expr = w.rhs_class.split(":", 1)[1]
            src_owner = src_expr.split(".", 1)[0]
            if not (w.function and w.owner and src_owner):
                continue
            key = (w.file, w.function, w.owner, src_owner)
            clusters.setdefault(key, {})[rec.field] = w

    deviations: list[FieldParityDeviation] = []
    for (file_path, function, dst, src), writes in sorted(
        clusters.items(),
    ):
        if len(writes) < min_cluster:
            continue
        cluster_fields = tuple(sorted(writes))
        for name, rec in sorted(census.fields.items()):
            if name in writes:
                continue
            # (b) provenance link: the field lives on the replaced
            # graph — an access with the cluster's dst or src owner.
            linked = [
                s for s in (list(rec.writes) + list(rec.reads))
                if s.owner in (dst, src)
            ]
            if not linked:
                continue
            # (a) read sites elsewhere (the accessor-returns-it shape).
            outside_reads = [
                r for r in rec.reads
                if (r.file, r.function) != (file_path, function)
            ]
            if not outside_reads:
                continue
            deviant_site = outside_reads[0]
            exhibits = [
                PeerExhibit(file=w.file, line=w.line, snippet=w.code)
                for w in list(writes.values())[:3]
            ]
            n = len(writes) + 1
            pe = PeerEvidence(
                dimension=DIMENSION_FIELD_PARITY,
                formation="cluster",
                group_key=f"{dst}<-{src}",
                n=n,
                conforming=len(writes),
                ratio=len(writes) / n,
                deviant=PeerExhibit(
                    file=deviant_site.file,
                    line=deviant_site.line,
                    snippet=deviant_site.code,
                ),
                exhibits=exhibits,
                contract_source="majority",
                provenance=(
                    f"cluster:{file_path}:{function}:"
                    f"{len(writes)}fields"
                ),
            )
            deviations.append(FieldParityDeviation(
                file=file_path,
                function=function,
                line=next(iter(writes.values())).line,
                field=name,
                cluster_fields=cluster_fields,
                src_owner=src,
                dst_owner=dst,
                description=(
                    f"{len(writes)} sibling fields of `{dst}` "
                    f"({', '.join(cluster_fields)}) are re-targeted "
                    f"from `{src}` in {function}; `{name}` is read "
                    f"elsewhere ({deviant_site.file}:"
                    f"{deviant_site.line}) but not re-assigned"
                ),
                peer_evidence=pe,
            ))
            if len(deviations) >= max_deviations:
                return deviations
    return deviations


# ── leg B: stale-alias census ───────────────────────────────────────


def _candidate_identifiers(hypothesis: str) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for regex in (_BACKTICK_IDENT_RE, _IDENT_RE):
        for m in regex.finditer(hypothesis):
            name = m.group(1).split("->")[-1].split(".")[-1]
            if name.lower() in _HYPOTHESIS_STOPWORDS or name in seen:
                continue
            seen.add(name)
            ordered.append(name)
    return ordered


def _language_supported(file_path: str) -> bool:
    try:
        from core.inventory.languages import detect_language
        lang = detect_language(file_path)
    except Exception:
        lang = None
    if lang is not None:
        return lang in ("c", "cpp")
    return Path(file_path).suffix in (
        ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp",
    )


def _entry_reachability(
    inventory: dict[str, Any] | None,
    context: Any,
    file_path: str,
    function_name: str,
) -> dict[str, Any] | None:
    """Standard outcome-gated escalator (the fail-open walk):
    reachability decides ``finding`` vs ``suspicious``, never the
    verdict itself."""
    if context is None:
        return None
    try:
        from .fail_open_verify import _entry_reachability as _fo_reach
    except ImportError:
        return None
    try:
        return _fo_reach(context, inventory, file_path, function_name)
    except Exception:
        logger.debug("ptr_lifecycle: reachability escalator failed",
                     exc_info=True)
        return None


@dataclass
class _AliasEdge:
    kind: str            # "field" | "local"
    name: str            # alias field name or local variable name
    owner: str           # aliased owner base (the freed object)
    owner_field: str     # field of the owner that was aliased
    file: str = ""
    line: int = 0
    code: str = ""
    holder: str = ""     # for field aliases: the holding owner base


def _alias_edges_for_owner(
    census: FieldCensus,
    owner: str,
) -> list[_AliasEdge]:
    """Alias edges whose SOURCE is a field of *owner*: field-to-field
    copies (``child->port = obj->port``) and local alias assignments
    (``p = obj->port``)."""
    edges: list[_AliasEdge] = []
    prefix = f"{RHS_FROM_FIELD}:{owner}."
    for rec in census.fields.values():
        for w in rec.writes:
            if w.rhs_class.startswith(prefix):
                edges.append(_AliasEdge(
                    kind="field",
                    name=rec.field,
                    owner=owner,
                    owner_field=w.rhs_class.split(".", 1)[1],
                    file=w.file,
                    line=w.line,
                    code=w.code,
                    holder=w.owner,
                ))
        for r in rec.reads:
            if r.owner == owner and \
                    r.context.startswith("alias_assign:"):
                edges.append(_AliasEdge(
                    kind="local",
                    name=r.context.split(":", 1)[1],
                    owner=owner,
                    owner_field=rec.field,
                    file=r.file,
                    line=r.line,
                    code=r.code,
                ))
    return edges


def _find_events(
    segment_lines: list[str],
    start_line: int,
    vocab: Any,
) -> list[dict[str, Any]]:
    """Lifecycle-event call sites (deallocator vocab, graded) inside
    one function segment."""
    names = tuple(sorted(
        _seed_set()
        | set(getattr(vocab, "deallocators", None) or ())
        | set(getattr(vocab, "refcount_puts", None) or ()),
    ))
    pattern = _event_call_re(names)
    events: list[dict[str, Any]] = []
    for offset, text in enumerate(segment_lines):
        for m in pattern.finditer(text):
            verb, target = m.group(1), m.group(2)
            source = _event_vocab_source(verb, vocab)
            if source is None:
                continue
            events.append({
                "verb": verb,
                "target": target,
                "line": start_line + offset,
                "code": text.strip()[:200],
                "vocab_source": source,
            })
    return events


def _invalidation_receipt(
    edge: _AliasEdge,
    event_line: int,
    function_span: Any,
    lines: list[str],
    source_texts: dict[str, str],
    census: FieldCensus,
) -> dict[str, Any] | None:
    """Search for an invalidating write to the alias after the event:
    in the event function's remainder, then in direct callees
    (depth ≤ 2, capped). Returns the receipt when found (→ refuted),
    else None (alias live)."""
    if edge.kind == "field":
        pattern = re.compile(
            rf"\b\w+\s*->\s*{re.escape(edge.name)}\s*=\s*"
            rf"(?:NULL|nullptr|0)\b",
        )
    else:
        pattern = re.compile(
            rf"\b{re.escape(edge.name)}\s*=\s*(?:NULL|nullptr|0)\b",
        )
    for offset in range(event_line - function_span.start,
                        len(lines)):
        if pattern.search(lines[offset]):
            return {
                "kind": "null-write",
                "line": function_span.start + offset,
                "code": lines[offset].strip()[:200],
            }
    # Census-wide NULL writes to the alias field on the same holder
    # (invalidate-in-helper).
    if edge.kind == "field":
        rec = census.fields.get(edge.name)
        for w in (rec.writes if rec else []):
            if w.owner == edge.holder and \
                    w.rhs_class == RHS_LITERAL_NULL and \
                    w.line != edge.line:
                return {
                    "kind": "null-write",
                    "file": w.file,
                    "line": w.line,
                    "code": w.code,
                }
    del source_texts  # depth-2 callee scan rides the census records
    return None


def _post_event_reads(
    census: FieldCensus,
    edge: _AliasEdge,
    event_function: str,
    event_line: int,
) -> list[dict[str, Any]]:
    """Read sites of the alias after the event: census reads of the
    alias field in other functions (the accessor-returns-it receipt)
    or after the event line in the same function."""
    if edge.kind == "local":
        return []  # local aliases are read within the function only
    rec = census.fields.get(edge.name)
    if rec is None:
        return []
    out: list[dict[str, Any]] = []
    for r in rec.reads:
        if r.function != event_function or r.line > event_line:
            out.append({
                "file": r.file,
                "line": r.line,
                "function": r.function,
                "context": r.context,
                "code": r.code,
            })
    return out[:3]


def _local_post_event_reads(
    edge: _AliasEdge,
    lines: list[str],
    function_span: Any,
    event_line: int,
) -> list[dict[str, Any]]:
    pattern = re.compile(rf"\b{re.escape(edge.name)}\b")
    assign = re.compile(rf"\b{re.escape(edge.name)}\s*=(?!=)")
    out: list[dict[str, Any]] = []
    # Clamped like _local_alias_escapes: an out-of-span event line
    # would start the walk at a negative offset (wrap-around reads
    # from the segment tail — wrong lines, not a crash, but still
    # garbage receipts).
    for offset in range(max(event_line - function_span.start + 1, 0),
                        len(lines)):
        text = lines[offset]
        if pattern.search(text) and not assign.search(text):
            out.append({
                "line": function_span.start + offset,
                "function": function_span.name,
                "context": "expr",
                "code": text.strip()[:200],
            })
    return out[:3]


def _local_alias_escapes(
    edge: _AliasEdge,
    lines: list[str],
    function_span: Any,
    event_line: int,
    known_functions: set[str],
) -> str | None:
    """A local alias handed to an out-of-census callee between assign
    and event may transfer ownership — mirror of the consistency
    ``ownership-unresolved`` convention."""
    call_re = re.compile(
        rf"\b([A-Za-z_]\w*)\s*\([^)]*\b{re.escape(edge.name)}\b",
    )
    # Clamp both ends: an alias edge recorded OUTSIDE this function's
    # span (the census matches edges to events by field name, so a
    # cross-function pairing is possible) yields a NEGATIVE start
    # offset — Python then indexes from the END of the segment and,
    # past -len(lines), raises IndexError. That single IndexError
    # aborted the whole census/prepass block in production (silently,
    # at debug level), taking the lock_region prepass down with it.
    start_off = max(edge.line - function_span.start + 1, 0)
    end_off = min(event_line - function_span.start, len(lines))
    for offset in range(start_off, end_off):
        m = call_re.search(lines[offset])
        if m and m.group(1) not in known_functions and \
                _event_vocab_source(m.group(1)) is None:
            return (
                f"`{edge.name}` passed to {m.group(1)}() at line "
                f"{function_span.start + offset} before the event"
            )
    return None


def _grade(vocab_source: str, census: FieldCensus) -> str:
    """Registry rule-id when the event verb is learned/pack/seed
    (registry vocabulary) AND the census is full-tier; naming-only
    verbs select the ``-naming`` detection variant."""
    if vocab_source in ("learned", "seed") and not census.degraded:
        return RULE_STALE_ALIAS
    return RULE_STALE_ALIAS + DETECTION_VARIANT_SUFFIX


def _adjudicate_alias(
    census: FieldCensus,
    source_texts: dict[str, str],
    file_path: str,
    function_span: Any,
    event: dict[str, Any],
    edge: _AliasEdge,
    *,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
) -> AliasEvidence:
    """Adjudicate one (event, alias-edge) pair."""
    lines = source_texts.get(file_path, "").splitlines()
    segment = lines[function_span.start - 1:function_span.end]

    # 6c parity: rcu-safe deferred free of an rcu-read alias refutes.
    if _RCU_SAFE_EVENT_RE.search(event["verb"]):
        assign_idx = edge.line - function_span.start
        if 0 <= assign_idx < len(segment) and \
                _RCU_DEREF_RE.search(segment[assign_idx]):
            return AliasEvidence(
                outcome="refuted",
                reason=(
                    f"{event['verb']}() at line {event['line']} is the "
                    f"rcu-safe deferred free of an rcu-read alias — "
                    f"the grace period covers the read"
                ),
                census_tier=census.tier,
                event=event,
                alias=_alias_dict(edge),
            )

    invalidation = _invalidation_receipt(
        edge, event["line"], function_span, segment, source_texts,
        census,
    )
    if invalidation is not None:
        return AliasEvidence(
            outcome="refuted",
            reason=(
                f"alias `{edge.name}` is invalidated after the "
                f"{event['verb']}() event ({invalidation['kind']} at "
                f"line {invalidation['line']})"
            ),
            census_tier=census.tier,
            event=event,
            alias=_alias_dict(edge),
            invalidation_search=invalidation,
        )

    if edge.kind == "local":
        known = {
            s.name for spans in census.functions.values() for s in spans
        } or {s.name for s in _census_spans(census, source_texts)}
        escape = _local_alias_escapes(
            edge, segment, function_span, event["line"], known,
        )
        if escape:
            return _inconclusive(
                REASON_ALIAS_ESCAPES, escape, census_tier=census.tier,
            )
        reads = _local_post_event_reads(
            edge, segment, function_span, event["line"],
        )
    else:
        reads = _post_event_reads(
            census, edge, function_span.name, event["line"],
        )
    if not reads:
        return AliasEvidence(
            outcome="refuted",
            reason=(
                f"no post-event read of alias `{edge.name}` exists "
                f"after the {event['verb']}() event at line "
                f"{event['line']} — a stale alias nobody reads is "
                f"not a use"
            ),
            census_tier=census.tier,
            event=event,
            alias=_alias_dict(edge),
        )

    rule = _grade(event["vocab_source"], census)
    result = AliasEvidence(
        outcome="confirmed",
        reason=(
            f"`{edge.holder + '->' if edge.holder else ''}{edge.name}` "
            f"aliases {edge.owner}->{edge.owner_field} (assigned at "
            f"{edge.file}:{edge.line}); {event['verb']}() releases "
            f"{event['target']} at {file_path}:{event['line']} with "
            f"the alias live (no invalidating write found), and the "
            f"alias is read at {reads[0].get('file', file_path)}:"
            f"{reads[0]['line']}"
        ),
        rule_id=rule,
        census_tier=census.tier,
        owner={"name": edge.owner, "field": edge.owner_field},
        alias=_alias_dict(edge),
        event={**event, "function": function_span.name,
               "file": file_path},
        post_event_reads=reads,
        invalidation_search={
            "scanned_functions": 1,
            "depth": _INVALIDATION_CALLEE_DEPTH,
            "found": None,
        },
    )
    result.reachability = _entry_reachability(
        inventory, context, file_path, function_span.name,
    )
    return result


def _alias_dict(edge: _AliasEdge) -> dict[str, Any]:
    return {
        "kind": edge.kind,
        "name": edge.name,
        "holder": edge.holder,
        "assign_site": {
            "file": edge.file,
            "line": edge.line,
            "code": edge.code,
        },
    }


def _census_spans(census: FieldCensus,
                  source_texts: dict[str, str]) -> list[Any]:
    from .field_census import function_spans
    out: list[Any] = []
    for fp, src in source_texts.items():
        spans = census.functions.get(fp)
        if spans is None:
            spans = function_spans(src, fp)
            census.functions[fp] = spans
        out.extend(spans)
    return out


def run_ptr_lifecycle_check(
    target_path: Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
    source_texts: dict[str, str] | None = None,
    census: FieldCensus | None = None,
    domain_vocab: Any = None,
    budget_s: float | None = None,
) -> AliasEvidence:
    """Adjudicate one stale-alias hypothesis (leg B).

    The lifecycle event is located in *function_name*; alias edges and
    post-event reads come from the field census (built over the one
    file when no prep census is supplied — O(one file), the fail_open
    cost discipline).
    """
    del budget_s  # phase-2 cross-file expansion parameter
    if not _language_supported(file_path):
        return _inconclusive(
            REASON_LANGUAGE_UNSUPPORTED,
            f"no ptr_lifecycle analyzer for {Path(file_path).suffix or 'unknown'}",
        )

    if source_texts is None:
        try:
            p = Path(target_path) / file_path
            source_texts = {
                file_path: p.read_text(encoding="utf-8",
                                       errors="replace"),
            }
        except OSError:
            return _inconclusive(
                REASON_HYPOTHESIS_UNBINDABLE,
                f"could not read {file_path}",
            )
    source = source_texts.get(file_path, "")
    if not source:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"could not read {file_path}",
        )

    if census is None:
        census = build_field_census(source_texts)
    if census.degraded:
        return _inconclusive(
            REASON_CENSUS_INCOMPLETE,
            "census is regex-tier — rhs provenance (the alias-edge "
            "premise) is unavailable; refusing to guess",
            census_tier=census.tier,
        )

    spans = census.functions.get(file_path)
    if spans is None:
        from .field_census import function_spans
        spans = function_spans(source, file_path)
        census.functions[file_path] = spans
    tail = function_name.rsplit(".", 1)[-1]
    span = next((s for s in spans if s.name == tail), None)
    if span is None:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"function {function_name} not found in {file_path}",
            census_tier=census.tier,
        )

    lines = source.splitlines()
    segment = lines[span.start - 1:span.end]
    events = _find_events(segment, span.start, domain_vocab)
    if not events:
        return _inconclusive(
            REASON_EVENT_VOCAB_UNBOUND,
            f"no learned/pack/seed deallocator (nor a free-shaped "
            f"name) is called in {function_name}",
            census_tier=census.tier,
        )

    idents = set(_candidate_identifiers(hypothesis))
    ranked = sorted(
        events,
        key=lambda e: (e["target"] not in idents
                       and e["verb"] not in idents),
    )
    fallbacks: list[AliasEvidence] = []
    for event in ranked:
        edges = _alias_edges_for_owner(census, event["target"])
        for edge in edges:
            res = _adjudicate_alias(
                census, source_texts, file_path, span, event, edge,
                inventory=inventory, context=context,
            )
            if res.outcome == "confirmed":
                return res
            fallbacks.append(res)
    if fallbacks:
        # A receipted refutation beats an inconclusive shrug.
        fallbacks.sort(key=lambda r: r.outcome != "refuted")
        return fallbacks[0]
    if census.capped:
        return _inconclusive(
            REASON_CENSUS_INCOMPLETE,
            "census caps were hit — the no-alias-edge conclusion is "
            "not trustworthy on a partial census",
            census_tier=census.tier,
        )
    return _inconclusive(
        REASON_HYPOTHESIS_UNBINDABLE,
        f"no alias edge found for any lifecycle-event target in "
        f"{function_name} "
        f"({', '.join(sorted({e['target'] for e in events}))})",
        census_tier=census.tier,
    )


# ── standing pre-pass ───────────────────────────────────────────────


def run_ptr_lifecycle_prepass(
    source_texts: dict[str, str],
    *,
    census: FieldCensus | None = None,
    domain_vocab: Any = None,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
    budget_s: float = PREPASS_BUDGET_S,
) -> dict[str, Any]:
    """Standing pre-pass: leg-A parity deviations (mechanical entries
    + leads under the consistency namespace) and leg-B stale-alias
    candidates (injected handoff hypotheses — verdicts stay with the
    dispatch channel). Returns ``{"leads", "mechanical", "handoffs",
    "telemetry"}`` (the consistency-prepass shape)."""
    t0 = time.monotonic()
    telemetry: dict[str, Any] = {
        "dimensions": {},
        "inconclusive_reasons": {},
        "budget_exceeded": False,
    }
    leads: list[dict[str, Any]] = []
    mechanical: list[dict[str, Any]] = []
    handoffs: list[dict[str, Any]] = []

    if census is None:
        census = build_field_census(source_texts)

    def _dim(name: str) -> dict[str, int]:
        return telemetry["dimensions"].setdefault(
            name, {"confirmed": 0, "refuted": 0, "inconclusive": 0},
        )

    # Leg A — parity (consistency namespace, detection grade).
    if not census.degraded:
        parity = detect_field_parity_deviations(census)
        counts = _dim(DIMENSION_FIELD_PARITY)
        for dev in parity:
            counts["confirmed"] += 1
            pe = dev.peer_evidence
            mechanical.append({
                "file": dev.file,
                "function": dev.function,
                "detector": "field_parity_deviation",
                "line": dev.line,
                "description": dev.description,
                # The cluster identity (re-target destination <-
                # source) is the grouping key, analogous to the
                # callee grouping of the return census.
                "callee": f"{dev.dst_owner}<-{dev.src_owner}",
                "rule_id": pe.rule_id,
                "cwe": DARK_VERIFY_CWE,
            })
            if len(leads) < MAX_LEADS:
                leads.append({
                    "dimension": DIMENSION_FIELD_PARITY,
                    "callee": dev.field,
                    "file": dev.file,
                    "function": dev.function,
                    "line": dev.line,
                    "rule_id": pe.rule_id,
                    "description": dev.description[:300],
                    "security_relevant": True,
                    "n": pe.n,
                    "conforming": pe.conforming,
                    "ratio": pe.ratio,
                    "contract_source": pe.contract_source,
                    "sites": [
                        f"{e.file}:{e.line} {e.snippet}".strip()
                        for e in pe.exhibits
                    ],
                })

    # Leg B — stale-alias candidates → handoff hypotheses.
    counts = _dim("stale-alias")
    if not census.degraded:
        candidates = 0
        for file_path in sorted(source_texts):
            if time.monotonic() - t0 > budget_s:
                telemetry["budget_exceeded"] = True
                break
            if not _language_supported(file_path):
                continue
            spans = census.functions.get(file_path)
            if spans is None:
                from .field_census import function_spans
                spans = function_spans(
                    source_texts[file_path], file_path,
                )
                census.functions[file_path] = spans
            lines = source_texts[file_path].splitlines()
            for span in spans:
                if candidates >= MAX_ALIAS_CANDIDATES:
                    break
                segment = lines[span.start - 1:span.end]
                events = _find_events(segment, span.start, domain_vocab)
                if not events:
                    continue
                candidates += 1
                for event in events:
                    for edge in _alias_edges_for_owner(
                        census, event["target"],
                    ):
                        res = _adjudicate_alias(
                            census, source_texts, file_path, span,
                            event, edge, inventory=inventory,
                            context=context,
                        )
                        counts[res.outcome] = (
                            counts.get(res.outcome, 0) + 1
                        )
                        if res.outcome == "inconclusive":
                            key = res.reason.split(":", 1)[0]
                            telemetry["inconclusive_reasons"][key] = (
                                telemetry["inconclusive_reasons"]
                                .get(key, 0) + 1
                            )
                            continue
                        if res.outcome != "confirmed":
                            continue
                        handoffs.append({
                            "file": file_path,
                            "function": span.name,
                            "line": event["line"],
                            "mechanism": (
                                f"stale alias: {res.reason} "
                                f"(field-census receipts attached; "
                                f"CWE-825/416 alias-hop class)"
                            ),
                        })
                        mechanical.append({
                            "file": file_path,
                            "function": span.name,
                            "detector": "stale_alias_candidate",
                            "line": event["line"],
                            "description": res.reason,
                            "callee": event["verb"],
                            "rule_id": res.rule_id,
                            "cwe": DARK_VERIFY_CWE,
                        })
    else:
        telemetry["inconclusive_reasons"][REASON_CENSUS_INCOMPLETE] = 1

    telemetry["census_tier"] = census.tier
    telemetry["wall_time_s"] = round(time.monotonic() - t0, 3)
    return {
        "leads": leads,
        "mechanical": mechanical,
        "handoffs": handoffs,
        "telemetry": telemetry,
    }
