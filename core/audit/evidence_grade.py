"""Evidence grading for /audit findings.

Each piece of evidence injected into the review context carries a source
tag and confidence level. Source tags distinguish mechanical extraction
(verifiable, deterministic) from LLM inference (probabilistic). Confidence
levels gate injection priority — HIGH evidence is never shed from the
prompt, LOW evidence is shed first under budget pressure.

Grading happens at two levels:
1. Per-evidence-item: each signal (taint flow, Joern result, spec
   deviation) gets a source tag and confidence.
2. Per-finding: a finding's overall confidence is the strongest
   evidence in its chain.
"""

from __future__ import annotations

import enum
import functools
import importlib
from dataclasses import dataclass
from typing import Any


class EvidenceSource(str, enum.Enum):
    """Where a piece of evidence came from."""

    TREE_SITTER = "mechanical:tree_sitter"
    TAINT_APPROX = "mechanical:taint_approx"
    CALL_GRAPH = "mechanical:call_graph"
    JOERN = "mechanical:joern"
    SEMGREP = "mechanical:semgrep"
    CODEQL = "mechanical:codeql"
    COCCINELLE = "mechanical:coccinelle"
    SMT = "mechanical:smt"
    BINARY_ORACLE = "mechanical:binary_oracle"
    TYPESTATE = "mechanical:typestate"
    NEGATIVE_SPACE = "mechanical:negative_space"
    PREFILTER = "mechanical:prefilter"
    LLM_INFERRED = "llm:inferred"
    LLM_SPEC = "llm:spec"
    LLM_CORROBORATED = "llm:corroborated"
    DYNAMIC_SANITIZER = "dynamic:sanitizer"
    DYNAMIC_FRIDA = "dynamic:frida"
    DYNAMIC_CRASH = "dynamic:crash"
    DARK_VERIFY = "mechanical:dark_verify"
    COMPILATION = "mechanical:compilation"
    COMPILER_ANALYZER = "mechanical:compiler_analyzer"
    PRECONDITION = "mechanical:precondition"


class Confidence(str, enum.Enum):
    """Confidence level for evidence injection priority."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


_SOURCE_CONFIDENCE: dict[EvidenceSource, Confidence] = {
    EvidenceSource.TREE_SITTER: Confidence.HIGH,
    EvidenceSource.TAINT_APPROX: Confidence.HIGH,
    EvidenceSource.CALL_GRAPH: Confidence.HIGH,
    EvidenceSource.JOERN: Confidence.HIGH,
    EvidenceSource.SEMGREP: Confidence.HIGH,
    EvidenceSource.CODEQL: Confidence.HIGH,
    EvidenceSource.COCCINELLE: Confidence.HIGH,
    EvidenceSource.SMT: Confidence.HIGH,
    EvidenceSource.BINARY_ORACLE: Confidence.HIGH,
    EvidenceSource.TYPESTATE: Confidence.MEDIUM,
    EvidenceSource.NEGATIVE_SPACE: Confidence.MEDIUM,
    EvidenceSource.PREFILTER: Confidence.MEDIUM,
    EvidenceSource.LLM_INFERRED: Confidence.LOW,
    EvidenceSource.LLM_SPEC: Confidence.LOW,
    EvidenceSource.LLM_CORROBORATED: Confidence.MEDIUM,
    EvidenceSource.DYNAMIC_SANITIZER: Confidence.HIGH,
    EvidenceSource.DYNAMIC_FRIDA: Confidence.HIGH,
    EvidenceSource.DYNAMIC_CRASH: Confidence.MEDIUM,
    EvidenceSource.DARK_VERIFY: Confidence.HIGH,
    EvidenceSource.COMPILATION: Confidence.MEDIUM,
    EvidenceSource.COMPILER_ANALYZER: Confidence.HIGH,
    # Precondition checks are regex + context-map reachability — real
    # mechanical evidence, but weaker than an engine match: MEDIUM,
    # never HIGH, so precondition-promoted findings grade tool-backed
    # rather than confirmed.
    EvidenceSource.PRECONDITION: Confidence.MEDIUM,
}

VALID_EVIDENCE_TOOLS: frozenset = frozenset({
    "semgrep", "coccinelle", "codeql", "smt", "joern",
    "compiler",
    "compilation", "dynamic:sanitizer", "dynamic:crash", "frida:runtime",
    "dark_verify:confirmed", "dark_verify:refuted",
})

# NOTE: "triage" is deliberately NOT a tool namespace. The triage
# stamps ("triage:batch" from the glance batcher, "triage:classifier"
# from the skip classifier) record which LLM/mechanical shortcut
# produced the verdict — they are provenance, not verification. A
# 500-token batch glance blessed as tool evidence used to short-circuit
# refutation gates, the G2 finding gate, and the promotion alarm.
_TOOL_NAMESPACES = frozenset(VALID_EVIDENCE_TOOLS | {
    "prefilter", "critique", "sweep", "sarif_cache",
    "dynamic", "frida", "dark_verify", "precondition",
    "fail_open", "consistency", "ptr_lifecycle", "lock_region",
    "resource_bounds", "release_order", "protocol_state",
})


# Channel namespaces whose modules own the detection-grade rule-id
# classification (each exports ``is_detection_rule_id``). The channel
# is the single authority for which of its stamps "may not promote
# alone" — consulting it here keeps this firewall from drifting when a
# channel adds a variant (the fail_open/ptr_lifecycle/lock_region
# ``-naming`` stamps passed as full tool evidence for exactly that
# reason).
_DETECTION_CLASSIFIER_MODULES: dict[str, str] = {
    "consistency": "core.audit.peer_evidence",
    "fail_open": "core.audit.fail_open_verify",
    "lock_region": "core.audit.lock_region",
    "ptr_lifecycle": "core.audit.ptr_lifecycle",
    "release_order": "core.audit.release_order",
    "resource_bounds": "core.audit.resource_bounds",
    "protocol_state": "core.audit.protocol_state",
}


@functools.lru_cache(maxsize=None)
def _channel_detection_classifier(namespace: str):
    """The channel's own ``is_detection_rule_id``, or None when the
    channel module is unavailable (fall back to the string heuristics
    below)."""
    mod_name = _DETECTION_CLASSIFIER_MODULES.get(namespace)
    if not mod_name:
        return None
    try:
        mod = importlib.import_module(mod_name)
    except ImportError:
        return None
    return getattr(mod, "is_detection_rule_id", None)


def _is_detection_variant(part: str) -> bool:
    """Detection-role channel stamps (``consistency:*-majority``,
    ``fail_open:*-naming``, ``ptr_lifecycle:*-naming``, ...).

    A majority statistic / uncorroborated-vocabulary premise
    corroborates; it does not convict (the ``git_history``
    epistemology). Such a stamp may ride along in a ``+``-joined
    aggregation receipt, but alone it is NOT tool evidence — a
    ``finding`` carrying only a detection variant trips the promotion
    alarm.
    """
    namespace = part.split(":", 1)[0] if ":" in part else part
    classify = _channel_detection_classifier(namespace)
    if classify is not None:
        try:
            return bool(classify(part))
        except Exception:  # noqa: BLE001 — fall back to string heuristics
            pass
    # String-heuristic fallback for hosts where a channel module is
    # unavailable — mirrors each channel's DETECTION_VARIANT_SUFFIX
    # contract.
    if part.startswith("consistency:") and part.endswith("-majority"):
        return True
    if part.startswith((
        "fail_open:", "ptr_lifecycle:", "lock_region:",
        "resource_bounds:", "release_order:",
    )) and part.endswith("-naming"):
        return True
    # protocol_state: the -unreceipted invariant variant plus the two
    # PERMANENTLY detection-grade lead rule-ids (CWE-563-adjacent /
    # proxy-quality — design §4.3).
    if part.startswith("protocol_state:"):
        return part.endswith("-unreceipted") or part in (
            "protocol_state:dead-state-field",
            "protocol_state:unvalidated-peer-write",
        )
    return False


# Provenance wrappers: prefixes that record HOW a tool receipt was
# earned, wrapped around the receipt itself.  ``clean-refuted:smt`` is
# _promote_clean_refuted's stamp for "the LLM refuted its own
# hypothesis and SMT then confirmed it" — the inner stamp is the
# evidence; the prefix is history.  Unwrapping keeps the promotion
# alarm honest: before this, every clean-refuted promotion (a
# policy-sanctioned, tool-confirmed lane) fired the
# promotion_without_tool_evidence CRITICAL because the wrapper
# namespace was unknown here, drowning the alarm channel that is
# supposed to be EMPTY on legitimate runs.
_PROVENANCE_WRAPPERS = ("clean-refuted:",)


def _is_single_tool_evidence(part: str) -> bool:
    """Check one atomic stamp (no ``+`` separator)."""
    if not part or part == "none":
        return False
    for wrapper in _PROVENANCE_WRAPPERS:
        if part.startswith(wrapper):
            # The wrapper records provenance; the wrapped stamp is the
            # receipt and must qualify on its own merits (a wrapped
            # detection-role variant still may not convict).
            return _is_single_tool_evidence(part[len(wrapper):])
    if _is_detection_variant(part):
        return False
    root = part.split(":")[0] if ":" in part else part
    return root in _TOOL_NAMESPACES or part in _TOOL_NAMESPACES


def is_tool_evidence(stamp: str) -> bool:
    """Return True if *stamp* was set by an actual tool run, not an LLM claim.

    Matches canonical stamps (``"dynamic:sanitizer"``, ``"semgrep"``, etc.),
    namespaced composites (``"semgrep:rule-123"``, ``"critique:prefilter:id"``),
    and ``+``-joined multi-tool stamps (``"semgrep+joern"``).

    Detection-role consistency variants (``consistency:*-majority``)
    qualify only inside a composite that also carries a qualifying
    receipt (the aggregation-promotion shape); alone they are a
    statistical prior, not verification.
    """
    if not stamp or stamp == "none":
        return False
    parts = stamp.split("+") if "+" in stamp else [stamp]
    qualifying = 0
    for p in parts:
        if _is_single_tool_evidence(p):
            qualifying += 1
        elif not _is_detection_variant(p):
            return False
    return qualifying > 0


_LLM_ONLY_EVIDENCE = frozenset({
    "manual", "manual code review", "manual review", "code review",
    "llm", "llm review", "none", "n/a", "",
})

LLM_CLAIM_PREFIX = "llm-claimed:"


def sanitize_llm_evidence_tool(raw: str) -> str:
    """Normalise an evidence_tool value that came from the LLM.

    Values meaning "no tool" collapse to empty string.  Everything else
    is namespaced under ``llm-claimed:`` so it cannot satisfy
    :func:`is_tool_evidence`.  A real receipt overwrites it later via
    ``_stamp_evidence`` once a tool has actually run.
    """
    value = (raw or "").strip()
    if not value or value.lower() in _LLM_ONLY_EVIDENCE:
        return ""
    if value.startswith(LLM_CLAIM_PREFIX):
        return value
    return f"{LLM_CLAIM_PREFIX}{value}"


_RECEIPT_MAP: dict[str, tuple] = {
    "dynamic:sanitizer": (EvidenceSource.DYNAMIC_SANITIZER, "confirmed by dynamic sanitizer"),
    "dynamic:crash": (EvidenceSource.DYNAMIC_CRASH, "non-zero exit without sanitizer confirmation"),
    "frida": (EvidenceSource.DYNAMIC_FRIDA, "confirmed by Frida runtime observation"),
    "joern": (EvidenceSource.JOERN, "confirmed by Joern CPG analysis"),
    "joern:guard-dominance": (
        EvidenceSource.JOERN,
        (
            "no check on the named identifier dominates the sink "
            "(Joern CPG dominator analysis)"
        ),
    ),
    "joern:flow": (
        EvidenceSource.JOERN,
        "source-to-sink dataflow confirmed by Joern reachableByFlows",
    ),
    "semgrep": (EvidenceSource.SEMGREP, "confirmed by Semgrep pattern match"),
    "codeql": (EvidenceSource.CODEQL, "confirmed by CodeQL analysis"),
    "coccinelle": (EvidenceSource.COCCINELLE, "confirmed by Coccinelle"),
    "smt": (EvidenceSource.SMT, "path feasibility confirmed by SMT solver"),
    "dark_verify:confirmed": (EvidenceSource.DARK_VERIFY, "confirmed by executed dark witness"),
    "dark_verify:refuted": (EvidenceSource.DARK_VERIFY, "refuted by executed dark witness"),
    "dark_verify": (EvidenceSource.DARK_VERIFY, "dark verification witness"),
    "compilation": (EvidenceSource.COMPILATION, "confirmed by compilation and execution"),
    "compiler": (EvidenceSource.COMPILER_ANALYZER, "confirmed by compiler static-analyzer diagnostic"),
    "critique": (EvidenceSource.PREFILTER, "confirmed by critique prefilter"),
    # Fail-open channel receipts (per rule-id; the bare namespace
    # covers the -naming detection variants).
    "fail_open:handler-outcome": (
        EvidenceSource.TREE_SITTER,
        (
            "a permissive error handler swallows failures of a "
            "security-role call (role + handler + fallibility receipts)"
        ),
    ),
    "fail_open:ignored-return": (
        EvidenceSource.TREE_SITTER,
        (
            "the return value of a security-role call is neither "
            "assigned nor compared at the flagged site"
        ),
    ),
    "fail_open:tristate": (
        EvidenceSource.TREE_SITTER,
        (
            "the error value of a tri-state security API is accepted "
            "by the comparison shape"
        ),
    ),
    "fail_open:recover-continue": (
        EvidenceSource.TREE_SITTER,
        (
            "a recover()-style handler swallows a security panic and "
            "control continues"
        ),
    ),
    "fail_open:unawaited": (
        EvidenceSource.TREE_SITTER,
        (
            "a security-role async call's rejection is unobserved "
            "(unawaited / empty catch)"
        ),
    ),
    "fail_open": (
        EvidenceSource.TREE_SITTER,
        "fail-open shape confirmed by the handler-outcome channel",
    ),
    # Resource-bounds channel receipts (the bare namespace covers the
    # -naming detection variants riding in aggregation composites).
    "resource_bounds:unbounded-accumulation": (
        EvidenceSource.TREE_SITTER,
        (
            "an accumulation site has no dominating bound witness in "
            "the function or its searched callers (guard walk + "
            "constant-resolution receipts; the searched scope is "
            "named in the receipt)"
        ),
    ),
    "resource_bounds": (
        EvidenceSource.TREE_SITTER,
        (
            "unbounded-accumulation shape confirmed by the "
            "bound-witness comparator"
        ),
    ),
    # Release-order channel receipts (the bare namespace covers the
    # -naming detection variants riding in aggregation composites).
    "release_order:release-before-verify": (
        EvidenceSource.TREE_SITTER,
        (
            "a release site handing data to an escaping destination "
            "is not dominated by the integrity finalizer's status "
            "check (per-site dominator receipts; cfg+joern when the "
            "engines agree)"
        ),
    ),
    "release_order": (
        EvidenceSource.TREE_SITTER,
        (
            "release-before-verify ordering confirmed by the "
            "dominance comparator"
        ),
    ),
    # Protocol-state channel receipts (the bare namespace covers the
    # -unreceipted variant and the detection-grade lead rule-ids
    # riding in aggregation composites).
    "protocol_state:invariant-violated": (
        EvidenceSource.SMT,
        (
            "a study-receipted protocol invariant is violable at a "
            "peer-writable census write site (per-site inductive SMT "
            "receipts with dominating guards encoded)"
        ),
    ),
    "protocol_state": (
        EvidenceSource.TREE_SITTER,
        (
            "protocol-state shape receipted by the field census "
            "(dead-state / unvalidated-peer-write legs)"
        ),
    ),
    # Consistency channel receipts (per dimension; the bare namespace
    # covers the -majority detection variants riding in aggregation
    # composites). Every premise is a deterministic fact: the usage
    # classification is AST, the contract is the target's own header
    # attribute or a receipted learned contract, the majority is
    # reproducible arithmetic.
    "consistency:return-check": (
        EvidenceSource.TREE_SITTER,
        (
            "a return-contract-bearing callee's result is discarded at "
            "the flagged site while the checking siblings exhibit the "
            "convention (census + contract witness receipts)"
        ),
    ),
    "consistency:flag-mode": (
        EvidenceSource.TREE_SITTER,
        (
            "a security-relevant flag/mode argument deviates from the "
            "constant the sibling call sites agree on"
        ),
    ),
    "consistency:cleanup": (
        EvidenceSource.TREE_SITTER,
        (
            "an error path omits the learned release call its sibling "
            "paths perform on the same acquisition"
        ),
    ),
    "consistency:argument-shape": (
        EvidenceSource.TREE_SITTER,
        (
            "a sizeof-over-pointer argument contradicts the declared "
            "type and the buffer-sizing convention of the sibling "
            "call sites (declared-type witness receipts)"
        ),
    ),
    "consistency:sanitize-sink": (
        EvidenceSource.TREE_SITTER,
        (
            "an operator-annotated sink's call site lacks the "
            "dominating sanitizer its sibling sites apply (annotation "
            "convention witness + sanitizing-exhibit receipts)"
        ),
    ),
    "consistency:guard-presence": (
        EvidenceSource.TREE_SITTER,
        (
            "an access site lacks the bounds/null guard its sibling "
            "sites apply and condition_smt proves the unguarded path "
            "feasible (solver witness + caller-walk receipts)"
        ),
    ),
    "consistency:clone-drift": (
        EvidenceSource.TREE_SITTER,
        (
            "a near-clone of a past-security-fix region lacks the "
            "guard the fix added (fix-commit contract witness + "
            "token-containment receipts)"
        ),
    ),
    "consistency": (
        EvidenceSource.TREE_SITTER,
        "peer-majority consistency evidence (PeerEvidence receipts)",
    ),
    # ptr_lifecycle channel receipts (leg B; the bare namespace covers
    # the -naming detection variants riding in aggregation
    # composites). Leg A (field-parity) emits under the consistency
    # namespace by construction and needs no row here.
    "ptr_lifecycle:stale-alias": (
        EvidenceSource.TREE_SITTER,
        (
            "a lifecycle event released the aliased owner with the "
            "alias live and read afterwards (alias edge + event + "
            "invalidation search + post-event read receipts)"
        ),
    ),
    "ptr_lifecycle": (
        EvidenceSource.TREE_SITTER,
        "stale-alias shape confirmed by the ptr_lifecycle census",
    ),
    # lock_region channel receipts (the bare namespace covers the
    # -naming detection variants).
    "lock_region:callback-under-lock": (
        EvidenceSource.TREE_SITTER,
        (
            "a callback-shaped invocation sits between a paired lock "
            "acquire and its release (region + invocation + setter "
            "receipts)"
        ),
    ),
    "lock_region": (
        EvidenceSource.TREE_SITTER,
        "callback-under-lock shape confirmed by the lock_region "
        "channel",
    ),
    "sarif_cache": (EvidenceSource.SEMGREP, "matched prior SARIF result"),
    "precondition": (
        EvidenceSource.PRECONDITION,
        (
            "LLM-stated preconditions mechanically verified in the "
            "vulnerability-supporting direction"
        ),
    ),
}

_CONFIDENCE_PRIORITY: dict[Confidence, int] = {
    Confidence.HIGH: 0,
    Confidence.MEDIUM: 1,
    Confidence.LOW: 2,
}


@dataclass
class GradedEvidence:
    """A single piece of evidence with source attribution and confidence."""

    source: EvidenceSource
    confidence: Confidence
    description: str
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "source": self.source.value,
            "confidence": self.confidence.value,
            "description": self.description,
        }
        if self.detail:
            d["detail"] = self.detail
        return d

    @property
    def priority(self) -> int:
        return _CONFIDENCE_PRIORITY.get(self.confidence, 2)


def default_confidence(source: EvidenceSource) -> Confidence:
    """Return the default confidence for an evidence source."""
    return _SOURCE_CONFIDENCE.get(source, Confidence.LOW)


def grade_evidence(
    source: EvidenceSource,
    description: str,
    *,
    detail: str | None = None,
    confidence_override: Confidence | None = None,
) -> GradedEvidence:
    """Create a graded evidence item."""
    conf = confidence_override or default_confidence(source)
    return GradedEvidence(
        source=source,
        confidence=conf,
        description=description,
        detail=detail,
    )


def finding_confidence(chain: list[GradedEvidence]) -> Confidence:
    """Compute overall confidence for a finding from its evidence chain.

    The finding's confidence is the highest confidence in the chain.
    If the chain has both mechanical and LLM evidence pointing at the
    same issue, the LLM evidence upgrades to MEDIUM (corroborated).
    """
    if not chain:
        return Confidence.LOW

    has_mechanical = any(
        e.source.value.startswith("mechanical:")
        or e.source.value.startswith("dynamic:")
        for e in chain
    )
    has_llm = any(
        e.source.value.startswith("llm:")
        for e in chain
    )

    best = Confidence.LOW
    for e in chain:
        conf = e.confidence
        if has_mechanical and has_llm and conf == Confidence.LOW:
            conf = Confidence.MEDIUM
        if _CONFIDENCE_PRIORITY[conf] < _CONFIDENCE_PRIORITY[best]:
            best = conf
    return best


def grade_evidence_record(record: Any) -> list[GradedEvidence]:
    """Convert an EvidenceRecord into a list of GradedEvidence items.

    Maps each populated field of the existing EvidenceRecord to graded
    evidence with appropriate source tags.
    """
    items: list[GradedEvidence] = []

    if getattr(record, "taint_approx", None) is not None:
        approx = record.taint_approx
        df = approx.get("dangerous_flows", {}) if isinstance(approx, dict) else getattr(approx, "dangerous_flows", {})
        if df:
            items.append(grade_evidence(
                EvidenceSource.TAINT_APPROX,
                f"{len(df)} tainted parameter flows",
            ))

    if getattr(record, "taint_summary", None) is not None:
        items.append(grade_evidence(
            EvidenceSource.TAINT_APPROX,
            "CFG path-sensitive taint flow",
        ))

    flows = getattr(record, "joern_flows", [])
    if flows:
        items.append(grade_evidence(
            EvidenceSource.JOERN,
            f"{len(flows)} Joern CPG flows",
        ))

    imported = getattr(record, "imported_joern_flows", [])
    if imported:
        items.append(grade_evidence(
            EvidenceSource.JOERN,
            f"{len(imported)} imported Joern flows",
        ))

    unguarded = getattr(record, "joern_unguarded_sinks", [])
    if unguarded:
        items.append(grade_evidence(
            EvidenceSource.JOERN,
            f"{len(unguarded)} unguarded sinks",
        ))

    codeql = getattr(record, "codeql_alerts", [])
    if codeql:
        items.append(grade_evidence(
            EvidenceSource.CODEQL,
            f"{len(codeql)} CodeQL alerts",
        ))

    semgrep = getattr(record, "semgrep_hits", [])
    if semgrep:
        items.append(grade_evidence(
            EvidenceSource.SEMGREP,
            f"{len(semgrep)} Semgrep matches",
        ))

    if getattr(record, "negative_space", None):
        ns = record.negative_space
        items.append(grade_evidence(
            EvidenceSource.NEGATIVE_SPACE,
            f"{len(ns)} convention deviations from sibling functions",
        ))

    if getattr(record, "sink_unreachable", False):
        items.append(grade_evidence(
            EvidenceSource.CALL_GRAPH,
            "sink unreachable from entry points",
        ))

    if getattr(record, "binary_sink_edges", None):
        items.append(grade_evidence(
            EvidenceSource.BINARY_ORACLE,
            f"{len(record.binary_sink_edges)} binary call edges to sinks",
        ))

    sink_args = getattr(record, "joern_sink_args", [])
    if sink_args:
        items.append(grade_evidence(
            EvidenceSource.JOERN,
            f"{len(sink_args)} sink argument flows",
        ))

    if getattr(record, "context_map_sink", None) is not None:
        items.append(grade_evidence(
            EvidenceSource.CALL_GRAPH,
            "context-map sink match",
        ))

    if getattr(record, "transitive_taint", None) is not None:
        items.append(grade_evidence(
            EvidenceSource.TAINT_APPROX,
            "transitive taint propagation",
        ))

    if getattr(record, "prefilter", None) is not None:
        items.append(grade_evidence(
            EvidenceSource.PREFILTER,
            "prefilter match",
        ))

    app_sinks = getattr(record, "app_sink_targets", [])
    if app_sinks:
        items.append(grade_evidence(
            EvidenceSource.CALL_GRAPH,
            f"{len(app_sinks)} application sink targets",
        ))

    sanitizers = getattr(record, "sanitizer_calls", [])
    if sanitizers:
        items.append(grade_evidence(
            EvidenceSource.TAINT_APPROX,
            f"{len(sanitizers)} sanitizer calls",
        ))

    if getattr(record, "binary_surface_category", None):
        items.append(grade_evidence(
            EvidenceSource.BINARY_ORACLE,
            f"surface category: {record.binary_surface_category}",
        ))

    if getattr(record, "binary_parser_boundary", False):
        items.append(grade_evidence(
            EvidenceSource.BINARY_ORACLE,
            "parser boundary function",
        ))

    layer0 = getattr(record, "binary_layer0_findings", [])
    if layer0:
        items.append(grade_evidence(
            EvidenceSource.BINARY_ORACLE,
            f"{len(layer0)} layer-0 binary findings",
        ))

    return items


def grade_review_result(
    review_result: dict[str, Any] | None,
    evidence_tool: str = "",
) -> list[GradedEvidence]:
    """Extract graded evidence from an LLM review result."""
    items: list[GradedEvidence] = []

    rr = review_result or {}

    hypothesis = rr.get("hypothesis", "")
    if hypothesis:
        items.append(grade_evidence(
            EvidenceSource.LLM_INFERRED,
            hypothesis[:200],
        ))

    spec_dev = rr.get("spec_deviation")
    if spec_dev and spec_dev.get("deviation"):
        items.append(grade_evidence(
            EvidenceSource.LLM_SPEC,
            f"spec deviation: {spec_dev['deviation'][:150]}",
        ))

    ts_viol = rr.get("typestate_violation")
    if ts_viol and ts_viol.get("confirmed"):
        items.append(grade_evidence(
            EvidenceSource.TYPESTATE,
            f"{ts_viol.get('violation_kind', 'violation')} on {ts_viol.get('type_name', '?')}",
            confidence_override=Confidence.HIGH,
        ))

    if evidence_tool and is_tool_evidence(evidence_tool):
        parts = evidence_tool.split("+") if "+" in evidence_tool else [evidence_tool]
        seen: set = set()
        for part in parts:
            namespace = part.split(":")[0] if ":" in part else part
            entry = _RECEIPT_MAP.get(part) or _RECEIPT_MAP.get(namespace)
            if entry and entry[0] not in seen:
                seen.add(entry[0])
                source, description = entry
                items.append(grade_evidence(source, description))

    return items


def format_evidence_chain(chain: list[GradedEvidence]) -> str:
    """Render an evidence chain as human-readable text."""
    if not chain:
        return ""

    lines = ["### Evidence chain"]
    for e in sorted(chain, key=lambda x: x.priority):
        tag = e.source.value.split(":")[-1]
        conf = e.confidence.value.upper()
        lines.append(f"- [{conf}] ({tag}) {e.description}")
        if e.detail:
            lines.append(f"  {e.detail}")
    return "\n".join(lines)
