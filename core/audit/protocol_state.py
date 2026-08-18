"""Protocol-state verification channel (CWE-372) — honesty-constrained.

Target class (the ACK-of-unsent shape): a protocol state variable is
updated from a peer-supplied value without validation against
locally-authoritative state (``largest_acked_pkt`` set from the
decoded ACK frame, never compared against ``highest_sent``;
``highest_sent`` itself written and read nowhere).

**What is mechanically verifiable, with receipts:**

1. *Written-never-read state fields* — from the field index (writes >
   0, reads = 0 target-wide). NOT a vulnerability; evidence that a
   defence the author began was never wired into validation.
   Permanently detection-grade (``protocol_state:dead-state-field``,
   CWE-563-adjacent).
2. *Unvalidated peer-sourced state writes* — a state-field write whose
   rhs provenance traces to a decode/parse source with no dominating
   guard mentioning a sibling field of the same object. Receipt-backed
   but a weak proxy (validation can be non-comparative), so
   permanently detection-grade
   (``protocol_state:unvalidated-peer-write``).
3. *Invariant preservation/violation at write sites* — the
   census-driven multi-site extension of :mod:`core.audit.
   invariant_smt` (:func:`~core.audit.invariant_smt.
   check_site_preservation`): every write site of every invariant
   identifier, across functions, gets one inductive step with
   polarity-resolved dominating guards as pre-conditions. Real
   verification — but only of *preservation of a stated invariant*.

**What is NOT mechanically verifiable — and is not claimed:** that the
protocol *requires* the invariant (RFC knowledge). The invariant
premise is study/LLM knowledge; the machine checks consequences,
never the premise. Grade accordingly:

* ``protocol_state:invariant-violated`` (registry, promote-capable)
  ONLY when (a) the invariant's provenance is study-receipted or
  operator-annotated (provenance ≠ ``llm_prior``, receipt present —
  the DomainVocabulary provenance rule applied to invariants) AND (b)
  SMT says violable with a model at a peer-writable site (the leg-2
  taint witness on that site).
* An LLM-stated invariant, or a violation without the peer-write
  witness, confirms only under the ``-unreceipted`` detection variant
  — an uncorroborated premise may aggregate but never promote alone.
* Legs 1+2 share the single ``protocol_state`` namespace with leg 3 —
  two of them can never satisfy the two-independent-namespaces
  aggregation rule by themselves (the self-corroboration firewall).

The channel-local field index rides regex extraction (the
``lifecycle_collector.collect_field_sites_from_source`` shape) plus
per-function attribution; when the shared field census
(``core/audit/field_census.py``, phase A of this programme) lands, it
supplies the same records with rhs-provenance tiers — fields only
added, this module's consumers read dicts. Guard-dependent verdicts
report ``census-degraded`` when the CFG leg is unavailable rather
than guessing. No LLM calls, no subprocesses.
"""

from __future__ import annotations

import json
import logging
import re
import time
# `field` is a receipt attribute name on StateEvidence (§4.2), so the
# dataclasses helper is imported under an alias.
from dataclasses import dataclass
from dataclasses import field as dc_field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

RULE_INVARIANT_VIOLATED = "protocol_state:invariant-violated"
DETECTION_VARIANT_SUFFIX = "-unreceipted"
RULE_INVARIANT_UNRECEIPTED = (
    RULE_INVARIANT_VIOLATED + DETECTION_VARIANT_SUFFIX
)
RULE_DEAD_STATE = "protocol_state:dead-state-field"
RULE_PEER_WRITE = "protocol_state:unvalidated-peer-write"

# Permanently detection-grade rule-ids (leads legs + the
# uncorroborated-premise variant). They aggregate, never promote
# alone; all share ONE namespace by design.
_DETECTION_RULE_IDS = frozenset({
    RULE_INVARIANT_UNRECEIPTED, RULE_DEAD_STATE, RULE_PEER_WRITE,
})

PROTOCOL_STATE_CWES = frozenset({"CWE-372"})
DEAD_STATE_LEAD_CWE = "CWE-563"

# Enumerated inconclusive reasons (each a distinct tested string).
REASON_INVARIANT_UNSTATED = "invariant-unstated"
REASON_INVARIANT_OUT_OF_SCOPE = "invariant-out-of-scope"
REASON_AUTHORITY_UNRESOLVED = "authority-unresolved"
REASON_CENSUS_DEGRADED = "census-degraded"
REASON_Z3_UNAVAILABLE = "z3-unavailable"
REASON_HYPOTHESIS_UNBINDABLE = "hypothesis-unbindable"

INCONCLUSIVE_REASONS = frozenset({
    REASON_INVARIANT_UNSTATED,
    REASON_INVARIANT_OUT_OF_SCOPE,
    REASON_AUTHORITY_UNRESOLVED,
    REASON_CENSUS_DEGRADED,
    REASON_Z3_UNAVAILABLE,
    REASON_HYPOTHESIS_UNBINDABLE,
})

# Cost bounds (§4.6).
MAX_SITES_PER_INVARIANT = 40
INVARIANT_BUDGET_S = 15.0
MAX_DEAD_STATE_LEADS = 20
MAX_PEER_WRITE_LEADS = 20
MAX_LEADS_PER_FILE = 3
MAX_CENSUS_FIELDS = 500
MAX_SITES_PER_FIELD = 200

_SOURCE_SUFFIXES = (".c", ".h", ".cc", ".cpp", ".cxx", ".hpp")

# Hypothesis prose shapes (§4.5).
_PROTOCOL_STATE_HYPOTHESIS_RE = re.compile(
    r"(?:(?:protocol|state)\s+(?:invariant|machine)"
    r"|never\s+sent|not\s+(?:previously\s+)?sent"
    r"|out.of.window|monoton"
    r"|acknowledg\w+.{0,40}(?:unsent|never|higher\s+than)"
    r"|peer.{0,40}(?:controls?|sets?|poisons?).{0,30}"
    r"(?:state|counter|sequence|window))",
    re.IGNORECASE | re.DOTALL,
)

# Protocol-state identifier stems — the dispatch-time gate that gives
# this channel precedence over the single-function smt_invariant chain
# for state-field invariants while local buffer invariants
# (obuf_len <= obuf_size) keep routing to smt_invariant (§4.5).
_STATE_STEM_RE = re.compile(
    r"(?:^|_)(?:seq|seqno|ack|acked|sent|recv|rcvd|window|epoch|"
    r"state|pkt|packet|frame|handshake|largest|highest|next|last)"
    r"(?:_|$)",
    re.IGNORECASE,
)

# Peer-sourced rhs provenance: decode/parse call stems.
_DECODER_STEM_RE = re.compile(
    r"(?:ntoh|decode|parse|deserial|unpack|read_|get_u|recv|extract)",
    re.IGNORECASE,
)

_FIELD_ACCESS_RE = re.compile(
    r"([A-Za-z_]\w*)\s*(?:->|\.)\s*([A-Za-z_]\w*)",
)
_WRITE_TAIL_RE = re.compile(r"^\s*(\+\+|--|(?:[+\-|&^]|<<|>>)?=(?!=))")
_BACKTICK_IDENT_RE = re.compile(r"`([A-Za-z_][\w.]*)\s*(?:\(\s*\))?`")
_IDENT_RE = re.compile(r"\b([A-Za-z_]\w{2,})\b")
_COND_LABEL_RE = re.compile(r"^(?:If|While|ElIf)\s*\((.+)\)$",
                            re.IGNORECASE)


def is_protocol_state_hypothesis(text: str) -> bool:
    """True when the hypothesis matches a protocol-state prose shape
    or states a parseable invariant over state-stemmed identifiers."""
    fires, _inv = classify_protocol_state_hypothesis(text)
    return fires


def classify_protocol_state_hypothesis(
    text: str,
) -> tuple[bool, str | None]:
    """``(fires, invariant)`` — ``invariant`` is set when the text
    contains a linear comparison whose sides both carry
    protocol-state-stemmed identifiers (that invariant then routes to
    the census-driven multi-site harness INSTEAD of the
    single-function ``smt_invariant`` chain — the precedence rule)."""
    if not text:
        return False, None
    invariant = None
    try:
        from .invariant_smt import extract_invariants
        for cand in extract_invariants(text):
            m = re.search(r"(<=|>=|==|!=|<|>)", cand)
            if not m:
                continue
            sides = (cand[:m.start()], cand[m.end():])
            if all(
                any(
                    _STATE_STEM_RE.search(ident)
                    for ident in re.findall(r"[A-Za-z_]\w*", side)
                )
                for side in sides
            ):
                invariant = cand
                break
    except ImportError:
        pass
    prose = bool(_PROTOCOL_STATE_HYPOTHESIS_RE.search(text))
    return prose or invariant is not None, invariant


def protocol_state_applicable(cwe: str) -> bool:
    norm = (cwe or "").upper().strip()
    if norm and not norm.startswith("CWE-"):
        norm = f"CWE-{norm}"
    return norm in PROTOCOL_STATE_CWES


def is_detection_rule_id(rule_id: str) -> bool:
    """True for the permanently-detection-grade rule-ids (both lead
    legs) and the ``-unreceipted`` variant: aggregation-only, never
    promote-alone."""
    return rule_id in _DETECTION_RULE_IDS or (
        rule_id.startswith("protocol_state:")
        and rule_id.endswith(DETECTION_VARIANT_SUFFIX)
    )


@dataclass
class StateEvidence:
    """Aggregate channel verdict for one protocol-state hypothesis."""

    outcome: str                 # confirmed | refuted | inconclusive
    reason: str
    rule_id: str = RULE_INVARIANT_VIOLATED
    field: dict[str, Any] | None = None
    dead_state: dict[str, Any] | None = None
    peer_write: dict[str, Any] | None = None
    invariant: dict[str, Any] | None = None
    reachability: dict[str, Any] | None = None
    corroboration: list[Any] = dc_field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "outcome": self.outcome,
            "reason": self.reason,
            "rule_id": self.rule_id,
        }
        for key in ("field", "dead_state", "peer_write", "invariant",
                    "reachability"):
            val = getattr(self, key)
            if val is not None:
                d[key] = val
        if self.corroboration:
            d["corroboration"] = [
                c.to_dict() if hasattr(c, "to_dict") else c
                for c in self.corroboration
            ]
        return d


def _inconclusive(reason: str, detail: str = "") -> StateEvidence:
    return StateEvidence(
        outcome="inconclusive",
        reason=f"{reason}: {detail}" if detail else reason,
    )


# ── learned protocol-state vocabulary (channel-local parsing) ───────


def learned_state_fields(
    domain_model: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Entries from the optional ``state_fields`` domain-model key
    ({field, struct, authority: local|peer|derived, monotonic,
    invariant_refs, provenance, receipt}) — parsed channel-locally,
    ``llm_prior`` excluded (the DomainVocabulary provenance rule)."""
    out: dict[str, dict[str, Any]] = {}
    for entry in (domain_model or {}).get("state_fields") or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("field") or "").strip()
        if not name:
            continue
        if str(entry.get("provenance") or "") == "llm_prior":
            continue
        out[name] = entry
    return out


def _invariant_receipt(
    domain_model: dict[str, Any] | None,
    invariant: str,
) -> dict[str, Any] | None:
    """The honesty gate's premise check: find a domain-model
    ``Invariant`` whose statement carries this comparison with a
    non-``llm_prior`` provenance AND a receipt. Returns the matching
    entry (provenance chain embedded verbatim in the evidence) or
    ``None`` — in which case only the ``-unreceipted`` detection
    variant may confirm."""
    norm = re.sub(r"\s+", "", invariant)
    for entry in (domain_model or {}).get("invariants") or []:
        if not isinstance(entry, dict):
            continue
        statement = str(entry.get("statement") or "")
        if norm not in re.sub(r"\s+", "", statement):
            continue
        provenance = str(entry.get("provenance") or "")
        if provenance in ("", "llm_prior"):
            continue
        if not entry.get("receipt"):
            continue
        return entry
    return None


# ── channel-local field index ───────────────────────────────────────


def build_state_field_index(
    source_texts: dict[str, str],
) -> dict[str, Any]:
    """Whole-source-set index of struct-field write/read sites with
    rhs provenance classes — ``{"fields": {name: {"writes": [...],
    "reads": [...]}}, "tier": ..., "skipped": bool}``.

    Site record: ``{file, line, function, code, base, field,
    rhs_class, rhs}`` with ``rhs_class`` ∈ from_param /
    from_call:<callee> / from_field:<field> / from_local:<name> /
    literal_null / literal_const / unknown."""
    from .resource_bounds import _c_function_spans

    fields: dict[str, dict[str, list[dict[str, Any]]]] = {}
    skipped = False

    for fp, source in sorted(source_texts.items()):
        if not fp.endswith(_SOURCE_SUFFIXES):
            continue
        spans = _c_function_spans(source)

        def _function_at(line: int) -> tuple[str, tuple[str, ...]]:
            for name, start, end in spans:
                if start <= line <= end:
                    return name, ()
            return "", ()

        for line_no, raw in enumerate(source.splitlines(), start=1):
            code = raw.split("//", 1)[0]
            for m in _FIELD_ACCESS_RE.finditer(code):
                base, fld = m.group(1), m.group(2)
                if len(fields) >= MAX_CENSUS_FIELDS and fld not in fields:
                    skipped = True
                    continue
                bucket = fields.setdefault(
                    fld, {"writes": [], "reads": []},
                )
                tail = code[m.end():]
                wm = _WRITE_TAIL_RE.match(tail)
                func, _params = _function_at(line_no)
                site: dict[str, Any] = {
                    "file": fp,
                    "line": line_no,
                    "function": func,
                    "code": raw.strip()[:200],
                    "base": base,
                    "field": fld,
                }
                if wm:
                    kind = "writes"
                    op = wm.group(1)
                    rhs = tail[wm.end():].split(";", 1)[0].strip()
                    site["rhs"] = rhs[:200]
                    site["rhs_class"] = (
                        "unknown" if op in ("++", "--")
                        else _classify_rhs(rhs)
                    )
                    if op != "=":
                        # Compound assignment reads the field too.
                        ro = dict(site)
                        ro.pop("rhs", None)
                        ro.pop("rhs_class", None)
                        if len(bucket["reads"]) < MAX_SITES_PER_FIELD:
                            bucket["reads"].append(ro)
                else:
                    kind = "reads"
                if len(bucket[kind]) >= MAX_SITES_PER_FIELD:
                    skipped = True
                    continue
                bucket[kind].append(site)

    return {"fields": fields, "tier": "regex", "skipped": skipped}


def _classify_rhs(rhs: str) -> str:
    rhs = rhs.strip()
    if not rhs:
        return "unknown"
    if rhs in ("NULL", "nullptr", "0", "NULL;"):
        return "literal_null" if not rhs.rstrip(";").isdigit() \
            else "literal_const"
    if re.fullmatch(r"\d+[uUlL]*", rhs.rstrip(";")):
        return "literal_const"
    m = re.match(r"([A-Za-z_]\w*)\s*\(", rhs)
    if m:
        return f"from_call:{m.group(1)}"
    m = _FIELD_ACCESS_RE.match(rhs)
    if m:
        return f"from_field:{m.group(2)}"
    m = re.fullmatch(r"([A-Za-z_]\w*)", rhs.rstrip(";").strip())
    if m:
        return f"from_local:{m.group(1)}"
    return "unknown"


def _local_call_sources(source: str, span: tuple[int, int] | None,
                        ) -> dict[str, str]:
    """One-hop local provenance: ``v = decode_ack_largest(frame)``
    → ``{"v": "decode_ack_largest"}`` within the function span."""
    lines = source.splitlines()
    seg = lines[span[0] - 1:span[1]] if span else lines
    out: dict[str, str] = {}
    assign_re = re.compile(
        r"\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*\(",
    )
    for raw in seg:
        for m in assign_re.finditer(raw.split("//", 1)[0]):
            out[m.group(1)] = m.group(2)
    return out


def _peer_source_chain(
    site: dict[str, Any],
    source_texts: dict[str, str],
    state_vocab: dict[str, dict[str, Any]],
) -> str | None:
    """Peer-provenance witness for a write site: a decoder-stem rhs
    call (directly or via a one-hop local), or a learned
    ``state_fields`` entry declaring the field peer-authoritative."""
    vocab_entry = state_vocab.get(site["field"])
    if vocab_entry and str(vocab_entry.get("authority")) == "peer":
        return f"state_fields:{site['field']}:authority=peer"
    rhs_class = str(site.get("rhs_class") or "")
    if rhs_class.startswith("from_call:"):
        callee = rhs_class.split(":", 1)[1]
        if _DECODER_STEM_RE.search(callee):
            return rhs_class
        return None
    if rhs_class.startswith("from_local:"):
        local = rhs_class.split(":", 1)[1]
        source = source_texts.get(site["file"], "")
        try:
            from .fail_open_lang import c_function_span
            span = c_function_span(source, site["function"],
                                   language="c")
        except ImportError:
            span = None
        callee = _local_call_sources(source, span).get(local, "")
        if callee and _DECODER_STEM_RE.search(callee):
            return f"from_call:{callee} via {local}"
    return None


# ── CFG guard extraction with branch polarity ───────────────────────


def _branch_guards(
    source: str,
    function_name: str,
    line: int,
) -> list[str] | None:
    """Polarity-resolved dominating conditions at *line* — the
    census-driven pre-conditions for the per-site inductive step.

    A condition node's constraint applies as stated only when the site
    is dominated by the condition's single-predecessor TRUE successor;
    negated (via :func:`invariant_smt.negate_comparison`) when
    dominated by the FALSE successor. Undecidable polarity ⇒ the guard
    is dropped (never a wrong-polarity guess); dropping only ever
    widens violability, the claim direction the honesty gate already
    caps. ``None`` = CFG unavailable."""
    try:
        from core.analysis.cfg_builder_cpp import build_cpp_intraproc_cfg
        from core.analysis.cfg_utils import find_node_at_line
        from core.analysis.dominators import build_dom_tree
    except ImportError:
        return None
    tail = function_name.rsplit(".", 1)[-1]
    try:
        cfg = build_cpp_intraproc_cfg(source, tail, language="c")
        if cfg is None:
            return None
        dom = build_dom_tree(cfg)
        site_node = find_node_at_line(cfg, line)
        if site_node is None:
            return []
        preds: dict[Any, list[Any]] = {}
        for node in cfg.nodes():
            for succ in cfg.successors(node):
                preds.setdefault(succ, []).append(node)
        conditions: list[str] = []
        from .invariant_smt import negate_comparison
        for d in dom.dominators_of(site_node):
            m = _COND_LABEL_RE.match((d.label or "").strip())
            if not m:
                continue
            cond = m.group(1).strip()
            succs = list(cfg.successors(d))
            if len(succs) != 2:
                continue
            for succ, polarity in ((succs[0], True), (succs[1], False)):
                if succ is site_node or (
                    len(preds.get(succ, [])) == 1
                    and dom.dominates(succ, site_node)
                ):
                    if polarity:
                        conditions.append(cond)
                    else:
                        neg = negate_comparison(cond)
                        if neg is not None:
                            conditions.append(neg)
                    break
        return conditions
    except Exception:
        logger.debug("protocol_state: branch guard walk failed",
                     exc_info=True)
        return None


def _bare_fields(text: str, names: set[str]) -> str:
    """Normalise ``base->field`` / ``base.field`` chains to bare field
    names for every invariant identifier, so site code and guards
    speak the invariant's vocabulary."""
    out = text
    for name in sorted(names, key=len, reverse=True):
        out = re.sub(
            rf"(?:[A-Za-z_]\w*\s*(?:->|\.)\s*)+({re.escape(name)})\b",
            r"\1", out,
        )
    return out


# ── leg 3: census-driven multi-site invariant harness ───────────────


def _invariant_variables(invariant: str) -> set[str]:
    return {
        ident for ident in re.findall(r"[A-Za-z_]\w*", invariant)
        if not ident.isdigit()
    }


def check_invariant_multi_site(
    invariant: str,
    index: dict[str, Any],
    source_texts: dict[str, str],
    *,
    max_sites: int = MAX_SITES_PER_INVARIANT,
    budget_s: float = INVARIANT_BUDGET_S,
) -> dict[str, Any]:
    """Every census write site of every invariant identifier, across
    functions, gets the existing inductive step
    (:func:`invariant_smt.check_site_preservation`) with
    polarity-resolved dominating guards. Returns ``{outcome, sites,
    reason, guard_leg}`` — ``outcome`` ∈ violable | preserved |
    inconclusive; ``guard_leg`` is False when the CFG leg was
    unavailable (a violable outcome then may NOT confirm:
    ``census-degraded``)."""
    t0 = time.monotonic()
    variables = _invariant_variables(invariant)
    fields = index.get("fields") or {}
    sites: list[dict[str, Any]] = []
    for var in sorted(variables):
        for site in (fields.get(var) or {}).get("writes") or []:
            sites.append(site)
            if len(sites) >= max_sites:
                break
        if len(sites) >= max_sites:
            break

    if not sites:
        return {
            "outcome": "preserved",
            "sites": [],
            "reason": (
                "no census write site mutates an invariant variable "
                "(vacuously preserved; base case not checked)"
            ),
            "guard_leg": True,
        }

    from .invariant_smt import check_site_preservation

    guard_leg = True
    per_site: list[dict[str, Any]] = []
    skipped = 0
    for site in sites:
        if time.monotonic() - t0 > budget_s:
            skipped += 1
            continue
        source = source_texts.get(site["file"], "")
        guards = _branch_guards(source, site["function"], site["line"]) \
            if site["function"] else []
        if guards is None:
            guard_leg = False
            guards = []
        bare_guards = tuple(
            _bare_fields(g, variables) for g in guards
            if any(v in _bare_fields(g, variables) for v in variables)
        )
        code = _bare_fields(site["code"], variables)
        res = check_site_preservation(
            invariant, code,
            line=site["line"],
            pre_conditions=bare_guards,
        )
        entry = res.to_dict()
        entry["file"] = site["file"]
        entry["function"] = site["function"]
        entry["rhs_class"] = site.get("rhs_class", "")
        entry["guards_applied"] = list(bare_guards)
        per_site.append(entry)

    verdicts = {e["verdict"] for e in per_site}
    if any(e["verdict"] == "unknown" and "z3" in (e.get("reason") or "")
           for e in per_site):
        outcome, reason = "inconclusive", "z3 unavailable"
    elif "violable" in verdicts:
        outcome = "violable"
        reason = (
            "at least one census write site can break the invariant "
            "(inductive step, dominating guards encoded)"
        )
    elif verdicts <= {"preserved", "preserved_nonneg"}:
        outcome = "preserved"
        reason = (
            f"all {len(per_site)} census write site(s) preserve the "
            "invariant (inductive step; base case not checked)"
        )
    else:
        outcome = "inconclusive"
        undecided = [
            f"{e['file']}:{e['line']} {e.get('reason') or e['verdict']}"
            for e in per_site
            if e["verdict"] in ("unknown", "out_of_scope")
        ]
        reason = "undecided sites — " + "; ".join(undecided[:4])
    if skipped:
        reason += f" ({skipped} site(s) skipped on budget)"
    return {
        "outcome": outcome,
        "sites": per_site,
        "reason": reason,
        "guard_leg": guard_leg,
    }


# ── channel entry points ────────────────────────────────────────────


def _entry_reachability(
    context: Any,
    inventory: dict[str, Any] | None,
    file_path: str,
    function_name: str,
) -> dict[str, Any] | None:
    try:
        from .fail_open_verify import _entry_reachability as _fo_reach
    except ImportError:
        return None
    try:
        return _fo_reach(context, inventory, file_path, function_name)
    except Exception:
        logger.debug("protocol_state: reachability escalator failed",
                     exc_info=True)
        return None


def _sibling_fields(
    index: dict[str, Any], base: str, function: str, fld: str,
) -> set[str]:
    """Fields accessed on the same base identifier anywhere in the
    index (the struct-membership approximation) minus the written
    field itself."""
    siblings: set[str] = set()
    for name, bucket in (index.get("fields") or {}).items():
        if name == fld:
            continue
        for site in bucket.get("writes", []) + bucket.get("reads", []):
            if site.get("base") == base:
                siblings.add(name)
                break
    return siblings


def _peer_write_verdict(
    site: dict[str, Any],
    index: dict[str, Any],
    source_texts: dict[str, str],
    state_vocab: dict[str, dict[str, Any]],
) -> tuple[str, dict[str, Any]]:
    """Leg 2 for one write site: ``("confirmed"|"refuted"|
    "census-degraded"|"not-peer", receipt)``."""
    chain = _peer_source_chain(site, source_texts, state_vocab)
    if chain is None:
        return "not-peer", {}
    source = source_texts.get(site["file"], "")
    guards = _branch_guards(source, site["function"], site["line"]) \
        if site["function"] else []
    if guards is None:
        return "census-degraded", {}
    siblings = _sibling_fields(
        index, site["base"], site["function"], site["field"],
    )
    validating = [
        g for g in guards
        if any(re.search(rf"\b{re.escape(s)}\b", g) for s in siblings)
    ]
    receipt = {
        "site": {k: site[k] for k in
                 ("file", "line", "function", "code")},
        "source_chain": chain,
        "guard_conjunction": guards,
        "sibling_fields": sorted(siblings),
    }
    if validating:
        receipt["validating_guard"] = validating[0]
        return "refuted", receipt
    return "confirmed", receipt


def _adjudicate_invariant(
    invariant: str,
    index: dict[str, Any],
    source_texts: dict[str, str],
    domain_model: dict[str, Any] | None,
    state_vocab: dict[str, dict[str, Any]],
    *,
    context: Any = None,
    inventory: dict[str, Any] | None = None,
    budget_s: float = INVARIANT_BUDGET_S,
) -> StateEvidence:
    try:
        import z3  # noqa: F401
    except ImportError:
        return _inconclusive(
            REASON_Z3_UNAVAILABLE, "pip install z3-solver",
        )

    multi = check_invariant_multi_site(
        invariant, index, source_texts, budget_s=budget_s,
    )
    receipt_entry = _invariant_receipt(domain_model, invariant)
    inv_receipt: dict[str, Any] = {
        "statement": invariant,
        "provenance": (
            str(receipt_entry.get("provenance"))
            if receipt_entry else "llm_stated"
        ),
        # The study receipt embedded verbatim (who asserted the
        # invariant and with what evidence) — or None.
        "receipt": receipt_entry.get("receipt") if receipt_entry else None,
        "per_site": multi["sites"],
    }

    if multi["outcome"] == "preserved":
        return StateEvidence(
            outcome="refuted",
            reason=multi["reason"],
            invariant=inv_receipt,
        )
    if multi["outcome"] == "inconclusive":
        if "z3" in multi["reason"]:
            return StateEvidence(
                outcome="inconclusive",
                reason=f"{REASON_Z3_UNAVAILABLE}: pip install z3-solver",
                invariant=inv_receipt,
            )
        if all(
            e["verdict"] == "out_of_scope" for e in multi["sites"]
        ) and multi["sites"]:
            return StateEvidence(
                outcome="inconclusive",
                reason=(
                    f"{REASON_INVARIANT_OUT_OF_SCOPE}: "
                    f"{multi['reason']}"
                ),
                invariant=inv_receipt,
            )
        return StateEvidence(
            outcome="inconclusive",
            reason=f"{REASON_INVARIANT_OUT_OF_SCOPE}: {multi['reason']}",
            invariant=inv_receipt,
        )

    # violable — the honesty gate decides the grade.
    if not multi["guard_leg"]:
        return StateEvidence(
            outcome="inconclusive",
            reason=(
                f"{REASON_CENSUS_DEGRADED}: a violable site exists but "
                "the CFG guard leg was unavailable — a dominating "
                "validation could be invisible; not confirming on a "
                "partial census"
            ),
            invariant=inv_receipt,
        )
    violable_sites = [
        e for e in multi["sites"] if e["verdict"] == "violable"
    ]
    peer_receipt: dict[str, Any] | None = None
    peer_site: dict[str, Any] | None = None
    for entry in violable_sites:
        fields = index.get("fields") or {}
        for site in (fields.get(_site_field(entry, fields)) or
                     {}).get("writes") or []:
            if (site["file"], site["line"]) == (entry["file"],
                                                entry["line"]):
                verdict, receipt = _peer_write_verdict(
                    site, index, source_texts, state_vocab,
                )
                if verdict == "confirmed":
                    peer_receipt, peer_site = receipt, site
                break
        if peer_receipt:
            break

    receipted = receipt_entry is not None
    first = violable_sites[0]
    if receipted and peer_receipt is not None:
        rule_id = RULE_INVARIANT_VIOLATED
        grade_note = (
            "study-receipted invariant, peer-write witness at the "
            "violable site"
        )
    else:
        rule_id = RULE_INVARIANT_UNRECEIPTED
        missing = []
        if not receipted:
            missing.append("invariant premise is LLM-stated "
                           "(no study receipt)")
        if peer_receipt is None:
            missing.append("no peer-write witness at a violable site")
        grade_note = "detection-grade: " + "; ".join(missing)

    result = StateEvidence(
        outcome="confirmed",
        reason=(
            f"SMT model breaks `{invariant}` at "
            f"{first['file']}:{first['line']} ({first['code']}) — "
            f"{grade_note}"
        ),
        rule_id=rule_id,
        invariant=inv_receipt,
        peer_write=peer_receipt,
    )
    if peer_site is not None:
        result.field = {
            "struct": "",
            "name": peer_site["field"],
            "authority": str(
                (state_vocab.get(peer_site["field"]) or {})
                .get("authority") or "unresolved",
            ),
            "provenance": str(
                (state_vocab.get(peer_site["field"]) or {})
                .get("provenance") or "",
            ),
        }
        result.reachability = _entry_reachability(
            context, inventory, peer_site["file"], peer_site["function"],
        )
    return result


def _site_field(entry: dict[str, Any],
                fields: dict[str, Any]) -> str:
    """Recover which census field a per-site entry belongs to."""
    for name, bucket in fields.items():
        for site in bucket.get("writes") or []:
            if (site["file"], site["line"]) == (entry["file"],
                                                entry["line"]):
                return name
    return ""


def _gather_source_texts(
    target_path: Path, primary_file: str,
) -> dict[str, str]:
    from .resource_bounds import (
        _gather_source_texts as _rb_gather,
    )
    return _rb_gather(target_path, primary_file)


def run_protocol_state_check(
    target_path: Path,
    file_path: str,
    function_name: str,
    hypothesis: str,
    *,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
    domain_model: dict[str, Any] | None = None,
    invariant: str | None = None,
    source_texts: dict[str, str] | None = None,
    budget_s: float = INVARIANT_BUDGET_S,
) -> StateEvidence:
    """Adjudicate one protocol-state hypothesis.

    With an invariant (explicit, extracted from the hypothesis, or
    study-stated) the census-driven multi-site harness runs (leg 3,
    the only promote-capable path — honesty gate in the module
    docstring). A hypothesis naming only the suspicious write
    re-derives the legs-1+2 receipts and confirms at the permanently
    detection-grade lead rule-ids, or reports
    ``invariant-unstated``."""
    if not file_path.endswith(_SOURCE_SUFFIXES):
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"no phase-1 protocol-state analyzer for {file_path}",
        )
    if source_texts is None:
        source_texts = _gather_source_texts(
            Path(target_path), file_path,
        )
    if not source_texts:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            f"no sources readable under {target_path}",
        )
    index = build_state_field_index(source_texts)
    state_vocab = learned_state_fields(domain_model)

    if invariant is None:
        _fires, invariant = classify_protocol_state_hypothesis(hypothesis)

    if invariant:
        return _adjudicate_invariant(
            invariant, index, source_texts, domain_model, state_vocab,
            context=context, inventory=inventory, budget_s=budget_s,
        )

    # Legs 1+2 — receipts re-derived, outcome capped at detection
    # grade (never above `suspicious` downstream).
    fields = index.get("fields") or {}
    candidates: list[str] = []
    seen: set[str] = set()
    for m in _BACKTICK_IDENT_RE.finditer(hypothesis):
        name = m.group(1).rsplit(".", 1)[-1]
        if name in fields and name not in seen:
            seen.add(name)
            candidates.append(name)
    for m in _IDENT_RE.finditer(hypothesis):
        name = m.group(1)
        if name in fields and name not in seen:
            seen.add(name)
            candidates.append(name)
    if not candidates:
        return _inconclusive(
            REASON_HYPOTHESIS_UNBINDABLE,
            "hypothesis names no field present in the field index",
        )

    refutation: StateEvidence | None = None
    degraded = False
    unresolved = False
    for fld in candidates:
        bucket = fields[fld]
        writes = bucket.get("writes") or []
        reads = bucket.get("reads") or []
        if writes and not reads:
            return StateEvidence(
                outcome="confirmed",
                reason=(
                    f"`{fld}` is written at "
                    + ", ".join(
                        f"{s['file']}:{s['line']}" for s in writes[:4]
                    )
                    + " and read nowhere in the scanned set — a "
                    "defence the author began was never wired into "
                    "validation (not itself a vulnerability; "
                    "permanently detection-grade)"
                ),
                rule_id=RULE_DEAD_STATE,
                field={"struct": "", "name": fld,
                       "authority": "unresolved", "provenance": ""},
                dead_state={
                    "writes": [
                        {k: s[k] for k in
                         ("file", "line", "function", "code")}
                        for s in writes[:6]
                    ],
                    "reads": 0,
                },
            )
        for site in writes:
            verdict, receipt = _peer_write_verdict(
                site, index, source_texts, state_vocab,
            )
            if verdict == "confirmed":
                return StateEvidence(
                    outcome="confirmed",
                    reason=(
                        f"`{fld}` at {site['file']}:{site['line']} is "
                        f"assigned from {receipt['source_chain']} with "
                        "no dominating guard referencing a sibling "
                        "field — unvalidated peer write (weak proxy; "
                        "permanently detection-grade)"
                    ),
                    rule_id=RULE_PEER_WRITE,
                    field={"struct": "", "name": fld,
                           "authority": "peer", "provenance": ""},
                    peer_write=receipt,
                )
            if verdict == "refuted":
                refutation = StateEvidence(
                    outcome="refuted",
                    reason=(
                        f"peer-sourced write of `{fld}` at "
                        f"{site['file']}:{site['line']} is dominated "
                        f"by `{receipt['validating_guard']}` — "
                        "validation against sibling state present"
                    ),
                    rule_id=RULE_PEER_WRITE,
                    peer_write=receipt,
                )
            elif verdict == "census-degraded":
                degraded = True
            elif verdict == "not-peer":
                unresolved = True

    if refutation is not None:
        return refutation
    if degraded:
        return _inconclusive(
            REASON_CENSUS_DEGRADED,
            "CFG guard leg unavailable for the peer-write check",
        )
    if unresolved:
        return _inconclusive(
            REASON_AUTHORITY_UNRESOLVED,
            f"cannot classify {', '.join(candidates[:3])} as local- "
            "or peer-authoritative (rhs provenance inconclusive, no "
            "state_fields vocabulary)",
        )
    return _inconclusive(
        REASON_INVARIANT_UNSTATED,
        "legs 1+2 derived no conclusive receipt and nobody supplied "
        "an invariant relating the named fields",
    )


# ── standing pre-pass (leads only + receipted-invariant harness) ────


def run_protocol_state_prepass(
    source_texts: dict[str, str],
    *,
    target_path: Path | None = None,
    out_dir: Path | None = None,
    inventory: dict[str, Any] | None = None,
    context: Any = None,
    domain_model: dict[str, Any] | None = None,
    budget_s: float = 30.0,
) -> dict[str, Any]:
    """Standing pre-pass: legs 1+2 emit **leads only** (they exist to
    make the LLM form the right hypothesis with receipts attached);
    leg 3 runs standing for STUDY-RECEIPTED domain-model invariants
    only. Lead caps ≤20+≤20/run, 3/file (§4.6)."""
    del target_path  # index is built from the provided source set
    t0 = time.monotonic()
    telemetry: dict[str, Any] = {
        "channel": "protocol_state",
        "dead_state_leads": 0, "peer_write_leads": 0,
        "invariants_checked": 0, "confirmed": 0, "refuted": 0,
        "inconclusive": 0, "budget_exceeded": False,
        "census_tier": "", "census_degraded_sites": 0,
    }
    findings: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []
    mechanical: list[dict[str, Any]] = []

    index = build_state_field_index(source_texts)
    telemetry["census_tier"] = index.get("tier", "")
    state_vocab = learned_state_fields(domain_model)
    fields = index.get("fields") or {}
    per_file: dict[str, int] = {}

    def _lead_ok(fp: str, cap_key: str, cap: int) -> bool:
        if telemetry[cap_key] >= cap:
            return False
        if per_file.get(fp, 0) >= MAX_LEADS_PER_FILE:
            return False
        per_file[fp] = per_file.get(fp, 0) + 1
        telemetry[cap_key] += 1
        return True

    def _stateish(fld: str) -> bool:
        return bool(_STATE_STEM_RE.search(fld)) or fld in state_vocab

    # Leg 1 — written-never-read state fields (the free census
    # by-product; CWE-563-adjacent lead, not a hypothesis).
    for fld in sorted(fields, key=lambda f: (not _stateish(f), f)):
        if time.monotonic() - t0 > budget_s:
            telemetry["budget_exceeded"] = True
            break
        bucket = fields[fld]
        writes = bucket.get("writes") or []
        if not writes or bucket.get("reads"):
            continue
        if not _stateish(fld):
            continue
        fp = writes[0]["file"]
        if not _lead_ok(fp, "dead_state_leads", MAX_DEAD_STATE_LEADS):
            continue
        sites_desc = ", ".join(
            f"{s['file']}:{s['line']}" for s in writes[:4]
        )
        leads.append({
            "channel": "protocol_state",
            "rule_id": RULE_DEAD_STATE,
            "cwe": DEAD_STATE_LEAD_CWE,
            "file": fp,
            "function": writes[0]["function"],
            "line": writes[0]["line"],
            "field": fld,
            "description": (
                f"`{fld}` is written at {sites_desc} and read "
                "nowhere in the scanned set"
            ),
            "mechanism": (
                f"`{fld}` is written at {sites_desc} and read nowhere "
                "— is there a protocol invariant relating it to the "
                "peer-updated state it was meant to validate?"
            ),
        })
        mechanical.append({
            "file": fp,
            "function": writes[0]["function"],
            "detector": "protocol_state",
            "line": writes[0]["line"],
            "description": leads[-1]["description"],
            "callee": fld,
            "rule_id": RULE_DEAD_STATE,
            "cwe": DEAD_STATE_LEAD_CWE,
        })

    # Leg 2 — unvalidated peer-sourced state writes.
    if not telemetry["budget_exceeded"]:
        for fld in sorted(fields, key=lambda f: (not _stateish(f), f)):
            if time.monotonic() - t0 > budget_s:
                telemetry["budget_exceeded"] = True
                break
            if not _stateish(fld):
                continue
            for site in (fields[fld].get("writes") or [])[:4]:
                verdict, receipt = _peer_write_verdict(
                    site, index, source_texts, state_vocab,
                )
                if verdict == "census-degraded":
                    telemetry["census_degraded_sites"] += 1
                    continue
                if verdict != "confirmed":
                    continue
                if not _lead_ok(site["file"], "peer_write_leads",
                                MAX_PEER_WRITE_LEADS):
                    continue
                leads.append({
                    "channel": "protocol_state",
                    "rule_id": RULE_PEER_WRITE,
                    "cwe": "CWE-372",
                    "file": site["file"],
                    "function": site["function"],
                    "line": site["line"],
                    "field": fld,
                    "description": (
                        f"`{fld}` at {site['file']}:{site['line']} is "
                        f"assigned from {receipt['source_chain']} "
                        "with no guard referencing a sibling field"
                    ),
                    "mechanism": (
                        f"`{fld}` is assigned from the decoded peer "
                        f"value at {site['file']}:{site['line']} with "
                        "no guard referencing a sibling field — is "
                        "there a protocol invariant relating them?"
                    ),
                    "receipts": receipt,
                })
                mechanical.append({
                    "file": site["file"],
                    "function": site["function"],
                    "detector": "protocol_state",
                    "line": site["line"],
                    "description": leads[-1]["description"],
                    "callee": fld,
                    "rule_id": RULE_PEER_WRITE,
                    "cwe": "CWE-372",
                })

    # Leg 3 — study-receipted invariants only (the honesty gate).
    try:
        from .invariant_smt import extract_invariants
    except ImportError:
        extract_invariants = None
    if extract_invariants is not None:
        for entry in (domain_model or {}).get("invariants") or []:
            if telemetry["budget_exceeded"]:
                break
            if time.monotonic() - t0 > budget_s:
                telemetry["budget_exceeded"] = True
                break
            if not isinstance(entry, dict):
                continue
            statement = str(entry.get("statement") or "")
            cands = extract_invariants(statement)
            if not cands:
                continue
            invariant = cands[0]
            if _invariant_receipt(domain_model, invariant) is None:
                # Unreceipted study invariants are not adjudicated
                # standing — they stay hypothesis-driven (the LLM
                # must own the premise).
                continue
            telemetry["invariants_checked"] += 1
            res = _adjudicate_invariant(
                invariant, index, source_texts, domain_model,
                state_vocab, context=context, inventory=inventory,
                budget_s=min(INVARIANT_BUDGET_S, budget_s),
            )
            telemetry[
                "confirmed" if res.outcome == "confirmed" else
                "refuted" if res.outcome == "refuted" else
                "inconclusive"
            ] += 1
            if res.outcome != "confirmed":
                continue
            detection = is_detection_rule_id(res.rule_id)
            status = (
                "finding"
                if not detection
                and (res.reachability or {}).get("status")
                == "entry_reachable"
                else "suspicious"
            )
            first = next(
                (s for s in (res.invariant or {}).get("per_site", [])
                 if s.get("verdict") == "violable"), {},
            )
            findings.append({
                "file": first.get("file", ""),
                "function": first.get("function", ""),
                "line": int(first.get("line") or 0),
                "rule_id": res.rule_id,
                "evidence_tool": res.rule_id,
                "status": status,
                "detection_grade": detection,
                "cwe": "CWE-372",
                "hypothesis": (
                    f"the protocol invariant `{invariant}` is violable "
                    f"at {first.get('file', '')}:{first.get('line', 0)}"
                ),
                "description": res.reason,
                "receipts": res.to_dict(),
            })

    telemetry["leads_seeded"] = len(leads)
    telemetry["wall_time_s"] = round(time.monotonic() - t0, 3)
    if out_dir is not None and (findings or leads):
        try:
            path = Path(out_dir) / "protocol-state.json"
            path.write_text(json.dumps(
                {"findings": findings, "leads": leads,
                 "telemetry": telemetry}, indent=1,
            ))
        except Exception:
            logger.debug("protocol-state.json write failed",
                         exc_info=True)
    return {
        "findings": findings,
        "leads": leads,
        "mechanical": mechanical,
        "telemetry": telemetry,
    }
