"""Unified evidence primitives for RAPTOR.

Every finding, observation, and annotation across RAPTOR carries an
evidence tier that grades how close the observation is to ground truth.
This module is the canonical home for that vocabulary.

Tier ordering (strongest to weakest):
    OBSERVED_RUNTIME  — Frida/runtime instrumentation saw it happen
    REPLAYED_CRASH    — ASan/fuzz witness reproduced the bug
    SMT_PROVED        — Z3/SMT solver proved the constraint (un)satisfiable
    XREF_BACKED       — CPG/dataflow/call-graph structural guarantee
    HEADER_BACKED     — ELF/Mach-O headers, symbol tables, AST extraction
    DECOMPILER_INFERRED — decompiled pseudo-code (approximate)
    HEURISTIC         — LLM inference, naming heuristic, pattern match

Also provides the per-function EvidenceRecord used by /audit's pre-sweep
to aggregate mechanical evidence (taint, Joern, CodeQL, Semgrep, binary
analysis) into a single record per function.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# ---------------------------------------------------------------------------
# Evidence tier vocabulary
# ---------------------------------------------------------------------------

class EvidenceTier(str, Enum):
    """How close an observation is to ground truth."""

    OBSERVED_RUNTIME = "observed_runtime"
    REPLAYED_CRASH = "replayed_crash"
    SMT_PROVED = "smt_proved"
    XREF_BACKED = "xref_backed"
    HEADER_BACKED = "header_backed"
    DECOMPILER_INFERRED = "decompiler_inferred"
    HEURISTIC = "heuristic"


# Ordered strongest-to-weakest for comparison.
TIER_RANK: dict[EvidenceTier, int] = {
    EvidenceTier.OBSERVED_RUNTIME: 6,
    EvidenceTier.REPLAYED_CRASH: 5,
    EvidenceTier.SMT_PROVED: 4,
    EvidenceTier.XREF_BACKED: 3,
    EvidenceTier.HEADER_BACKED: 2,
    EvidenceTier.DECOMPILER_INFERRED: 1,
    EvidenceTier.HEURISTIC: 0,
}


def stronger(a: EvidenceTier, b: EvidenceTier) -> EvidenceTier:
    """Return whichever tier is closer to ground truth."""
    return a if TIER_RANK[a] >= TIER_RANK[b] else b


# ---------------------------------------------------------------------------
# Binary evidence record (used by packages/binary_analysis/)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class BinaryEvidenceRecord:
    """One mechanically attributable observation.

    ``confidence`` is intentionally a label, not a score. A consumer should
    not turn a heuristic into a proof by doing arithmetic over it.
    """

    id: str
    kind: str
    source: str
    summary: str
    tier: EvidenceTier
    confidence: str
    reproducible: bool
    tool: str
    location: str | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "source": self.source,
            "summary": self.summary,
            "tier": self.tier.value,
            "confidence": self.confidence,
            "reproducible": self.reproducible,
            "tool": self.tool,
            "location": self.location,
            "data": dict(self.data),
        }


def evidence_id(binary_sha256: str, kind: str, source: str, data: Any) -> str:
    """Stable evidence id bound to the binary bytes and observation."""
    payload = json.dumps(
        {
            "binary_sha256": binary_sha256,
            "kind": kind,
            "source": source,
            "data": data,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8", "surrogateescape")
    return f"evidence:{hashlib.sha256(payload).hexdigest()[:20]}"


def make_evidence(
    binary_sha256: str,
    *,
    kind: str,
    source: str,
    summary: str,
    tier: EvidenceTier,
    confidence: str,
    reproducible: bool,
    tool: str,
    location: str | None = None,
    data: dict[str, Any] | None = None,
) -> BinaryEvidenceRecord:
    payload = dict(data or {})
    return BinaryEvidenceRecord(
        id=evidence_id(binary_sha256, kind, source, payload),
        kind=kind,
        source=source,
        summary=summary,
        tier=tier,
        confidence=confidence,
        reproducible=reproducible,
        tool=tool,
        location=location,
        data=payload,
    )


# ---------------------------------------------------------------------------
# Prompt-safe text helpers
# ---------------------------------------------------------------------------

_logger = logging.getLogger(__name__)

_IDENTIFIER_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*"
    r"((?:\.|::|/)[A-Za-z_][A-Za-z0-9_]*)*$"
)
_NAME_CAP = 120


def _is_valid_identifier(name: str) -> bool:
    """True when *name* looks like a qualified identifier across languages."""
    return bool(_IDENTIFIER_RE.match(name))


def _safe_name(name: str) -> str:
    """Sanitize an identifier for prompt injection safety."""
    if not name or not _is_valid_identifier(name):
        return "<invalid-name>"
    return name.replace("\n", "").replace("\r", "")[:_NAME_CAP]


_CWE_TAG_RE = re.compile(r"CWE-\d{1,5}$")


def _safe_cwe(value: Any) -> str:
    """Charset-pinned CWE tag ("CWE-NNN") or empty string."""
    if isinstance(value, str) and _CWE_TAG_RE.fullmatch(value):
        return value
    return ""


def _safe_text(text: str, max_len: int = 120) -> str:
    """Sanitize untrusted text for prompt interpolation."""
    if not text:
        return ""
    sanitized = text.replace("\n", " ").replace("\r", "")
    sanitized = re.sub(r"[#`\-]{3,}", "", sanitized)
    return sanitized[:max_len]


# ---------------------------------------------------------------------------
# Per-function evidence record (used by /audit pre-sweep)
# ---------------------------------------------------------------------------

_SINK_DEPENDENT_CWES = (
    "CWE-22",   # path traversal
    "CWE-78",   # OS command injection
    "CWE-79",   # XSS
    "CWE-89",   # SQL injection
    "CWE-90",   # LDAP injection
    "CWE-91",   # XML injection
    "CWE-94",   # code injection
    "CWE-120",  # buffer overflow (classic)
    "CWE-122",  # heap buffer overflow
    "CWE-134",  # format string
    "CWE-502",  # deserialization of untrusted data
    "CWE-611",  # XXE
    "CWE-918",  # SSRF
    "CWE-1336", # template injection
)


@dataclass
class ContextMapSink:
    """A sink imported from /understand context-map.json."""

    sink_type: str
    notes: str = ""


@dataclass
class EvidenceRecord:
    """Aggregated mechanical evidence for one function."""

    file: str
    function: str

    line_start: int = 0
    line_end: int = 0

    sink_unreachable: bool = False
    sink_narrowed_classes: list[str] = field(default_factory=list)

    taint_approx: Any | None = None

    taint_summary: Any | None = None

    joern_flows: list[Any] = field(default_factory=list)

    imported_joern_flows: list[Any] = field(default_factory=list)

    joern_unguarded_sinks: list[dict[str, Any]] = field(default_factory=list)

    joern_sink_args: list[dict[str, Any]] = field(default_factory=list)

    codeql_alerts: list[dict[str, Any]] = field(default_factory=list)

    semgrep_hits: list[dict[str, Any]] = field(default_factory=list)

    prefilter: Any | None = None

    context_map_sink: ContextMapSink | None = None

    transitive_taint: Any | None = None

    app_sink_targets: list[str] = field(default_factory=list)

    sanitizer_calls: list[dict[str, str]] = field(default_factory=list)

    binary_sink_edges: list[dict[str, str]] = field(default_factory=list)

    binary_surface_category: str | None = None

    binary_parser_boundary: bool = False

    negative_space: list[Any] = field(default_factory=list)

    binary_layer0_findings: list[Any] = field(default_factory=list)

    def has_any_evidence(self) -> bool:
        return bool(
            self.taint_approx
            or self.taint_summary
            or self.joern_flows
            or self.imported_joern_flows
            or self.joern_unguarded_sinks
            or self.joern_sink_args
            or self.codeql_alerts
            or self.semgrep_hits
            or self.context_map_sink
            or self.transitive_taint
            or self.prefilter
            or self.app_sink_targets
            or self.binary_sink_edges
            or self.binary_layer0_findings
            or self.negative_space
            or self.sanitizer_calls
            or self.binary_surface_category
            or self.binary_parser_boundary
        )

    def all_joern_flows(self) -> list:
        return self.joern_flows + self.imported_joern_flows


# ---------------------------------------------------------------------------
# Evidence formatting
# ---------------------------------------------------------------------------

def format_evidence_prose(
    record: EvidenceRecord,
    target_path: str | None = None,
) -> str:
    """Format an EvidenceRecord as prose for the LLM prompt.

    Uses only structural fields (function, param, sink, line) — never
    FlowStep.code snippets. See design §"Prompt injection defense for
    pre-evidence".
    """
    lines: list[str] = []

    approx = record.taint_approx
    if approx is not None and hasattr(approx, "dangerous_flows"):
        for pidx, flows in sorted(approx.dangerous_flows.items()):
            if pidx < len(approx.params):
                pname = _safe_name(approx.params[pidx])
            else:
                pname = f"param_{pidx}"
            for callee, arg_idx in flows:
                cname = _safe_name(callee)
                lines.append(
                    f"- param `{pname}` flows directly to "
                    f"`{cname}` arg {arg_idx} "
                    f"(mechanical, AST-level)"
                )
        if approx.has_opaque_flow:
            lines.append(
                "- opaque flow detected (pointer/struct/cast assignment "
                "from parameter) — AST analysis incomplete"
            )

    if record.taint_summary is not None:
        ts = record.taint_summary
        if hasattr(ts, "call_arg_taint") and ts.call_arg_taint:
            seen = set()
            for callee, arg_idx, pidx in sorted(ts.call_arg_taint):
                key = (pidx, callee, arg_idx)
                if key in seen:
                    continue
                seen.add(key)
                pname = ts.params[pidx] if pidx < len(ts.params) else f"param_{pidx}"
                pname = _safe_name(pname)
                cname = _safe_name(callee)
                lines.append(
                    f"- param `{pname}` flows to "
                    f"`{cname}` arg {arg_idx} "
                    f"(CFG path-sensitive)"
                )
        if hasattr(ts, "param_taints_return"):
            for pidx in range(len(getattr(ts, "params", []))):
                if ts.param_taints_return(pidx):
                    pname = _safe_name(ts.params[pidx]) if pidx < len(ts.params) else f"param_{pidx}"
                    sanitizers = ts.return_sanitizers_for_param(pidx) if hasattr(ts, "return_sanitizers_for_param") else frozenset()
                    if sanitizers:
                        slist = ", ".join(
                            _safe_name(s[0] if isinstance(s, tuple) else s)
                            for s in sorted(sanitizers)
                        )
                        lines.append(
                            f"- param `{pname}` taints return value "
                            f"(sanitized by: {slist})"
                        )
                    else:
                        lines.append(
                            f"- param `{pname}` taints return value "
                            f"(no sanitizer)"
                        )
        if hasattr(ts, "summary_unknown") and ts.summary_unknown:
            lines.append(
                "- taint summary incomplete (dynamic dispatch) — "
                "don't trust absence"
            )

    if record.app_sink_targets:
        for target in record.app_sink_targets[:10]:
            lines.append(
                f"- APPLICATION SINK: this function directly calls "
                f"`{_safe_name(target)}` (dangerous API)"
            )

    if record.sanitizer_calls:
        for sc in record.sanitizer_calls[:8]:
            lines.append(
                f"- SANITIZER: `{_safe_name(sc.get('callable', '?'))}` "
                f"transforms param `{_safe_name(sc.get('param', '?'))}` "
                f"before return (taint summary)"
            )

    if record.transitive_taint is not None:
        tt = record.transitive_taint
        for pidx, paths in sorted(tt.param_sinks.items()):
            for tp in paths[:5]:
                chain = " → ".join(_safe_name(h) for h in tp.hops)
                sink = _safe_name(tp.sink_name)
                lines.append(
                    f"- CROSS-FUNCTION taint: param {pidx} reaches "
                    f"`{sink}` arg {tp.sink_arg} via: {chain} "
                    f"(transitive AST)"
                )

    all_joern = record.all_joern_flows()
    for flow in all_joern:
        src = _safe_name(getattr(flow, "source_method", ""))
        param = _safe_name(getattr(flow, "source_param", ""))
        sink = _safe_name(getattr(flow, "sink_call", ""))
        steps = getattr(flow, "steps", [])
        n_steps = len(steps)
        is_inter = getattr(flow, "is_inter_procedural", False)

        scope = "inter-procedural" if is_inter else "intra-procedural"
        lines.append(
            f"- {scope} taint: param `{param}` in `{src}` "
            f"flows to `{sink}` ({n_steps} steps) (Joern CPG)"
        )

    for ug in record.joern_unguarded_sinks:
        ug_sink = _safe_name(ug.get("sink", ""))
        ug_line = ug.get("line", 0)
        ug_code = _safe_text(ug.get("code", ""), 120)
        lines.append(
            f"- UNGUARDED sink: `{ug_sink}` at line {ug_line} has no "
            f"dominating conditional: `{ug_code}` (Joern CPG)"
        )

    for sa in record.joern_sink_args:
        sa_sink = _safe_name(sa.get("sink", ""))
        arg_idx = sa.get("arg_index", -1)
        src_param = _safe_name(sa.get("source_param", ""))
        lines.append(
            f"- tainted arg: param `{src_param}` reaches `{sa_sink}` "
            f"arg #{arg_idx} (Joern CPG)"
        )

    for alert in record.codeql_alerts:
        rule_id = _safe_name(alert.get("rule_id", "unknown"))
        message = _safe_text(alert.get("message", ""), 200)
        line = alert.get("line", 0)
        provenance = " (prior scan run)" if alert.get("_sarif_sibling") else ""
        cwe = _safe_cwe(alert.get("_sarif_cwe", ""))
        cwe_note = f" [{cwe}]" if cwe else ""
        lines.append(
            f"- CodeQL {rule_id}{cwe_note} at line {line}{provenance}: "
            f"{message}"
        )

    for hit in record.semgrep_hits:
        rule_id = _safe_name(hit.get("rule_id", "unknown"))
        line = hit.get("line", 0)
        provenance = " (prior scan run)" if hit.get("_sarif_sibling") else ""
        cwe = _safe_cwe(hit.get("_sarif_cwe", ""))
        cwe_note = f" [{cwe}]" if cwe else ""
        lines.append(
            f"- Semgrep {rule_id}{cwe_note} matched at line "
            f"{line}{provenance}"
        )

    if record.context_map_sink is not None:
        cms = record.context_map_sink
        detail = f"- context-map sink: type={cms.sink_type}"
        if cms.notes:
            detail += f" — {_safe_text(cms.notes, 200)}"
        detail += " (from /understand --map)"
        lines.append(detail)

    for bse in record.binary_sink_edges:
        sink = _safe_name(bse.get("sink", ""))
        tier = _safe_name(bse.get("tier", "xref"))
        lines.append(
            f"- BINARY: calls dangerous API `{sink}` "
            f"(evidence tier: {tier}, from binary analysis)"
        )

    if record.binary_surface_category:
        lines.append(
            f"- BINARY surface: classified as "
            f"`{_safe_name(record.binary_surface_category)}` "
            f"by binary investigation"
        )

    if record.binary_parser_boundary:
        lines.append(
            "- BINARY parser boundary: identified as a parser "
            "entry point (ingress → parser path) by binary analysis"
        )

    if record.binary_layer0_findings:
        try:
            from core.audit.binary_layer0 import format_layer0_context
            l0_block = format_layer0_context(record.binary_layer0_findings)
            if l0_block:
                lines.append(l0_block)
        except ImportError:
            pass

    if record.negative_space:
        try:
            from core.audit.negative_space import format_negative_space_prose
            ns_block = format_negative_space_prose(record.negative_space)
            if ns_block:
                lines.append(ns_block)
        except ImportError:
            pass

    if not lines:
        return ""

    header = "## Mechanical pre-sweep results\n\n"
    return header + "\n".join(lines)


_TOOL_TIER_MAP: dict[str, str] = {
    "taint_approx": "xref_backed",
    "taint_summary": "xref_backed",
    "joern": "xref_backed",
    "joern_unguarded": "xref_backed",
    "joern_sink_arg": "xref_backed",
    "codeql": "xref_backed",
    "semgrep": "header_backed",
    "context_map_sink": "header_backed",
}


def format_evidence_structured(
    record: EvidenceRecord,
) -> list[dict[str, Any]]:
    """Build the structured evidence list for downstream validation.

    Not injected into the LLM prompt — used by the review schema
    cross-referencer and tier diagnostic counters.
    """
    entries: list[dict[str, Any]] = []

    approx = record.taint_approx
    if approx is not None and hasattr(approx, "dangerous_flows"):
        for pidx, flows in sorted(approx.dangerous_flows.items()):
            pname = approx.params[pidx] if pidx < len(approx.params) else f"param_{pidx}"
            for callee, arg_idx in flows:
                entries.append({
                    "tier": "taint_approx",
                    "evidence_tier": "xref_backed",
                    "param": pname,
                    "param_idx": pidx,
                    "sink": callee,
                    "sink_arg_idx": arg_idx,
                    "source": "this_run",
                })

    if record.taint_summary is not None:
        ts = record.taint_summary
        if hasattr(ts, "call_arg_taint"):
            for callee, arg_idx, pidx in sorted(ts.call_arg_taint):
                pname = ts.params[pidx] if pidx < len(ts.params) else f"param_{pidx}"
                entries.append({
                    "tier": "taint_summary",
                    "evidence_tier": "xref_backed",
                    "param": pname,
                    "param_idx": pidx,
                    "sink": callee,
                    "sink_arg_idx": arg_idx,
                    "source": "this_run",
                })

    for flow in record.joern_flows:
        entries.append({
            "tier": "joern",
            "evidence_tier": "xref_backed",
            "source_method": getattr(flow, "source_method", ""),
            "source_param": getattr(flow, "source_param", ""),
            "sink_call": getattr(flow, "sink_call", ""),
            "is_inter_procedural": getattr(flow, "is_inter_procedural", False),
            "source": "this_run",
        })

    for flow in record.imported_joern_flows:
        entries.append({
            "tier": "joern",
            "evidence_tier": "xref_backed",
            "source_method": getattr(flow, "source_method", ""),
            "source_param": getattr(flow, "source_param", ""),
            "sink_call": getattr(flow, "sink_call", ""),
            "is_inter_procedural": getattr(flow, "is_inter_procedural", False),
            "source": "imported",
        })

    for ug in record.joern_unguarded_sinks:
        entries.append({
            "tier": "joern_unguarded",
            "evidence_tier": "xref_backed",
            "sink": ug.get("sink", ""),
            "line": ug.get("line", 0),
            "code": ug.get("code", ""),
            "source": "this_run",
        })

    for sa in record.joern_sink_args:
        entries.append({
            "tier": "joern_sink_arg",
            "evidence_tier": "xref_backed",
            "sink": sa.get("sink", ""),
            "arg_index": sa.get("arg_index", -1),
            "source_param": sa.get("source_param", ""),
            "source": "this_run",
        })

    for alert in record.codeql_alerts:
        entry = {
            "tier": "codeql",
            "evidence_tier": "xref_backed",
            "rule_id": alert.get("rule_id", ""),
            "line": alert.get("line", 0),
            "source": (
                "sibling_run" if alert.get("_sarif_sibling") else "this_run"
            ),
        }
        if alert.get("_sarif_cwe"):
            entry["cwe"] = alert["_sarif_cwe"]
        entries.append(entry)

    for hit in record.semgrep_hits:
        entry = {
            "tier": "semgrep",
            "evidence_tier": "header_backed",
            "rule_id": hit.get("rule_id", ""),
            "line": hit.get("line", 0),
            "source": (
                "sibling_run" if hit.get("_sarif_sibling") else "this_run"
            ),
        }
        if hit.get("_sarif_cwe"):
            entry["cwe"] = hit["_sarif_cwe"]
        entries.append(entry)

    if record.context_map_sink is not None:
        cms = record.context_map_sink
        entry: dict[str, Any] = {
            "tier": "context_map_sink",
            "evidence_tier": "header_backed",
            "sink_type": cms.sink_type,
            "source": "understand",
        }
        if cms.notes:
            entry["notes"] = cms.notes
        entries.append(entry)

    return entries


def strongest_evidence_tier(
    entries: list[dict[str, Any]],
) -> EvidenceTier:
    """Return the strongest ``evidence_tier`` across structured entries.

    Returns ``HEURISTIC`` when the list is empty (no mechanical evidence,
    so anything derived from it is LLM-inferred at best).
    """
    best = EvidenceTier.HEURISTIC
    for entry in entries:
        raw = entry.get("evidence_tier")
        if raw is None:
            continue
        try:
            tier = EvidenceTier(raw)
        except ValueError:
            continue
        best = stronger(best, tier)
    return best


# ---------------------------------------------------------------------------
# Evidence index builder
# ---------------------------------------------------------------------------

def build_evidence_index(
    *,
    checklist: dict,
    sink_results: Any | None = None,
    taint_approx_results: dict[str, Any] | None = None,
    taint_summary_results: dict[str, Any] | None = None,
    joern_flows: dict[str, list] | None = None,
    imported_joern_flows: dict[str, list] | None = None,
    sarif_cache: Any | None = None,
    prefilter_results: dict[str, Any] | None = None,
    context_map_sinks: list[dict[str, Any]] | None = None,
    binary_bridge: Any | None = None,
    scope: str | list[str] | None = None,
) -> dict[str, EvidenceRecord]:
    """Build the per-function evidence index from pre-sweep outputs.

    Keys are "file:function". Each value aggregates all available
    mechanical evidence for that function.

    When *scope* is set, only functions whose file path starts with the
    prefix are indexed.  This avoids building evidence records (and
    running downstream layer0 scans) for thousands of out-of-scope
    functions when auditing a single file or subdirectory.
    """
    scope_tuple: tuple[str, ...] | None = None
    if scope:
        scope_tuple = (scope,) if isinstance(scope, str) else tuple(scope)

    index: dict[str, EvidenceRecord] = {}

    for file_entry in checklist.get("files") or []:
        file_path = file_entry.get("path", "")
        if not file_path:
            continue
        if scope_tuple and not file_path.startswith(scope_tuple):
            continue
        for item in file_entry.get("items", []):
            func_name = item.get("name", "")
            if not func_name:
                continue
            key = f"{file_path}:{func_name}"
            ls = item.get("line_start", 0)
            le = item.get("line_end", 0)
            index[key] = EvidenceRecord(
                file=file_path, function=func_name,
                line_start=ls, line_end=le,
            )

    if sink_results is not None:
        _reachable = set()
        if hasattr(sink_results, "transitive_reach"):
            for t in sink_results.transitive_reach:
                _reachable.add(f"{t.file}:{t.function}")
        if hasattr(sink_results, "direct_sinks"):
            for s in sink_results.direct_sinks:
                _reachable.add(f"{s.file}:{s.function}")
            direct_sink_index: dict[str, list[str]] = {}
            for s in sink_results.direct_sinks:
                key = f"{s.file}:{s.function}"
                direct_sink_index.setdefault(key, []).append(s.target)
            for key, targets in direct_sink_index.items():
                if key in index:
                    index[key].app_sink_targets = targets
        eligible = getattr(sink_results, "unreachable_eligible", None)
        # Guard: only mark functions as sink_unreachable when Joern
        # actually produced valid flow data.  When _reachable is empty
        # AND there's no eligible-verdict map, we can't distinguish
        # "every function is genuinely unreachable" from "CPG failed to
        # load" — default to no-signal rather than false suppression.
        has_valid_data = bool(_reachable) or eligible is not None
        if has_valid_data:
            for key, rec in index.items():
                if key not in _reachable:
                    if eligible is not None:
                        fk = (rec.file, rec.function)
                        verdict = eligible.get(fk)
                        if verdict is not None and verdict.eligible:
                            rec.sink_unreachable = True
                            rec.sink_narrowed_classes = list(
                                _SINK_DEPENDENT_CWES,
                            )
                        elif verdict is not None:
                            rec.sink_unreachable = False
                    else:
                        rec.sink_unreachable = True
                        rec.sink_narrowed_classes = list(
                            _SINK_DEPENDENT_CWES,
                        )

    if taint_approx_results:
        for key, approx in taint_approx_results.items():
            if key in index:
                index[key].taint_approx = approx
        try:
            from core.analysis.taint_approx import compute_transitive_taint
            approx_by_key = {
                k: v
                for k, v in taint_approx_results.items()
                if hasattr(v, "direct_flows")
            }
            if approx_by_key:
                transitive = compute_transitive_taint(approx_by_key)
                for key, rec in index.items():
                    if key in transitive:
                        rec.transitive_taint = transitive[key]
        except Exception:
            _logger.debug("transitive taint computation failed", exc_info=True)

    if taint_summary_results:
        for key, summary in taint_summary_results.items():
            if key in index:
                index[key].taint_summary = summary
            if key in index and hasattr(summary, "return_effects"):
                sanitizers = []
                params = getattr(summary, "params", ())
                for pidx in range(len(params)):
                    for callable_name, arg_idx in summary.return_sanitizers_for_param(pidx):
                        sanitizers.append({
                            "callable": callable_name,
                            "param": params[pidx] if pidx < len(params) else str(pidx),
                            "arg_idx": str(arg_idx),
                        })
                if sanitizers:
                    index[key].sanitizer_calls = sanitizers

    if joern_flows:
        for key, flows in joern_flows.items():
            if key in index:
                index[key].joern_flows = list(flows)

    if imported_joern_flows:
        for key, flows in imported_joern_flows.items():
            if key in index:
                index[key].imported_joern_flows = list(flows)

    if sarif_cache is not None:
        for key, rec in index.items():
            hits = sarif_cache.lookup(rec.file, rec.line_start, rec.line_end)
            if hits is None:
                continue
            for hit in hits:
                source = hit.get("_sarif_source", "semgrep")
                if source == "codeql":
                    rec.codeql_alerts.append(hit)
                else:
                    rec.semgrep_hits.append(hit)

    if context_map_sinks:
        _attach_context_map_sinks(index, context_map_sinks)

    if binary_bridge is not None:
        _attach_binary_bridge(index, binary_bridge)

    return index


def _attach_context_map_sinks(
    index: dict[str, EvidenceRecord],
    sinks: list[dict[str, Any]],
) -> None:
    """Match context-map sink_details entries to evidence records."""
    for sink in sinks:
        sink_file = sink.get("file", "")
        sink_func = sink.get("name") or sink.get("function", "")
        if not sink_file or not sink_func:
            continue

        key = f"{sink_file}:{sink_func}"
        rec = index.get(key)
        if rec is None:
            continue

        sink_type = sink.get("type", "unknown")
        notes = sink.get("notes", "")
        rec.context_map_sink = ContextMapSink(
            sink_type=_safe_name(sink_type),
            notes=notes[:500] if notes else "",
        )


def _attach_binary_bridge(
    index: dict[str, EvidenceRecord],
    bridge: Any,
) -> None:
    """Enrich evidence records with binary analysis data."""
    func_to_keys: dict[str, list[str]] = {}
    for key in index:
        func_name = key.split(":")[-1]
        func_to_keys.setdefault(func_name, []).append(key)

    for edge in bridge.sink_edges:
        for key in func_to_keys.get(edge.caller, []):
            index[key].binary_sink_edges.append({
                "sink": edge.sink,
                "tier": edge.evidence_tier,
                "confidence": edge.confidence,
            })

    for surface in bridge.ranked_surfaces:
        for key in func_to_keys.get(surface.function, []):
            rec = index[key]
            if rec.binary_surface_category is None:
                rec.binary_surface_category = surface.category

    for boundary in bridge.parser_boundaries:
        for key in func_to_keys.get(boundary.function, []):
            index[key].binary_parser_boundary = True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "TIER_RANK",
    "BinaryEvidenceRecord",
    "ContextMapSink",
    "EvidenceRecord",
    "EvidenceTier",
    "_safe_name",
    "_safe_text",
    "build_evidence_index",
    "evidence_id",
    "format_evidence_prose",
    "format_evidence_structured",
    "make_evidence",
    "stronger",
    "strongest_evidence_tier",
]
