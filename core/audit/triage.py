"""Triage classifier — assigns every function to a depth bucket before review.

The mechanical triage pass sorts functions into 4 buckets with a 100x budget
range so LLM tokens are concentrated on functions most likely to contain bugs.
All classification is deterministic — no LLM calls.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, TYPE_CHECKING

from core.source import read_text_capped, split_lines

from ._util import safe_join
from .vendored_detector import (
    KIND_GENERATED,
    VendorVerdict,
    detect_vendored_files,
)

if TYPE_CHECKING:
    from .prefilter import PrefilterResult
    from pathlib import Path
    from collections.abc import Sequence


class TriageBucket(str, Enum):
    SKIP = "skip"
    GLANCE = "glance"
    INVESTIGATE = "investigate"
    DEEP_DIVE = "deep_dive"


TOKEN_BUDGETS: dict[TriageBucket, int] = {
    TriageBucket.SKIP: 0,
    TriageBucket.GLANCE: 500,
    TriageBucket.INVESTIGATE: 6000,
    TriageBucket.DEEP_DIVE: 50000,
}


@dataclass(frozen=True)
class TriageResult:
    bucket: TriageBucket
    reasons: tuple
    token_budget: int
    priority_score: float = 0.0
    # Set (to the VendorVerdict kind) when the vendored/generated tier
    # routed this function. Structured so the suppressions.jsonl audit
    # trail never depends on the wording of a prose reason string.
    vendor_tier: str | None = None


_DEEP_DIVE_SLOC = 200
_INVESTIGATE_SLOC = 20
_GLANCE_MAX_SLOC = 20
_HIGH_COMPLEXITY_BRANCHES = 15


# ── Fixed-size stack-buffer write detection (C-family) ───────────────
#
# The sink-unreachable skip rule reasons about CALLEES ("no sink path,
# no dangerous callees") — a function that writes into its own
# fixed-size local buffer has an intra-procedural overflow surface
# with no callee signal at all. A real stack overflow (81-byte local,
# loop-written, cap applied on only one branch) was triage-skipped
# exactly this way. Cheap, deterministic veto: a local fixed-size
# array declaration plus write evidence into that array keeps the
# function reviewable (INVESTIGATE) instead of SKIP.
_FIXED_BUF_DECL = re.compile(
    # Size may be a literal, a macro, or a constant expression
    # (``buf[OSSL_TRACE_STRING_MAX + 1]`` — the real missed overflow's
    # shape); anything short of a statement boundary counts. VLAs
    # match too: a runtime-sized local array with write evidence is
    # just as review-worthy.
    # The dimension span is bounded: unbounded, a body repeating the
    # type head inside the span re-scans the remainder from every
    # occurrence — quadratic in hostile source length. A real
    # dimension expression sits far inside 1000 chars.
    r"\b(?:unsigned\s+char|signed\s+char|char|uint8_t|int8_t|u_char|"
    r"wchar_t|BYTE|WCHAR)\s+(\w+)\s*\[[^\];]{0,1000}\]",
)
_MEM_WRITERS = (
    "memcpy", "memmove", "memset", "strcpy", "strncpy", "strcat",
    "strncat", "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "gets", "fgets", "read", "fread", "recv", "recvfrom",
)


def writes_fixed_stack_buffer(source: str) -> bool:
    """True when *source* declares a fixed-size local array and shows
    write evidence into it (indexed store, or the buffer passed as the
    destination of a mem/str writer). Conservative by construction:
    no declaration or no write evidence → False."""
    if not source:
        return False
    names = {m.group(1) for m in _FIXED_BUF_DECL.finditer(source)}
    if not names:
        return False
    for name in names:
        esc = re.escape(name)
        # buf[i] = …  (indexed store; excludes == comparisons).
        # Index span bounded — same rationale as _FIXED_BUF_DECL.
        if re.search(rf"\b{esc}\s*\[[^\]]{{1,1000}}\]\s*=[^=]", source):
            return True
        # memcpy(buf, …) / snprintf(buf, …) / read(fd, buf, …)-style
        # first-or-second-arg destination uses.
        writer_alt = "|".join(_MEM_WRITERS)
        # \S-headed first argument and gated '&' — the naive
        # ``\(\s*(?:[^,()]+,\s*)?&?\s*`` chained whitespace spans
        # around two optional atoms (quadratic on a writer call
        # followed by a whitespace run). The dropped corner is a
        # whitespace-only first argument, not real C.
        if re.search(
            rf"\b(?:{writer_alt})\s*\(\s*(?:[^,()\s][^,()]*,\s*)?(?:&\s*)?{esc}\b",
            source,
        ):
            return True
    return False


def classify_function(
    *,
    file: str,
    function: str,
    sloc: int = 0,
    source: str = "",
    priority_score: float = 0.0,
    is_entry_point: bool = False,
    is_sink: bool = False,
    is_trust_boundary: bool = False,
    on_taint_path: bool = False,
    has_joern_flows: bool = False,
    has_dangerous_callees: bool = False,
    is_callback_target: bool = False,
    binary_absent: bool = False,
    sink_unreachable: bool = False,
    validate_confirmed: bool = False,
    prefilter: PrefilterResult | None = None,
    branch_count: int = 0,
    caller_count: int = 0,
    vendor_verdict: VendorVerdict | None = None,
    vendor_file_dangerous: str | None = None,
) -> TriageResult:
    """Classify a single function into a triage bucket.

    All inputs are mechanical signals already available from the pre-sweep
    (Joern CPG, binary oracle, prefilter, priority scoring, context map).
    """
    reasons: list[str] = []

    # A prior /validate run CONFIRMED a defect in this function: the
    # strongest possible review signal. The mechanical skip evidence
    # ("no sink path", binary-absent, a prefilter skip_llm verdict) is
    # precisely what a confirmed detection-evasion defect looks like
    # from the outside (observed live: an audit-mask selection function
    # with a validated audit evasion bug was skipped as "no sink path,
    # no dangerous callees, small"). This rung must precede EVERY
    # mechanical skip — including the prefilter early-return, which
    # used to sit above it and made the floor dead. Never skip or
    # glance it — full review.
    if validate_confirmed:
        reasons.append("validate-confirmed defect — full review forced")
        return TriageResult(
            bucket=TriageBucket.INVESTIGATE,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.INVESTIGATE],
            priority_score=priority_score,
        )

    if prefilter and prefilter.skip_llm:
        reasons.append(f"prefilter skip: {prefilter.skip_reason}")
        return TriageResult(
            bucket=TriageBucket.SKIP,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.SKIP],
            priority_score=priority_score,
        )

    stack_buffer_writer = writes_fixed_stack_buffer(source)

    # A function registered as a callback / dispatch-table handler is
    # never "callerless": its callers are invisible to the static call
    # graph (invoked through a function pointer), so the mechanical
    # "no sink path" evidence that feeds this skip cannot be trusted
    # for it. Consumes the dispatch-table census — no new detection.
    if (
        sink_unreachable
        and not is_entry_point
        and not is_sink
        and not is_trust_boundary
        and not has_dangerous_callees
        and not is_callback_target
        and not stack_buffer_writer
        and sloc <= 30
    ):
        reasons.append("no sink path, no dangerous callees, small")
        return TriageResult(
            bucket=TriageBucket.SKIP,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.SKIP],
            priority_score=priority_score,
        )

    # Binary-oracle absent (suppression-earning: callers pass keys only
    # for full-DWARF-tier verdicts on trusted binaries — see the
    # chokepoint rules in core.analysis.reachability). The compiler
    # removed the function from every analysed binary: spending
    # hypothesis budget on it wastes review slots. Entry points, sinks
    # and trust boundaries stay exempt.
    if (
        binary_absent
        and not is_entry_point
        and not is_sink
        and not is_trust_boundary
    ):
        reasons.append(
            "binary_oracle_absent (not present in any analysed binary)"
        )
        return TriageResult(
            bucket=TriageBucket.SKIP,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.SKIP],
            priority_score=priority_score,
        )

    # (No binary_absent+sink_unreachable rule here: after the rule
    # above returns, the only remaining binary_absent population is
    # sinks and trust boundaries — exactly the classes the exemption
    # comment protects. A rule for that residue silently defeated the
    # exemption, and without the is_callback_target guard it skipped
    # callback-dispatched sinks the static graph cannot see.)

    # Vendored/generated tier (see core.audit.vendored_detector for
    # the trust model). Boundary-adjacent functions never skip:
    # generated ones demote to GLANCE, vendored ones keep their normal
    # routing. The skip tier requires corroborated generator
    # provenance (two distinct signals) — a bare in-file banner, a
    # bare generated-output filename, or a structural shape (all
    # target-controlled) only ever earn GLANCE, so nothing becomes
    # invisible on the target's say-so. Corroboration is still two
    # TARGET-plantable signals (banner text + generated-shaped
    # filename), so live review signals from the code itself —
    # dangerous callees, a taint-path position, or the file-level
    # import-RESOLVED dangerous check (surface-spelling evidence is
    # evadable via aliased imports / method-value references; see
    # _alias_resolved_dangerous) — demote even the corroborated skip
    # to GLANCE: a planted "generated" file with dangerous calls never
    # becomes invisible. Every decision leaves a suppressions.jsonl
    # record (orchestrator side).
    if vendor_verdict is not None:
        boundary = (
            is_entry_point or is_sink or is_trust_boundary
            or has_joern_flows
        )
        if vendor_verdict.kind == KIND_GENERATED:
            if boundary:
                reasons.append(
                    f"generated code ({vendor_verdict.signal}), "
                    f"boundary-adjacent — glance: {vendor_verdict.detail}"
                )
                return TriageResult(
                    bucket=TriageBucket.GLANCE,
                    reasons=tuple(reasons),
                    token_budget=TOKEN_BUDGETS[TriageBucket.GLANCE],
                    priority_score=priority_score,
                    vendor_tier=vendor_verdict.kind,
                )
            if vendor_verdict.corroborated:
                if (
                    has_dangerous_callees
                    or on_taint_path
                    or vendor_file_dangerous
                ):
                    if has_dangerous_callees:
                        signal = "dangerous callees"
                    elif on_taint_path:
                        signal = "on taint path"
                    else:
                        # The per-function evidence matches surface
                        # spellings; this signal is the file-level
                        # import-RESOLVED check (aliased imports,
                        # method-value references) — the value carries
                        # the resolver's own wording (resolved
                        # dangerous callee, or an over-cap file whose
                        # resolution is incomplete).
                        signal = vendor_file_dangerous
                    reasons.append(
                        f"generated code ({vendor_verdict.signal}) "
                        f"with {signal} — glance: {vendor_verdict.detail}"
                    )
                    return TriageResult(
                        bucket=TriageBucket.GLANCE,
                        reasons=tuple(reasons),
                        token_budget=TOKEN_BUDGETS[TriageBucket.GLANCE],
                        priority_score=priority_score,
                        vendor_tier=vendor_verdict.kind,
                    )
                reasons.append(
                    f"generated code ({vendor_verdict.signal}): "
                    f"{vendor_verdict.detail}"
                )
                return TriageResult(
                    bucket=TriageBucket.SKIP,
                    reasons=tuple(reasons),
                    token_budget=TOKEN_BUDGETS[TriageBucket.SKIP],
                    priority_score=priority_score,
                    vendor_tier=vendor_verdict.kind,
                )
            reasons.append(
                f"generated code ({vendor_verdict.signal}): "
                f"{vendor_verdict.detail}"
            )
            return TriageResult(
                bucket=TriageBucket.GLANCE,
                reasons=tuple(reasons),
                token_budget=TOKEN_BUDGETS[TriageBucket.GLANCE],
                priority_score=priority_score,
                vendor_tier=vendor_verdict.kind,
            )
        if not boundary:
            reasons.append(
                f"vendored code ({vendor_verdict.signal}): "
                f"{vendor_verdict.detail}"
            )
            return TriageResult(
                bucket=TriageBucket.GLANCE,
                reasons=tuple(reasons),
                token_budget=TOKEN_BUDGETS[TriageBucket.GLANCE],
                priority_score=priority_score,
                vendor_tier=vendor_verdict.kind,
            )
        # Boundary-adjacent vendored code: normal routing below.

    if is_entry_point:
        reasons.append("entry point")
    if is_sink:
        reasons.append("sink")
    if is_trust_boundary:
        reasons.append("trust boundary")
    if has_joern_flows:
        reasons.append("Joern taint-to-sink flow")
    if sloc >= _DEEP_DIVE_SLOC:
        reasons.append(f"large ({sloc} SLOC)")
    if branch_count >= _HIGH_COMPLEXITY_BRANCHES:
        reasons.append(f"high complexity ({branch_count} branches)")
    if caller_count >= 5 and (is_sink or has_dangerous_callees):
        reasons.append(f"widely called sink/dangerous ({caller_count} callers)")

    if reasons:
        return TriageResult(
            bucket=TriageBucket.DEEP_DIVE,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.DEEP_DIVE],
            priority_score=priority_score,
        )

    if on_taint_path or has_dangerous_callees or stack_buffer_writer:
        if on_taint_path:
            reasons.append("on taint path")
        elif has_dangerous_callees:
            reasons.append("has dangerous callees")
        else:
            reasons.append("writes fixed-size stack buffer")
        return TriageResult(
            bucket=TriageBucket.INVESTIGATE,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.INVESTIGATE],
            priority_score=priority_score,
        )

    if sloc > _GLANCE_MAX_SLOC:
        reasons.append(f"moderate size ({sloc} SLOC)")
        return TriageResult(
            bucket=TriageBucket.INVESTIGATE,
            reasons=tuple(reasons),
            token_budget=TOKEN_BUDGETS[TriageBucket.INVESTIGATE],
            priority_score=priority_score,
        )

    reasons.append("low complexity, no taint exposure")
    return TriageResult(
        bucket=TriageBucket.GLANCE,
        reasons=tuple(reasons),
        token_budget=TOKEN_BUDGETS[TriageBucket.GLANCE],
        priority_score=priority_score,
    )


def classify_all(
    gaps: Sequence[dict[str, Any]],
    *,
    entry_points: frozenset[str] = frozenset(),
    sinks: frozenset[str] = frozenset(),
    trust_boundaries: frozenset[str] = frozenset(),
    taint_path_keys: frozenset[str] = frozenset(),
    joern_flow_keys: frozenset[str] = frozenset(),
    binary_absent_keys: frozenset[str] = frozenset(),
    sink_unreachable_keys: frozenset[str] = frozenset(),
    validate_confirmed_keys: frozenset[str] = frozenset(),
    dangerous_callee_keys: frozenset[str] = frozenset(),
    callback_target_names: frozenset[str] = frozenset(),
    priority_scores: dict[str, float] | None = None,
    prefilter_results: dict[str, PrefilterResult] | None = None,
    target_path: Path | None = None,
    vendor_verdicts: dict[str, VendorVerdict] | None = None,
) -> dict[str, TriageResult]:
    """Classify all gap functions. Returns {file:function: TriageResult}.

    ``target_path`` enables the lazy source read behind the
    stack-buffer skip veto: only functions the sink-unreachable skip
    rule could otherwise drop (small, no exempting signal) get their
    line range read — a handful per run, never the whole tree.

    ``callback_target_names`` are bare function names known to be
    registered in dispatch/ops tables (function-pointer callers): the
    sink-unreachable skip never fires for them. Names, not
    ``file:function`` keys — a registration site knows the handler's
    name, not its defining file.

    ``vendor_verdicts`` are per-FILE vendored/generated verdicts (see
    core.audit.vendored_detector). Pinned and force-review gaps are
    exempt — an operator pin (or a corpus label pin) is an explicit
    review order the vendored tier must never eat.
    """
    scores = priority_scores or {}
    prefilters = prefilter_results or {}
    results: dict[str, TriageResult] = {}
    vendor_dangerous_files: dict[str, bool] = {}

    for gap in gaps:
        bare_key = f"{gap['file']}:{gap['name']}"
        line_start = gap.get("line_start", 0)
        key = f"{bare_key}:{line_start}"
        sloc = gap.get("sloc", (gap.get("line_end", 0) or 0) - (gap.get("line_start", 0) or 0))
        # Clamp BEFORE the veto gate below: a malformed record with a
        # negative sloc still classifies as small (skip-eligible), so
        # its source must be read for the stack-buffer veto — an
        # unclamped negative value failed the 0 <= sloc gate and
        # bypassed the read while the function went on to SKIP.
        sloc = max(sloc, 0)
        caller_count = len(gap.get("callers", []))

        source = gap.get("source", "") or ""
        if (
            not source
            and target_path is not None
            and bare_key in sink_unreachable_keys
            and 0 <= sloc <= 30
            and bare_key not in entry_points
            and bare_key not in sinks
            and bare_key not in trust_boundaries
            and bare_key not in dangerous_callee_keys
            and gap["name"] not in callback_target_names
        ):
            source = _read_function_source(gap, target_path)

        vendor_verdict = None
        if (
            vendor_verdicts
            and not gap.get("pinned")
            and not gap.get("force_review")
        ):
            vendor_verdict = vendor_verdicts.get(gap["file"])

        # Import-resolved dangerous-callee signal for the corroborated
        # generated skip candidates only (the per-function mechanical
        # signals match surface spellings — aliased imports and
        # method-value references evade them). One resolver run per
        # file, memoised for the call.
        vendor_file_dangerous = None
        if (
            vendor_verdict is not None
            and vendor_verdict.kind == KIND_GENERATED
            and vendor_verdict.corroborated
            and target_path is not None
        ):
            f = gap["file"]
            if f not in vendor_dangerous_files:
                vendor_dangerous_files[f] = _vendor_file_dangerous(
                    f, target_path,
                )
            vendor_file_dangerous = vendor_dangerous_files[f]

        results[key] = classify_function(
            file=gap["file"],
            function=gap["name"],
            sloc=sloc,
            source=source,
            priority_score=scores.get(bare_key, 0.0),
            is_entry_point=bare_key in entry_points,
            is_sink=bare_key in sinks,
            is_trust_boundary=bare_key in trust_boundaries,
            on_taint_path=bare_key in taint_path_keys,
            has_joern_flows=bare_key in joern_flow_keys,
            has_dangerous_callees=bare_key in dangerous_callee_keys,
            is_callback_target=gap["name"] in callback_target_names,
            binary_absent=bare_key in binary_absent_keys,
            sink_unreachable=bare_key in sink_unreachable_keys,
            validate_confirmed=bare_key in validate_confirmed_keys,
            prefilter=prefilters.get(bare_key),
            branch_count=gap.get("branch_count", 0),
            caller_count=caller_count,
            vendor_verdict=vendor_verdict,
            vendor_file_dangerous=vendor_file_dangerous,
        )

    return results


def vendor_decision(tr: TriageResult) -> str | None:
    """``"skip"`` / ``"glance"`` when the vendored/generated tier
    routed this function; ``None`` when it did not fire (no verdict,
    pinned, or boundary-adjacent vendored code on normal routing).
    Consumed by the orchestrator's suppressions.jsonl recorder — every
    decision this reports gets one audit record. Reads the structured
    ``vendor_tier`` field, never the prose reason strings: rewording a
    reason must not silently drop audit-trail records."""
    if tr.vendor_tier is None:
        return None
    if tr.bucket == TriageBucket.SKIP:
        return "skip"
    if tr.bucket == TriageBucket.GLANCE:
        return "glance"
    return None


def format_triage_summary(results: dict[str, TriageResult]) -> str:
    """One-line summary of triage distribution."""
    counts = dict.fromkeys(TriageBucket, 0)
    for tr in results.values():
        counts[tr.bucket] += 1
    total = len(results)
    if total == 0:
        return "Triage: no functions"
    parts = []
    for bucket in TriageBucket:
        c = counts[bucket]
        pct = 100 * c / total
        parts.append(f"{bucket.value}={c} ({pct:.0f}%)")
    return f"Triage: {total} functions — {', '.join(parts)}"


# ── Generated code detection ─────────────────────────────────────────


def detect_generated_files(
    gaps: Sequence[dict[str, Any]],
    *,
    target_path: Path | None = None,
) -> list[str]:
    """Files with explicit generator provenance (banner / filename).

    Thin view over :func:`core.audit.vendored_detector.
    detect_vendored_files` kept for the post-loop reporting consumer;
    the triage tier itself consumes the full per-file verdicts.
    """
    return [
        file_path
        for file_path, verdict in detect_vendored_files(
            gaps, target_path=target_path,
        ).items()
        if verdict.kind == KIND_GENERATED
    ]


def _alias_resolved_dangerous(source: str, ext: str) -> bool:
    """True when a call or reference in *source*, resolved through the
    file's extracted import table, targets a dangerous function.

    The mechanical dangerous-callee evidence the vendored tier
    consumes matches SURFACE spellings, so a planted "generated" file
    using an aliased import (``import zz "os/exec"``, ``import
    subprocess as sp``) or a method-value reference (``f := zz.
    Command``) carries zero evidence. This resolver checks the
    RESOLVED names: every call chain and every ``alias.attr``
    reference is rewritten through the import table (full import
    target and its last path segment — Go's ``os/exec.Command`` and
    ``exec.Command`` are both catalogued) and tested against
    ``core.inventory.sink_discovery.DANGEROUS_TARGETS``. The table is
    extended one hop through local re-aliases (``q = sp``) and, when
    the extractor flags a wildcard import, unqualified names are
    tried under every dot-/star-imported module.

    Fail direction: unknown extension, missing grammar, unparseable
    source → False — the tier keeps its documented skip (no invented
    review load); the demotion only ever needs positive evidence.
    """
    try:
        from core.inventory.call_graph import _extractor_for
        from core.inventory.sink_discovery import _is_dangerous
    except ImportError:
        return False
    extractor = _extractor_for(ext)
    if extractor is None:
        return False
    try:
        graph = extractor(source)
    except Exception:  # noqa: BLE001 — parse failure is no-evidence
        return False
    imports: dict[str, str] = dict(graph.imports or {})

    # One-hop local re-aliases: `q = sp` / `q := sp` re-binds an
    # import alias to a name the call chains then start with. Single
    # hop, single pass — a longer alias chain stays unresolved (the
    # surface spelling remains visible to the per-function evidence
    # layers, so the residual is prefilter-tier).
    for am in re.finditer(r"(?m)^[^\S\n]*(\w+)\s*:?=\s*(\w+)\s*$", source):
        local, rhs = am.group(1), am.group(2)
        if rhs in imports and local not in imports:
            imports[local] = imports[rhs]

    # Wildcard imports drop the qualifier entirely (Go dot-import
    # `import . "os/exec"; Command(...)`, Python `from x import *`):
    # the extractor flags the indirection but discards the module, so
    # recover the module names lexically — only when the flag is set.
    wildcard_modules: list[str] = []
    try:
        from core.inventory.call_graph import INDIRECTION_WILDCARD_IMPORT
        flagged = INDIRECTION_WILDCARD_IMPORT in (graph.indirection or set())
    except ImportError:
        flagged = False
    if flagged:
        for wm in re.finditer(
            r'(?m)^[^\S\n]*(?:import\s+)?\.\s+"([^"]+)"', source,
        ):
            wildcard_modules.append(wm.group(1))
        for wm in re.finditer(
            r"(?m)^[^\S\n]*from\s+([\w.]+)\s+import\s+\*", source,
        ):
            wildcard_modules.append(wm.group(1))

    def _qualified_dangerous(target: str, rest: list[str]) -> bool:
        if _is_dangerous([target, *rest]):
            return True
        seg = target.replace("::", "/").rsplit("/", 1)[-1]
        return seg != target and _is_dangerous([seg, *rest])

    def _dangerous(chain: list[str]) -> bool:
        if _is_dangerous(chain):
            return True
        target = imports.get(chain[0]) if chain else None
        if target and _qualified_dangerous(target, chain[1:]):
            return True
        # Unqualified name under a wildcard import: try every
        # dot-imported / star-imported module as the qualifier.
        if len(chain) == 1:
            return any(
                _qualified_dangerous(w, chain) for w in wildcard_modules
            )
        return False

    for call in graph.calls or []:
        if call.chain and _dangerous(list(call.chain)):
            return True
    # Method-value references never emit a call site (`f := zz.
    # Command`; `r = sp.run`): scan alias.attr spellings lexically and
    # resolve the same way. Aliases only — a bare-word scan would be
    # noise; the from-import single-name case is covered by the call
    # path above when called, and by this scan's alias iteration when
    # the alias itself maps to a dangerous dotted target.
    for alias, target in imports.items():
        for m in re.finditer(
            rf"\b{re.escape(alias)}\s*\.\s*(\w+)", source,
        ):
            if _dangerous([alias, m.group(1)]):
                return True
        if "." in target and _is_dangerous([target]) and re.search(
            rf"(?<![\w.]){re.escape(alias)}\b(?!\s*\()", source,
        ):
            return True
    return False


def _vendor_file_dangerous(
    file_path: str, target_path: Path,
) -> str | None:
    """Import-resolved dangerous-callee check for one vendored file.

    Returns the glance-demotion signal string, or None when the skip
    may stand. Containment identical to :func:`_read_function_source`;
    a read FAILURE is no-evidence (skip stays) — but a TRUNCATED read
    is not: this check exists so a planted "generated" file with
    dangerous calls never becomes invisible, and a plant that pads the
    read cap before its `import subprocess as sp` would otherwise keep
    the corroborated skip. An over-cap file demotes to glance with the
    incompleteness named (unlike the stack-buffer veto's documented
    fail-open-toward-SKIP, which preserves pre-veto behaviour — here
    fail-open would contradict the check's anti-plant purpose)."""
    resolved = safe_join(target_path, file_path)
    if resolved is None:
        return None
    got = read_text_capped(resolved)
    if got is None:
        return None
    text, truncated = got
    ext = "." + file_path.rsplit(".", 1)[-1] if "." in file_path else ""
    if _alias_resolved_dangerous(text, ext):
        return "import-resolved dangerous callees"
    if truncated:
        return (
            "file exceeds the dangerous-callee resolver cap — "
            "resolution incomplete"
        )
    return None


def _read_function_source(gap: dict[str, Any], target_path: Path) -> str:
    """Read one function's line range for the stack-buffer skip veto.

    Path-traversal-safe via ``safe_join``; any read failure returns ""
    (the veto then simply doesn't fire — fail-open toward SKIP keeps
    the pre-veto behaviour rather than inventing review load)."""
    resolved = safe_join(target_path, gap.get("file", ""))
    if resolved is None:
        return ""
    start = int(gap.get("line_start") or 0)
    end = int(gap.get("line_end") or 0)
    if start <= 0 or end < start:
        return ""
    # Capped read (core.source): an over-cap planted file yields only
    # the in-cap prefix — lines past it are missing and the veto
    # simply doesn't fire (the documented fail-open-toward-SKIP
    # direction), instead of the whole file buffering into memory.
    # newline="" + split_lines: the gap span is a raw-byte-model line
    # range, so neither a universal-newline read nor an exotic
    # terminator may shift the window.
    got = read_text_capped(resolved, newline="")
    if got is None:
        return ""
    lines = split_lines(got[0])
    return "\n".join(lines[start - 1:end])


