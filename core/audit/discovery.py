"""Cross-scope discovery engine.

Post-structured-pass analysis that finds contract mismatches between
callers and callees across module boundaries, and state-machine
violations across cross-file field handlers.  Produces weakness
records in the same schema as the structured pass, consumable by the
composition engine and verification pipeline.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from core.llm.prompt_budget import estimate_tokens

logger = logging.getLogger(__name__)

# ── constants ───────────────────────────────────────────────────────

DEFAULT_MAX_SEAMS = 500
DEFAULT_TOKEN_BUDGET = 8000
CALL_SITE_CONTEXT_LINES = 2

_INPUT_PREFIX_RE = re.compile(
    r"(?:recv|read|parse|decode|process|handle)", re.IGNORECASE,
)
_INPUT_SUFFIX_RE = re.compile(
    r"(?:input|packet|request|message|buffer|data|frame|query)", re.IGNORECASE,
)

_STATE_NAME_RE = re.compile(
    r"(state|status|phase|mode|flag[s]?|is_|has_|enabled|active|locked)",
    re.IGNORECASE,
)

DEFAULT_SM_MIN_FILES = 2
DEFAULT_SM_MIN_HANDLERS = 3
DEFAULT_SM_MAX_BUNDLES = 50
HANDLER_CONTEXT_LINES = 10

DEFAULT_MAX_SWEEP_TARGETS = 40
MIN_SWEEP_LINES = 10
MAX_CALLER_SIGNATURES = 3

# Canonical guard-type vocabulary — must match collector._GUARD_TYPE_VALUES
# and the llm_review schema enum.
_GUARD_TYPES = frozenset({
    "bounds", "null_safety", "validation", "sanitisation",
    "lifetime", "ordering", "concurrency", "other",
})

# LLM-emitted synonyms → canonical form.  Applied once at parse time
# so downstream consumers never see the variant spelling.
_GUARD_TYPE_ALIASES: dict[str, str] = {
    "null_check": "null_safety",
    "lifecycle": "lifetime",
    "init": "validation",
    "type": "validation",
}


def _normalise_guard_type(raw: str) -> str:
    """Return canonical guard type, or empty string if unrecognised."""
    gt = raw.strip().lower()
    gt = _GUARD_TYPE_ALIASES.get(gt, gt)
    return gt if gt in _GUARD_TYPES else ""


_CONFIDENCE_VALUES = frozenset({"high", "medium", "low"})


def _normalise_confidence(raw: str) -> str:
    """Return canonical confidence, defaulting to ``"medium"``."""
    c = raw.strip().lower()
    return c if c in _CONFIDENCE_VALUES else "medium"


# Single-character or very short names that are almost always macros,
# aliases, or wrappers — not interesting contract surfaces.
MIN_CALLEE_LINES = 5

_LANG_MAP = {
    ".c": "c", ".h": "c",
    ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp", ".hh": "cpp", ".hpp": "cpp",
    ".py": "python",
    ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
}


# ── data structures ────────────────────────────────────────────────

@dataclass
class SeamBundle:
    """One cross-module seam packaged for LLM review."""

    caller_fid: str
    callee_fid: str
    caller_source: str
    callee_source: str
    call_site_snippet: str
    annotation: str
    priority_score: float
    priority_reason: str


@dataclass
class HandlerSite:
    """One access site for a state field."""

    file: str
    function: str
    line: int
    code: str
    access: str  # "read" or "write"
    context: str  # surrounding source lines


@dataclass
class StateMachineBundle:
    """All handlers of one state field, packaged for LLM review."""

    field_name: str
    handler_sites: list[HandlerSite]
    annotation: str
    priority_score: float
    priority_reason: str


@dataclass
class DiscoveryResult:
    """Output from one discovery prompt."""

    weaknesses: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    source: str = "contract_perspective"
    seam_or_field: str = ""
    cost_usd: float = 0.0


@dataclass
class SweepTarget:
    """One high-priority function selected for multi-perspective sweep."""

    fid: str
    source: str
    callers_source: str
    annotation: str
    priority_score: float
    priority_reason: str


# ── checklist helpers ───────────────────────────────────────────────

def _build_func_index(
    checklist: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Map ``file:function`` → checklist item dict."""
    idx: dict[str, dict[str, Any]] = {}
    for f_entry in checklist.get("files", []):
        fname = f_entry.get("path", "")
        for item in f_entry.get("items", []):
            fn = item.get("name", "")
            if fn:
                idx[f"{fname}:{fn}"] = {
                    "file": fname,
                    "name": fn,
                    "line_start": item.get("line_start", 0),
                    "line_end": item.get("line_end", 0),
                    "signature": item.get("signature", ""),
                }
    return idx


def _build_defined_funcs(
    checklist: dict[str, Any],
) -> dict[str, set[str]]:
    """Map function name → set of files that define it.

    When a name appears in multiple files and at least one instance
    carries a parsed signature, instances without a signature are
    dropped — they are almost always false extractions where the
    regex parser mistook a multi-line *call* for a definition.
    """
    raw: dict[str, list[tuple[str, bool]]] = defaultdict(list)
    for f_entry in checklist.get("files", []):
        fname = f_entry.get("path", "")
        for item in f_entry.get("items", []):
            fn = item.get("name", "")
            if fn:
                raw[fn].append((fname, bool(item.get("signature"))))

    defined: dict[str, set[str]] = {}
    for fn, locs in raw.items():
        if len(locs) > 1 and any(has_sig for _, has_sig in locs):
            defined[fn] = {f for f, has_sig in locs if has_sig}
        else:
            defined[fn] = {f for f, _ in locs}
    return defined


# ── seam extraction ─────────────────────────────────────────────────

def _extract_cross_file_seams(
    checklist: dict[str, Any],
) -> set[tuple[str, str]]:
    """Extract (caller_fid, callee_fid) pairs crossing file boundaries.

    Only includes seams where both the caller and callee are defined
    in the checklist (internal functions).  External functions (libc
    etc.) are excluded by definition — they have no checklist item.
    """
    defined = _build_defined_funcs(checklist)
    seams: set[tuple[str, str]] = set()

    for f_entry in checklist.get("files", []):
        fname = f_entry.get("path", "")
        cg = f_entry.get("call_graph")
        if not cg:
            continue
        calls = cg.get("calls", [])
        if not isinstance(calls, list):
            continue
        for call in calls:
            if not isinstance(call, dict):
                continue
            chain = call.get("chain", [])
            caller = call.get("caller", "")
            if not chain or not caller:
                continue
            callee_name = chain[-1] if isinstance(chain, list) else chain
            if not isinstance(callee_name, str):
                continue
            for callee_file in defined.get(callee_name, ()):
                if callee_file != fname:
                    seams.add(
                        (f"{fname}:{caller}", f"{callee_file}:{callee_name}")
                    )
    return seams


# ── seam prioritisation ────────────────────────────────────────────

def _score_seam(
    caller_fid: str,
    callee_fid: str,
    *,
    sinks: set[str],
    entry_reachable: set[str],
    weakness_fids: set[str],
    fan_in: Counter[str],
) -> tuple[float, str]:
    """Score a seam for priority.  Returns (score, reason)."""
    callee_file, callee_name = callee_fid.rsplit(":", 1)
    caller_file = caller_fid.rsplit(":", 1)[0]
    score = 0.0
    reasons: list[str] = []

    if callee_fid in sinks or callee_fid in entry_reachable:
        score += 3
        reasons.append("sink/entry-reachable")

    if callee_fid in weakness_fids:
        score += 2
        reasons.append("existing-weakness")

    fi = fan_in[callee_fid]
    if fi >= 5:
        score += 1
        reasons.append(f"fan-in={fi}")

    caller_dir = str(Path(caller_file).parent)
    callee_dir = str(Path(callee_file).parent)
    if caller_dir != callee_dir:
        score += 1
        reasons.append("cross-directory")

    if _INPUT_PREFIX_RE.search(callee_name) and _INPUT_SUFFIX_RE.search(callee_name):
        score += 2
        reasons.append("input-handler-name")

    return score, "; ".join(reasons) if reasons else "cross-file"


def build_seam_bundles(
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    entry_points: set[str],
    *,
    target_path: Path,
    max_seams: int = DEFAULT_MAX_SEAMS,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    weakness_fids: set[str] | None = None,
) -> list[SeamBundle]:
    """Select and prioritise cross-module seams, read source, budget-fit."""

    seams = _extract_cross_file_seams(checklist)
    if not seams:
        logger.info("discovery: no cross-file seams found")
        return []

    func_index = _build_func_index(checklist)

    # Build scoring inputs
    sinks: set[str] = set()
    if context_map:
        from core.audit._util import extract_context_map_set
        sinks = extract_context_map_set(context_map, "sinks")
        entry_points = entry_points | extract_context_map_set(
            context_map, "entry_points",
        )

    fan_in: Counter[str] = Counter()
    for _, callee_fid in seams:
        fan_in[callee_fid] += 1

    wf = weakness_fids or set()

    # Score and sort
    scored: list[tuple[float, int, str, str, str]] = []
    for caller_fid, callee_fid in seams:
        score, reason = _score_seam(
            caller_fid, callee_fid,
            sinks=sinks,
            entry_reachable=entry_points,
            weakness_fids=wf,
            fan_in=fan_in,
        )
        scored.append((
            -score, -fan_in[callee_fid], caller_fid, callee_fid, reason,
        ))
    scored.sort()

    # Build bundles up to max_seams.  First pass: one caller per
    # callee (maximum callee diversity).  Second pass: fill remaining
    # slots with additional callers for callees already seen.
    half_budget = token_budget // 2
    bundles: list[SeamBundle] = []
    seen_callees: set[str] = set()
    deferred: list[tuple[float, str, str, str]] = []

    for neg_score, neg_fi, caller_fid, callee_fid, reason in scored:
        if callee_fid in seen_callees:
            deferred.append((neg_score, caller_fid, callee_fid, reason))
            continue
        bundle = _try_build_bundle(
            caller_fid, callee_fid, reason, -neg_score,
            func_index, target_path, half_budget, token_budget,
        )
        if bundle is not None:
            bundles.append(bundle)
            seen_callees.add(callee_fid)
            if len(bundles) >= max_seams:
                break

    # Second pass: additional callers for already-seen callees
    for neg_score, caller_fid, callee_fid, reason in deferred:
        if len(bundles) >= max_seams:
            break
        bundle = _try_build_bundle(
            caller_fid, callee_fid, reason, -neg_score,
            func_index, target_path, half_budget, token_budget,
        )
        if bundle is not None:
            bundles.append(bundle)

    logger.info(
        "discovery: %d seams → %d bundles (max %d)",
        len(seams), len(bundles), max_seams,
    )
    return bundles


def _try_build_bundle(
    caller_fid: str,
    callee_fid: str,
    reason: str,
    score_val: float,
    func_index: dict[str, dict[str, Any]],
    target_path: Path,
    half_budget: int,
    token_budget: int,
) -> SeamBundle | None:
    """Try to build a SeamBundle; returns None if source is unreadable
    or the callee is too small to be interesting."""
    caller_info = func_index.get(caller_fid)
    callee_info = func_index.get(callee_fid)
    if not caller_info or not callee_info:
        return None

    if not callee_info.get("signature"):
        return None

    callee_span = callee_info.get("line_end", 0) - callee_info.get("line_start", 0)
    if callee_span < MIN_CALLEE_LINES:
        return None

    callee_source = _read_function_source(target_path, callee_info, half_budget)
    caller_source = _read_function_source(target_path, caller_info, half_budget)
    if not callee_source or not caller_source:
        return None

    callee_name = callee_info["name"]
    call_snippet = _extract_call_site_snippet(
        target_path / caller_info["file"],
        callee_name,
        caller_info["line_start"],
        caller_info["line_end"],
    )

    combined_tokens = estimate_tokens(caller_source) + estimate_tokens(callee_source)
    if combined_tokens > token_budget:
        caller_source = _demote_to_signature(caller_info, call_snippet)

    lang = _detect_lang(callee_info["file"])
    annotation = _render_annotation(
        caller_fid, callee_fid,
        caller_info, callee_info,
        caller_source, callee_source,
        call_snippet, lang,
    )
    return SeamBundle(
        caller_fid=caller_fid,
        callee_fid=callee_fid,
        caller_source=caller_source,
        callee_source=callee_source,
        call_site_snippet=call_snippet,
        annotation=annotation,
        priority_score=score_val,
        priority_reason=reason,
    )


# ── source reading ──────────────────────────────────────────────────

def _read_function_source(
    target_path: Path,
    func_info: dict[str, Any],
    max_tokens: int,
) -> str | None:
    """Read a function's source, truncating to fit the token budget."""
    full_path = target_path / func_info["file"]
    from core.audit.context import _read_target_text
    text = _read_target_text(full_path)
    if text is None:
        return None

    from core.source.lines import split_lines

    lines = split_lines(text)
    start = max(0, func_info["line_start"] - 1)
    end = func_info.get("line_end") or len(lines)
    func_lines = lines[start:end]
    source = "\n".join(func_lines)

    if estimate_tokens(source) <= max_tokens:
        return source

    # Truncate from the centre, keeping head and tail
    chars = max_tokens * 4
    if len(source) <= chars:
        return source
    half = chars // 2
    return source[:half] + "\n/* ... truncated ... */\n" + source[-half:]


def _extract_call_site_snippet(
    file_path: Path,
    callee_name: str,
    caller_start: int,
    caller_end: int,
) -> str:
    """Extract lines around the call to callee_name within the caller."""
    from core.audit.context import _read_target_text
    text = _read_target_text(file_path)
    if not text:
        return ""

    from core.source.lines import split_lines

    lines = split_lines(text)
    start = max(0, caller_start - 1)
    end = caller_end or len(lines)
    caller_lines = lines[start:end]

    pattern = re.compile(r"\b" + re.escape(callee_name) + r"\s*\(")
    for i, line in enumerate(caller_lines):
        if pattern.search(line):
            abs_line = start + i
            snippet_start = max(0, abs_line - CALL_SITE_CONTEXT_LINES)
            snippet_end = min(len(lines), abs_line + CALL_SITE_CONTEXT_LINES + 1)
            return "\n".join(
                f"{j + 1}: {lines[j]}"
                for j in range(snippet_start, snippet_end)
            )
    return ""


def _demote_to_signature(
    func_info: dict[str, Any],
    call_snippet: str,
) -> str:
    """Demote a function to its signature + the call-site snippet."""
    sig = func_info.get("signature", func_info["name"])
    parts = [sig]
    if call_snippet:
        parts.append(f"\n// Call site:\n{call_snippet}")
    return "\n".join(parts)


def _detect_lang(file_path: str) -> str:
    suffix = Path(file_path).suffix.lower()
    return _LANG_MAP.get(suffix, "")


def _render_annotation(
    caller_fid: str,
    callee_fid: str,
    caller_info: dict[str, Any],
    callee_info: dict[str, Any],
    caller_source: str,
    callee_source: str,
    call_snippet: str,
    lang: str,
) -> str:
    """Render the structural annotation for a seam bundle."""
    caller_file = caller_info["file"]
    callee_file = callee_info["file"]
    caller_name = caller_info["name"]
    callee_name = callee_info["name"]

    parts = [
        f"## Contract analysis: {caller_file}:{caller_name}"
        f" → {callee_file}:{callee_name}",
        "",
        f"**Producer** ({callee_file}, line {callee_info['line_start']}):"
        " full source below.",
        f"**Consumer** ({caller_file}, line {caller_info['line_start']}):"
        f" calls the producer.",
        "",
        "### Producer source",
        f"```{lang}",
        callee_source,
        "```",
        "",
        "### Consumer source",
        f"```{lang}",
        caller_source,
        "```",
    ]
    if call_snippet:
        parts.extend([
            "",
            "### Call site",
            f"```{lang}",
            call_snippet,
            "```",
        ])
    return "\n".join(parts)


# ── contract perspective prompt ─────────────────────────────────────

CONTRACT_PROMPT_TEMPLATE = """\
You are examining a cross-module call.  The consumer ({caller_fid}) \
calls the producer ({callee_fid}).

{annotation}

Analyse the contract between them:

1. Does the producer guarantee what the consumer assumes about \
return values — range, type, nullability, lifetime?
2. Does the consumer validate the producer's output, or trust it?
3. Are there parameter constraints the producer requires but the \
consumer doesn't establish?
4. What happens when the producer returns an error or edge-case value?
5. Would a reasonable future change to either side break the other?

For each contract gap you find:

- Classify the gap: bounds | null_safety | validation | sanitisation | \
lifetime | ordering | concurrency | other
- State the assumed property as a single phrase
- Describe the mechanism (how the gap leads to a bug)
- Map to a CWE class if applicable
- State whether the gap is a weakness (composable with other \
conditions) or a standalone vulnerability
- Confidence: high (strong evidence — specific code paths, concrete \
values), medium (plausible but needs caller/build context to confirm), \
low (speculative or depends on uncommon configurations)

Respond in JSON: {{ "findings": [ {{ "guard_type": "...", \
"assumed_property": "...", "mechanism": "...", "cwe_class": "...", \
"standalone": true/false, "confidence": "high|medium|low" }} ] }}

If the contract is sound, respond: {{ "findings": [] }}
"""


def _build_contract_prompt(bundle: SeamBundle) -> str:
    return CONTRACT_PROMPT_TEMPLATE.format(
        caller_fid=bundle.caller_fid,
        callee_fid=bundle.callee_fid,
        annotation=bundle.annotation,
    )


def _parse_findings(
    raw: str,
    bundle: SeamBundle,
) -> DiscoveryResult:
    """Parse LLM JSON response into a DiscoveryResult."""
    text = raw.strip()
    # Extract JSON from code fences — take the last fenced block
    # (LLMs commonly emit preamble text before the fence).
    _fence_matches = list(
        re.finditer(r"```(?:json)?[ \t]*\n(.+?)```", text, re.DOTALL),
    )
    if _fence_matches:
        text = _fence_matches[-1].group(1).strip()
    elif text.startswith("```"):
        lines = text.splitlines()
        lines = [l for l in lines if not l.startswith("```")]
        text = "\n".join(lines)

    result = DiscoveryResult(
        source="contract_perspective",
        seam_or_field=f"{bundle.caller_fid}->{bundle.callee_fid}",
    )

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        logger.warning(
            "discovery: failed to parse LLM response for %s → %s",
            bundle.caller_fid, bundle.callee_fid,
        )
        return result

    findings = parsed.get("findings", [])
    if not isinstance(findings, list):
        return result

    callee_file, callee_func = bundle.callee_fid.rsplit(":", 1)
    caller_file, caller_func = bundle.caller_fid.rsplit(":", 1)

    for f in findings:
        if not isinstance(f, dict):
            continue
        gt = _normalise_guard_type(f.get("guard_type", ""))
        if not gt:
            continue

        conf = _normalise_confidence(f.get("confidence", ""))
        weakness = {
            "property": f.get("assumed_property", ""),
            "guard_type": gt,
            "mechanism": f.get("mechanism", ""),
            "cwe_class": f.get("cwe_class"),
            "confidence": conf,
            "source": "contract_perspective",
            "guarded_by": (
                [] if f.get("standalone") else [bundle.caller_fid]
            ),
        }
        result.weaknesses.append(weakness)

        hypothesis = {
            "text": (
                f"Contract gap: {caller_file}:{caller_func} assumes "
                f"{gt} on {callee_file}:{callee_func} — "
                f"{f.get('mechanism', 'unspecified')}"
            ),
            "source": "contract_perspective",
            "standalone": bool(f.get("standalone")),
            "caller": bundle.caller_fid,
            "callee": bundle.callee_fid,
        }
        result.hypotheses.append(hypothesis)

    return result


# ── discovery runner ────────────────────────────────────────────────

def run_contract_discovery(
    bundles: list[SeamBundle],
    *,
    review_fn: Callable[[str, str], tuple[str, float]],
    max_cost_usd: float = 5.0,
) -> list[DiscoveryResult]:
    """Run the contract perspective prompt on each bundle.

    ``review_fn(system_prompt, user_prompt) -> (response_text, cost_usd)``
    is the LLM dispatch function.  The caller provides it so this
    module stays transport-agnostic.

    Stops early if cumulative cost exceeds ``max_cost_usd``.
    """
    results: list[DiscoveryResult] = []
    total_cost = 0.0

    system = (
        "You are a security auditor analysing cross-module contracts. "
        "Respond only with the JSON object described in the prompt."
    )

    for bundle in bundles:
        if total_cost >= max_cost_usd:
            logger.info(
                "discovery: cost cap reached ($%.2f >= $%.2f), "
                "stopping after %d/%d bundles",
                total_cost, max_cost_usd, len(results), len(bundles),
            )
            break

        prompt = _build_contract_prompt(bundle)
        try:
            response, cost = review_fn(system, prompt)
        except Exception as exc:
            from core.llm.client import is_budget_exceeded_error
            if is_budget_exceeded_error(exc):
                logger.info(
                    "discovery: run budget exhausted after %d/%d bundles",
                    len(results), len(bundles),
                )
                break
            logger.exception(
                "discovery: LLM call failed for %s → %s",
                bundle.caller_fid, bundle.callee_fid,
            )
            continue

        result = _parse_findings(response, bundle)
        result.cost_usd = cost
        total_cost += cost
        results.append(result)

    total_findings = sum(len(r.weaknesses) for r in results)
    logger.info(
        "discovery: %d bundles reviewed, %d findings, $%.2f total",
        len(results), total_findings, total_cost,
    )
    return results


# ── state machine discovery ───────────────────────────────────────

def build_state_machine_bundles(
    field_census: dict[str, Any],
    *,
    target_path: Path,
    min_files: int = DEFAULT_SM_MIN_FILES,
    min_handlers: int = DEFAULT_SM_MIN_HANDLERS,
    max_bundles: int = DEFAULT_SM_MAX_BUNDLES,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
) -> list[StateMachineBundle]:
    """Select cross-file state fields, read handler sites, budget-fit."""
    fields = field_census.get("fields", {})
    if not fields:
        logger.info("discovery: field census empty, no state machine bundles")
        return []

    candidates: list[tuple[float, str, dict[str, Any]]] = []

    for name, data in fields.items():
        writes = data.get("writes", [])
        reads = data.get("reads", [])
        all_sites = writes + reads
        if len(all_sites) < min_handlers:
            continue
        file_set = {s.get("file", "") for s in all_sites} - {""}
        if len(file_set) < min_files:
            continue
        score, reason = _score_field(name, writes, reads, file_set)
        candidates.append((-score, name, data))

    candidates.sort()

    bundles: list[StateMachineBundle] = []
    for neg_score, name, data in candidates[:max_bundles]:
        bundle = _try_build_sm_bundle(
            name, data, target_path, token_budget,
            -neg_score,
        )
        if bundle is not None:
            bundles.append(bundle)

    logger.info(
        "discovery: %d fields → %d state machine bundles (cap %d)",
        len(fields), len(bundles), max_bundles,
    )
    return bundles


def _score_field(
    name: str,
    writes: list[dict[str, Any]],
    reads: list[dict[str, Any]],
    file_set: set[str],
) -> tuple[float, str]:
    """Score a state field for priority."""
    score = 0.0
    reasons: list[str] = []

    if _STATE_NAME_RE.search(name):
        score += 2
        reasons.append("state-name")

    write_files = {s.get("file", "") for s in writes} - {""}
    read_files = {s.get("file", "") for s in reads} - {""}
    if write_files and read_files and write_files != read_files:
        score += 2
        reasons.append("cross-file-rw")

    if len(file_set) >= 4:
        score += 1
        reasons.append(f"spread={len(file_set)}")

    return score, "; ".join(reasons) if reasons else "cross-file"


def _try_build_sm_bundle(
    field_name: str,
    field_data: dict[str, Any],
    target_path: Path,
    token_budget: int,
    score: float,
) -> StateMachineBundle | None:
    """Build a StateMachineBundle from field census data."""
    writes = field_data.get("writes", [])
    reads = field_data.get("reads", [])

    handler_sites: list[HandlerSite] = []
    total_tokens = 0

    for access_type, sites in [("write", writes), ("read", reads)]:
        for site in sites:
            file_path = site.get("file", "")
            line = site.get("line", 0)
            function = site.get("function", "")
            code = site.get("code", "")
            if not file_path or not line:
                continue

            context = _read_handler_context(
                target_path / file_path, line,
            )

            hs = HandlerSite(
                file=file_path,
                function=function,
                line=line,
                code=code,
                access=access_type,
                context=context,
            )
            handler_sites.append(hs)
            total_tokens += estimate_tokens(context)

            if total_tokens > token_budget:
                break
        if total_tokens > token_budget:
            break

    if not handler_sites:
        return None

    _, reason = _score_field(
        field_name, writes, reads,
        {s.file for s in handler_sites},
    )
    annotation = _render_sm_annotation(field_name, handler_sites)
    return StateMachineBundle(
        field_name=field_name,
        handler_sites=handler_sites,
        annotation=annotation,
        priority_score=score,
        priority_reason=reason,
    )


def _read_handler_context(
    file_path: Path,
    line: int,
) -> str:
    """Read HANDLER_CONTEXT_LINES around a handler site."""
    from core.audit.context import _read_target_text

    text = _read_target_text(file_path)
    if not text:
        return ""

    from core.source.lines import split_lines

    lines = split_lines(text)
    start = max(0, line - 1 - HANDLER_CONTEXT_LINES)
    end = min(len(lines), line + HANDLER_CONTEXT_LINES)
    return "\n".join(
        f"{j + 1}: {lines[j]}" for j in range(start, end)
    )


def _render_sm_annotation(
    field_name: str,
    handler_sites: list[HandlerSite],
) -> str:
    """Render the structural annotation for a state machine bundle."""
    files = sorted({s.file for s in handler_sites})

    parts = [
        f"## State machine analysis: field `{field_name}` "
        f"across {len(files)} files",
        "",
        f"**Handlers:** {len(handler_sites)} sites "
        f"({sum(1 for s in handler_sites if s.access == 'write')} writes, "
        f"{sum(1 for s in handler_sites if s.access == 'read')} reads)",
        "",
    ]

    for site in handler_sites:
        label = "(W)" if site.access == "write" else "(R)"
        lang = _detect_lang(site.file)
        parts.extend([
            f"### {label} {site.file}:{site.function} (line {site.line})",
            f"```{lang}",
            site.context,
            "```",
            "",
        ])

    return "\n".join(parts)


STATE_MACHINE_PROMPT_TEMPLATE = """\
Here are all handlers that read or write the field `{field_name}` \
across {n_files} files.

Each handler is shown with its surrounding context.  Handlers are \
labelled (R) for read and (W) for write.

{annotation}
{concurrency_hint}
Analyse the state machine:

1. What are the valid states and transitions?
2. What happens if handler B fires before handler A completes?
3. Are there reachable states that shouldn't exist?
4. Is there a handler that writes without checking the current value?
5. Can an error path leave the field in an intermediate state?

For each issue, rate confidence: high (specific code paths prove the \
issue), medium (plausible but needs runtime context), low (speculative).

Respond in JSON: {{ "findings": [ {{ "guard_type": "...", \
"assumed_property": "...", "mechanism": "...", "cwe_class": "...", \
"standalone": true/false, "confidence": "high|medium|low" }} ] }}

If the state machine is sound, respond: {{ "findings": [] }}
"""


_HINT_SINGLE_THREADED = (
    "\nThis target is single-threaded (no threading primitives detected). "
    "Do NOT report race conditions, data races, or concurrency issues. "
    "Do NOT use CWE-362. "
    "Valid CWEs for single-threaded state machines: "
    "CWE-908, CWE-457, CWE-662, CWE-672, CWE-416, CWE-401, CWE-476. "
    "Focus on ordering, reachable-state, error-path cleanup, and "
    "unguarded-write bugs only.\n"
)
_HINT_MULTI_THREADED = (
    "\nThis target uses threads / concurrent execution. "
    "Consider data races and unsynchronised access when relevant.\n"
)


def detect_single_threaded(target_path: Path | str) -> bool:
    """Detect whether the target is single-threaded.

    Uses the mechanical veto scanner from refutation — the same regex
    that gates CWE-362 demotion in the structured pass.
    """
    from core.audit.refutation import _threading_primitives_seen

    return not _threading_primitives_seen(target_path).seen


def _build_sm_prompt(
    bundle: StateMachineBundle,
    concurrency_hint: str = "",
) -> str:
    files = sorted({s.file for s in bundle.handler_sites})
    return STATE_MACHINE_PROMPT_TEMPLATE.format(
        field_name=bundle.field_name,
        n_files=len(files),
        annotation=bundle.annotation,
        concurrency_hint=concurrency_hint,
    )


_RACE_CWES = frozenset({"CWE-362", "CWE-366", "CWE-367"})


def _parse_sm_findings(
    raw: str,
    bundle: StateMachineBundle,
    *,
    single_threaded: bool = False,
) -> DiscoveryResult:
    """Parse LLM JSON response into a DiscoveryResult for state machine."""
    text = raw.strip()
    _fence_matches = list(
        re.finditer(r"```(?:json)?[ \t]*\n(.+?)```", text, re.DOTALL),
    )
    if _fence_matches:
        text = _fence_matches[-1].group(1).strip()
    elif text.startswith("```"):
        lines = text.splitlines()
        lines = [ln for ln in lines if not ln.startswith("```")]
        text = "\n".join(lines)

    result = DiscoveryResult(
        source="state_machine",
        seam_or_field=bundle.field_name,
    )

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        logger.warning(
            "discovery: failed to parse SM response for field %s",
            bundle.field_name,
        )
        return result

    findings = parsed.get("findings", [])
    if not isinstance(findings, list):
        return result

    handler_files = sorted({s.file for s in bundle.handler_sites})

    for f in findings:
        if not isinstance(f, dict):
            continue
        gt = _normalise_guard_type(f.get("guard_type", ""))
        if not gt:
            continue

        cwe = f.get("cwe_class") or ""
        if single_threaded and any(cwe.startswith(c) for c in _RACE_CWES):
            continue

        conf = _normalise_confidence(f.get("confidence", ""))
        weakness = {
            "property": f.get("assumed_property", ""),
            "guard_type": gt,
            "mechanism": f.get("mechanism", ""),
            "cwe_class": cwe or None,
            "confidence": conf,
            "source": "state_machine",
            "guarded_by": [],
        }
        result.weaknesses.append(weakness)

        hypothesis = {
            "text": (
                f"State machine gap: field `{bundle.field_name}` — "
                f"{gt} — {f.get('mechanism', 'unspecified')}"
            ),
            "source": "state_machine",
            "standalone": bool(f.get("standalone")),
            "field": bundle.field_name,
            "files": handler_files,
        }
        result.hypotheses.append(hypothesis)

    return result


def run_state_machine_discovery(
    bundles: list[StateMachineBundle],
    *,
    review_fn: Callable[[str, str], tuple[str, float]],
    max_cost_usd: float = 5.0,
    single_threaded: bool = False,
) -> list[DiscoveryResult]:
    """Run the state machine prompt on each bundle."""
    results: list[DiscoveryResult] = []
    total_cost = 0.0
    hint = _HINT_SINGLE_THREADED if single_threaded else _HINT_MULTI_THREADED

    system = (
        "You are a security auditor analysing cross-module state machines. "
        "Respond only with the JSON object described in the prompt."
    )

    for bundle in bundles:
        if total_cost >= max_cost_usd:
            logger.info(
                "discovery: SM cost cap reached ($%.2f >= $%.2f), "
                "stopping after %d/%d bundles",
                total_cost, max_cost_usd, len(results), len(bundles),
            )
            break

        prompt = _build_sm_prompt(bundle, concurrency_hint=hint)
        try:
            response, cost = review_fn(system, prompt)
        except Exception as exc:
            from core.llm.client import is_budget_exceeded_error
            if is_budget_exceeded_error(exc):
                logger.info(
                    "discovery: SM run budget exhausted after %d/%d bundles",
                    len(results), len(bundles),
                )
                break
            logger.exception(
                "discovery: SM LLM call failed for field %s",
                bundle.field_name,
            )
            continue

        result = _parse_sm_findings(
            response, bundle, single_threaded=single_threaded,
        )
        result.cost_usd = cost
        total_cost += cost
        results.append(result)

    total_findings = sum(len(r.weaknesses) for r in results)
    logger.info(
        "discovery: SM %d bundles reviewed, %d findings, $%.2f total",
        len(results), total_findings, total_cost,
    )
    return results


# ── sweep target selection ─────────────────────────────────────────

def _score_sweep_target(
    fid: str,
    info: dict[str, Any],
    *,
    sinks: set[str],
    entry_reachable: set[str],
    weakness_fids: set[str],
    fan_in: Counter[str],
    cross_dir_callers: set[str],
) -> tuple[float, str]:
    """Score a function for sweep priority."""
    score = 0.0
    reasons: list[str] = []

    if fid in sinks or fid in entry_reachable:
        score += 3
        reasons.append("sink/entry-reachable")

    if fid in weakness_fids:
        score += 2
        reasons.append("existing-weakness")

    fi = fan_in[fid]
    if fi >= 5:
        score += 2
        reasons.append(f"fan-in={fi}")

    span = info.get("line_end", 0) - info.get("line_start", 0)
    if span >= 50:
        score += 1
        reasons.append(f"complex={span}L")

    func_name = fid.rsplit(":", 1)[-1] if ":" in fid else fid
    if (_INPUT_PREFIX_RE.search(func_name)
            and _INPUT_SUFFIX_RE.search(func_name)):
        score += 1
        reasons.append("input-handler-name")

    if fid in cross_dir_callers:
        score += 1
        reasons.append("cross-dir-callers")

    return score, "; ".join(reasons) if reasons else "eligible"


def _build_cross_dir_caller_set(
    checklist: dict[str, Any],
) -> set[str]:
    """Identify functions called from ≥2 directories."""
    callers_by_dir: dict[str, set[str]] = defaultdict(set)
    for f_entry in checklist.get("files", []):
        fname = f_entry.get("path", "")
        cg = f_entry.get("call_graph")
        if not cg:
            continue
        caller_dir = str(Path(fname).parent)
        calls = cg.get("calls", [])
        if not isinstance(calls, list):
            continue
        for call in calls:
            if not isinstance(call, dict):
                continue
            chain = call.get("chain", [])
            if not chain:
                continue
            callee_name = chain[-1] if isinstance(chain, list) else chain
            if isinstance(callee_name, str):
                callers_by_dir[callee_name].add(caller_dir)

    result: set[str] = set()
    func_index = _build_func_index(checklist)
    for func_name, dirs in callers_by_dir.items():
        if len(dirs) >= 2:
            for fid, info in func_index.items():
                if fid.endswith(f":{func_name}"):
                    result.add(fid)
    return result


def _collect_caller_signatures(
    fid: str,
    checklist: dict[str, Any],
    target_path: Path,
    max_callers: int = MAX_CALLER_SIGNATURES,
) -> str:
    """Collect top callers' signatures + call-site snippets."""
    func_name = fid.rsplit(":", 1)[-1] if ":" in fid else fid
    callers: list[tuple[str, str, str]] = []

    for f_entry in checklist.get("files", []):
        fname = f_entry.get("path", "")
        cg = f_entry.get("call_graph")
        if not cg:
            continue
        calls = cg.get("calls", [])
        if not isinstance(calls, list):
            continue
        for call in calls:
            if not isinstance(call, dict):
                continue
            chain = call.get("chain", [])
            caller = call.get("caller", "")
            if not chain or not caller:
                continue
            callee = chain[-1] if isinstance(chain, list) else chain
            if callee == func_name:
                caller_fid = f"{fname}:{caller}"
                for item in f_entry.get("items", []):
                    if item.get("name") == caller:
                        sig = item.get("signature", caller)
                        snippet = _extract_call_site_snippet(
                            target_path / fname,
                            func_name,
                            item.get("line_start", 0),
                            item.get("line_end", 0),
                        )
                        callers.append((caller_fid, sig, snippet))
                        break

    callers = callers[:max_callers]
    if not callers:
        return ""

    parts: list[str] = []
    for caller_fid, sig, snippet in callers:
        parts.append(f"Caller: {caller_fid}")
        parts.append(f"  Signature: {sig}")
        if snippet:
            parts.append(f"  Call site:\n{snippet}")
        parts.append("")
    return "\n".join(parts)


def build_sweep_targets(
    checklist: dict[str, Any],
    context_map: dict[str, Any] | None,
    entry_points: set[str],
    *,
    target_path: Path,
    max_targets: int = DEFAULT_MAX_SWEEP_TARGETS,
    token_budget: int = DEFAULT_TOKEN_BUDGET,
    weakness_fids: set[str] | None = None,
) -> list[SweepTarget]:
    """Select high-priority functions for sweep analysis."""
    func_index = _build_func_index(checklist)

    sinks: set[str] = set()
    if context_map:
        from core.audit._util import extract_context_map_set
        sinks = extract_context_map_set(context_map, "sinks")
        entry_points = entry_points | extract_context_map_set(
            context_map, "entry_points",
        )

    fan_in: Counter[str] = Counter()
    for f_entry in checklist.get("files", []):
        cg = f_entry.get("call_graph")
        if not cg:
            continue
        calls = cg.get("calls", [])
        if not isinstance(calls, list):
            continue
        for call in calls:
            if not isinstance(call, dict):
                continue
            chain = call.get("chain", [])
            if chain:
                callee_name = chain[-1] if isinstance(chain, list) else chain
                if isinstance(callee_name, str):
                    for callee_fid in func_index:
                        if callee_fid.endswith(f":{callee_name}"):
                            fan_in[callee_fid] += 1

    wf = weakness_fids or set()
    cross_dir = _build_cross_dir_caller_set(checklist)

    scored: list[tuple[float, int, str, dict[str, Any]]] = []
    for fid, info in func_index.items():
        span = info.get("line_end", 0) - info.get("line_start", 0)
        if span < MIN_SWEEP_LINES:
            continue
        score, reason = _score_sweep_target(
            fid, info,
            sinks=sinks,
            entry_reachable=entry_points,
            weakness_fids=wf,
            fan_in=fan_in,
            cross_dir_callers=cross_dir,
        )
        scored.append((-score, -fan_in[fid], fid, info))

    scored.sort()

    targets: list[SweepTarget] = []
    for neg_score, neg_fi, fid, info in scored[:max_targets]:
        source = _read_function_source(target_path, info, token_budget)
        if not source:
            continue

        callers_src = _collect_caller_signatures(
            fid, checklist, target_path,
        )

        lang = _detect_lang(info["file"])
        file_part, func_part = fid.rsplit(":", 1)
        annotation = (
            f"## Function: {func_part} ({file_part})\n\n"
            f"```{lang}\n{source}\n```"
        )

        _, reason = _score_sweep_target(
            fid, info,
            sinks=sinks,
            entry_reachable=entry_points,
            weakness_fids=wf,
            fan_in=fan_in,
            cross_dir_callers=cross_dir,
        )

        targets.append(SweepTarget(
            fid=fid,
            source=source,
            callers_source=callers_src,
            annotation=annotation,
            priority_score=-neg_score,
            priority_reason=reason,
        ))

    logger.info(
        "discovery: %d functions → %d sweep targets (max %d)",
        len(func_index), len(targets), max_targets,
    )
    return targets


def _parse_discovery_findings(
    raw: str,
    target: SweepTarget,
    source_tag: str,
) -> DiscoveryResult:
    """Parse LLM JSON response into a DiscoveryResult."""
    text = raw.strip()
    _fence_matches = list(
        re.finditer(r"```(?:json)?[ \t]*\n(.+?)```", text, re.DOTALL),
    )
    if _fence_matches:
        text = _fence_matches[-1].group(1).strip()
    elif text.startswith("```"):
        lines = text.splitlines()
        lines = [ln for ln in lines if not ln.startswith("```")]
        text = "\n".join(lines)

    result = DiscoveryResult(
        source=source_tag,
        seam_or_field=target.fid,
    )

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        logger.warning(
            "discovery: failed to parse response for %s",
            target.fid,
        )
        return result

    findings = parsed.get("findings", [])
    if not isinstance(findings, list):
        return result

    file_part = target.fid.rsplit(":", 1)[0] if ":" in target.fid else ""
    func_part = target.fid.rsplit(":", 1)[1] if ":" in target.fid else target.fid

    for f in findings:
        if not isinstance(f, dict):
            continue
        gt = _normalise_guard_type(f.get("guard_type", ""))
        if not gt:
            continue

        conf = _normalise_confidence(f.get("confidence", ""))
        weakness = {
            "property": f.get("assumed_property", ""),
            "guard_type": gt,
            "mechanism": f.get("mechanism", ""),
            "cwe_class": f.get("cwe_class"),
            "confidence": conf,
            "source": source_tag,
            "guarded_by": [],
        }
        result.weaknesses.append(weakness)

        hypothesis = {
            "text": (
                f"Sweep ({source_tag}): {file_part}:{func_part} — "
                f"{gt}: {f.get('mechanism', 'unspecified')}"
            ),
            "source": source_tag,
            "standalone": bool(f.get("standalone")),
            "fid": target.fid,
        }
        result.hypotheses.append(hypothesis)

    return result


# ── assumption mining ──────────────────────────────────────────────

ASSUMPTION_EXTRACT_TEMPLATE = """\
{annotation}

List the assumptions this function makes that are:
- **Implicit** (not checked or asserted in the code), AND
- **Specific** to this function's logic (reference a concrete variable, \
field, return value, or code path — not generic properties like "pointer \
is valid" or "no concurrent access")

For each assumption, state:
- The property assumed (reference the specific variable or field)
- Whether the assumption is explicit (checked/asserted) or implicit \
(unchecked)
- The consequence if violated (cite the specific line or operation \
that would fail)

Respond in JSON: {{ "assumptions": [ {{ "property": "...", \
"explicit": true/false, "consequence": "..." }} ] }}
"""

ASSUMPTION_VERIFY_TEMPLATE = """\
Function `{fid}` makes these implicit assumptions:

{assumptions_list}

Here are the callers that invoke this function:

{callers_source}

For each assumption, determine whether ALL callers guarantee it.

Report ONLY assumptions that are UNGUARANTEED and where you can identify \
a CONCRETE triggering path: a specific caller that fails to establish \
the property, with the variable or field name involved.

For each finding you MUST provide:
- guard_type: the kind of guard missing (bounds, null_safety, validation, \
sanitisation, lifetime, ordering, concurrency, other)
- assumed_property: the specific variable/field and what is assumed \
(e.g. "h->size is initialised")
- mechanism: name the specific caller function and the code path that \
violates the assumption (e.g. "process_raw() calls pool_alloc(len, 1) \
which skips memset, leaving h->size uninitialised")
- cwe_class: the CWE ID
- standalone: true if this finding is useful without the others
- confidence: high (named a specific caller that concretely violates the \
assumption), medium (plausible but the violating path needs runtime \
confirmation), low (speculative)

Do NOT report:
- Generic concurrency or memory-model assumptions unless a specific \
race is identified between named functions
- Properties guaranteed by the language or type system
- Assumptions where every caller does establish the property

Respond in JSON: {{ "findings": [ {{ "guard_type": "...", \
"assumed_property": "...", "mechanism": "...", "cwe_class": "...", \
"standalone": true/false, "confidence": "high|medium|low" }} ] }}

If all assumptions are guaranteed, respond: {{ "findings": [] }}
"""


def _parse_assumptions(raw: str) -> list[dict[str, Any]]:
    """Parse the pass-1 assumption extraction response."""
    text = raw.strip()
    _fence_matches = list(
        re.finditer(r"```(?:json)?[ \t]*\n(.+?)```", text, re.DOTALL),
    )
    if _fence_matches:
        text = _fence_matches[-1].group(1).strip()
    elif text.startswith("```"):
        lines = text.splitlines()
        lines = [l for l in lines if not l.startswith("```")]
        text = "\n".join(lines)

    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return []

    assumptions = parsed.get("assumptions", [])
    if not isinstance(assumptions, list):
        return []

    return [
        a for a in assumptions
        if isinstance(a, dict) and not a.get("explicit", True)
    ]


_IDENT_RE = re.compile(r"\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b")

_NOISE_IDENTS: frozenset[str] = frozenset({
    "int", "void", "char", "size_t", "NULL", "return", "const",
    "struct", "enum", "unsigned", "signed", "short", "long",
    "static", "extern", "typedef", "sizeof", "include",
    "true", "false", "for", "while", "break", "continue",
    "switch", "case", "default", "goto", "volatile", "register",
    "inline", "restrict", "the", "that", "this", "from", "with",
    "not", "and", "but", "are", "was", "has", "have",
})


def _source_identifiers(source: str) -> frozenset[str]:
    """Extract meaningful C identifiers from source text."""
    raw = _IDENT_RE.findall(source)
    return frozenset(raw) - _NOISE_IDENTS


def _filter_grounded_findings(
    weaknesses: list[dict[str, Any]],
    source_idents: frozenset[str],
) -> list[dict[str, Any]]:
    """Keep only findings whose mechanism references source identifiers."""
    if not source_idents:
        return weaknesses
    kept = []
    for w in weaknesses:
        mechanism = w.get("mechanism", "")
        assumed = w.get("assumed_property", "")
        text = f"{mechanism} {assumed}"
        found = _IDENT_RE.findall(text)
        if any(tok in source_idents for tok in found):
            kept.append(w)
        else:
            logger.debug(
                "discovery: dropped ungrounded finding: %s",
                w.get("assumed_property", "?"),
            )
    return kept


def run_assumption_mining(
    targets: list[SweepTarget],
    *,
    review_fn: Callable[[str, str], tuple[str, float]],
    max_cost_usd: float = 5.0,
) -> list[DiscoveryResult]:
    """Two-pass assumption mining on each target."""
    results: list[DiscoveryResult] = []
    total_cost = 0.0

    system_extract = (
        "You are a security auditor extracting implicit assumptions "
        "from code. Respond only with the JSON object described in "
        "the prompt."
    )
    system_verify = (
        "You are a security auditor verifying whether implicit "
        "assumptions are guaranteed by callers and environment. "
        "Respond only with the JSON object described in the prompt."
    )

    for target in targets:
        if total_cost >= max_cost_usd:
            logger.info(
                "discovery: assumption mining cost cap reached "
                "($%.2f >= $%.2f)",
                total_cost, max_cost_usd,
            )
            break

        # Pass 1: extract assumptions
        prompt1 = ASSUMPTION_EXTRACT_TEMPLATE.format(
            annotation=target.annotation,
        )
        try:
            response1, cost1 = review_fn(system_extract, prompt1)
        except Exception as exc:
            from core.llm.client import is_budget_exceeded_error
            if is_budget_exceeded_error(exc):
                break
            logger.exception(
                "discovery: assumption extract failed for %s",
                target.fid,
            )
            continue
        total_cost += cost1

        implicit = _parse_assumptions(response1)
        if not implicit:
            continue

        # Pass 2: verify implicit assumptions against callers
        assumptions_list = "\n".join(
            f"- {a.get('property', '?')} "
            f"(consequence: {a.get('consequence', 'unknown')})"
            for a in implicit
        )

        callers_src = target.callers_source or "(no caller context available)"

        prompt2 = ASSUMPTION_VERIFY_TEMPLATE.format(
            fid=target.fid,
            assumptions_list=assumptions_list,
            callers_source=callers_src,
        )
        try:
            response2, cost2 = review_fn(system_verify, prompt2)
        except Exception as exc:
            from core.llm.client import is_budget_exceeded_error
            if is_budget_exceeded_error(exc):
                break
            logger.exception(
                "discovery: assumption verify failed for %s",
                target.fid,
            )
            continue
        total_cost += cost2

        result = _parse_discovery_findings(
            response2, target, "assumption_mining",
        )

        # Mechanical post-filter: drop findings that don't reference
        # any identifier from the target source or callers.
        if result.weaknesses:
            all_source = (target.source or "") + "\n" + (
                target.callers_source or ""
            )
            idents = _source_identifiers(all_source)
            result.weaknesses = _filter_grounded_findings(
                result.weaknesses, idents,
            )

        result.cost_usd = cost1 + cost2
        results.append(result)

    total_findings = sum(len(r.weaknesses) for r in results)
    logger.info(
        "discovery: assumption mining %d targets, %d findings, $%.2f total",
        len(targets), total_findings, total_cost,
    )
    return results


# ── journal integration ─────────────────────────────────────────────

def write_discovery_weaknesses(
    out_dir: Path,
    callee_fid: str,
    weaknesses: list[dict[str, Any]],
    *,
    run_id: str = "",
    cost_usd: float = 0.0,
) -> None:
    """Write discovery weaknesses as a journal entry."""
    if not weaknesses:
        return

    from core.coverage.journal import (
        ReviewJournalEntry,
        append_entry,
        now_iso,
    )

    callee_file, callee_func = callee_fid.rsplit(":", 1)

    entry = ReviewJournalEntry(
        ts=now_iso(),
        run_id=run_id,
        file=callee_file,
        function=callee_func,
        verdict="weakness",
        source_hash="",
        weaknesses=weaknesses,
        cost_usd=cost_usd,
    )
    append_entry(out_dir, entry)


# ── CLI ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    import sys

    from core.logging import configure_cli_logging
    configure_cli_logging(logging.INFO, fmt="%(message)s")

    parser = argparse.ArgumentParser(
        description="Cross-scope contract discovery engine",
    )
    parser.add_argument(
        "--run-dir", required=True,
        help="Audit output directory (contains checklist.json)",
    )
    parser.add_argument(
        "--target", required=True,
        help="Path to the scanned codebase",
    )
    parser.add_argument("--max-seams", type=int, default=DEFAULT_MAX_SEAMS)
    parser.add_argument("--token-budget", type=int, default=DEFAULT_TOKEN_BUDGET)
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Extract and score seams without calling the LLM",
    )
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    target = Path(args.target)

    from core.json.utils import load_json

    checklist_path = run_dir / "checklist.json"
    checklist = load_json(checklist_path, strict=True)
    assert isinstance(checklist, dict)

    context_map = load_json(run_dir / "context-map.json")

    entry_points: set[str] = set()
    if context_map:
        from core.audit._util import extract_context_map_set
        entry_points = extract_context_map_set(context_map, "entry_points")

    weakness_fids: set[str] = set()
    journal_path = run_dir
    try:
        from core.audit.composition import build_weakness_inventory
        inventory = build_weakness_inventory(journal_path)
        weakness_fids = {w.fid for w in inventory}
    except (ImportError, Exception):
        pass

    bundles = build_seam_bundles(
        checklist, context_map, entry_points,
        target_path=target,
        max_seams=args.max_seams,
        token_budget=args.token_budget,
        weakness_fids=weakness_fids,
    )

    if args.dry_run:
        print(f"\n{'='*60}")
        print(f"Seam bundles: {len(bundles)}")
        print(f"{'='*60}")
        for i, b in enumerate(bundles):
            print(
                f"  {i + 1:3d}. [{b.priority_score:.0f}] "
                f"{b.caller_fid} → {b.callee_fid}"
                f"  ({b.priority_reason})"
            )
            caller_tok = estimate_tokens(b.caller_source)
            callee_tok = estimate_tokens(b.callee_source)
            snippet_lines = len(b.call_site_snippet.splitlines()) if b.call_site_snippet else 0
            print(f"       caller={caller_tok}tok  callee={callee_tok}tok  snippet={snippet_lines}L")
        total_tok = sum(
            estimate_tokens(b.caller_source) + estimate_tokens(b.callee_source)
            for b in bundles
        )
        print(f"\nTotal tokens: ~{total_tok}")
        print(f"Estimated cost: ~${len(bundles) * 0.01:.2f}")
        sys.exit(0)

    print("error: live LLM dispatch not wired in CLI yet", file=sys.stderr)
    print("use --dry-run to inspect seam bundles", file=sys.stderr)
    sys.exit(1)
