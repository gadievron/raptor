"""Early refutation gates for /audit.

Cheap mechanical checks that can kill false-positive hypotheses before
expensive tool confirmation runs.  Each gate returns a demoted
``ReviewOutcome`` if the hypothesis is refuted, or ``None`` to pass.

Gate ordering (cost order, short-circuit on first hit):

1. Architecture model        — CWE-362 in single-threaded targets
2. Lifecycle phase           — resource leaks in init-only code
3. Contract provenance       — hypothesis-vs-contract contradiction
4. Input-bound Tier 0        — known-return-type table
5. Anti-self-refutation      — rescue self-refuted concurrency/lifecycle hyps
6. Callee-inheritance        — demote thin wrappers flagged for callee's bug

Gates 1-4 are demotion gates (finding/suspicious → clean).
Gate 5 is a promotion gate (clean → suspicious) for self-refuted hypotheses.
Gate 6 is a demotion gate (finding/suspicious → clean) for callee attribution.

"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from types import SimpleNamespace
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


@dataclass
class RefutationVerdict:
    """Result of a refutation gate firing.

    ``refuter_grade`` is the evidence class of the REFUTING FACT, not
    of the hypothesis it defeats:

    * ``"proof"`` — the refuting fact is mechanically true regardless
      of how the hypothesis text is interpreted (e.g. a libc return
      range).  Only proof-grade refuters may override a
      detection-grade receipt floor (see :func:`rescue_self_refuted`).
    * ``"heuristic"`` — the refuting fact rests on keyword/lookup
      matching, partial call graphs, or unverified model claims.  A
      heuristic refuter never outranks a detection receipt.

    The default is ``"heuristic"`` so a producer that does not declare
    a grade can never dominate a receipt by omission.
    """

    gate: str
    reason: str  # human-readable explanation
    demote_to: str  # "clean" or "suspicious"
    refuter_grade: str = "heuristic"  # "proof" or "heuristic"


def refute_hypothesis(
    outcome,  # ReviewOutcome — avoid circular import
    *,
    domain_model: dict[str, Any] | None,
    checklist: dict[str, Any] | None,
    config,  # OrchestratorConfig
    joern_server=None,
) -> RefutationVerdict | None:
    """Run refutation gates in cost order.  Return verdict or None."""
    # Never refute a finding with mechanical tool confirmation.
    from .evidence_grade import is_tool_evidence

    raw_et = outcome.evidence_tool or ""
    if is_tool_evidence(raw_et):
        return None

    hyp = outcome.hypothesis or ""
    if not hyp:
        return None

    # Gate 1: Architecture model
    v = _refute_by_architecture(outcome, domain_model, checklist, config)
    if v is not None:
        return v

    # Gate 2: Lifecycle phase
    v = _refute_by_lifecycle(outcome, checklist)
    if v is not None:
        return v

    # Gate 3: Contract provenance
    v = _refute_by_contract(outcome, domain_model)
    if v is not None:
        return v

    # Gate 4: Input-bound Tier 0 (known-return-type table)
    v = _refute_by_known_return_type(outcome, config)
    if v is not None:
        return v

    # Gate 6: Callee-inheritance suppression
    source, callees = _get_function_source_and_callees(outcome, checklist)
    if source and callees:
        v = _refute_by_callee_inheritance(outcome, source, callees)
        if v is not None:
            return v

    return None


# ---------------------------------------------------------------------------
# Gate 1: Architecture model
# ---------------------------------------------------------------------------

_RACE_CWES = frozenset({"CWE-362", "CWE-364", "CWE-366", "CWE-367"})


# Thread-spawn primitives across the supported languages. Seed set,
# deliberately small: this drives a one-way VETO (see below) where a
# miss only means the veto doesn't fire — never new suppression.
_THREADING_PRIMITIVE_RE = re.compile(
    rb"pthread_create|std::j?thread|std::async"
    rb"|CreateThread|_beginthread"
    rb"|threading\.Thread|multiprocessing\.|concurrent\.futures"
    rb"|\bgo\s+func\b|thread::spawn|tokio::spawn"
    rb"|new\s+Thread\s*\(|ExecutorService"
)
_SOURCE_EXTS = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp",
    ".py", ".go", ".rs", ".java", ".kt", ".cs",
})
_SKIP_DIRS = frozenset({".git", "node_modules", "vendor", "third_party"})
_VETO_SCAN_MAX_FILES = 2000
_VETO_SCAN_MAX_BYTES = 256 * 1024

_threading_seen_cache: dict[str, bool] = {}


def _threading_primitives_seen(target_path) -> bool:
    """Bounded scan: does the target visibly spawn threads anywhere?

    Cached per target path. Read errors and the file/byte caps fail
    toward False — i.e. toward NOT vetoing — so a partial scan can
    only under-veto, never over-suppress.
    """
    key = str(target_path)
    cached = _threading_seen_cache.get(key)
    if cached is not None:
        return cached
    import os as _os
    seen = False
    scanned = 0
    for root, dirnames, filenames in _os.walk(key):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            if _os.path.splitext(fn)[1] not in _SOURCE_EXTS:
                continue
            scanned += 1
            if scanned > _VETO_SCAN_MAX_FILES:
                break
            try:
                with open(_os.path.join(root, fn), "rb") as f:
                    if _THREADING_PRIMITIVE_RE.search(
                            f.read(_VETO_SCAN_MAX_BYTES)):
                        seen = True
                        break
            except OSError:
                continue
        if seen or scanned > _VETO_SCAN_MAX_FILES:
            break
    _threading_seen_cache[key] = seen
    return seen


def _is_single_threaded(
    domain_model: dict[str, Any] | None,
    config,
) -> bool:
    """Determine if the target is single-threaded.

    Only the domain model's ``architecture.threading_model`` field
    (produced by the study loop) is authoritative enough to suppress
    race-condition findings.  Source-grep heuristics are too fragile
    to PROVE threading: kernel code uses its own primitives, excerpt
    trees are partial, and framework-spawned threads leave no source
    footprint.

    The claim is an unverified LLM output derived from the untrusted
    target, and this gate fails toward suppression — so a mechanical
    VETO applies in the safe direction: when the source visibly
    spawns threads, the single-threaded claim is provably wrong and
    must not demote race findings. The veto can only prevent wrong
    suppression, never add it.
    """
    if not domain_model:
        return False
    arch = domain_model.get("architecture", {})
    if arch.get("threading_model", "") != "single_threaded":
        return False
    target = getattr(config, "target_path", None) if config else None
    if target and _threading_primitives_seen(target):
        logger.info(
            "architecture gate: single_threaded claim vetoed — thread "
            "primitives visible in %s; race findings NOT demoted", target,
        )
        return False
    return True


# Per-checklist memoisation for the call-graph structures the gates
# derive: both gates run per outcome, and the adjacency / caller-map
# rebuild was repeated for every hypothesis on the same run's
# checklist. Keyed by object identity (the stored strong reference
# pins the id); the small FIFO bound keeps long-lived processes from
# accumulating dead checklists.
_CHECKLIST_CACHE_MAX = 4
_signal_reachable_cache: list = []
_caller_map_cache: list = []


def _checklist_cache_get(cache: list, checklist: Any) -> Any:
    for obj, value in cache:
        if obj is checklist:
            return value
    return None


def _checklist_cache_put(cache: list, checklist: Any,
                         value: Any) -> None:
    cache.append((checklist, value))
    if len(cache) > _CHECKLIST_CACHE_MAX:
        cache.pop(0)


def _signal_reachable_set(
    checklist: dict[str, Any] | None,
) -> frozenset[str]:
    """Build set of functions transitively reachable from signal handlers.

    Walks the call graph from any function registered via signal() or
    sigaction().  Returns frozenset of ``"file:function"`` keys.

    Falls back to empty set if signal handlers can't be identified
    (safe: gate won't suppress).  Memoised per checklist identity —
    the gate runs once per outcome on the same checklist.
    """
    if not checklist:
        return frozenset()

    cached = _checklist_cache_get(_signal_reachable_cache, checklist)
    if cached is not None:
        return cached

    files = checklist.get("files", [])

    # Phase 1: find signal handler registrations
    handler_names: set[str] = set()
    for fentry in files:
        calls = _get_calls(fentry)
        for c in calls:
            chain = c.get("chain", [])
            if not chain:
                continue
            callee = chain[0]
            if callee in ("signal", "sigaction", "bsd_signal", "sysv_signal"):
                # The handler is typically the 2nd or 3rd argument,
                # but in the call graph it might appear as another call
                # in the chain.  We look for the next identifier.
                if len(chain) > 1:
                    handler_names.add(chain[1])

    # Phase 2: also find handler names by scanning for signal-related
    # patterns in the source — function names containing "sig" that
    # are used as callback arguments.
    # This is a heuristic fallback.
    for fentry in files:
        for item in fentry.get("items", []):
            name = item.get("name", "")
            if re.search(r"sig(?:nal)?_?handler|sighandler|sig_action", name,
                         re.IGNORECASE):
                handler_names.add(name)

    if not handler_names:
        _checklist_cache_put(
            _signal_reachable_cache, checklist, frozenset(),
        )
        return frozenset()

    # Phase 3: transitive closure over call graph
    # Build caller→callees adjacency from all files
    adjacency: dict[str, set[str]] = {}
    func_to_file: dict[str, str] = {}
    for fentry in files:
        path = fentry.get("path", "")
        for item in fentry.get("items", []):
            name = item.get("name", "")
            if name:
                func_to_file[name] = path
        calls = _get_calls(fentry)
        for c in calls:
            caller = c.get("caller", "")
            chain = c.get("chain", [])
            if caller and chain:
                adjacency.setdefault(caller, set()).update(chain)

    # BFS from handler names
    visited: set[str] = set()
    queue = list(handler_names)
    while queue:
        func = queue.pop()
        if func in visited:
            continue
        visited.add(func)
        queue.extend(callee for callee in adjacency.get(func, set()) if callee not in visited)

    # Convert to file:function keys
    result: set[str] = set()
    for func in visited:
        fpath = func_to_file.get(func, "")
        if fpath:
            result.add(f"{fpath}:{func}")
        # Also add bare name for matching
        result.add(f":{func}")

    frozen = frozenset(result)
    _checklist_cache_put(_signal_reachable_cache, checklist, frozen)
    return frozen


def _refute_by_architecture(
    outcome,
    domain_model: dict[str, Any] | None,
    checklist: dict[str, Any] | None,
    config,
) -> RefutationVerdict | None:
    """Refute race-condition hypotheses in single-threaded targets."""
    cwes = _extract_all_cwes(outcome)
    matched = cwes & _RACE_CWES
    if not matched:
        return None

    if not _is_single_threaded(domain_model, config):
        return None

    # Exception: functions reachable from signal handlers can race
    sig_set = _signal_reachable_set(checklist)
    func_key = f"{outcome.file}:{outcome.function}"
    bare_key = f":{outcome.function}"
    if func_key in sig_set or bare_key in sig_set:
        return None

    cwe_label = ", ".join(sorted(matched))
    # Grade: HEURISTIC. The refuting fact ("the target is
    # single-threaded") is the domain model's threading claim — an
    # unverified LLM output derived from the untrusted target. The
    # thread-primitive veto only bounds the failure direction; it
    # cannot make the claim mechanically true.
    return RefutationVerdict(
        gate="architecture",
        reason=(
            f"single-threaded target, function {outcome.function} not "
            f"reachable from signal handlers — {cwe_label} impossible"
        ),
        demote_to="clean",
        refuter_grade="heuristic",
    )


# ---------------------------------------------------------------------------
# Gate 2: Lifecycle phase
# ---------------------------------------------------------------------------

_RESOURCE_LEAK_CWES = frozenset({
    "CWE-401", "CWE-404", "CWE-772", "CWE-775",
})

_RESOURCE_LEAK_KW = re.compile(
    r"\bleak|unref|not\s+freed|resource\s+(?:exhaust|leak)"
    r"|handle\s+not\s+closed|missing\s+(?:free|close|release|unref)",
    re.IGNORECASE,
)

# Functions that mark the transition from init to event loop.
_EVENT_LOOP_CALLS = frozenset({
    "select", "pselect", "poll", "ppoll", "epoll_wait",
    "kqueue", "kevent", "event_base_dispatch", "ev_run",
    "do_poll", "poll_listen", "event_loop",
    "uv_run", "g_main_loop_run",
})


def _classify_lifecycle(
    function_name: str,
    _file_path: str,
    checklist: dict[str, Any],
) -> str:
    """Classify a function as init, request, shutdown, or unknown.

    Walks the call graph from main() to find:
    - The event loop boundary (first call to select/poll/epoll_wait/etc.)
    - Whether the function is called before or after that boundary

    Handles both direct calls (``main → target``) and one-hop indirect
    calls (``main → setup → target``).  Deeper chains return "unknown"
    — the checklist call graph is per-file and rarely has more depth.
    """
    # Build a global caller→[(callee, line)] map for indirect lookup.
    # Memoised per checklist identity — the gate runs per outcome and
    # the map only depends on the checklist.
    caller_map: dict[str, list[tuple[str, int]]] | None = (
        _checklist_cache_get(_caller_map_cache, checklist)
    )
    if caller_map is None:
        caller_map = {}
        for fentry in checklist.get("files", []):
            for c in _get_calls(fentry):
                caller = c.get("caller", "")
                chain = c.get("chain", [])
                line = c.get("line", 0)
                if caller and chain:
                    caller_map.setdefault(caller, []).append(
                        (chain[0], line),
                    )
        _checklist_cache_put(_caller_map_cache, checklist, caller_map)

    main_calls = caller_map.get("main", [])
    if not main_calls:
        return "unknown"

    # Find the event loop boundary line — check both direct calls from
    # main and one-hop indirect (main → wrapper → event_loop_call).
    event_loop_line = None
    for callee, line in sorted(main_calls, key=lambda x: x[1]):
        if callee in _EVENT_LOOP_CALLS:
            event_loop_line = line
            break
        # One-hop: main calls wrapper, wrapper calls event loop
        for sub_callee, _ in caller_map.get(callee, []):
            if sub_callee in _EVENT_LOOP_CALLS:
                event_loop_line = line
                break
        if event_loop_line is not None:
            break

    if event_loop_line is None:
        return "unknown"

    # Find all calls to our target function from main (direct)
    target_lines = [
        line for callee, line in main_calls if callee == function_name
    ]

    # One-hop indirect: main → intermediate → target
    if not target_lines:
        for callee, line in main_calls:
            for sub_callee, _ in caller_map.get(callee, []):
                if sub_callee == function_name:
                    target_lines.append(line)

    if not target_lines:
        return "unknown"

    before = any(ln < event_loop_line for ln in target_lines)
    after = any(ln >= event_loop_line for ln in target_lines)

    if before and after:
        return "request"  # conservative: both init and request → request
    if before:
        return "init"
    return "request"


def _refute_by_lifecycle(
    outcome,
    checklist: dict[str, Any] | None,
) -> RefutationVerdict | None:
    """Refute resource-leak findings in init-only functions."""
    if not checklist:
        return None

    phase = _classify_lifecycle(
        outcome.function, outcome.file, checklist,
    )
    if phase != "init":
        return None

    cwes = _extract_all_cwes(outcome)
    hyp_lower = (outcome.hypothesis or "").lower()

    # Resource leaks in init-only code can't accumulate.
    is_leak = (
        bool(cwes & _RESOURCE_LEAK_CWES)
        or bool(_RESOURCE_LEAK_KW.search(hyp_lower))
    )
    # Grade: HEURISTIC (both verdicts below). The refuting fact
    # ("this function only runs during init") comes from a line-order
    # walk over a per-file call graph with one-hop indirection depth,
    # an event-loop name table, and leak-keyword matching — every
    # premise is a lookup over partial data, not a mechanical truth.
    if is_leak:
        return RefutationVerdict(
            gate="lifecycle",
            reason=(
                f"init-only function {outcome.function} (called before "
                f"event loop) — resource leak cannot accumulate"
            ),
            demote_to="clean",
            refuter_grade="heuristic",
        )

    # DoS via resource exhaustion requires repeated triggering
    if "denial" in hyp_lower or "exhaust" in hyp_lower or "dos" in hyp_lower:
        if "restart" not in hyp_lower and "reconnect" not in hyp_lower:
            return RefutationVerdict(
                gate="lifecycle",
                reason=(
                    f"init-only function {outcome.function} — DoS "
                    f"requires repeated triggering, function runs once"
                ),
                demote_to="clean",
                refuter_grade="heuristic",
            )

    return None


# ---------------------------------------------------------------------------
# Gate 3: Contract provenance
# ---------------------------------------------------------------------------

_DEFENDER_PROVENANCE = re.compile(
    r"\boriginal\s+query\b|\bstash(?:ed)?\b"
    r"|\blocal(?:ly)?\s+(?:copy|generated|constructed)\b"
    r"|\bcached\s+(?:copy|version|data)\b"
    r"|\bpre-computed\b|\binternally\s+generated\b",
    re.IGNORECASE,
)


def _refute_by_contract(
    outcome,
    domain_model: dict[str, Any] | None,
) -> RefutationVerdict | None:
    """Refute when contract says input is defender-sourced."""
    if not domain_model:
        return None

    # Only relevant for hypotheses claiming attacker-controlled input
    hyp_lower = (outcome.hypothesis or "").lower()
    if not any(w in hyp_lower for w in (
        "attacker", "user-controlled", "user controlled",
        "untrusted", "external input", "remote",
    )):
        return None

    for contract in domain_model.get("contracts", []):
        if contract.get("function") != outcome.function:
            continue
        semantics = contract.get("input_semantics", "")
        if not semantics:
            continue
        if _DEFENDER_PROVENANCE.search(semantics):
            # Grade: HEURISTIC. The refuting fact is a provenance
            # keyword match against an LLM-authored contract field —
            # fragile on both sides (the gate already demotes only to
            # suspicious for exactly that reason, and that fragility
            # target stays regardless of any receipt on the function).
            return RefutationVerdict(
                gate="contract",
                reason=(
                    f"domain model contract for {outcome.function} says "
                    f"input is '{semantics[:80]}' — not attacker-controlled"
                ),
                demote_to="suspicious",  # keyword match is fragile
                refuter_grade="heuristic",
            )

    return None


# ---------------------------------------------------------------------------
# Gate 4: Input-bound Tier 0 — known return-type table
# ---------------------------------------------------------------------------

# Functions whose return range is small enough that integer overflow
# is impossible when the result is used in int-width arithmetic.
# Entries carry (type description, min, max).  Only functions whose
# max value fits in signed int (≤ 0x7FFF_FFFF) are included.
# ntohl/htonl are excluded: uint32_t can overflow signed int.
# atoi is excluded: it returns the full int range including negative
# values, so wraparound in unsigned contexts is possible.
# getchar/fgetc/tolower/toupper carry min = -1: they return EOF, and a
# negative value is exactly what a CWE-191 underflow claim needs.
# No entry refutes underflow (CWE-191) claims — even a min-0 value
# wraps when subtracted from something smaller — and none refutes a
# claim naming a wrap-capable operation (subtraction, addition,
# multiplication, shift, truncating store); see the bail-outs in
# _refute_by_known_return_type.
_KNOWN_RETURN_BOUNDS: dict[str, tuple[str, int, int]] = {
    "ntohs":    ("uint16_t", 0, 0xFFFF),
    "htons":    ("uint16_t", 0, 0xFFFF),
    "getchar":  ("int [0..255 or EOF]", -1, 0xFF),
    "fgetc":    ("int [0..255 or EOF]", -1, 0xFF),
    "tolower":  ("int [0..255 or EOF]", -1, 0xFF),
    "toupper":  ("int [0..255 or EOF]", -1, 0xFF),
    "isdigit":  ("int [0..1]", 0, 1),
    "isalpha":  ("int [0..1]", 0, 1),
    "isspace":  ("int [0..1]", 0, 1),
    "isalnum":  ("int [0..1]", 0, 1),
    "isupper":  ("int [0..1]", 0, 1),
    "islower":  ("int [0..1]", 0, 1),
    "isprint":  ("int [0..1]", 0, 1),
}

# Keywords that suggest an INTEGER overflow/wraparound claim.
# Does NOT match buffer/heap/stack overflow — those are a different bug
# class where a bounded return value (e.g. ntohs → 65535) can still
# overflow a smaller destination buffer.
_OVERFLOW_KW = re.compile(
    r"integer\s+overflow|integer\s+underflow"
    r"|arithmetic\s+overflow|arithmetic\s+wraparound"
    r"|wraparound|wrap\s*around",
    re.IGNORECASE,
)

# Buffer overflow indicators — if present, Gate 4 must not fire even
# when the value source is bounded, because the value may exceed the
# destination buffer size.
_BUFFER_OVERFLOW_KW = re.compile(
    r"buffer\s+overflow|heap\s+overflow|stack\s+overflow"
    r"|out[- ]of[- ]bounds|memcpy|memmove|sprintf|strcpy|strcat"
    r"|write\s+past|write\s+beyond|overrun|oob\b",
    re.IGNORECASE,
)

# Known token families whose hyphen-digit shape is NOT arithmetic:
# vulnerability/hash/encoding identifiers ("CWE-190", "CVE-2024-12345",
# "sha-256" — multi-part numeric tails consumed whole).  `len-1` and
# `CWE-190` share the letter-hyphen-digit SHAPE, so no lookaround can
# separate them — the ambiguity is resolved by token KNOWLEDGE
# instead: these get pre-stripped from the probe string before the
# wrap-op search, and the operator alternates below then stay
# shape-generic.  An unknown letter-digit hyphen token ("P-521")
# reads as possible subtraction and stands the gate down — the safe
# polarity.
_ID_TOKEN_STRIP_RE = re.compile(
    r"\b(?:cwe|cve|sha|md|utf|crc|rfc|iso|x86)(?:-\d+)+\b",
    re.IGNORECASE,
)

# Width prose ("16-bit", "2 bytes") is stripped DIGIT-PRESERVINGLY:
# the unit word goes, the number stays.  Deleting the whole phrase
# ate the subtrahend of real arithmetic — "writes n-1 bytes … wraps"
# became "writes n- " and the leak refuted proof-grade.  Keeping the
# digit, "n-1 bytes" → "n- 1" still matches the unspaced-operator
# alternate; a stranded bare digit is harmless because every code
# shape requires an adjacent operator.
_WIDTH_PROSE_RE = re.compile(
    r"\b(\d+)[- ](?:bit|byte)s?\b",
    re.IGNORECASE,
)

# Operations under which a BOUNDED value still wraps: subtraction
# (an unsigned result below zero wraps to a huge value regardless of
# the operands' upper bound), addition (two in-range values exceed a
# narrower accumulator/store), multiplication and left shift (the
# product of two in-range uint16_t values exceeds signed int), and
# truncating/narrowing stores (the docstring's own out-of-scope
# class).  The return-range table refutes none of these claims, so
# the gate must stand down — inconclusive, never refuted.  Matches
# prose ("subtracted", "plus", "times", "scaled by", "shifted to the
# left", "truncated", "cast to uint8_t") and code shapes, spaced or
# unspaced ("a - b", "ntohs(a)-1", "len-2", "seq+1", "nmemb*12",
# "len -= 2").  Searched against the two-pass-stripped probe
# (_ID_TOKEN_STRIP_RE, then digit-preserving _WIDTH_PROSE_RE), never
# the raw hypothesis.  Over-matching is safe (the gate
# only stands down), so the net is deliberately generous.  Known
# residual: identifier-minus-IDENTIFIER unspaced ("size-len") is
# indistinguishable from hyphenated prose ("fail-open",
# "attacker-controlled") and stays unmatched — spaced spellings and
# all prose forms are covered.
_WRAP_CAPABLE_OP_KW = re.compile(
    # subtraction / addition prose
    r"subtract|\bminus\b|difference|decrement|increment"
    r"|\badd(?:s|ed|ing)?\b|\baddition\b|\bsum\w*\b|\bplus\b"
    # multiplication / scaling prose
    r"|multipl|\bproduct\b|\btimes\b|\bscal(?:e|ed|es|ing)\b"
    r"|\bdoubl|\bsquar"
    # shift: "left shift", "left-shifted", "shifted (to the) left", <<
    r"|left[- ]shift|shift\w*\s+(?:\S+\s+){0,2}left|<<"
    # truncation / cast narrowing
    r"|truncat|narrow(?:ed|ing)?|\bcast(?:s|ed|ing)?\b|\bdowncast"
    r"|\bmodulo\b"
    # code shapes: compound assignment, inc/dec, spaced binary op,
    # and UNSPACED operator beside a digit / paren (identifier-
    # adjacent forms like "len-2" / "seq+1" included — known
    # identifier-hyphen tokens were already stripped from the probe)
    r"|[-*+]=|--|\+\+"
    r"|[\w)\]]\s+[-*+]\s+[\w(]"
    r"|[)\]\d]\s*[-*+]"
    r"|[-+]\s*[(\d]"
    r"|\*\s*[(\d]",
    re.IGNORECASE,
)


def _refute_by_known_return_type(
    outcome,
    _config,
) -> RefutationVerdict | None:
    """Refute integer overflow claims when value comes from a bounded function.

    Checks if the hypothesis claims an integer overflow/wraparound on a
    variable whose value comes from a function with a known bounded return
    type.  Does NOT handle buffer overflows (a bounded value can still
    exceed a destination buffer) or truncation (needs destination type).
    """
    hyp = outcome.hypothesis or ""
    hyp_lower = hyp.lower()
    cwe = _extract_cwe(outcome)

    # Only relevant for integer overflow/truncation claims.
    # Buffer overflow (CWE-120/122) is excluded — a bounded return value
    # like ntohs (max 65535) can still overflow a smaller buffer.
    has_keywords = bool(_OVERFLOW_KW.search(hyp_lower))
    has_cwe = cwe in ("CWE-190", "CWE-191")
    if not (has_keywords or has_cwe):
        return None

    # Bail out if the hypothesis describes a buffer overflow, not an
    # integer overflow.  The gate's reasoning ("value fits in its type")
    # doesn't apply when the value is used as a length/index into a
    # smaller destination.
    if _BUFFER_OVERFLOW_KW.search(hyp_lower):
        return None

    # A bounded value still wraps under subtraction, addition,
    # multiplication, left shift, or a truncating/narrowing store —
    # the range table precludes none of those, so the gate stands
    # down (inconclusive) instead of proof-refuting.  The search runs
    # on a two-pass-stripped probe: known identifier tokens (CWE-190,
    # sha-256) and width prose (16-bit) share the operator shapes but
    # are not arithmetic, and removing them by KNOWLEDGE lets the
    # operator alternates stay shape-generic ("len-2" bails).  The
    # width pass keeps its digit so real arithmetic whose operand
    # carries a unit ("writes n-1 bytes") keeps its subtrahend.
    wrap_probe = _ID_TOKEN_STRIP_RE.sub(" ", hyp_lower)
    wrap_probe = _WIDTH_PROSE_RE.sub(r" \1 ", wrap_probe)
    if _WRAP_CAPABLE_OP_KW.search(wrap_probe):
        return None

    # An underflow claim needs the result to go NEGATIVE (or wrap
    # below zero).  The table only bounds values ABOVE: it precludes
    # neither the EOF-returners' negative sentinel (getchar → -1) nor
    # an unsigned wrap when a min-0 value (ntohs) is subtracted from
    # something smaller.  No entry can refute underflow — stand down.
    if cwe == "CWE-191" or "underflow" in hyp_lower:
        return None

    # Check if any known-bounded function appears in the hypothesis.
    # When multiple match, pick the one closest to an overflow keyword
    # for audit trail clarity.
    best: tuple[str, str, int, int] | None = None  # (name, type, max, dist)
    for func_name, (ret_type, _min_val, max_val) in \
            _KNOWN_RETURN_BOUNDS.items():
        func_pos = hyp_lower.find(func_name)
        if func_pos < 0:
            continue

        # When CWE is explicit (CWE-190/191), the function name alone
        # is enough — the CWE already establishes the claim.
        # When CWE is inferred from keywords, require proximity:
        # the function name and an overflow keyword must appear within
        # ~200 chars of each other.
        if has_cwe:
            dist = 0
        else:
            nearby_start = max(0, func_pos - 100)
            nearby = hyp_lower[nearby_start:func_pos + 100]
            m = _OVERFLOW_KW.search(nearby)
            if not m:
                continue
            dist = abs(func_pos - nearby_start - m.start())

        if best is None or dist < best[3]:
            best = (func_name, ret_type, max_val, dist)

    if best is not None:
        func_name, ret_type, max_val, _ = best
        # Grade: PROOF. The refuting fact is the named function's
        # return range — an ISO C / POSIX guarantee that is
        # mechanically true regardless of how the hypothesis text is
        # interpreted; the table admits only ranges that fit signed
        # int, and the underflow / buffer-overflow / wrap-capable-op
        # bail-outs above keep the range argument applicable to what
        # remains (the raw value in int-width use). Known residual: a target
        # that shadows the libc name (macro or local redefinition)
        # breaks the premise — the gate matches the NAME in the
        # hypothesis text, not the resolved symbol.
        return RefutationVerdict(
            gate="input_bound_t0",
            reason=(
                f"{func_name}() returns {ret_type} (max {max_val:#x})"
                f" — cannot cause integer {cwe or 'overflow'}"
            ),
            demote_to="clean",
            refuter_grade="proof",
        )

    return None


# ---------------------------------------------------------------------------
# Gate 5: Anti-self-refutation (promotion gate: clean → suspicious)
# ---------------------------------------------------------------------------

_SELF_REFUTATION_CWES = frozenset({
    "CWE-362", "CWE-364", "CWE-366",
    "CWE-416", "CWE-415",
})


def _receipt_matches_mechanism(check_type: str, mechanism: str) -> bool:
    """Does a structural receipt's family appear in the hypothesis text?

    Token-stem match: at least two distinct stems of the check_type
    (``auth_mode_registration`` → auth/mode/regist) must occur in the
    mechanism, so an unrelated receipt on the same function cannot
    rescue an unrelated hypothesis.
    """
    mech = (mechanism or "").lower()
    if not mech or not check_type:
        return False
    stems = {t[:6] for t in check_type.lower().split("_") if len(t) >= 4}
    return sum(1 for s in stems if s in mech) >= 2


# Race-family CWEs whose self-refutation a mechanically verified
# lock-protection receipt can discharge (deliberately excludes
# CWE-367: a TOCTOU can span lock scopes).
_LOCK_DISCHARGEABLE_RACE_CWES = frozenset({
    "CWE-362", "CWE-364", "CWE-366",
})

# Lifetime families the safe-teardown witness can discharge
# (callback_lifetime.check_safe_teardown): a UAF/double-free
# self-refutation corroborated by waiting-cancel / RCU-deferred /
# no-deallocation evidence is accepted instead of floored.
_TEARDOWN_DISCHARGEABLE_CWES = frozenset({
    "CWE-415", "CWE-416",
})

from pathlib import Path

# Go internal-concurrency witness (goconc): the Go analog of the
# race-protection discharge.  The C witness bails on Go sources, so a
# race-family self-refutation on a Go function always floored even
# when the package mechanically cannot race with the claimed state.
# The fence below decides only which dismissals the witness may
# EXAMINE (the proof is always the mechanical package analysis in
# core/audit/goconc.py, never the phrasing).

# The dismissal must be a concurrency claim at all.
_GOCONC_CONCURRENCY_HYP_RE = re.compile(
    r"race|concurren|goroutine|synchroni[sz]|interleav"
    r"|torn\s+(?:read|write)|simultaneous|parallel",
    re.IGNORECASE,
)

# In-family: the dismissal (or the reviewer's counter) names
# PACKAGE-INTERNAL concurrency — a goroutine the library itself
# spawns, or the package's own option-application machinery running
# concurrently.  Claims about concurrent callers of an exported API
# are a different family (the caller-contract race) and stay with the
# floor.
_GOCONC_INTERNAL_HYP_RE = re.compile(
    r"package[-\s]?internal"
    r"|internal\s+(?:goroutine|concurrency)"
    r"|library[-\s]?internal"
    r"|goroutines?\s+(?:spawned|started|launched)\s+"
    r"(?:by|in|inside|within)\s+(?:the\s+|this\s+)?(?:same\s+)?"
    r"(?:package|library|module)"
    r"|(?:package|library)\s+spawns?\b"
    r"|spawns?\s+no\s+goroutines?"
    r"|no\s+goroutines?\s+(?:in|inside|within)\b"
    r"|concurrent\w*\s+(?:\w+\s+){0,2}?\w*opt(?:s|ions?)?\b"
    r"|\w*opt(?:s|ions?)\b[^.;]{0,80}?concurrent",
    re.IGNORECASE,
)

# Hard out-of-family: the mechanism attributes the concurrency to an
# actor outside the package — callers, clients, other packages, user/
# application code, or "N goroutines calling" the API.  Checked on
# the mechanism only and it wins over any in-family match — a counter
# asserting "no internal goroutine" must not drag a claim about an
# EXPLICITLY external actor into scope.  (An actor-NEUTRAL mechanism
# may still be examined when the counter names package-internal
# concurrency; the witness corroborates the counter.)
_GOCONC_EXTERNAL_CALLER_RE = re.compile(
    r"concurrent\s+(?:\w+\s+){0,2}?callers?"
    r"|callers?\s+(?:\w+\s+){0,3}?(?:concurrent|simultaneous)"
    r"|external\s+(?:callers?|goroutines?|code|threads?|users?)"
    r"|caller[-\s]side\s+concurrenc"
    r"|\bcallers?\b"
    r"|\bclients?\b"
    r"|\bother\s+packages?\b"
    r"|outside\s+(?:this|the)\s+package"
    r"|\busers?\s+of\b"
    r"|\buser\s+code\b"
    r"|\bapplication\s+(?:code|using|calling|invoking)\b"
    r"|(?:multiple|two|several|many)\s+goroutines?\s+"
    r"(?:that\s+)?(?:may\s+|might\s+|could\s+|can\s+)?"
    r"(?:call|invoke|use|access|share)\w*\b",
    re.IGNORECASE,
)


def _goconc_claim_in_family(mechanism: str, counter: str) -> bool:
    """Applicability fence for the Go internal-concurrency witness.

    True when the dismissed hypothesis is a concurrency claim whose
    operative content is package-internal concurrency: either the
    mechanism names it, or the reviewer's counter refutes it on
    exactly that ground (the witness corroborates the counter).  A
    mechanism that attributes the race to concurrent CALLERS of the
    API is out of family unconditionally.
    """
    mech = mechanism or ""
    if not _GOCONC_CONCURRENCY_HYP_RE.search(mech):
        return False
    if _GOCONC_EXTERNAL_CALLER_RE.search(mech):
        return False
    return bool(
        _GOCONC_INTERNAL_HYP_RE.search(mech)
        or _GOCONC_INTERNAL_HYP_RE.search(counter or "")
    )


# C lifetime witness family (W-FREEPATH / W-NOUSE / W-BRACKET /
# W-DELEG + async-handoff): the C analog of the goconc discharge for
# CWE-415/416 self-refutations.  The safe-teardown witness covers the
# waiting-cancel / RCU idioms; these arms cover path-shaped safety
# arguments (path-exclusive frees, no-use-after-release, paired
# refcount brackets, delegation-only bodies, sentinel handoff paths)
# over a goto-resolved CFG (core/audit/lifetime_witness.py).  The
# claim-phrasing fences live in that module; the gate only decides
# WHEN the witness may run: C sources, trust-gated, never on a
# function carrying a structural receipt, record-or-refuse.


def _record_lifetime_discharge(
    outcome,
    out_dir,
    *,
    mechanism: str,
    result,
) -> bool:
    """Accept-with-record: persist a lifetime-witness discharge.

    Same contract as the goconc record: the discharged dismissal goes
    through the suppressions.jsonl single-writer chokepoint with
    ``dropped: false`` and a verdict naming the witness.  Returns True
    only when the record call completed; the caller refuses the
    discharge on False — an unrecordable discharge must not happen.
    """
    if not out_dir:
        logger.debug(
            "lifetime discharge for %s:%s refused (no out_dir to record)",
            getattr(outcome, "file", "?"),
            getattr(outcome, "function", "?"),
        )
        return False
    try:
        from core.analysis.reach_chokepoint import record_suppression

        line = getattr(outcome, "line", 0) or 0
        fpath = getattr(outcome, "file", "")
        func = getattr(outcome, "function", "")
        record_suppression(
            Path(out_dir),
            finding={
                "finding_id": f"audit-refutation:{fpath}:{func}:{line}",
                "rule_id": "audit:lifetime-witness",
                "file_path": fpath,
                "line": line,
                "function": func,
            },
            verdict="lifetime_witness_corroborates_dismissal",
            reason=(
                f"lifetime self-refutation accepted: the dismissal is "
                f"mechanically corroborated by the C lifetime witness "
                f"({result.reason})"
            ),
            dropped=False,
            extra={
                "stage": "anti-self-refutation",
                "witness": "lifetime",
                "floor_gate": "cwe_allowlist",
                "arms": sorted({p.arm for p in result.proofs}),
                "pointers": sorted({p.pointer for p in result.proofs}),
                "covered_cwes": sorted(result.covered_cwes),
                "hypothesis": (mechanism or "")[:160],
            },
        )
        return True
    except Exception:
        logger.debug("lifetime discharge record failed", exc_info=True)
        return False


def _record_goconc_discharge(
    outcome,
    out_dir,
    *,
    mechanism: str,
    result,
) -> bool:
    """Accept-with-record: persist a goconc-discharged dismissal.

    A witness overriding the receipt-free CWE-allowlist floor must
    never be silent — the discharged dismissal goes through the
    suppressions.jsonl single-writer chokepoint with ``dropped:
    false`` and a verdict naming the witness, so operators can grep
    every function the witness kept clean.  Returns True only when
    the record call completed; the caller refuses the discharge on
    False — an unrecordable discharge must not happen at all.
    (``record_suppression`` itself swallows pure IO errors by its
    single-writer contract; this guard covers a missing sink and
    unexpected failures.)
    """
    if not out_dir:
        logger.debug(
            "goconc discharge for %s:%s refused (no out_dir to record)",
            getattr(outcome, "file", "?"),
            getattr(outcome, "function", "?"),
        )
        return False
    try:
        from core.analysis.reach_chokepoint import record_suppression

        line = getattr(outcome, "line", 0) or 0
        fpath = getattr(outcome, "file", "")
        func = getattr(outcome, "function", "")
        record_suppression(
            Path(out_dir),
            finding={
                "finding_id": f"audit-refutation:{fpath}:{func}:{line}",
                "rule_id": "audit:goconc-witness",
                "file_path": fpath,
                "line": line,
                "function": func,
            },
            verdict="goconc_witness_corroborates_dismissal",
            reason=(
                f"race-family self-refutation accepted: the dismissal "
                f"is mechanically corroborated by the Go internal-"
                f"concurrency witness ({result.reasoning})"
            ),
            dropped=False,
            extra={
                "stage": "anti-self-refutation",
                "witness": "goconc",
                "floor_gate": "cwe_allowlist",
                "spawn_count": result.spawn_count,
                "claimed_types": list(result.claimed_types),
                "hypothesis": (mechanism or "")[:160],
            },
        )
        return True
    except Exception:
        logger.debug("goconc discharge record failed", exc_info=True)
        return False


# TU-local caller-held-lock witness (caller_lock): the caller-context
# analog of the race-protection discharge.  The in-function C witness
# only sees lexical lock scopes inside the reviewed function, so a
# race/TOCTOU self-refutation whose operative safety argument is a
# lock the CALLER holds across the call always floored even when the
# caller set is TU-complete and mechanically provable.  The fence
# below decides only which dismissals the witness may EXAMINE (the
# proof is always the mechanical TU analysis in
# core/audit/caller_lock.py, never the phrasing).

# Race/TOCTOU families the caller-held-lock witness can discharge.
# CWE-367 is deliberately excluded from the in-function witness's
# set (_LOCK_DISCHARGEABLE_RACE_CWES: a TOCTOU can span lock scopes)
# but joins here: the witness proves the lock is held across the
# whole call, so check and use both execute inside ONE held region —
# the exclusion's reason does not apply.
_CALLERLOCK_DISCHARGEABLE_CWES = frozenset({
    "CWE-362", "CWE-364", "CWE-366", "CWE-367",
})

# A lock-ish object must be named somewhere in the dismissal — the
# witness adjudicates lock-based serialization, nothing else.
_CALLERLOCK_LOCK_TOKEN_RE = re.compile(
    r"lock|mutex|rwsem|semaphore|spinlock", re.IGNORECASE,
)

# In-family: the dismissal (or the reviewer's counter) attributes the
# safety to a lock held by the caller / held across or around the
# call — the exact claim the TU-local caller analysis can adjudicate.
# Claims attributing safety to the function's own locking, to
# single-threadedness, or to anything else never match.
_CALLERLOCK_HELD_BY_CALLER_RE = re.compile(
    r"caller[-\s]held"
    r"|\bheld\s+(?:by|in)\s+(?:the\s+|its\s+|every\s+|all\s+|each\s+"
    r"|any\s+|both\s+|the\s+only\s+)?callers?\b"
    r"|\bcallers?\b[^.;]{0,100}?\b(?:hold|holds|held|holding"
    r"|acquires?|acquired|takes?|taken|took)\b"
    r"|\b(?:hold|holds|held|holding|acquires?|acquired|takes?|taken"
    r"|took)\b[^.;]{0,100}?\bcall(?:ers?|ing)?\b"
    r"|\bheld\s+(?:across|around|over|during|for)\b[^.;]{0,60}?"
    r"\bcall"
    r"|\bcalled\s+(?:with|under|while)\b[^.;]{0,80}?\b(?:held"
    r"|locked)\b"
    r"|\b(?:under|with)\b[^.;]{0,60}?\bheld\s+by\b"
    r"|serial\w*\s+(?:by|via|through|at)\s+(?:the\s+|its\s+|each\s+"
    r"|every\s+)?call(?:er|ers|ing)?\b",
    re.IGNORECASE,
)


def _callerlock_claim_in_family(mechanism: str, counter: str) -> bool:
    """Applicability fence for the caller-held-lock witness.

    True when the dismissed race/TOCTOU hypothesis's operative safety
    argument is caller-held lock serialization: a lock-ish token
    appears in the dismissal, and either the mechanism or the
    reviewer's counter attributes the protection to a lock the caller
    holds (the witness corroborates the counter, mirroring the goconc
    precedent).  The fence decides only which dismissals the witness
    may examine — never the verdict.
    """
    both = f"{mechanism or ''} {counter or ''}"
    if not _CALLERLOCK_LOCK_TOKEN_RE.search(both):
        return False
    return bool(
        _CALLERLOCK_HELD_BY_CALLER_RE.search(mechanism or "")
        or _CALLERLOCK_HELD_BY_CALLER_RE.search(counter or "")
    )


def _record_callerlock_discharge(
    outcome,
    out_dir,
    *,
    mechanism: str,
    result,
) -> bool:
    """Accept-with-record: persist a caller-lock-discharged dismissal.

    Same never-silent contract as the goconc discharge: the record
    goes through the suppressions.jsonl single-writer chokepoint with
    ``dropped: false`` and a verdict naming the witness; returns True
    only when the record call completed, and the caller refuses the
    discharge on False (an unrecordable discharge must not happen).
    """
    if not out_dir:
        logger.debug(
            "caller-lock discharge for %s:%s refused (no out_dir to "
            "record)",
            getattr(outcome, "file", "?"),
            getattr(outcome, "function", "?"),
        )
        return False
    try:
        from core.analysis.reach_chokepoint import record_suppression

        line = getattr(outcome, "line", 0) or 0
        fpath = getattr(outcome, "file", "")
        func = getattr(outcome, "function", "")
        record_suppression(
            Path(out_dir),
            finding={
                "finding_id": f"audit-refutation:{fpath}:{func}:{line}",
                "rule_id": "audit:callerlock-witness",
                "file_path": fpath,
                "line": line,
                "function": func,
            },
            verdict="callerlock_witness_corroborates_dismissal",
            reason=(
                f"race/TOCTOU self-refutation accepted: the dismissal "
                f"is mechanically corroborated by the TU-local caller-"
                f"held-lock witness ({result.reasoning})"
            ),
            dropped=False,
            extra={
                "stage": "anti-self-refutation",
                "witness": "caller_lock",
                "floor_gate": "cwe_allowlist",
                "lock_class": result.lock_class,
                "lock_object": result.lock_object,
                "call_sites": result.call_sites,
                "callers": list(result.callers),
                "hypothesis": (mechanism or "")[:160],
            },
        )
        return True
    except Exception:
        logger.debug("caller-lock discharge record failed", exc_info=True)
        return False


# Pre-loop screen families whose injected evidence can corroborate a
# same-family self-refutation, and the hypothesis-text family matcher.
_INT_CONTRACT_PRE_EVIDENCE = ("check-parsed-int-contract",
                              "check-integer-narrowing")

# Mechanical detector families whose per-function receipt corroborates
# a same-family hypothesis the reviewer raised then dismissed or
# refuted. Keyed by the detector name's last path segment.
_DETECTOR_FAMILY_HYP_RES: dict[str, re.Pattern] = {
    "uninitialized_return": re.compile(
        r"uninitiali[sz]|no default|left unset|garbage|indetermin|"
        r"without (?:being )?initiali[sz]", re.IGNORECASE,
    ),
    # Return-domain mismatch: a hypothesis about a callee failure
    # signal escaping an exact-sentinel comparison (a return value
    # other than the tested -1, a non-exact sentinel check, a wide
    # error domain treated as binary). The paired `return_domain`
    # detector receipt carries a constructive domain proof, so this
    # regex only needs to recognise the hypothesis phrasing, never
    # decide the code.
    # Out-of-bounds on an undersized scatterlist: a hypothesis about
    # a scatterlist/sg table too small for a fragmented (frag_list /
    # non-linear) skb, or an OOB write past it. The paired
    # `scatterlist_frag_undersize` receipt carries the mechanical
    # sizing evidence (bare frag count mapped via skb_to_sgvec), so
    # this regex only recognises the hypothesis phrasing. Kept away
    # from lifetime ("sg freed then used") and bare integer-overflow
    # phrasings — those are other families' lanes.
    "scatterlist_frag_undersize": re.compile(
        # \boob\b: out-of-bounds shorthand, NOT out-of-band socket
        # vocabulary (OOB data / MSG_OOB lives in other families).
        r"out.of.bounds|\boob\b(?![-\s]+(?:data|band|byte|message))|"
        # undersiz* only next to a table/segment-shaped object — a
        # ring/allocation "undersized" by a race or an integer wrap
        # is another family's lane.
        r"undersiz\w*[^.;]{0,80}?(?:scatterlist|"
        r"sg (?:table|list|array|vec|entr\w*)|entr\w*|segments?|"
        r"fragments?|frag_list|mapping|\btable\b)|"
        r"(?:scatterlist|sg (?:table|list|array|vec|entr\w*)|"
        r"frag_list|fragmented|non.linear|\btable\b|mapping)"
        r"[^.;]{0,80}?undersiz|"
        r"undercount\w*[^.;]{0,80}?(?:entr\w*|segments?|fragments?|"
        r"scatterlist|sg |slots?)|"
        r"(?:scatterlist|sg (?:table|list|array|vec|entr\w*))"
        r"[^.;]{0,80}?(?:overflow|overrun|too small|too few|short|"
        r"exceed|past the end|beyond)|"
        r"(?:overflow|overrun|writes? past|walks? (?:beyond|past)|"
        r"exceed\w*)[^.;]{0,80}?(?:scatterlist|"
        r"sg (?:table|list|array|vec|entr\w*)|allocated entr\w*|"
        r"the table)|"
        r"too few (?:sg )?(?:slots?|entr\w*|elements?)|"
        # Fragmented-layout claims only in a sizing/bounds context —
        # a UAF/refcount/race/info-leak sentence that merely mentions
        # frag_list or a fragmented skb is another family's lane.
        r"(?:frag_list|fragmented|non.linear)[^.;]{0,120}?"
        r"(?:overflow|overrun|out.of.bounds|undersiz|undercount|"
        r"too small|too few|not counted|uncounted|unaccounted|"
        r"more (?:segments?|entries|fragments?) than)|"
        r"(?:too small|too few|not counted|uncounted|unaccounted)"
        r"[^.;]{0,120}?(?:frag_list|fragmented|non.linear)",
        re.IGNORECASE,
    ),
    "return_domain": re.compile(
        r"(?:return|error|failure)[^.;]{0,160}?(?:other than|"
        r"instead of|outside|beyond|different from|not the exact|"
        r"not the (?:expected|tested|checked))|"
        r"sentinel value|"
        r"(?:failure|error) (?:return|signal|code|value)"
        r"[^.;]{0,80}?(?:not fail.closed|fail.open)|"
        r"tri-?state[^.;]{0,80}?binary|"
        r"bypass\w*[^.;]{0,80}?(?:==\s*-1|-1 (?:check|comparison|"
        r"test))|"
        r"(?:==\s*-1|-1 (?:check|comparison))[^.;]{0,80}?"
        r"(?:bypass|miss|escape|fall)",
        re.IGNORECASE,
    ),
}
_INT_FAMILY_HYP_RE = re.compile(
    r"overflow|narrow|truncat|wraps?\b|int(?:8|16|32|64)\b|width",
    re.IGNORECASE,
)

# Detector receipt families the anti-self-refutation floor consumes
# (the last ``:``-segment of a mechanical detector name).  The
# merge-lane receipt fence (:mod:`core.audit.merge_fence`) reuses this
# exact taxonomy — one source of truth for what counts as a
# floor-grade detection receipt; a family added here is covered by
# the fence automatically.
FLOOR_DETECTOR_FAMILIES: frozenset[str] = frozenset(
    _DETECTOR_FAMILY_HYP_RES,
)

# Verdict string of the demote-with-record row a proof-grade refuter
# writes when it dominates a receipt floor (see
# :func:`_record_floor_dominance`).  The merge-lane receipt fence
# treats a receipt named by such a row as mechanically refuted.
DOMINANCE_VERDICT = "refuter_dominates_receipt"


@dataclass
class _ProbeContext:
    """What a proof-gate probe may see beyond the hypothesis text.

    ``source`` is the reviewed function's raw disk span,
    ``target_path`` the analysed tree's root (for gates that read the
    tree's own headers), ``repo_trusted`` the operator's repo-trust
    assertion (trust-gated gates refuse without it), and
    ``detector_finding`` the receipt's own record when the floor being
    probed is a mechanical-detector receipt (its description can name
    the exact variable the detector flagged).
    """

    source: str | None = None
    target_path: Any = None
    repo_trusted: bool = False
    detector_finding: dict | None = None


def _bounded_name_near_overflow_claim(mechanism_lower: str) -> bool:
    """A known-bounded function name must sit NEXT TO the overflow
    claim it refutes (~100 chars). Gate 4 waives its own proximity
    check when a CWE is established — including CWEs merely INFERRED
    from overflow keywords — which is fine for demoting a live
    hypothesis but too loose to override a receipt: an incidental
    mention of ntohs() three sentences away from an unrelated
    overflow claim must not read as a range proof for that claim."""
    for func_name in _KNOWN_RETURN_BOUNDS:
        pos = mechanism_lower.find(func_name)
        if pos < 0:
            continue
        window = mechanism_lower[max(0, pos - 100):pos + 100]
        if _OVERFLOW_KW.search(window):
            return True
    return False


def _probe_input_bound(
    outcome, hypothesis, ctx: _ProbeContext | None,
) -> RefutationVerdict | None:
    """Return-range probe (Gate 4's table).  Probe context is TIGHTER
    than the live gate: the refuting fact must sit next to the claim
    it refutes (see :func:`_bounded_name_near_overflow_claim`)."""
    mechanism = hypothesis.get("mechanism") or ""
    if not _bounded_name_near_overflow_claim(mechanism.lower()):
        return None
    explicit = _CWE_ID_RE.findall(
        (hypothesis.get("cwe") or "") + " " + mechanism,
    )
    probe = SimpleNamespace(
        file=getattr(outcome, "file", ""),
        function=getattr(outcome, "function", ""),
        hypothesis=mechanism,
        review_result={"cwe": explicit[0]} if explicit else {},
        evidence_tool="",
    )
    return _refute_by_known_return_type(probe, None)


# Names the detector-receipt description may use to pin the exact
# variable a mechanical uninitialised-value detector flagged.
_UNINIT_VAR_QUOTED_RE = re.compile(
    r"[Vv]ariable\s+['\"`]([A-Za-z_][A-Za-z0-9_]*)['\"`]",
)
_C_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _uninit_claim_variables(
    mechanism: str,
    detector_finding: dict | None,
    source: str,
) -> set[str]:
    """Variables an uninitialised-value claim concerns, resolved
    against the function's own declarations.

    When a detector receipt is in scope it MUST name its variable
    (``Variable 'x'``) and that variable must be among the function's
    declarations — otherwise the whole extraction refuses: proving a
    variable GUESSED from prose does not cover the receipt's claim.
    Prose identifiers that name declared locals join the set (proving
    more is stricter).  A candidate set consisting solely of
    PARAMETERS also refuses: parameters are assigned by the caller by
    definition, an uninitialised-value detector cannot flag one, so a
    parameter-only "proof" is trivial and covers nothing (the
    prose-only-parameter laundering shape).
    """
    from .defassign import (
        function_local_names,
        function_parameter_names,
    )

    declared = function_local_names(source)
    if not declared:
        return set()
    receipt_vars: set[str] = set()
    if detector_finding is not None:
        desc = ""
        if isinstance(detector_finding, dict):
            desc = str(detector_finding.get("description") or "")
        receipt_vars = {
            m.group(1) for m in _UNINIT_VAR_QUOTED_RE.finditer(desc)
        }
        if not receipt_vars or not receipt_vars <= declared:
            return set()
    prose_vars = {
        w for w in _C_IDENT_RE.findall(mechanism or "") if w in declared
    }
    candidates = receipt_vars | prose_vars
    if not candidates or candidates <= function_parameter_names(source):
        return set()
    return candidates


def _probe_definite_assignment(
    outcome, hypothesis, ctx: _ProbeContext | None,
) -> RefutationVerdict | None:
    """Definite-assignment probe for uninitialised-value claims on C.

    Proves the variable named by the detector receipt (and any
    declared locals the dismissed hypothesis names) is assigned on
    every path to every use in the function — a dataflow tautology
    over the macro-expanded source (:mod:`core.audit.defassign`),
    hence proof-grade.  Every candidate variable must prove; any
    refusal is no proof.  A receipt that does not name its variable,
    or a candidate set consisting solely of parameters, refuses (see
    :func:`_uninit_claim_variables`).

    TRUST-GATED: macro expansion reads the target tree's own headers,
    and a crafted tree can make the expansion diverge from what the
    build compiles (unreadable/generated headers, include-path games,
    command-line definitions).  The probe therefore runs only under
    the operator's repo-trust assertion — the same gate, for the same
    reason, as the Go internal-concurrency witness.
    """
    if ctx is None or not ctx.source or not ctx.target_path:
        return None
    if not ctx.repo_trusted:
        return None
    fpath = getattr(outcome, "file", "") or ""
    if not fpath.endswith(".c"):
        return None
    mechanism = hypothesis.get("mechanism") or ""
    if not _DETECTOR_FAMILY_HYP_RES["uninitialized_return"].search(
        mechanism,
    ):
        return None
    try:
        variables = _uninit_claim_variables(
            mechanism, ctx.detector_finding, ctx.source,
        )
        if not variables:
            return None
        from .defassign import check_definite_assignment
        proofs = []
        for var in sorted(variables):
            res = check_definite_assignment(
                ctx.source, var,
                target_path=ctx.target_path, rel_file=fpath,
            )
            if not res.proven:
                logger.debug(
                    "definite-assignment probe: no proof for %s (%s)",
                    var, res.reason,
                )
                return None
            proofs.append(res)
    except Exception:
        logger.debug(
            "definite-assignment probe failed", exc_info=True,
        )
        return None
    facts = "; ".join(
        f"{p.variable}: {p.reason}" for p in proofs
    )
    # Grade: PROOF. The refuting fact is a definite-assignment walk
    # over the macro-expanded function source — mechanically true
    # however the claim's prose is read. Conservative by
    # construction: every unresolvable construct in the prover
    # refuses, so reaching this point means the obligations fully
    # discharged.
    return RefutationVerdict(
        gate="definite_assignment",
        reason=(
            f"definite assignment proven for the claimed "
            f"variable(s) — {facts[:400]}"
        ),
        demote_to="clean",
        refuter_grade="proof",
    )


# Proof-grade probe registry. Membership here IS the dominance
# authority: the receipt-floor probe consults ONLY these probes, so a
# heuristic gate firing at probe time can never masquerade as a
# proof-grade refuter. Each member has the uniform signature
# ``(outcome, hypothesis, ctx) -> RefutationVerdict | None`` and
# decides its own applicability; only a verdict with
# ``refuter_grade == "proof"`` and a clean demote target counts.
# Today: the known-return-type table and the definite-assignment
# prover; an SMT-unsat-backed refuter would join it.
_PROOF_GATES = (_probe_input_bound, _probe_definite_assignment)


def _probe_proof_refuter(
    outcome, hypothesis, ctx: _ProbeContext | None = None,
) -> RefutationVerdict | None:
    """Ask the proof-grade probes whether they refute a hypothesis the
    reviewer raised then dismissed.

    The dismissed hypothesis never went through the demotion gates
    (they run on finding/suspicious outcomes only), so the receipt
    floor used to weigh the receipt against nothing but the LLM's
    unverified dismissal. This probe supplies the missing refuter
    side: the hypothesis is run through the PROOF probes alone
    (:data:`_PROOF_GATES`), and only a proof-grade verdict with a
    confident clean target counts.
    """
    if not isinstance(hypothesis, dict):
        return None
    mechanism = hypothesis.get("mechanism") or ""
    if not mechanism:
        return None
    for gate_fn in _PROOF_GATES:
        try:
            v = gate_fn(outcome, hypothesis, ctx)
        except Exception:
            logger.debug("proof-refuter probe failed", exc_info=True)
            continue
        if (
            v is not None
            and v.refuter_grade == "proof"
            and v.demote_to == "clean"
        ):
            return v
    return None


# Receipt names a Gate-4 (return-range) refuter may dominate: only
# integer-family receipts corroborate the claim the range fact
# refutes. A receipt from another family (uninitialised return, auth
# registration, shared-writer race, ...) corroborates an aspect the
# range argument says nothing about — no dominance across families.
_INT_RECEIPT_TOKEN_RE = re.compile(
    r"(?:^|[_\-: ])(?:int(?:eger)?|overflow|narrow\w*|truncat\w*|"
    r"wrap\w*|width)(?:$|[_\-: ])",
    re.IGNORECASE,
)

# Receipt names the definite-assignment prover may dominate: only
# uninitialised-value receipts (the cocci uninitialized_return
# detector and typestate-uninit shapes) corroborate the claim a
# definite-assignment fact refutes.
_UNINIT_RECEIPT_TOKEN_RE = re.compile(
    r"uninit", re.IGNORECASE,
)


def _refuter_covers_receipt(
    refuter: RefutationVerdict, receipt: str,
) -> bool:
    """Family alignment for dominance: the proof gate must refute the
    same claim family the receipt corroborates. Unknown gates default
    to False — a proof gate gains dominance only by declaring which
    receipt families its refuting fact covers."""
    if refuter.gate == "input_bound_t0":
        return bool(_INT_RECEIPT_TOKEN_RE.search(receipt or ""))
    if refuter.gate == "definite_assignment":
        return bool(_UNINIT_RECEIPT_TOKEN_RE.search(receipt or ""))
    return False


def _dominating_refuter(
    outcome, hypothesis, receipt: str,
    ctx: _ProbeContext | None = None,
) -> RefutationVerdict | None:
    """Proof-grade refuter that refutes the dismissed hypothesis AND
    covers the receipt's claim family, or None (floor stands)."""
    refuter = _probe_proof_refuter(outcome, hypothesis, ctx)
    if refuter is None:
        return None
    if not _refuter_covers_receipt(refuter, receipt):
        logger.debug(
            "proof refuter %s fired but does not cover receipt "
            "family %s — floor stands", refuter.gate, receipt,
        )
        return None
    return refuter


def _record_floor_dominance(
    outcome,
    config,
    *,
    refuter: RefutationVerdict,
    receipt: str,
    floor_gate: str,
    verdict: str = DOMINANCE_VERDICT,
    reason: str | None = None,
) -> bool:
    """Demote-with-record: persist the overridden detection receipt.

    A refuter overriding a receipt floor must never be silent — the
    receipt that would have held the function at suspicious goes
    through the suppressions.jsonl single-writer chokepoint with
    ``dropped: false`` and a reason naming the dominance decision.
    Record-or-refuse: returns True only when the record call
    completed; the caller refuses the dominance on False — the floor
    stands, because an unrecorded override would be silent.
    (``record_suppression`` itself swallows pure IO errors by its
    single-writer contract; this guard covers a missing sink and
    unexpected failures.)
    """
    out_dir = getattr(config, "out_dir", None) if config else None
    if not out_dir:
        logger.debug(
            "floor dominance for %s:%s refused (no out_dir to record)",
            getattr(outcome, "file", "?"), getattr(outcome, "function", "?"),
        )
        return False
    try:
        from pathlib import Path

        from core.analysis.reach_chokepoint import record_suppression

        line = getattr(outcome, "line", 0) or 0
        fpath = getattr(outcome, "file", "")
        func = getattr(outcome, "function", "")
        record_suppression(
            Path(out_dir),
            finding={
                "finding_id": f"audit-refutation:{fpath}:{func}:{line}",
                "rule_id": "audit:receipt-floor-dominance",
                "file_path": fpath,
                "line": line,
                "function": func,
            },
            verdict=verdict,
            reason=reason or (
                f"receipt floor overridden: {refuter.gate} refutes the "
                f"dismissed hypothesis with proof-grade evidence "
                f"({refuter.reason}); the {receipt} receipt is "
                f"detection-grade and does not outrank a mechanical "
                f"refutation — the full demote stands"
            ),
            dropped=False,
            extra={
                "stage": "refutation-floor",
                "floor_gate": floor_gate,
                "refuter_gate": refuter.gate,
                "refuter_grade": refuter.refuter_grade,
                "receipt": receipt,
            },
        )
        return True
    except Exception:
        logger.debug("floor-dominance record failed", exc_info=True)
        return False


def rescue_self_refuted(
    outcome,
    *,
    domain_model: dict[str, Any] | None = None,
    checklist: dict[str, Any] | None = None,
    config=None,
    negative_space: list | None = None,
    source: str | None = None,
    pre_evidence: str | None = None,
    detector_findings: list | None = None,
    target_path: Path | str | None = None,
    out_dir: Path | str | None = None,
    repo_trusted: bool | None = None,
) -> RefutationVerdict | None:
    """Rescue hypotheses the LLM formed then refuted without evidence.

    Fires when ALL of:
      - outcome.status == "clean"
      - at least one hypothesis has confidence == "refuted"
      - that hypothesis's CWE is in _SELF_REFUTATION_CWES, OR a
        structural negative-space receipt on this same function
        matches the hypothesis's family (the checker flagged the
        exact shape the reviewer refuted without evidence)
      - no mechanical tool has confirmed OR denied the hypothesis
      - the hypothesis has a non-empty counter field

    When *pre_evidence* names a pre-loop screen hit from the
    parsed-int/integer-narrowing family and a refuted hypothesis is in
    the same family, the screen receipt outranks the self-refutation —
    the mechanical checker flagged the exact contract the reviewer
    talked itself out of (same philosophy as the structural
    negative-space clause; the CWE allowlist cannot carry this case
    because integer CWEs are not in it).

    When *detector_findings* (this function's mechanical detector
    hits, as injected into the review prompt) contain a detector whose
    family matches a hypothesis the reviewer raised then REFUTED OR
    DISMISSED at low confidence, the detector receipt outranks the
    dismissal — the reviewer named the mechanical finding's exact
    defect and talked itself out of it without tool evidence.

    RECEIPT-FLOOR DOMINANCE: both receipt floors (detector and
    structural) weigh the receipt against the REFUTER, not just the
    dismissal. A detection-grade receipt outranks an unverified
    dismissal (today's floor), but a proof-grade refuter of the same
    claim family — a demotion gate whose refuting fact is
    mechanically true regardless of interpretation — outranks the
    receipt: the floor does not fire, the full demote stands, and the
    overridden receipt is persisted through the suppressions.jsonl
    chokepoint (``dropped: false``) so the decision is never silent.
    Resolution is over the WHOLE set of receipts matching a
    hypothesis, order-independently: if ANY matching receipt is not
    dominated, the floor stands and no dominance row is written.  A
    dominance whose record cannot be written is refused — the floor
    stands (record-or-refuse; an unrecorded override would be
    silent).  A heuristic refuter never dominates; findings with
    confirming tool evidence are never refuted at all (the
    ``is_tool_evidence`` guard above). Resolution is entirely
    mechanical — no LLM output participates.

    When *source* is provided and every shared-state access in it is
    mechanically lock-protected (:func:`check_race_protection`), a
    race-family (CWE-362/364/366) self-refutation is ACCEPTED instead
    of floored: the refutation is corroborated by the very evidence
    class this gate exists to demand, so re-flagging it manufactures a
    false positive (heavily serialized kernel code is the canonical
    shape). UAF/double-free self-refutations are unaffected — lock
    protection says nothing about object lifetime.

    On GO sources (where the C race witness bails), the same
    authority is granted to the Go internal-concurrency witness
    (:func:`core.audit.goconc.check_goroutine_isolation`): a
    race-family (CWE-362/364/366) self-refutation whose operative
    claim is package-internal concurrency is ACCEPTED when no
    goroutine spawned inside the owning package can reach the claimed
    state.  *target_path* (with the outcome's file path) locates the
    package on disk; the claim-phrasing fence decides only which
    dismissals the witness may examine — the proof is the package
    analysis.  The arm runs only when the operator asserted repo
    trust for the target (*repo_trusted*, or ``config.repo_trusted``
    resolved from the project's ``config`` trust marker): the
    witness's documented soundness bound — receiver-derived pointers
    laundered through package globals — is reachable by a crafted
    package on an untrusted target.  The discharge is never silent:
    an accept-with-record row MUST land in
    ``out_dir``/suppressions.jsonl (``dropped: false``) or the
    discharge is refused.  The witness never touches hypotheses on
    functions that carry a structural negative-space receipt — the
    structural-receipt floor outranks it by construction.

    Returns a verdict that promotes clean → suspicious so the sweep
    pass can attempt mechanical verification.
    """
    if outcome.status != "clean":
        return None

    race_protected = False
    teardown_safe = False
    teardown_reason = ""
    if source:
        try:
            from .condition_smt import check_race_protection
            race_protected = check_race_protection(source).protected
        except Exception:
            logger.debug("race-protection probe failed", exc_info=True)
        try:
            from .callback_lifetime import check_safe_teardown
            _st = check_safe_teardown(source)
            teardown_safe = _st.safe
            teardown_reason = _st.reason
            # The no-deallocation arm alone is too weak to discharge a
            # lifetime claim (the free may live elsewhere); demand the
            # serialization witness on top of it.
            if _st.no_dealloc and not race_protected:
                teardown_safe = False
        except Exception:
            logger.debug("safe-teardown probe failed", exc_info=True)

    # Go internal-concurrency witness — lazy: the package is loaded
    # and parsed only when a race-family dismissal is actually in
    # scope for it.  Memoised per gate invocation.  Gated on the
    # operator's repo-trust assertion (the project 'config' marker /
    # trust-repo umbrella): the witness's documented soundness bound
    # (receiver-derived pointers laundered through package globals)
    # is exactly what a crafted package on an UNTRUSTED target could
    # exploit to discharge a planted race, so without the assertion
    # the arm stays off.
    _witness_target = target_path or getattr(config, "target_path", None)
    _witness_out = out_dir or getattr(config, "out_dir", None)
    _witness_trusted = (
        repo_trusted if repo_trusted is not None
        else bool(getattr(config, "repo_trusted", False))
    )
    _goconc_memo: list = []

    def _goconc_probe():
        if _goconc_memo:
            return _goconc_memo[0]
        result = None
        fpath = getattr(outcome, "file", "") or ""
        if source and fpath.endswith(".go") and _witness_target:
            try:
                from .goconc import (
                    check_goroutine_isolation,
                    load_go_package,
                )
                pkg_files = load_go_package(_witness_target, fpath)
                if pkg_files:
                    anchor = fpath.replace("\\", "/").rsplit("/", 1)[-1]
                    result = check_goroutine_isolation(
                        source, pkg_files, anchor_file=anchor,
                    )
            except Exception:
                logger.debug("goconc probe failed", exc_info=True)
                result = None
        _goconc_memo.append(result)
        return result

    # TU-local caller-held-lock witness — lazy: the defining TU and
    # the tree-visibility scan run only when a race/TOCTOU dismissal
    # is actually in scope for it.  Memoised per gate invocation.
    # C only; same trust gate as the other source-level witnesses
    # (TU-locality claims are launderable by a crafted tree).
    _callerlock_memo: list = []

    def _callerlock_probe():
        if _callerlock_memo:
            return _callerlock_memo[0]
        result = None
        fpath = getattr(outcome, "file", "") or ""
        if source and fpath.endswith(".c") and _witness_target:
            try:
                from .caller_lock import check_caller_lock_serialization
                result = check_caller_lock_serialization(
                    source,
                    getattr(outcome, "function", "") or "",
                    rel_file=fpath,
                    target_path=_witness_target,
                )
            except Exception:
                logger.debug("caller-lock probe failed", exc_info=True)
                result = None
        _callerlock_memo.append(result)
        return result

    # Study-learned vocabulary for the lifetime witness (seed growth
    # rides the domain model only — never claim text).  Memoised per
    # gate invocation.
    _lt_vocab_memo: list = []

    def _lifetime_vocab():
        if _lt_vocab_memo:
            return _lt_vocab_memo[0]
        vocab = None
        dm = domain_model
        if dm is None and _witness_out:
            try:
                from core.json import load_json

                dm = load_json(Path(_witness_out) / "domain-model.json")
            except Exception:
                dm = None
        if isinstance(dm, dict):
            try:
                from .condition_smt import DomainVocabulary

                dv = DomainVocabulary.from_domain_model(dm)
                if dv.has_content:
                    vocab = dv
            except Exception:
                logger.debug("lifetime vocab load failed", exc_info=True)
        _lt_vocab_memo.append(vocab)
        return vocab

    def _probe_ctx(detector_finding: dict | None = None) -> _ProbeContext:
        """Context the proof-grade probes may see (dominance lane)."""
        return _ProbeContext(
            source=source,
            target_path=_witness_target,
            repo_trusted=_witness_trusted,
            detector_finding=detector_finding,
        )

    hypotheses = getattr(outcome, "hypotheses", None) or []
    if not hypotheses:
        rr = outcome.review_result or {}
        hypotheses = rr.get("hypotheses") or []

    from .evidence_grade import is_tool_evidence
    if is_tool_evidence(outcome.evidence_tool or ""):
        return None

    fn_receipts: list = []
    for nf in negative_space or []:
        ct = getattr(nf, "check_type", None) or (
            nf.get("check_type") if isinstance(nf, dict) else None
        )
        nf_fn = getattr(nf, "function", None) or (
            nf.get("function") if isinstance(nf, dict) else None
        )
        if ct and nf_fn == outcome.function:
            fn_receipts.append(ct)

    detector_families: list = []
    for df in detector_findings or []:
        det = (df.get("detector") if isinstance(df, dict)
               else getattr(df, "detector", "")) or ""
        fam = det.rsplit(":", 1)[-1]
        if fam in _DETECTOR_FAMILY_HYP_RES:
            detector_families.append(
                (det, _DETECTOR_FAMILY_HYP_RES[fam], df),
            )
    # The pre-loop screen's parsed-int/integer-narrowing receipt is a
    # detector receipt in everything but plumbing: same family
    # semantics, same dismissal modes (refuted OR low).
    if pre_evidence and any(
        t in pre_evidence for t in _INT_CONTRACT_PRE_EVIDENCE
    ):
        detector_families.append((pre_evidence, _INT_FAMILY_HYP_RE, None))

    if detector_families:
        for h in hypotheses:
            if not isinstance(h, dict):
                continue
            conf = (h.get("confidence") or "").lower()
            if conf not in ("refuted", "low"):
                continue
            mechanism = h.get("mechanism", "")
            matched = [
                (det, det_finding)
                for det, fam_re, det_finding in detector_families
                if fam_re.search(mechanism)
            ]
            if not matched:
                continue
            # Dominance: the receipts outrank an UNVERIFIED dismissal,
            # but not a proof-grade refuter. Resolution is over the
            # WHOLE matching set, order-independently: the full demote
            # stands only when EVERY matching receipt is dominated —
            # dominance over one receipt family must never silence
            # another. Probe first, record after: a floor that fires
            # writes no dominance rows (a row saying the demote stands
            # must never accompany a floor that fired), and a dominance
            # whose record cannot be written is REFUSED — the floor
            # stands (an unrecorded override would be silent).
            refuters = []
            undominated = None
            for det, det_finding in matched:
                refuter = _dominating_refuter(
                    outcome, h, det, ctx=_probe_ctx(det_finding),
                )
                if refuter is None:
                    undominated = det
                    break
                refuters.append((det, refuter))
            if undominated is None:
                recorded = True
                for det, refuter in refuters:
                    if not _record_floor_dominance(
                        outcome, config,
                        refuter=refuter, receipt=det,
                        floor_gate="anti_self_refutation",
                    ):
                        recorded = False
                        break
                if recorded:
                    for det, refuter in refuters:
                        logger.info(
                            "receipt floor overridden for %s:%s — "
                            "%s (%s) dominates %s",
                            getattr(outcome, "file", "?"),
                            getattr(outcome, "function", "?"),
                            refuter.gate, refuter.refuter_grade, det,
                        )
                    continue
                logger.info(
                    "receipt floor dominance for %s:%s refused — "
                    "demote-with-record could not write its record",
                    getattr(outcome, "file", "?"),
                    getattr(outcome, "function", "?"),
                )
                undominated = matched[0][0]
            return RefutationVerdict(
                gate="anti_self_refutation",
                reason=(
                    f"hypothesis '{mechanism[:80]}' raised then "
                    f"dismissed ({conf}) against an active "
                    f"{undominated} detector receipt on this "
                    f"function; the mechanical receipt outranks an "
                    f"unverified dismissal"
                ),
                demote_to="suspicious",
            )

    for h in hypotheses:
        if not isinstance(h, dict):
            continue
        conf = (h.get("confidence") or "").lower()
        if conf != "refuted":
            continue
        counter = h.get("counter", "")
        if not counter:
            continue

        mechanism = h.get("mechanism", "")
        cwes = _extract_cwes_from_text(mechanism)
        # Mechanically-discharged CWE families: a self-refutation whose
        # every claimed class is covered by a corroborating witness is
        # ACCEPTED — re-flagging it manufactures a false positive.
        discharged: set = set()
        if race_protected:
            discharged |= _LOCK_DISCHARGEABLE_RACE_CWES
        if teardown_safe:
            # Lifetime self-refutations are corroborated by the
            # safe-teardown witness (waiting cancel / RCU-deferred
            # reclamation / self-handler / no deallocation in scope).
            # The async-cancel-then-free shape grades UNSAFE, so a
            # reviewer talking itself out of that real race is still
            # floored.
            discharged |= _TEARDOWN_DISCHARGEABLE_CWES
        if cwes and cwes <= discharged:
            logger.info(
                "anti-self-refutation: accepting self-refutation for "
                "%s — mechanically corroborated (%s)",
                getattr(outcome, "function", "?"),
                "; ".join(
                    ([("race: full lock protection")] if race_protected
                     and cwes & _LOCK_DISCHARGEABLE_RACE_CWES else [])
                    + ([f"lifetime: {teardown_reason}"] if teardown_safe
                       and cwes & _TEARDOWN_DISCHARGEABLE_CWES else [])
                ),
            )
            continue
        # Go internal-concurrency discharge: race-family only, Go
        # sources only, in-family claims only, only under the
        # operator's repo-trust assertion, and NEVER on a function
        # carrying a structural receipt (the structural-receipt floor
        # is a different lane and outranks the witness).  The
        # discharge must be recorded or it does not happen.
        if (
            cwes
            and cwes <= _LOCK_DISCHARGEABLE_RACE_CWES
            and _witness_trusted
            and not fn_receipts
            and _goconc_claim_in_family(mechanism, counter)
        ):
            _giso = _goconc_probe()
            if _giso is not None and _giso.isolated:
                if _record_goconc_discharge(
                    outcome, _witness_out,
                    mechanism=mechanism, result=_giso,
                ):
                    logger.info(
                        "anti-self-refutation: accepting self-"
                        "refutation for %s — mechanically "
                        "corroborated (goconc: %s)",
                        getattr(outcome, "function", "?"),
                        _giso.reasoning,
                    )
                    continue
                logger.info(
                    "anti-self-refutation: goconc discharge for %s "
                    "refused — accept-with-record could not write "
                    "its record",
                    getattr(outcome, "function", "?"),
                )
        # TU-local caller-held-lock discharge: race/TOCTOU families
        # only, C translation units only, in-family claims only
        # (the dismissal must attribute the safety to caller-held
        # serialization), only under the operator's repo-trust
        # assertion, and NEVER on a function carrying a structural
        # receipt (that floor is a different lane and outranks the
        # witness).  CWE-367 is dischargeable HERE and not by the
        # in-function witness because the caller holds the lock
        # across the whole call — check and use both execute inside
        # one held region.  The discharge must be recorded or it
        # does not happen.  The floor-membership conjunct keeps the
        # arm scoped to dismissals the CWE-allowlist floor would
        # actually catch: a pure CWE-367 claim never floors, so
        # there is nothing to discharge (and a record claiming
        # otherwise would be misleading).
        if (
            cwes
            and cwes <= _CALLERLOCK_DISCHARGEABLE_CWES
            and cwes & _SELF_REFUTATION_CWES
            and _witness_trusted
            and not fn_receipts
            and _callerlock_claim_in_family(mechanism, counter)
        ):
            _clw = _callerlock_probe()
            if _clw is not None and _clw.held:
                if _record_callerlock_discharge(
                    outcome, _witness_out,
                    mechanism=mechanism, result=_clw,
                ):
                    logger.info(
                        "anti-self-refutation: accepting self-"
                        "refutation for %s — mechanically "
                        "corroborated (caller_lock: %s)",
                        getattr(outcome, "function", "?"),
                        _clw.reasoning,
                    )
                    continue
                logger.info(
                    "anti-self-refutation: caller-lock discharge "
                    "for %s refused — accept-with-record could not "
                    "write its record",
                    getattr(outcome, "function", "?"),
                )
        # C lifetime witness discharge: CWE-415/416 claims on C
        # sources whose non-lifetime remainder is already discharged,
        # only under the operator's repo-trust assertion, and NEVER on
        # a function carrying a structural receipt.  The witness's own
        # claim-phrasing fences and proof obligations decide the rest;
        # the discharge must be recorded or it does not happen.
        if (
            cwes
            and cwes & _TEARDOWN_DISCHARGEABLE_CWES
            and not (cwes - _TEARDOWN_DISCHARGEABLE_CWES - discharged)
            and source
            and _witness_trusted
            and not fn_receipts
            and (getattr(outcome, "file", "") or "").endswith(".c")
            and _witness_target
        ):
            _lt = None
            try:
                from .lifetime_witness import check_lifetime_claim

                _lt = check_lifetime_claim(
                    source, mechanism, cwes,
                    target_path=_witness_target,
                    rel_file=getattr(outcome, "file", "") or "",
                    vocab=_lifetime_vocab(),
                )
            except Exception:
                logger.debug(
                    "lifetime witness probe failed", exc_info=True,
                )
            if (
                _lt is not None
                and _lt.discharged
                and (cwes & _TEARDOWN_DISCHARGEABLE_CWES)
                <= _lt.covered_cwes
            ):
                if _record_lifetime_discharge(
                    outcome, _witness_out,
                    mechanism=mechanism, result=_lt,
                ):
                    logger.info(
                        "anti-self-refutation: accepting self-"
                        "refutation for %s — mechanically "
                        "corroborated (lifetime: %s)",
                        getattr(outcome, "function", "?"),
                        _lt.reason,
                    )
                    continue
                logger.info(
                    "anti-self-refutation: lifetime discharge for "
                    "%s refused — accept-with-record could not "
                    "write its record",
                    getattr(outcome, "function", "?"),
                )
        if cwes & _SELF_REFUTATION_CWES:
            return RefutationVerdict(
                gate="anti_self_refutation",
                reason=(
                    f"hypothesis '{mechanism[:80]}' self-refuted without "
                    f"mechanical evidence; concurrency/lifecycle "
                    f"self-refutations are unreliable"
                ),
                demote_to="suspicious",
            )
        matched_receipts = [
            ct for ct in fn_receipts
            if _receipt_matches_mechanism(ct, mechanism)
        ]
        if matched_receipts:
            # Same dominance rule as the detector-receipt floor,
            # resolved over the WHOLE matching set order-independently:
            # the demote stands only when EVERY matching structural
            # receipt is dominated; probe first, record after; a
            # dominance whose record cannot be written is refused.
            refuters = []
            undominated = None
            for receipt in matched_receipts:
                refuter = _dominating_refuter(
                    outcome, h, receipt, ctx=_probe_ctx(),
                )
                if refuter is None:
                    undominated = receipt
                    break
                refuters.append((receipt, refuter))
            if undominated is None:
                recorded = True
                for receipt, refuter in refuters:
                    if not _record_floor_dominance(
                        outcome, config,
                        refuter=refuter, receipt=receipt,
                        floor_gate="anti_self_refutation",
                    ):
                        recorded = False
                        break
                if recorded:
                    for receipt, refuter in refuters:
                        logger.info(
                            "receipt floor overridden for %s:%s — "
                            "%s (%s) dominates %s",
                            getattr(outcome, "file", "?"),
                            getattr(outcome, "function", "?"),
                            refuter.gate, refuter.refuter_grade,
                            receipt,
                        )
                    continue
                logger.info(
                    "receipt floor dominance for %s:%s refused — "
                    "demote-with-record could not write its record",
                    getattr(outcome, "file", "?"),
                    getattr(outcome, "function", "?"),
                )
                undominated = matched_receipts[0]
            return RefutationVerdict(
                gate="anti_self_refutation",
                reason=(
                    f"hypothesis '{mechanism[:80]}' self-refuted "
                    f"against an active {undominated} receipt on "
                    f"this function; the structural receipt outranks "
                    f"an unverified self-refutation"
                ),
                demote_to="suspicious",
            )

    return None


def diagnose_rescue(
    outcome,
    *,
    negative_space: list | None = None,
) -> dict[str, Any] | None:
    """Explain why :func:`rescue_self_refuted` did not fire.

    Mirrors the gate's precondition chain link by link and reports the
    first one that broke, so a run leaves a durable receipt whenever a
    structural negative-space receipt exists on a function the reviewer
    ruled clean but the rescue stayed silent.  Returns ``None`` when the
    gate would fire (nothing to explain), otherwise a JSON-safe dict:

    - ``blocked_on``: the first failed precondition
      (``status`` / ``no_hypotheses`` / ``tool_evidence`` /
      ``no_refuted_hypothesis`` / ``no_counter`` /
      ``no_matching_receipt_or_cwe``)
    - ``receipts``: structural check types on this function
    - ``confidences``: per-hypothesis confidence values
    """
    if outcome.status != "clean":
        return {"blocked_on": "status", "status": outcome.status}

    hypotheses = getattr(outcome, "hypotheses", None) or []
    if not hypotheses:
        rr = outcome.review_result or {}
        hypotheses = rr.get("hypotheses") or []

    fn_receipts: list = []
    for nf in negative_space or []:
        ct = getattr(nf, "check_type", None) or (
            nf.get("check_type") if isinstance(nf, dict) else None
        )
        nf_fn = getattr(nf, "function", None) or (
            nf.get("function") if isinstance(nf, dict) else None
        )
        if ct and nf_fn == outcome.function:
            fn_receipts.append(ct)

    confidences = [
        (h.get("confidence") or "").lower()
        for h in hypotheses if isinstance(h, dict)
    ]
    base: dict[str, Any] = {
        "receipts": fn_receipts,
        "confidences": confidences,
    }

    if not hypotheses:
        return {"blocked_on": "no_hypotheses", **base}

    from .evidence_grade import is_tool_evidence
    if is_tool_evidence(outcome.evidence_tool or ""):
        return {
            "blocked_on": "tool_evidence",
            "evidence_tool": outcome.evidence_tool,
            **base,
        }

    refuted = [
        h for h in hypotheses
        if isinstance(h, dict)
        and (h.get("confidence") or "").lower() == "refuted"
    ]
    if not refuted:
        return {"blocked_on": "no_refuted_hypothesis", **base}
    with_counter = [h for h in refuted if h.get("counter")]
    if not with_counter:
        return {"blocked_on": "no_counter", **base}

    for h in with_counter:
        mechanism = h.get("mechanism", "")
        if _extract_cwes_from_text(mechanism) & _SELF_REFUTATION_CWES:
            return None
        receipt = next(
            (ct for ct in fn_receipts
             if _receipt_matches_mechanism(ct, mechanism)),
            None,
        )
        if receipt:
            # Mirror the gate's dominance rule: a proof-grade refuter
            # of the receipt's family means the floor deliberately
            # did not fire — report that instead of "would fire".
            if _dominating_refuter(outcome, h, receipt) is not None:
                return {
                    "blocked_on": "proof_refuter_dominance",
                    "receipt": receipt,
                    **base,
                }
            return None
    return {"blocked_on": "no_matching_receipt_or_cwe", **base}


# ---------------------------------------------------------------------------
# Gate 6: Callee-inheritance suppression (demotion gate)
# ---------------------------------------------------------------------------

_CALLEE_VULN_PATTERNS = re.compile(
    r"(?:call(?:s|ed|ing)?|invok(?:es?|ing)|delegat(?:es?|ing)|"
    r"pass(?:es|ing)?(?:\s+to)?)\s+(?:a\s+)?(?:buggy|vulnerable|"
    r"unsafe|flawed)\s+(?:function|callee|routine|method|helper|"
    r"implementation)",
    re.IGNORECASE,
)

_CALLEE_NAME_IN_HYPO = re.compile(
    r"(?:the\s+)?(?:function|callee|call\s+to)\s+[`'\"]?(\w+)[`'\"]?\s+"
    r"(?:is|has|contains|suffers|may|could|might)\s+",
    re.IGNORECASE,
)

_WRAPPER_EXCLUSION_RE = re.compile(
    r"\*\s*\(|\([^)]*\*\s*\)"
    r"|\b(?:memcpy|memset|memmove|copy_from_user|copy_to_user)\b"
    r"|\b(?:k?m?alloc|calloc|realloc|kzalloc|kmalloc|vmalloc)\b",
)


def _refute_by_callee_inheritance(
    outcome,
    source: str,
    callees: list,
) -> RefutationVerdict | None:
    """Refute when the hypothesis names a callee's bug, not ours.

    Fires when:
      1. The hypothesis text attributes the bug to a named callee
      2. The function body is a thin wrapper (<=10 SLOC)
      3. The function does not transform data (no casts, memcpy, allocs)
    """
    hyp = outcome.hypothesis or ""
    if not hyp:
        return None

    matched_callee = False
    if _CALLEE_VULN_PATTERNS.search(hyp):
        matched_callee = True
    else:
        m = _CALLEE_NAME_IN_HYPO.search(hyp)
        if m:
            named_callee = m.group(1)
            if named_callee in callees:
                matched_callee = True

    if not matched_callee:
        return None

    code_lines = [
        ln.strip() for ln in source.strip().splitlines()
        if ln.strip()
        and not ln.strip().startswith("//")
        and not ln.strip().startswith("/*")
        and not ln.strip().startswith("*")
        and not ln.strip().startswith("#")
        and ln.strip() not in ("{", "}")
    ]
    body_lines = code_lines[1:] if code_lines else []

    if len(body_lines) > 10:
        return None

    body = "\n".join(body_lines)
    if _WRAPPER_EXCLUSION_RE.search(body):
        return None

    # Grade: HEURISTIC. The refuting fact ("the bug belongs to the
    # callee") comes from regex attribution over the hypothesis text
    # plus an SLOC threshold and a transform-pattern exclusion list —
    # interpretation of prose, not a mechanical property of the code.
    return RefutationVerdict(
        gate="callee_inheritance",
        reason=(
            f"hypothesis attributes bug to callee, but {outcome.function} "
            f"is a thin delegation wrapper ({len(body_lines)} SLOC) that "
            f"does not transform data"
        ),
        demote_to="clean",
        refuter_grade="heuristic",
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


_CWE_ID_RE = re.compile(r"CWE-\d+")


def _extract_cwe(outcome) -> str | None:
    """Extract CWE ID(s) from outcome, falling back to hypothesis inference.

    LLMs return CWEs in many formats:
      - bare:      ``"CWE-362"``
      - described: ``"CWE-362: Concurrent Execution..."``
      - multi:     ``"CWE-476: ...; CWE-362: ..."``
      - parens:    ``"CWE-362 (Race Condition), CWE-667 (Locking)"``

    We normalise to just the ``CWE-NNN`` ID so frozenset membership
    checks in the gates work regardless of description noise.
    When the string contains multiple CWE IDs, return the first one
    found — callers that need to match any of several CWEs should
    use :func:`_extract_all_cwes` instead.
    """
    review = outcome.review_result or {}
    cwe_raw = review.get("cwe") or review.get("cwe_class") or ""
    if cwe_raw:
        m = _CWE_ID_RE.search(cwe_raw)
        if m:
            return m.group(0)
        return cwe_raw  # unrecognised format — pass through

    # Fall back to keyword inference
    hyp = outcome.hypothesis or ""
    if not hyp:
        return None
    try:
        from .cwe_dispatch import infer_cwe_from_hypothesis
        return infer_cwe_from_hypothesis(hyp)
    except ImportError:
        return None


def _extract_all_cwes(outcome) -> frozenset[str]:
    """Extract all CWE IDs from outcome as a frozenset.

    Used by gates that should fire when *any* listed CWE matches
    (e.g. ``"CWE-476; CWE-362"`` should still trigger the
    architecture gate for CWE-362).
    """
    review = outcome.review_result or {}
    cwe_raw = review.get("cwe") or review.get("cwe_class") or ""
    if cwe_raw:
        ids = _CWE_ID_RE.findall(cwe_raw)
        if ids:
            return frozenset(ids)

    # Fall back to keyword inference (returns single CWE)
    hyp = outcome.hypothesis or ""
    if not hyp:
        return frozenset()
    try:
        from .cwe_dispatch import infer_cwe_from_hypothesis
        inferred = infer_cwe_from_hypothesis(hyp)
        if inferred:
            return frozenset({inferred})
    except ImportError:
        pass
    return frozenset()


def _extract_cwes_from_text(text: str) -> frozenset[str]:
    """Extract CWE IDs from free-form text (mechanism, hypothesis, etc.).

    Unlike ``_extract_all_cwes`` which reads from an outcome's
    ``review_result``, this operates on arbitrary strings — used by
    Gate 5 to extract CWEs from a hypothesis mechanism field.
    Falls back to keyword inference when no explicit CWE-NNN is found.
    """
    ids = _CWE_ID_RE.findall(text)
    if ids:
        return frozenset(ids)
    try:
        from .cwe_dispatch import infer_cwe_from_hypothesis
        inferred = infer_cwe_from_hypothesis(text)
        if inferred:
            return frozenset({inferred})
    except ImportError:
        pass
    return frozenset()


def _get_calls(fentry: dict[str, Any]) -> list:
    """Extract the calls list from a checklist file entry."""
    cg = fentry.get("call_graph", {})
    if isinstance(cg, dict):
        calls = cg.get("calls", [])
        if isinstance(calls, list):
            return calls
    return []


def _get_function_source_and_callees(
    outcome,
    checklist: dict[str, Any] | None,
) -> tuple:
    """Look up function source and callee names from checklist.

    Returns (source, callees) where source is the function body text
    and callees is a list of called function names.  Both may be empty
    if the checklist doesn't have the data.
    """
    if not checklist:
        return "", []

    for fentry in checklist.get("files", []):
        if fentry.get("path") != outcome.file:
            continue
        for item in fentry.get("items", []):
            if item.get("name") != outcome.function:
                continue
            source = item.get("source", "")
            callees = []
            for c in _get_calls(fentry):
                if c.get("caller") == outcome.function:
                    chain = c.get("chain", [])
                    if chain:
                        callees.extend(chain)
            return source, callees

    return "", []
