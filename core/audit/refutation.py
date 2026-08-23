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
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


@dataclass
class RefutationVerdict:
    """Result of a refutation gate firing."""

    gate: str
    reason: str  # human-readable explanation
    demote_to: str  # "clean" or "suspicious"


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
    return RefutationVerdict(
        gate="architecture",
        reason=(
            f"single-threaded target, function {outcome.function} not "
            f"reachable from signal handlers — {cwe_label} impossible"
        ),
        demote_to="clean",
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
    if is_leak:
        return RefutationVerdict(
            gate="lifecycle",
            reason=(
                f"init-only function {outcome.function} (called before "
                f"event loop) — resource leak cannot accumulate"
            ),
            demote_to="clean",
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
            return RefutationVerdict(
                gate="contract",
                reason=(
                    f"domain model contract for {outcome.function} says "
                    f"input is '{semantics[:80]}' — not attacker-controlled"
                ),
                demote_to="suspicious",  # keyword match is fragile
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
# negative value is exactly what a CWE-191 underflow claim needs, so
# they refute overflow (CWE-190) claims only.
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

    # An underflow claim needs the value to go NEGATIVE (or wrap below
    # zero) — a return type bounded above refutes nothing when the
    # function can already return a negative sentinel (EOF).
    claims_underflow = cwe == "CWE-191" or "underflow" in hyp_lower

    # Check if any known-bounded function appears in the hypothesis.
    # When multiple match, pick the one closest to an overflow keyword
    # for audit trail clarity.
    best: tuple[str, str, int, int] | None = None  # (name, type, max, dist)
    for func_name, (ret_type, min_val, max_val) in \
            _KNOWN_RETURN_BOUNDS.items():
        func_pos = hyp_lower.find(func_name)
        if func_pos < 0:
            continue
        if claims_underflow and min_val < 0:
            # getchar()/fgetc()/tolower() return EOF (-1): the table
            # only bounds the value above, which cannot refute a
            # CWE-191 (underflow) hypothesis.
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
        return RefutationVerdict(
            gate="input_bound_t0",
            reason=(
                f"{func_name}() returns {ret_type} (max {max_val:#x})"
                f" — cannot cause integer {cwe or 'overflow'}"
            ),
            demote_to="clean",
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

    When *source* is provided and every shared-state access in it is
    mechanically lock-protected (:func:`check_race_protection`), a
    race-family (CWE-362/364/366) self-refutation is ACCEPTED instead
    of floored: the refutation is corroborated by the very evidence
    class this gate exists to demand, so re-flagging it manufactures a
    false positive (heavily serialized kernel code is the canonical
    shape). UAF/double-free self-refutations are unaffected — lock
    protection says nothing about object lifetime.

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
            detector_families.append((det, _DETECTOR_FAMILY_HYP_RES[fam]))
    # The pre-loop screen's parsed-int/integer-narrowing receipt is a
    # detector receipt in everything but plumbing: same family
    # semantics, same dismissal modes (refuted OR low).
    if pre_evidence and any(
        t in pre_evidence for t in _INT_CONTRACT_PRE_EVIDENCE
    ):
        detector_families.append((pre_evidence, _INT_FAMILY_HYP_RE))

    if detector_families:
        for h in hypotheses:
            if not isinstance(h, dict):
                continue
            conf = (h.get("confidence") or "").lower()
            if conf not in ("refuted", "low"):
                continue
            mechanism = h.get("mechanism", "")
            for det, fam_re in detector_families:
                if fam_re.search(mechanism):
                    return RefutationVerdict(
                        gate="anti_self_refutation",
                        reason=(
                            f"hypothesis '{mechanism[:80]}' raised then "
                            f"dismissed ({conf}) against an active {det} "
                            f"detector receipt on this function; the "
                            f"mechanical receipt outranks an unverified "
                            f"dismissal"
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
        receipt = next(
            (ct for ct in fn_receipts
             if _receipt_matches_mechanism(ct, mechanism)),
            None,
        )
        if receipt:
            return RefutationVerdict(
                gate="anti_self_refutation",
                reason=(
                    f"hypothesis '{mechanism[:80]}' self-refuted "
                    f"against an active {receipt} receipt on this "
                    f"function; the structural receipt outranks an "
                    f"unverified self-refutation"
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
        if any(
            _receipt_matches_mechanism(ct, mechanism)
            for ct in fn_receipts
        ):
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

    return RefutationVerdict(
        gate="callee_inheritance",
        reason=(
            f"hypothesis attributes bug to callee, but {outcome.function} "
            f"is a thin delegation wrapper ({len(body_lines)} SLOC) that "
            f"does not transform data"
        ),
        demote_to="clean",
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
