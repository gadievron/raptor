"""Bridge frida runtime evidence into the validation pipeline.

Discovers frida evidence for a target and produces runtime_evidence
annotations that Stage B can use to floor proximity scores, and
Stage D can use as independent corroboration.

Pattern follows understand_bridge.py -- discovers output from a prior
/frida run and feeds it into the validation pipeline's data model.
"""

from __future__ import annotations

import copy
import os
import re
from dataclasses import dataclass
from pathlib import Path

from core.logging import get_logger

log = get_logger("orchestration.frida_validation_bridge")

__all__ = [
    "PROXIMITY_FLOOR",
    "RuntimeEvidence",
    "annotate_attack_paths",
    "collect_runtime_evidence",
    "extract_step_function_name",
]

PROXIMITY_FLOOR = 6


@dataclass
class RuntimeEvidence:
    """Runtime evidence from a frida session for one attack path step."""

    function_observed: bool
    call_count: int = 0
    observed_args: list | None = None
    trace_id: str = ""
    # Source-resolved call sites: [{"module", "offset", "source"}]
    # where source is "file:line" (addr2line on the run's target
    # binary) or None when unresolvable. Bounded, deduped.
    observed_callsites: list | None = None


def collect_runtime_evidence(
    search_dirs: list[Path],
    target_path: str | None = None,
) -> dict[str, RuntimeEvidence]:
    """Discover frida evidence and build a function->RuntimeEvidence map.

    Searches ``search_dirs`` for frida run directories via the shared
    evidence discovery layer.  When ``target_path`` is given, only runs
    whose metadata target matches are used.

    Returns {function_name: RuntimeEvidence} for all functions frida
    observed.  Empty dict if no frida evidence found.
    """
    try:
        from packages.frida import parse_events
        from packages.frida.evidence import discover_evidence
    except ImportError:
        log.debug("packages.frida not importable; skipping frida evidence")
        return {}

    evidence_list = discover_evidence(search_dirs, target_path=target_path)
    if not evidence_list:
        return {}

    result: dict[str, RuntimeEvidence] = {}
    dropped_unattributed = 0
    dropped_callers: dict[str, int] = {}

    for ev in evidence_list:
        if not ev.has_events:
            continue
        events_path = ev.run_dir / "events.jsonl"
        trace_id = str(ev.run_dir)
        target_name = (Path(ev.target_binary).name
                       if ev.target_binary else None)
        target_dir = (str(Path(ev.target_binary).parent)
                      if ev.target_binary else None)

        # Per-run counters: track call_count within this run, then take
        # the max across runs (represents the hottest single run).
        run_counts: dict[str, int] = {}
        run_first_args: dict[str, list | None] = {}
        run_callsites: dict[str, list[dict]] = {}

        for record in parse_events(events_path):
            if not isinstance(record, dict):
                continue
            if record.get("type") != "send":
                continue
            payload = record.get("payload")
            if not isinstance(payload, dict):
                continue
            if "_meta" in payload:
                # Lifecycle / cap markers, not calls (some carry a fn
                # key for operator display).
                continue
            fn = payload.get("fn")
            if not isinstance(fn, str) or not fn:
                continue
            category = payload.get("category")
            if category in _EVIDENCE_EXCLUDED_CATEGORIES:
                # seed-harvest (ingest) exists to produce seeds and
                # emits no callsite; jni maps registration, not calls.
                continue
            if not _attributed_to_target(payload, target_name,
                                          target_dir):
                dropped_unattributed += 1
                caller = payload.get("caller_module")
                if isinstance(caller, str) and caller:
                    dropped_callers[caller] = dropped_callers.get(caller, 0) + 1
                continue

            # Alias groups (IFUNC-shared implementations like
            # memcpy/memmove) credit every name: the hook cannot know
            # which name the call site used, and a finding may name
            # either. Deduplicated — a self-alias (the same fn watched
            # plain and module-scoped) must not double-count — and
            # bounded like every other payload field: the agent runs
            # inside the target process, and an unbounded list would
            # let one forged event mint evidence for thousands of
            # names.
            names = [fn]
            aliases = payload.get("aliases")
            if isinstance(aliases, list):
                names.extend(
                    a for a in aliases[:_MAX_ALIASES]
                    if isinstance(a, str)
                    and 0 < len(a) <= _MAX_OBSERVED_ARG_STR)
            names = list(dict.fromkeys(names))

            args = payload.get("args")
            callsite = _event_callsite(payload)
            for name in names:
                run_counts[name] = run_counts.get(name, 0) + 1
                if run_first_args.get(name) is None:
                    run_first_args[name] = _sanitize_observed_args(args)
                if callsite is not None:
                    sites = run_callsites.setdefault(name, [])
                    if (len(sites) < _MAX_CALLSITES
                            and callsite not in sites):
                        sites.append(callsite)

        _resolve_run_callsites(run_callsites, ev.target_binary)

        for fn, count in run_counts.items():
            if fn in result:
                existing = result[fn]
                new_args = existing.observed_args
                if new_args is None:
                    new_args = run_first_args.get(fn)
                # trace_id follows the run that produced the reported
                # (max) count — a record must never cite a run that did
                # not show its own numbers.
                if count > existing.call_count:
                    new_count, new_trace = count, trace_id
                else:
                    new_count, new_trace = existing.call_count, existing.trace_id
                new_sites = existing.observed_callsites
                if not new_sites:
                    new_sites = run_callsites.get(fn)
                result[fn] = RuntimeEvidence(
                    function_observed=True,
                    call_count=new_count,
                    observed_args=new_args,
                    trace_id=new_trace,
                    observed_callsites=new_sites,
                )
            else:
                result[fn] = RuntimeEvidence(
                    function_observed=True,
                    call_count=count,
                    observed_args=run_first_args.get(fn),
                    trace_id=trace_id,
                    observed_callsites=run_callsites.get(fn),
                )

    log.info("collected runtime evidence: %d functions from %d runs",
             len(result), len(evidence_list))
    if dropped_unattributed:
        top = sorted(dropped_callers.items(), key=lambda kv: -kv[1])[:3]
        detail = ", ".join(f"{m}×{n}" for m, n in top) or "<none recorded>"
        if result:
            # A handful of pre-main libc startup calls drop on every
            # healthy spawn run — routine, not actionable.
            log.debug(
                "%d sink-family event(s) failed target attribution "
                "(top caller modules: %s)",
                dropped_unattributed, detail)
        else:
            # Never let attribution loss look like "no sink calls
            # occurred": name the dropped callers so the operator can
            # see the evidence exists but could not be tied to the
            # target.
            log.warning(
                "%d sink-family event(s) failed target attribution and "
                "NO evidence was collected (top caller modules: %s) — "
                "evidence requires the target binary on the call stack; "
                "spawn a binary target, and note calls made entirely "
                "inside shipped libraries without the main binary on "
                "the stack cannot be attributed",
                dropped_unattributed, detail)
    return result


def annotate_attack_paths(
    attack_paths: list[dict],
    evidence_map: dict[str, RuntimeEvidence],
    finding_locations: dict[str, tuple[str, int]] | None = None,
) -> list[dict]:
    """Annotate attack paths with runtime_evidence from frida.

    For each attack path step whose function appears in the evidence
    map, adds a ``runtime_evidence`` dict to the step.  If any step
    has runtime evidence that does not CONTRADICT the step (a
    ``callsite_match`` of False means every resolved call site is a
    different location), floors the path's proximity at
    ``PROXIMITY_FLOOR`` (precedent: SMT feasible:true floor in
    Stage B).

    Returns a deep copy of attack_paths with annotations.  The
    original list is never mutated.
    """
    if not evidence_map:
        return attack_paths

    result = copy.deepcopy(attack_paths)

    for path in result:
        if not isinstance(path, dict):
            continue

        has_evidence = False
        floor_eligible = False
        first_trace_id = None

        steps = path.get("steps")
        if not isinstance(steps, list):
            continue

        for step in steps:
            if not isinstance(step, dict):
                continue

            fn_name = _extract_function_name(step)
            if not fn_name:
                continue

            ev = evidence_map.get(fn_name)
            if ev is None:
                continue

            has_evidence = True
            if first_trace_id is None:
                first_trace_id = ev.trace_id
            runtime_evidence: dict = {
                "function_observed": ev.function_observed,
                "call_count": ev.call_count,
                "observed_args": ev.observed_args,
                "trace_id": ev.trace_id,
            }
            match = None
            if ev.observed_callsites:
                runtime_evidence["observed_callsites"] = [
                    dict(s) for s in ev.observed_callsites]
                match = _callsite_match(
                    ev.observed_callsites, step,
                    finding_locations, path.get("finding"))
                if match is not None:
                    runtime_evidence["callsite_match"] = match
            # A False match means every resolved call site is a
            # DIFFERENT location than the step/finding names — this
            # step's evidence contradicts the path rather than
            # corroborating it, so it must not establish the
            # proximity floor (None — nothing resolved — keeps the
            # original name-level flooring semantics).
            if match is not False:
                floor_eligible = True
            step["runtime_evidence"] = runtime_evidence

        if has_evidence:
            path["runtime_evidence_available"] = True
            if first_trace_id:
                path["frida_trace_id"] = first_trace_id
            if floor_eligible:
                current_proximity = path.get("proximity")
                if isinstance(current_proximity, (int, float)):
                    if current_proximity < PROXIMITY_FLOOR:
                        path["proximity"] = PROXIMITY_FLOOR
                else:
                    path["proximity"] = PROXIMITY_FLOOR

    return result


# Line tolerance when matching a resolved call site against a step or
# finding location: the caller offset resolves to the CALL line, which
# sits at or near the location a finding/step names.
_STEP_LINE_TOLERANCE = 2
_FINDING_LINE_TOLERANCE = 5

_LOCATION_RE = re.compile(r"^(.*):(\d+)$")


def _callsite_match(
    callsites: list[dict],
    step: dict,
    finding_locations: dict[str, tuple[str, int]] | None,
    finding_id: object,
) -> bool | None:
    """True/False when a comparison was possible, None when the step
    and finding carry no usable location.

    True upgrades ``function_observed`` from "this function ran" to
    "this SPECIFIC call site ran" — the distinction that matters for
    ubiquitous sinks, which attribute from any target I/O.
    """
    expectations: list[tuple[str, int, int]] = []
    for key, tolerance in (("call_site", _STEP_LINE_TOLERANCE),
                           ("definition", _STEP_LINE_TOLERANCE)):
        value = step.get(key)
        if isinstance(value, str):
            m = _LOCATION_RE.match(value.strip())
            if m:
                expectations.append((m.group(1), int(m.group(2)),
                                     tolerance))
    if finding_locations and isinstance(finding_id, str):
        loc = finding_locations.get(finding_id)
        if loc and isinstance(loc[0], str) and isinstance(loc[1], int):
            expectations.append((loc[0], loc[1],
                                 _FINDING_LINE_TOLERANCE))
    if not expectations:
        return None

    # No comparison is possible when nothing resolved to source
    # (release builds, library callsites, addr2line unavailable) —
    # that is None, never False: False must always mean "resolved to
    # a DIFFERENT call site".
    if not any(isinstance(s.get("source"), str) for s in callsites):
        return None

    for site in callsites:
        source = site.get("source")
        if not isinstance(source, str):
            continue
        m = _LOCATION_RE.match(source)
        if not m:
            continue
        src_path, src_line = m.group(1), int(m.group(2))
        for want_path, want_line, tolerance in expectations:
            if abs(src_line - want_line) > tolerance:
                continue
            # Resolved paths are compile-dir absolute; step/finding
            # paths are repo-relative — compare by suffix on whole
            # path components.
            if (src_path == want_path
                    or src_path.endswith("/" + want_path)
                    or want_path.endswith("/" + src_path)):
                return True
    return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


# Event categories that require target attribution before they count
# as runtime evidence. These are the sink/exec/loader hook families:
# their function names (memcpy, system, dlopen, ...) fire constantly
# from library internals — an IDLE process calls memcpy — so an
# unattributed observation says nothing about a finding's call path,
# and annotate_attack_paths joins evidence to steps by name (the
# floor is withheld only when a resolved call site actively
# contradicts the step). Legacy categories (file/network/parser/
# process) keep their original semantics.
_TARGET_ATTRIBUTED_CATEGORIES = frozenset({"sink", "exec", "load", "heap"})

# Categories that never count as call evidence: seed-harvest's ingest
# events exist to produce seeds (no callsite is captured, so they can
# never attribute); jni events map RegisterNatives registrations, not
# calls to a finding's function; call_edge events feed the
# frida_call_edge reachability witness through their own collector
# (counting them here would double-dip aggregated edge counts into
# per-call evidence).
_EVIDENCE_EXCLUDED_CATEGORIES = frozenset({"ingest", "jni", "call_edge"})

# Observed-args bounds: a template may embed captured payload bytes in
# its args (an execve argv is 30+ target-controlled strings; custom
# scripts may nest data_hex); none of that may ride into
# attack-paths.json and LLM prompts.
_MAX_OBSERVED_ARGS = 8
_MAX_OBSERVED_ARG_STR = 128
_MAX_OBSERVED_DEPTH = 2
_MAX_ATTRIBUTION_FRAMES = 16
# An IFUNC alias group has 2-3 members in practice; anything larger is
# a forged event.
_MAX_ALIASES = 8

# Callsite bounds: unique call sites kept per function, and unique
# addresses resolved per run (one sandboxed addr2line batch per run).
_MAX_CALLSITES = 8
_MAX_RESOLVE_ADDRS = 128


def _attributed_to_target(payload: dict, target_name: str | None,
                          target_dir: str | None) -> bool:
    """True when this event may count as runtime evidence.

    The target's code must appear at the call site OR anywhere on the
    captured backtrace: real projects ship the vulnerable code in
    their own libraries and call sinks through wrappers, so requiring
    the immediate caller alone would silently drop that evidence. A
    caller module whose on-disk PATH lives under the target binary's
    directory tree also attributes — that covers project-shipped
    libraries whose call chains never touch the main binary (plugin
    callbacks, dlopen'd codecs) without admitting system libraries.
    """
    if payload.get("category") not in _TARGET_ATTRIBUTED_CATEGORIES:
        return True
    if not target_name:
        # Attach-by-name run: no binary to attribute against —
        # conservative (evidence promotes, so dropping is safe).
        return False
    caller = payload.get("caller_module")
    if isinstance(caller, str) and caller == target_name:
        return True
    caller_path = payload.get("caller_module_path")
    if (isinstance(caller_path, str) and target_dir
            and caller_path.startswith("/")):
        # realpath BOTH normalizes ".." segments and resolves symlink
        # traversals: the loader reports the path the target dlopen'd
        # (possibly through a symlinked project dir), while target_dir
        # comes from parse_target's RESOLVED binary path — comparing
        # the raw forms silently no-ops in exactly the symlinked-tree
        # case this rule exists for.
        resolved = os.path.realpath(caller_path)
        if resolved.startswith(target_dir + "/"):
            return True
    frames = payload.get("backtrace_frames")
    if isinstance(frames, list):
        for frame in frames[:_MAX_ATTRIBUTION_FRAMES]:
            if (isinstance(frame, dict)
                    and frame.get("module") == target_name):
                return True
    return False


def _event_callsite(payload: dict) -> dict | None:
    """Extract a resolvable call site from an event payload."""
    module = payload.get("caller_module")
    offset = payload.get("caller_offset")
    if not (isinstance(module, str) and module
            and isinstance(offset, str) and offset):
        return None
    site: dict = {"module": module[:128], "offset": offset[:32],
                  "source": None}
    base = payload.get("caller_module_base")
    if isinstance(base, str) and base:
        site["_base"] = base[:32]
    path = payload.get("caller_module_path")
    if isinstance(path, str) and path:
        site["_path"] = path[:512]
    return site


def _resolve_run_callsites(run_callsites: dict[str, list[dict]],
                           target_binary: str | None) -> None:
    """Resolve call sites in the run's TARGET BINARY to file:line.

    Mutates the site dicts in place: fills ``source`` and strips the
    private working keys. Only sites whose caller module is the run's
    target binary are resolvable (that is the binary we have); library
    callsites keep source=None. Best-effort — a resolution failure
    leaves the raw module+offset, which is still evidence.
    """
    try:
        _do_resolve_run_callsites(run_callsites, target_binary)
    except Exception:  # noqa: BLE001 — resolution is additive
        log.debug("callsite resolution failed", exc_info=True)
    finally:
        for sites in run_callsites.values():
            for site in sites:
                site.pop("_base", None)
                site.pop("_path", None)


def _do_resolve_run_callsites(run_callsites: dict[str, list[dict]],
                              target_binary: str | None) -> None:
    if not target_binary or not run_callsites:
        return
    binary = Path(target_binary)
    if not binary.is_file():
        return
    target_name = binary.name

    # Unique candidate addresses across the run. Dual-candidate PIE
    # handling (same trick as the drcov import): resolve the offset
    # both as a PIE file-vaddr (offset itself) and as base+offset;
    # the wrong interpretation yields ?? and drops out.
    wanted: list[tuple[dict, int, int | None]] = []
    addrs: set[int] = set()
    for sites in run_callsites.values():
        for site in sites:
            if site["module"] != target_name:
                continue
            try:
                offset = int(site["offset"], 16)
            except (TypeError, ValueError):
                continue
            absolute: int | None = None
            base_raw = site.get("_base")
            if isinstance(base_raw, str):
                try:
                    absolute = int(base_raw, 16) + offset
                except ValueError:
                    absolute = None
            wanted.append((site, offset, absolute))
            addrs.add(offset)
            if absolute is not None:
                addrs.add(absolute)
            if len(addrs) >= _MAX_RESOLVE_ADDRS:
                break
        if len(addrs) >= _MAX_RESOLVE_ADDRS:
            break
    if not wanted:
        return

    resolved = _addr2line_batch(binary, sorted(addrs))
    if not resolved:
        # Routine for release builds (no DWARF) — but also the shape a
        # sandbox-unreadable binary produces (a binary directly under
        # /tmp is masked by the sandbox's fresh tmpfs). Say so once.
        log.info(
            "0/%d callsites resolved for %s (no debug info, addr2line "
            "unavailable, or binary unreadable inside the sandbox — "
            "binaries directly under /tmp are masked)",
            len(addrs), binary)
        return
    for site, offset, absolute in wanted:
        source = resolved.get(offset)
        if source is None and absolute is not None:
            source = resolved.get(absolute)
        if source is not None:
            site["source"] = source


def _addr2line_batch(binary: Path, addrs: list[int]) -> dict[int, str]:
    """Resolve addresses to "file:line" via sandboxed addr2line.

    Returns only real resolutions (?? and line 0 dropped). The binary
    is operator/target-supplied: binutils DWARF parsers have a CVE
    history, so the invocation runs inside the sandbox with the
    binary's directory as the readable target (the binary_oracle
    convention).
    """
    import shutil as _shutil

    if not addrs or _shutil.which("addr2line") is None:
        return {}
    from core.sandbox import run as _sandbox_run

    out: dict[int, str] = {}
    argv = (["addr2line", "-e", str(binary)]
            + [hex(a) for a in addrs])
    try:
        proc = _sandbox_run(
            argv,
            block_network=True,
            target=str(binary.resolve().parent),
            capture_output=True, text=True, timeout=120,
        )
    except Exception:  # noqa: BLE001 — resolution is additive
        log.debug("addr2line invocation failed", exc_info=True)
        return {}
    if proc.returncode != 0:
        return {}
    lines = (proc.stdout or "").splitlines()
    # addr2line emits exactly one line per input address, in order.
    for addr, line in zip(addrs, lines):
        path, sep, rest = line.rpartition(":")
        if not sep or not path or path.startswith("??"):
            continue
        num = rest.split()[0] if rest else ""
        if num.isdigit() and int(num) > 0:
            out[addr] = f"{path}:{num}"
    return out


def _bound_value(value: object, depth: int = 0) -> object:
    """Recursively bound one observed-args value."""
    if isinstance(value, str):
        if len(value) > _MAX_OBSERVED_ARG_STR:
            return value[:_MAX_OBSERVED_ARG_STR] + "…"
        return value
    if isinstance(value, list):
        if depth >= _MAX_OBSERVED_DEPTH:
            return "…"
        return [_bound_value(v, depth + 1)
                for v in value[:_MAX_OBSERVED_ARGS]]
    if isinstance(value, dict):
        if depth >= _MAX_OBSERVED_DEPTH:
            return "…"
        return {k: _bound_value(v, depth + 1)
                for k, v in list(value.items())[:_MAX_OBSERVED_ARGS]
                if k != "data_hex"}
    return value


def _sanitize_observed_args(args: object) -> list | None:
    """Bound the args sample stored in RuntimeEvidence.observed_args."""
    if isinstance(args, dict):
        values = [v for k, v in args.items() if k != "data_hex"]
    elif isinstance(args, list):
        values = list(args)
    else:
        return None
    return [_bound_value(v) for v in values[:_MAX_OBSERVED_ARGS]]


_ACTION_FN_RE = re.compile(r'\b([a-zA-Z_]\w*)\s*\(')
_KEYWORDS = frozenset({
    "if", "for", "while", "switch", "catch", "return", "sizeof", "typeof",
    "alignof", "decltype", "throw", "new", "delete",
})


def _extract_function_name(step: dict) -> str | None:
    """Extract a function name from an attack path step.

    Steps use varying formats: some have a ``function`` or ``name``
    key, others have ``action`` strings like ``"call strcpy(buf, in)"``.
    For action strings we take the LAST function-call pattern since
    earlier tokens are typically callers, not the vulnerable callee.
    """
    for key in ("function", "name"):
        val = step.get(key)
        if isinstance(val, str) and val:
            return _strip_parens(val)

    action = step.get("action")
    if isinstance(action, str) and action:
        last_match = None
        for m in _ACTION_FN_RE.finditer(action):
            candidate = m.group(1)
            if candidate not in _KEYWORDS:
                last_match = candidate
        if last_match:
            return last_match

    return None


# Public name: packages.frida.sink_watch derives watch lists from
# attack-path steps with the same extraction rules Stage B uses, so
# the two surfaces cannot drift.
def extract_step_function_name(step: dict) -> str | None:
    """Extract a function name from an attack path step (public form
    of :func:`_extract_function_name`)."""
    return _extract_function_name(step)


def _strip_parens(name: str) -> str:
    """Remove trailing parentheses from a function name."""
    name = name.strip()
    if name.endswith("()"):
        return name[:-2]
    idx = name.find("(")
    if idx > 0:
        return name[:idx].strip()
    return name
