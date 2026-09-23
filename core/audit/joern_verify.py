"""Joern no-execution verification channels for /audit hypotheses.

Two mechanical verifiers on the live Joern CPG server:

* **Guard-dominance** — for "missing check" hypotheses (missing
  bounds / null / auth check on identifier X before sink Y).  A CPGQL
  query determines whether a control-structure condition mentioning X
  DOMINATES the claimed sink call site (every path from function entry
  to the sink evaluates the check).  A dominating check mechanically
  REFUTES the "missing check" hypothesis, with the dominator node as
  evidence.  No dominating check is confirm-capable only when the sink
  and identifier both match the hypothesis (identifier-consistency
  negative control, same discipline as sweep.py's semgrep controls).

* **Flow reachability** — for taint-style hypotheses ("attacker data
  from X reaches Y").  A ``reachableByFlows`` query from the named
  source to the named sink within the function (or across the file).
  A flow with matching identifiers confirms with the flow path as
  evidence; no flow on a well-formed query refutes only when the CPG
  actually covered the function — if the function is not in the CPG
  the outcome is inconclusive, never refuted (vacuity guard).

Security posture matches ``packages/joern``: the scanned repo is
untrusted and nothing from it executes.  Queries are RAPTOR-authored
CPGQL with every substituted value validated against the identifier
allowlist and Scala-escaped; results come back over the loopback-only
server API.  When Joern is unavailable the outcome is ``error`` with a
clear reason — never a crash, never a fabricated verdict.

Returns :class:`core.audit.sweep.SweepResult`-compatible outcomes.
Evidence stamps are namespaced ``joern:guard-dominance`` /
``joern:flow``.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, TYPE_CHECKING

from ._util import is_valid_identifier
from .sweep import SweepResult, _check_path_containment

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

GUARD_DOMINANCE_STAMP = "joern:guard-dominance"
FLOW_STAMP = "joern:flow"
# Sanitizer-aware flow lane (CWE-116): the confirm additionally claims
# "no required-class sanitizer name on the flow path" — a textual
# name-membership test that cannot prove the encoding was correct for
# the context, so the stamp is detection-grade (below).
FLOW_ENCODING_STAMP = "joern:flow-encoding"

# Detection-grade joern stamps: bare taint reachability (``joern:live``
# from the orchestrator's live-query corroboration, ``joern:pre_sweep``
# from the batch pre-sweep) proves a source→sink dataflow EXISTS and
# nothing about the hypothesis mechanism — ``reachableByFlows`` is
# guard-blind, so a correctly clamped copy still "flows". Such
# receipts corroborate through multi-channel aggregation and never
# convict or sustain alone. The hypothesis-endpoint-bound stamps
# (``joern:flow``, ``joern:guard-dominance``, ``joern:taint:*``) keep
# verification role. ``joern:flow-encoding`` is endpoint-bound too but
# its extra premise — no sanitizer NAME on the path — is textual, so
# it corroborates without convicting alone.
DETECTION_STAMPS = frozenset({
    "joern:live", "joern:pre_sweep", FLOW_ENCODING_STAMP,
})


def is_detection_rule_id(rule_id: str) -> bool:
    """Joern-channel detection-grade stamp classification.

    The single authority for which joern stamps may not promote or
    sustain a verdict alone — consulted by the orchestrator's
    promote-role check (``_is_detection_only``) and by the
    evidence-grade firewall (``is_tool_evidence`` via
    ``_DETECTION_CLASSIFIER_MODULES``), so the two can never drift.
    """
    return rule_id in DETECTION_STAMPS

# CWE families dispatched to each channel (wired via
# orchestrator._cwe_fallback_chain).
GUARD_DOMINANCE_CWES = frozenset({
    # CWE-121: stack variant of the 120/122/787 buffer family.
    "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-476",
    # P10 web families: "missing validation before sink" shapes — a
    # dominating check on the hypothesis identifier refutes, an
    # unguarded sink site confirms.
    "CWE-22", "CWE-23", "CWE-502", "CWE-918", "CWE-611", "CWE-601",
    "CWE-77",
})
FLOW_CWES = frozenset({
    "CWE-20", "CWE-74", "CWE-78", "CWE-89", "CWE-79",
    # CWE-130: length-parameter inconsistency — the recv-length →
    # parse/copy flow question (sinks come from cwe_dispatch).
    "CWE-130",
    # CWE-908: uninitialised-resource disclosure — the uninitialised
    # object → copy-out sink flow question (sinks from cwe_dispatch;
    # the joern live-query receipts on this family's promoted finding
    # were exactly these memcpy flows).
    "CWE-908",
    # P10 web families: source→sink reachability is verification-grade
    # for all of these (sinks come from cwe_dispatch).
    "CWE-22", "CWE-23", "CWE-502", "CWE-918", "CWE-611", "CWE-601",
    "CWE-77", "CWE-94", "CWE-95", "CWE-1321",
    # CWE-116: taint reaching an encoding-relevant emitter — the
    # sanitizer-aware lane (confirms are detection-grade, see
    # FLOW_ENCODING_STAMP / _FLOW_SANITIZER_CLASSES).
    "CWE-116",
})

# CWE → required sanitizer classes (the sanitizer_catalog sink-class
# vocabulary) for the sanitizer-aware flow lane. Scoped to CWE-116
# only: filtering flows for the established families would be strictly
# more conservative but is a behaviour change needing its own fixture
# evidence — extend per class, never wholesale. Both directions
# weighed at this site: adding a class here downgrades its flow
# confirms to detection grade (FLOW_ENCODING_STAMP) in exchange for
# the sanitizer-path premise; removing CWE-116 would let a bare
# reachableByFlows confirm an "unencoded" claim it never tested.
# Every class listed here MUST have seeds in _SANITIZER_NAME_SEEDS
# (the lane-arming invariant — see that table's comment).
_FLOW_SANITIZER_CLASSES: dict[str, tuple[str, ...]] = {
    "CWE-116": ("xss",),
}

# Fallback sink lists for CWEs without a sink-carrying cwe_dispatch
# entry (CWE-476 is joern=False there; CWE-20/74 have no entry at
# all).  Deref-adjacent libc calls stand in for "sink the pointer
# must be checked before"; the injection families get the classic
# copy/exec/format sinks.
_DEFAULT_GUARD_SINKS: dict[str, list[str]] = {
    "CWE-476": ["memcpy", "memmove", "memset", "strcpy", "strncpy",
                "strlen", "free"],
    "CWE-20": ["memcpy", "strcpy", "strncpy", "sprintf", "system",
               "popen"],
    "CWE-74": ["system", "popen", "execve", "execl", "sprintf",
               "printf"],
}

_DEFAULT_QUERY_TIMEOUT_S = 300

# Output-protocol sentinels (kept distinct from packages/joern's
# JOERN_FLOW / JOERN_DARK markers, which the server parser also reads).
# Each query invocation stamps a fresh random nonce after the marker
# (``RAPTOR_GD_FUNC:<nonce>:payload``) and the parsers accept only
# lines that START with the nonce'd marker.  The sentinel payloads
# quote target source code (``s.code``), so an unanchored / un-nonce'd
# parse lets a scanned repo forge facts by simply containing the
# marker text in a string or comment near a sink — minting refutations
# or suppressing confirmations.  The nonce is minted per invocation
# (the merge_fence record_nonce pattern), so target bytes present in
# the CPG at scan time cannot predict it.
_GD_FUNC = "RAPTOR_GD_FUNC:"
_GD_SINKS = "RAPTOR_GD_SINKS:"
_GD_UNGUARDED = "RAPTOR_GD_UNGUARDED:"
_GD_GUARDED = "RAPTOR_GD_GUARDED:"
_FLOW_FUNC = "RAPTOR_FLOW_FUNC:"
_FLOW_SRC = "RAPTOR_FLOW_SRC:"
_FLOW_SNK = "RAPTOR_FLOW_SNK:"
_FLOW_COUNT = "RAPTOR_FLOW_COUNT:"
# Count of internal (CPG-resident) methods reachable one call level
# BEYOND the engine's maxCallDepth — the depth-bound witness for the
# refutation lane. -1 = probe failed (Try fallback).
_FLOW_DEEP = "RAPTOR_FLOW_DEEP:"
# UNCAPPED count of unguarded sink sites, emitted alongside the
# evidence lines (which ARE capped). The refutation is a universal
# quantifier over every sink — it must key on the full-set count, or
# a cap on evidence emission silently truncates the quantifier and a
# genuinely unguarded 51st sink books a false refutation. Name is
# deliberately not a prefix-extension of _GD_UNGUARDED: the parsers
# anchor by startswith.
_GD_UNG_TOTAL = "RAPTOR_GD_UNG_TOTAL:"


# Scala expression template flattening a payload before it joins a
# sentinel line. Payloads quote hostile source, and the parse is
# line-anchored, so every code point Python's splitlines() treats as a
# line break must flatten (\\n alone left \\r/\\v/\\f and the Unicode
# separators able to push payload bytes to line-anchored positions);
# '|' is the field separator; 'JOERN_' is neutralised so hostile text
# cannot mint record-marker lines that the server-side flow parser
# tries (and fails) to decode.
_PAYLOAD_FLATTEN_SCALA = (
    '{expr}.take(200)'
    '.replaceAll("[\\\\r\\\\n\\\\u000B\\\\f\\\\u0085\\\\u2028\\\\u2029]",'
    ' " ")'
    '.replace("|", "/").replace("JOERN_", "JOERN-")'
)


def _mint_nonce() -> str:
    """Fresh per-invocation sentinel nonce (hex — Scala-string-safe)."""
    return os.urandom(8).hex()


def _anchored(marker: str, nonce: str) -> str:
    """The full line prefix a genuine sentinel line carries."""
    return f"{marker}{nonce}:"


def normalize_cwe(cwe: str) -> str:
    """Normalise ``"120"`` / ``"cwe-120"`` → ``"CWE-120"``."""
    normalized = (cwe or "").upper().strip()
    if normalized and not normalized.startswith("CWE-"):
        normalized = f"CWE-{normalized}"
    return normalized


def default_query_timeout() -> int:
    """Resolve the query timeout from the central Joern tunables."""
    try:
        from packages.joern.tunables import JoernTunables
        return JoernTunables.from_tuning().query_timeout_s
    except Exception:  # noqa: BLE001 — tuning backends vary; any failure means "use default"
        return _DEFAULT_QUERY_TIMEOUT_S


# ── chain-entry helpers (consumed by orchestrator._cwe_fallback_chain) ──


def guard_chain_entry(cwe: str) -> dict[str, Any] | None:
    """Tool-chain entry for the guard-dominance channel, or None."""
    norm = normalize_cwe(cwe)
    if norm not in GUARD_DOMINANCE_CWES:
        return None
    sinks = _sinks_for(norm)
    if not sinks:
        return None
    # The CWE rides the entry so the dispatcher can bind the
    # refutation to the check KIND the hypothesis asserts
    # (guard_check_kind).
    return {"type": "joern_guard", "config": {"sinks": sinks,
                                              "cwe": norm}}


def flow_chain_entry(
    cwe: str, file_path: str | None = None,
) -> dict[str, Any] | None:
    """Tool-chain entry for the flow-reachability channel, or None.

    Classes in :data:`_FLOW_SANITIZER_CLASSES` carry their required
    sanitizer classes in the config — the dispatch site resolves them
    to concrete names (catalog + IRIS specs + seeds) at check time.
    ``file_path`` feeds the dispatch entry's ``joern_langs`` gate
    (CWE-116 legs are c/cpp-only); entries without the key keep their
    pre-existing ungated behaviour for every caller.
    """
    norm = normalize_cwe(cwe)
    if norm not in FLOW_CWES:
        return None
    try:
        from .cwe_dispatch import joern_language_permitted
    except ImportError:
        pass
    else:
        if not joern_language_permitted(norm, file_path):
            return None
    sinks = _sinks_for(norm)
    if not sinks:
        return None
    config: dict[str, Any] = {"sinks": sinks}
    sanitizer_classes = _FLOW_SANITIZER_CLASSES.get(norm)
    if sanitizer_classes:
        config["sanitizer_classes"] = list(sanitizer_classes)
    return {"type": "joern_flow", "config": config}


def _sinks_for(norm_cwe: str) -> list[str]:
    sinks: list[str] = []
    try:
        from .cwe_dispatch import sinks_for_cwe
        sinks = sinks_for_cwe(norm_cwe)
    except ImportError:
        pass
    if not sinks:
        sinks = _DEFAULT_GUARD_SINKS.get(norm_cwe, [])
    return sinks


# ── sanitizer-name resolution for the sanitizer-aware flow lane ──────

# File suffix → known_safe_calls catalog language. Only the languages
# the curated catalog actually carries entries for — other targets get
# their sanitizer vocabulary from the IRIS specs and the seeds.
_CATALOG_LANG_BY_EXT: dict[str, str] = {
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}

# SEED-tier encoder names per sanitizer class: small, curated,
# universal library encoders only (the seed-set policy). The real
# per-target vocabulary is learned — IRIS sanitiser-role specs read
# from the run's out dir at check time. INVARIANT (pinned by test):
# every class in _FLOW_SANITIZER_CLASSES has a non-empty seed tuple
# here, so flow_sanitizer_names never resolves empty for an armed
# lane — an empty resolution would silently stamp the confirm with
# the verification-grade FLOW_STAMP instead of FLOW_ENCODING_STAMP.
_SANITIZER_NAME_SEEDS: dict[str, tuple[str, ...]] = {
    "xss": ("htmlspecialchars", "htmlentities", "urlencode",
            "rawurlencode"),
}

# Per-path memo of IRIS sanitiser names, keyed on mtime_ns so a
# refreshed spec file re-reads (the specs are written once per run
# but the checks run for hours).
_IRIS_SANITIZER_MEMO: dict[str, tuple[int, tuple[str, ...]]] = {}


def _iris_sanitizer_names(out_dir: Path | None) -> tuple[str, ...]:
    """Sanitiser-role function names from the run's IRIS specs.

    Reads ``iris-taint-specs.json`` from *out_dir* (the file the
    orchestrator's spec-prep phase writes). Missing/unreadable/
    unparseable file → empty; a malformed ENTRY is skipped
    individually (one junk spec must not drop the valid ones) — the
    lane degrades to catalog + seeds, never errors.
    """
    if out_dir is None:
        return ()
    path = Path(out_dir) / "iris-taint-specs.json"
    try:
        mtime = path.stat().st_mtime_ns
    except OSError:
        return ()
    key = str(path)
    memo = _IRIS_SANITIZER_MEMO.get(key)
    if memo is not None and memo[0] == mtime:
        return memo[1]
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001 — degrade per the docstring contract
        # A defective spec FILE (unreadable bytes, invalid JSON)
        # degrades this tier to empty — a malformed run artifact must
        # never abort the flow check itself.
        return ()
    if not isinstance(raw, list):
        return ()
    found: set[str] = set()
    for item in raw:
        # Per-entry tolerance: skip junk entries individually. Both
        # role spellings accepted — parse_spec_response normalises
        # "sanitizer" → "sanitiser" at LLM-parse time, but a spec
        # file written by another producer may carry either form.
        if not isinstance(item, dict):
            continue
        if item.get("role") not in ("sanitiser", "sanitizer"):
            continue
        fn = item.get("function")
        if isinstance(fn, str) and is_valid_identifier(fn):
            found.add(fn)
    names = tuple(sorted(found))
    _IRIS_SANITIZER_MEMO[key] = (mtime, names)
    return names


def flow_sanitizer_names(
    sanitizer_classes: Sequence[str],
    file_path: str,
    out_dir: Path | None,
) -> tuple[str, ...]:
    """Concrete sanitizer names for the sanitizer-aware flow lane.

    Union of three tiers: the curated known-safe catalog (sink-class
    match, language from the file suffix), the run's IRIS-synthesised
    sanitiser specs (the learned per-target vocabulary), and the
    per-class seeds. Empty when *sanitizer_classes* is empty — the
    plain flow lane is untouched.
    """
    classes = {c for c in sanitizer_classes if c}
    if not classes:
        return ()
    names: set[str] = set()
    lang = _CATALOG_LANG_BY_EXT.get(Path(file_path or "").suffix.lower())
    if lang:
        try:
            from core.dataflow.known_safe_calls import all_entries
        except ImportError:
            pass
        else:
            names.update(
                entry.library_call
                for entry in all_entries()
                if entry.sink_class in classes and lang in entry.languages
            )
    names.update(_iris_sanitizer_names(out_dir))
    for cls in classes:
        names.update(_SANITIZER_NAME_SEEDS.get(cls, ()))
    return tuple(sorted(names))


def _partition_sanitized_flows(
    flows: list[Any],
    sanitizer_names: Sequence[str],
) -> tuple[list[Any], list[Any]]:
    """Split flows into (unsanitized, sanitized) by path-step calls.

    A flow is *sanitized* when any step's code calls a sanitizer name
    (word boundary + open paren; dotted catalog names match on their
    trailing segment, mirroring the sink-name handling). Textual by
    design — the honest claim is "no sanitizer NAME on the returned
    path", nothing stronger. Known suppression trigger: step code is
    raw source text, so a sanitizer name followed by ``(`` inside a
    STRING LITERAL or comment on a path step also counts as sanitized
    — a target can suppress this lane's confirms by mentioning
    encoder names in strings. Suppression-direction only (the lane
    goes inconclusive, the class stays dark for review); the stamp is
    detection-grade regardless, so nothing convicting is lost.
    """
    patterns = [
        re.compile(
            rf"\b{re.escape(name.rsplit('.', maxsplit=1)[-1])}\s*\(",
        )
        for name in sanitizer_names
    ]
    unsanitized: list[Any] = []
    sanitized: list[Any] = []
    for flow in flows:
        texts = " ".join(
            str(getattr(s, "code", ""))
            for s in (getattr(flow, "steps", []) or [])
        )
        if any(p.search(texts) for p in patterns):
            sanitized.append(flow)
        else:
            unsanitized.append(flow)
    return unsanitized, sanitized


# ── hypothesis extraction ────────────────────────────────────────────

_BACKTICK_RE = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")

_GUARD_IDENT_PATTERNS = (
    # "missing bounds check on `len` before memcpy"
    re.compile(
        r"(?:check|validation|bounds[- ]check|null[- ]check)\s+"
        r"(?:on|of|for|against)\s+[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?",
        re.IGNORECASE,
    ),
    # "`len` is not checked / never validated"
    re.compile(
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?\s+is\s+"
        r"(?:not|never)\s+(?:checked|validated|verified|bounded)",
        re.IGNORECASE,
    ),
    # "unchecked `len`" / "unvalidated size"
    re.compile(
        r"\b(?:unchecked|unvalidated|unbounded)\s+"
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?",
        re.IGNORECASE,
    ),
)

_FLOW_PATTERNS = (
    # "from `argv` reaches/flows to/into `system`"
    re.compile(
        r"from\s+[`'\"]?([A-Za-z_][A-Za-z0-9_]*)(?:\(\))?[`'\"]?\s+"
        r".{0,80}?\b(?:reach(?:es)?|flows?(?:\s+(?:to|into))?|"
        r"propagates?\s+to|to|into)\s+"
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_.]*)(?:\(\))?[`'\"]?",
        re.IGNORECASE,
    ),
    # "`buf` reaches `system`" / "`buf` flows into `system`"
    re.compile(
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?\s+"
        r"(?:reach(?:es)?|flows?\s+(?:to|into)|is\s+passed\s+to)\s+"
        r"[`'\"]?([A-Za-z_][A-Za-z0-9_.]*)(?:\(\))?[`'\"]?",
        re.IGNORECASE,
    ),
)

# Prose words that regex capture groups must never treat as code
# identifiers (mirrors sweep.py's stop-word discipline).
_STOP_WORDS = frozenset({
    "a", "an", "and", "any", "are", "attacker", "be", "before",
    "buffer", "by", "call", "check", "checked", "checks", "data",
    "for", "from", "function", "in", "input", "into", "is", "it",
    "missing", "no", "not", "of", "on", "or", "pointer", "reaches",
    "sink", "that", "the", "then", "this", "to", "user",
    "value", "which", "with", "without",
})


def _plausible_identifier(name: str | None) -> str | None:
    if not name:
        return None
    if name.lower() in _STOP_WORDS:
        return None
    if not is_valid_identifier(name):
        return None
    return name


def extract_guard_target(
    hypothesis: str,
    candidate_sinks: list[str],
) -> tuple[str | None, str | None]:
    """Extract (identifier, sink) for a guard-dominance check.

    The sink must be one of *candidate_sinks* (or a callee named
    right after "before") appearing verbatim in the hypothesis; the
    identifier is the checked variable named by the hypothesis.
    Returns ``(None, None)`` when either cannot be bound — the
    identifier-consistency negative control: no binding, no verdict.
    """
    hyp = hypothesis or ""

    sink: str | None = None
    for cand in candidate_sinks:
        bare = cand.split(".")[-1]
        if re.search(rf"\b{re.escape(bare)}\b", hyp):
            sink = bare
            break
    if sink is None:
        m = re.search(
            r"before\s+(?:the\s+)?(?:call\s+to\s+)?"
            r"[`'\"]?([A-Za-z_][A-Za-z0-9_]*)[`'\"]?",
            hyp, re.IGNORECASE,
        )
        if m:
            sink = _plausible_identifier(m.group(1))

    ident: str | None = None
    for pat in _GUARD_IDENT_PATTERNS:
        m = pat.search(hyp)
        if m:
            ident = _plausible_identifier(m.group(1))
            if ident and ident != sink:
                break
            ident = None
    if ident is None:
        for cand in _BACKTICK_RE.findall(hyp):
            cand = _plausible_identifier(cand)
            if cand and cand != sink:
                ident = cand
                break

    if not sink or not ident or sink == ident:
        return (None, None)
    return (ident, sink)


def extract_flow_endpoints(
    hypothesis: str,
    candidate_sinks: list[str],
) -> tuple[str | None, str | None]:
    """Extract (source identifier, sink call) for a flow check.

    Source is the tainted variable / parameter the hypothesis names;
    sink is a call name (matched against *candidate_sinks* when the
    prose pattern doesn't name one).  Returns ``(None, None)`` when
    either endpoint cannot be bound to the hypothesis text.
    """
    hyp = hypothesis or ""

    for pat in _FLOW_PATTERNS:
        m = pat.search(hyp)
        if m:
            source = _plausible_identifier(m.group(1))
            sink_raw = m.group(2) or ""
            sink = _plausible_identifier(sink_raw.split(".")[-1])
            if source and sink and source != sink:
                return (source, sink)

    # Fallback: a candidate sink named in the hypothesis plus a
    # backticked identifier that isn't the sink.
    sink = None
    for cand in candidate_sinks:
        bare = cand.split(".")[-1]
        if re.search(rf"\b{re.escape(bare)}\b", hyp):
            sink = bare
            break
    if sink:
        for cand in _BACKTICK_RE.findall(hyp):
            cand = _plausible_identifier(cand)
            if cand and cand != sink:
                return (cand, sink)

    return (None, None)


# ── check-kind binding for guard-dominance refutations ──────────────

# Families whose "missing check" hypotheses assert a SPECIFIC check
# kind. The dominance query collects EVERY condition mentioning the
# identifier, so without kind-binding a mere use dominates: verified
# against a live joern, `while (ptr->next)` — a dereference, not a
# null check — dominates a later `free(ptr)` and refuted "missing
# null check on ptr before free". The web validation families keep
# the mention-based semantics (any dominating check on the tainted
# identifier is a plausible validation).
_NULL_CHECK_KIND_CWES = frozenset({"CWE-476"})
_BOUNDS_CHECK_KIND_CWES = frozenset({
    "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787",
})


def guard_check_kind(cwe: str) -> str | None:
    """The check kind a "missing check" hypothesis asserts, from its
    CWE family — ``None`` when the family has no bindable kind."""
    norm = normalize_cwe(cwe)
    if norm in _NULL_CHECK_KIND_CWES:
        return "null"
    if norm in _BOUNDS_CHECK_KIND_CWES:
        return "bounds"
    return None


def _guard_matches_kind(code: str, identifier: str, kind: str) -> bool:
    """Does a dominating condition actually PERFORM the asserted
    check kind on *identifier*, rather than merely mentioning it?

    * ``null`` — negation, (in)equality against NULL/nullptr/0, or a
      bare truth-test of the identifier (`if (ptr)`,
      `while (ptr && ...)`); a member/index/call use (`ptr->next`)
      does not qualify.
    * ``bounds`` — the identifier participates in a RELATIONAL
      comparison; equality against zero is not a bounds check.
    """
    # Paren runs gate their own trailing whitespace ((?:\(\s*)*):
    # the ``\s*\(*\s*`` chains overlapped two unbounded whitespace
    # spans around the optional parens — quadratic on a space run.
    ident = re.escape(identifier)
    if kind == "null":
        shapes = (
            rf"!\s*(?:\(\s*)*{ident}\b(?!\s*(?:->|\.|\[))",
            rf"\b{ident}\b\s*[!=]=\s*(?:\(\s*)*(?:NULL|nullptr|0)\b",
            rf"\b(?:NULL|nullptr|0)\s*[!=]=\s*(?:\(\s*)*{ident}\b",
            # Bare truth-test conjunct: the identifier alone as a
            # boolean operand — not followed by a member/index/call
            # use, and not an argument of a call (a call paren is
            # preceded by an identifier character).
            rf"(?:^|!|&&|\|\||(?<!\w)\()\s*{ident}\s*(?:[)&|]|$)",
        )
    elif kind == "bounds":
        shapes = (
            rf"\b{ident}\b\s*(?:<=|>=|<(?!<)|>(?!>))",
            # (?<![->])> : the > of a -> member access is not a
            # comparison (live shape: `if (s->len)` must not count
            # as a bounds check on len).
            rf"(?:<=|>=|(?<!<)<|(?<![->])>)\s*(?:\(\s*)*{ident}\b",
        )
    else:
        return True
    return any(re.search(shape, code) for shape in shapes)


# ── query builders (pure; all inputs pre-validated + escaped) ────────


def _escape(value: str) -> str:
    from packages.joern.runner import _escape_scala_string
    return _escape_scala_string(value)


def _valid_sub(value: str) -> bool:
    from packages.joern.runner import _validate_substitution_value
    return _validate_substitution_value(value)


def build_guard_dominance_query(
    function_name: str,
    sink_call: str,
    identifier: str,
    *,
    nonce: str,
) -> str:
    r"""CPGQL: does a condition on *identifier* dominate each *sink_call*?

    Emits one ``RAPTOR_GD_*`` sentinel line per fact, each stamped
    with the caller's per-invocation *nonce*; parsed by
    :func:`_parse_guard_output` with the same nonce (anchored parse —
    marker text inside quoted target code cannot mint facts).  All
    sentinel lines ride the query's FINAL EXPRESSION string echo:
    println output does not come back through the server's query-sync
    transport, so a println-emitting query answers with an empty
    protocol stream on a real server and the channel reads
    structurally dead.  All three name inputs must already have
    passed identifier validation (bare identifiers are regex-safe, so
    the ``\b<ident>\b`` interpolation cannot change the regex shape).
    """
    fn = _escape(function_name)
    sink = _escape(sink_call)
    ident = _escape(identifier)
    gd_func = _anchored(_GD_FUNC, nonce)
    gd_sinks = _anchored(_GD_SINKS, nonce)
    gd_unguarded = _anchored(_GD_UNGUARDED, nonce)
    gd_guarded = _anchored(_GD_GUARDED, nonce)
    gd_ung_total = _anchored(_GD_UNG_TOTAL, nonce)
    ident_pat = f"(?s).*\\\\b{ident}\\\\b.*"
    # Transport discipline (same REPL facts the batch taint builder
    # documents, plus one it does not): println output does NOT come
    # back through the server's query-sync transport — every sentinel
    # must ride the FINAL EXPRESSION's string echo; intermediate vals
    # AND the buffer itself live inside locally{} — a top-level
    # binder echoes its POPULATED final state, and quote-bearing
    # elements echo with raw inner quotes that the marker parser
    # tokenises into broken fragments; so the locally block IS the
    # final expression, returning the framed string.
    return (
        'import io.shiftleft.semanticcpg.language._\n'
        'locally {\n'
        '  val raptorOut = '
        'scala.collection.mutable.ListBuffer.empty[String]\n'
        f'  val raptorFn = cpg.method.nameExact("{fn}").l\n'
        '  if (raptorFn.isEmpty) {\n'
        f'    raptorOut += ("{gd_func}missing")\n'
        '  } else {\n'
        f'    raptorOut += ("{gd_func}found")\n'
        '    val raptorSinks = raptorFn.flatMap(\n'
        f'      _.call.nameExact("{sink}")'
        f'.where(_.argument.code("{ident_pat}")).l)\n'
        f'    raptorOut += ("{gd_sinks}" + raptorSinks.size)\n'
        '    val raptorConds = raptorFn.flatMap(\n'
        f'      _.controlStructure.condition.code("{ident_pat}").l)\n'
        '    var raptorUngN = 0\n'
        '    var raptorGrdN = 0\n'
        '    raptorSinks.foreach { s =>\n'
        # Control-dependence, NOT dominance: a condition node
        # dominates both branches AND the join after them, so
        # `if (len < 64) { }` followed by an unguarded memcpy read
        # as "guarded" under dominatedBy — a false refutation on the
        # canonical missing-check shape (live-reproduced on a real
        # server at this base). controlledBy is the CDG relation: a
        # sink inside the guarded branch (or behind an early-return
        # guard) IS control-dependent on the condition; a sink at
        # the join point is NOT.
        '      val ctrls = s.controlledBy.id.toSet\n'
        '      val guards = raptorConds.filter(c => ctrls.contains(c.id))\n'
        '      if (guards.isEmpty) {\n'
        '        raptorUngN += 1\n'
        '        if (raptorUngN <= 50) {\n'
        f'          val sCode = '
        f'{_PAYLOAD_FLATTEN_SCALA.format(expr="s.code")}\n'
        f'          raptorOut += ("{gd_unguarded}" + '
        's.lineNumber.getOrElse(0) + "|" + sCode)\n'
        '        }\n'
        '      } else {\n'
        '        raptorGrdN += 1\n'
        '        if (raptorGrdN <= 50) {\n'
        '          val g = guards.head\n'
        f'          val sCode = '
        f'{_PAYLOAD_FLATTEN_SCALA.format(expr="s.code")}\n'
        f'          val gCode = '
        f'{_PAYLOAD_FLATTEN_SCALA.format(expr="g.code")}\n'
        f'          raptorOut += ("{gd_guarded}" + '
        's.lineNumber.getOrElse(0) + "|" + '
        'g.lineNumber.getOrElse(0) + "|" + gCode + "|" + sCode)\n'
        '        }\n'
        '      }\n'
        '    }\n'
        f'    raptorOut += ("{gd_ung_total}" + raptorUngN)\n'
        '  }\n'
        '  "RAPTOR_VERIFY_START\\n" + raptorOut.mkString("\\n") + '
        '"\\nRAPTOR_VERIFY_END"\n'
        '}\n'
    )


def build_flow_query(
    function_name: str,
    source_id: str,
    sink_call: str,
    *,
    max_call_depth: int = 2,
    nonce: str,
) -> str:
    """CPGQL: reachableByFlows from *source_id* to *sink_call* args.

    Scoped to *function_name*.  Sources are the parameter(s) and
    identifier occurrences named *source_id* inside the function;
    sinks are the arguments of calls to *sink_call* inside the same
    function.  Emits ``RAPTOR_FLOW_*`` sentinels (stamped with the
    caller's per-invocation *nonce* — see :func:`_parse_flow_facts`)
    plus standard ``JOERN_FLOW:`` lines (the server's parser turns
    those into :class:`packages.joern.models.TaintFlow` objects for
    us).  Everything rides the query's FINAL EXPRESSION string echo —
    println output does not come back through the query-sync
    transport (the server's echo-tolerant marker parsing handles the
    echoed shape, same as the batch taint lane).
    """
    from packages.joern.runner import SCALA_JSON_ESC_DEF

    fn = _escape(function_name)
    src = _escape(source_id)
    sink = _escape(sink_call)
    flow_func = _anchored(_FLOW_FUNC, nonce)
    flow_src = _anchored(_FLOW_SRC, nonce)
    flow_snk = _anchored(_FLOW_SNK, nonce)
    flow_count = _anchored(_FLOW_COUNT, nonce)
    meth = f'cpg.method.nameExact("{fn}")'
    # jsonEsc (the shared Scala helper) escapes every value that lands
    # in a JSON-string position; .take(200) truncates the RAW string
    # BEFORE escaping — escape-then-truncate can bisect an injected \"
    # and leave a dangling backslash.
    flow_print = (
        '    raptorFlows.foreach { flow =>\n'
        '      val steps = flow.elements.map { e =>\n'
        '        val ln = e.lineNumber.getOrElse(0)\n'
        '        val cd = jsonEsc(e.code.take(200))\n'
        '        val (fnName, fl) = e match {\n'
        '          case n: CfgNode =>\n'
        '            (Try(n.method.name).getOrElse(""), '
        'Try(n.method.filename).getOrElse(""))\n'
        '          case _ => ("", "")\n'
        '        }\n'
        '        val fnEsc = jsonEsc(fnName)\n'
        '        val flEsc = jsonEsc(fl)\n'
        '        s"""{"line":$ln,"code":"$cd",'
        '"function":"$fnEsc","file":"$flEsc"}"""\n'
        '      }.mkString(",")\n'
        '      raptorOut += ("JOERN_FLOW:[" + steps + "]")\n'
        '    }\n'
    )
    # Same transport discipline as build_guard_dominance_query: every
    # sentinel AND every JOERN_FLOW record rides the final
    # expression's string echo (println does not return through the
    # query-sync transport); the buffer and all work live inside
    # locally{}, whose value IS the framed string — a top-level
    # binder would echo its populated final state and break the
    # marker parser on quote-bearing elements. The implicit
    # EngineContext stays at top level — it must be in implicit
    # scope for reachableByFlows.
    return (
        'import io.joern.dataflowengineoss.queryengine._\n'
        'import io.joern.dataflowengineoss.language._\n'
        'import io.shiftleft.semanticcpg.language._\n'
        'import io.shiftleft.codepropertygraph.generated.nodes.CfgNode\n'
        'import scala.util.Try\n'
        f'{SCALA_JSON_ESC_DEF}\n'
        'implicit val raptorCtx: EngineContext = EngineContext('
        f'config = EngineConfig(maxCallDepth = {int(max_call_depth)}))\n'
        'locally {\n'
        '  val raptorOut = '
        'scala.collection.mutable.ListBuffer.empty[String]\n'
        f'  val raptorFn = {meth}.l\n'
        '  if (raptorFn.isEmpty) {\n'
        f'    raptorOut += ("{flow_func}missing")\n'
        '  } else {\n'
        f'    raptorOut += ("{flow_func}found")\n'
        f'    val raptorSrcCount = {meth}.parameter.nameExact("{src}").size'
        f' + {meth}.ast.isIdentifier.nameExact("{src}").size\n'
        f'    raptorOut += ("{flow_src}" + raptorSrcCount)\n'
        f'    val raptorSnkCount = '
        f'{meth}.call.nameExact("{sink}").argument.size\n'
        f'    raptorOut += ("{flow_snk}" + raptorSnkCount)\n'
        '    val raptorSources = ('
        f'{meth}.parameter.nameExact("{src}") ++ '
        f'{meth}.ast.isIdentifier.nameExact("{src}")'
        ').collectAll[CfgNode]\n'
        f'    val raptorSinkArgs = '
        f'{meth}.call.nameExact("{sink}").argument\n'
        '    val raptorFlows = '
        'raptorSinkArgs.reachableByFlows(raptorSources).take(20).l\n'
        f'{flow_print}'
        f'    raptorOut += ("{flow_count}" + raptorFlows.size)\n'
        f'{_depth_probe_scala(int(max_call_depth), nonce=nonce)}'
        '  }\n'
        '  "RAPTOR_VERIFY_START\\n" + raptorOut.mkString("\\n") + '
        '"\\nRAPTOR_VERIFY_END"\n'
        '}\n'
    )


def _depth_probe_scala(max_call_depth: int, *, nonce: str) -> str:
    """Scala for the depth-bound witness: count internal methods one
    call level beyond the engine's ``maxCallDepth`` horizon.

    Zero flows is a refutation only within the engine's depth bound —
    a genuine flow threaded through more nested helper calls is
    invisible and produces the same silence. The probe walks the
    static call tree ``max_call_depth + 1`` levels (internal callees
    only; the bounded unroll tolerates recursion — a cycle just keeps
    the frontier non-empty, which is exactly the depth-exceeded
    answer). Wrapped in Try: a probe failure prints -1 and the
    consumer refuses to refute rather than trusting an unverified
    silence.
    """
    hop = (
        "raptorLvl = raptorLvl.flatMap("
        "_.call.callee.filterNot(_.isExternal).dedup.l).distinct\n"
    )
    return (
        "    val raptorDeepCount = scala.util.Try {\n"
        "      var raptorLvl = raptorFn.flatMap("
        "_.call.callee.filterNot(_.isExternal).dedup.l).distinct\n"
        + ("      " + hop) * max_call_depth
        + "      raptorLvl.size\n"
        "    }.getOrElse(-1)\n"
        f'    raptorOut += ("{_anchored(_FLOW_DEEP, nonce)}"'
        ' + raptorDeepCount)\n'
    )


# ── output parsing ───────────────────────────────────────────────────

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _sentinel_lines(raw: str) -> list[str]:
    """De-ANSI and strip REPL echo noise, keeping sentinel payloads."""
    lines = [_ANSI_RE.sub("", raw_line).strip() for raw_line in (raw or "").splitlines()]
    return lines


def _parse_guard_output(raw: str, nonce: str) -> dict[str, Any]:
    """Parse RAPTOR_GD_* sentinels into a fact dict.

    Anchored parse: a line contributes a fact only when it STARTS with
    the nonce'd marker the query was built with.  Sentinel payloads
    quote target source code, so a substring scan would let the
    scanned repo forge facts (mint refutations / flip
    ``function_found``) by containing marker text near a sink.
    """
    facts: dict[str, Any] = {
        "function_found": None,
        "sink_count": None,
        "unguarded": [],
        "guarded": [],
        "unguarded_total": None,
    }
    gd_func = _anchored(_GD_FUNC, nonce)
    gd_ung_total = _anchored(_GD_UNG_TOTAL, nonce)
    gd_sinks = _anchored(_GD_SINKS, nonce)
    gd_unguarded = _anchored(_GD_UNGUARDED, nonce)
    gd_guarded = _anchored(_GD_GUARDED, nonce)
    for line in _sentinel_lines(raw):
        if line.startswith(gd_ung_total):
            try:
                facts["unguarded_total"] = int(
                    line[len(gd_ung_total):].split("|")[0].strip()
                    .strip('"')
                )
            except ValueError:
                pass
            continue
        if line.startswith(gd_func):
            val = line[len(gd_func):].strip()
            if val.startswith("found"):
                facts["function_found"] = True
            elif val.startswith("missing"):
                facts["function_found"] = False
            continue
        if line.startswith(gd_sinks):
            try:
                facts["sink_count"] = int(
                    line[len(gd_sinks):].split("|")[0].strip().strip('"')
                )
            except ValueError:
                pass
            continue
        if line.startswith(gd_unguarded):
            parts = line[len(gd_unguarded):].split("|")
            entry = {"line": _to_int(parts[0]),
                     "code": parts[1].strip().strip('"') if len(parts) > 1 else ""}
            if entry not in facts["unguarded"]:
                facts["unguarded"].append(entry)
            continue
        if line.startswith(gd_guarded):
            parts = line[len(gd_guarded):].split("|")
            entry = {
                "sink_line": _to_int(parts[0]),
                "guard_line": _to_int(parts[1]) if len(parts) > 1 else 0,
                "guard_code": parts[2].strip().strip('"') if len(parts) > 2 else "",
                "sink_code": parts[3].strip().strip('"') if len(parts) > 3 else "",
            }
            if entry not in facts["guarded"]:
                facts["guarded"].append(entry)
    return facts


def _parse_flow_facts(raw: str, nonce: str) -> dict[str, Any]:
    """Parse RAPTOR_FLOW_* sentinels into a fact dict.

    Anchored parse (see :func:`_parse_guard_output`): JOERN_FLOW step
    payloads quote target source code, so a substring scan over the
    same stream would let the scanned repo flip ``function_found`` or
    forge counts.
    """
    facts: dict[str, Any] = {
        "function_found": None,
        "source_count": None,
        "sink_count": None,
        "flow_count": None,
        "deep_callee_count": None,
    }
    flow_func = _anchored(_FLOW_FUNC, nonce)
    for line in _sentinel_lines(raw):
        if line.startswith(flow_func):
            val = line[len(flow_func):].strip()
            if val.startswith("found"):
                facts["function_found"] = True
            elif val.startswith("missing"):
                facts["function_found"] = False
            continue
        for marker, key in (
            (_FLOW_SRC, "source_count"),
            (_FLOW_SNK, "sink_count"),
            (_FLOW_COUNT, "flow_count"),
            (_FLOW_DEEP, "deep_callee_count"),
        ):
            anchored = _anchored(marker, nonce)
            if line.startswith(anchored):
                try:
                    facts[key] = int(
                        line[len(anchored):].split("|")[0].strip().strip('"')
                    )
                except ValueError:
                    pass
                break
    return facts


def _to_int(value: str) -> int:
    try:
        return int(value.strip().strip('"'))
    except (ValueError, AttributeError):
        return 0


def _word_in(needle: str, haystack: str) -> bool:
    return bool(re.search(rf"\b{re.escape(needle)}\b", haystack or ""))


# ── sweep entry points ───────────────────────────────────────────────


def _error(
    tool_stamp: str, file_path: str, function_name: str, reason: str,
) -> SweepResult:
    return SweepResult(
        tool="joern",
        file_path=file_path,
        function_name=function_name,
        outcome="error",
        errors=[reason],
        rule_id=tool_stamp,
    )


def _inconclusive(
    tool_stamp: str, file_path: str, function_name: str, reason: str,
    details: dict[str, Any] | None = None,
) -> SweepResult:
    d = dict(details or {})
    d.setdefault("reason", reason)
    return SweepResult(
        tool="joern",
        file_path=file_path,
        function_name=function_name,
        outcome="inconclusive",
        rule_id=tool_stamp,
        details=d,
    )


def _validate_common(
    tool_stamp: str,
    target_path: Path,
    file_path: str,
    function_name: str,
    server: Any,
    names: dict[str, str],
) -> SweepResult | None:
    """Shared precondition checks. Returns an error SweepResult or None."""
    escape = _check_path_containment(target_path, file_path, "joern")
    if escape:
        escape.rule_id = tool_stamp
        return escape

    if not is_valid_identifier(function_name):
        return _error(
            tool_stamp, file_path, function_name,
            f"invalid function name: {function_name!r}",
        )
    for label, value in names.items():
        try:
            ok = _valid_sub(value)
        except ImportError:
            return _error(
                tool_stamp, file_path, function_name,
                "joern package not available",
            )
        if not ok:
            return _error(
                tool_stamp, file_path, function_name,
                f"invalid {label}: {value!r}",
            )

    if server is None:
        return _error(
            tool_stamp, file_path, function_name,
            "no live Joern server (joern not installed or server "
            "unavailable)",
        )
    return None


def run_guard_dominance_check(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    identifier: str,
    sink_call: str,
    server: Any = None,
    timeout: int | None = None,
    check_kind: str | None = None,
) -> SweepResult:
    """Guard-dominance verdict for a "missing check" hypothesis.

    ``check_kind`` (``"null"`` / ``"bounds"`` / ``None``, see
    :func:`guard_check_kind`) binds the REFUTED branch to the check
    kind the hypothesis asserts: when set, a dominating condition
    that merely mentions *identifier* without performing that kind
    of check demotes the refutation to inconclusive. ``None`` keeps
    the mention-based semantics (the release-order and propagation
    callers ask exactly the mention-dominance question).

    Outcomes:
      * ``refuted`` — a condition mentioning *identifier* dominates
        every matched sink call site (evidence: the dominator nodes);
        with a ``check_kind``, every dominator also performs that
        kind of check.
      * ``confirmed`` — at least one matched sink call site has no
        dominating check on *identifier* (evidence: the unguarded
        sink sites).  Only reachable when both the sink and the
        identifier from the hypothesis matched in the CPG.
      * ``inconclusive`` — function not in the CPG (vacuity guard) or
        no sink call passing *identifier* exists (identifier-
        consistency control: the hypothesis premise did not bind).
      * ``error`` — Joern unavailable, invalid input, or query error.
    """
    tool_stamp = GUARD_DOMINANCE_STAMP
    sink_bare = sink_call.rsplit(".", maxsplit=1)[-1]
    pre = _validate_common(
        tool_stamp, target_path, file_path, function_name, server,
        {"identifier": identifier, "sink_call": sink_bare},
    )
    if pre:
        return pre
    if not is_valid_identifier(identifier):
        return _error(
            tool_stamp, file_path, function_name,
            f"invalid identifier: {identifier!r}",
        )

    if timeout is None:
        timeout = default_query_timeout()

    nonce = _mint_nonce()
    query = build_guard_dominance_query(
        function_name, sink_bare, identifier, nonce=nonce,
    )
    try:
        result = server.query(query, timeout=timeout, check_length=False)
    except Exception as exc:  # noqa: BLE001 — degrade to outcome=error, never crash
        return _error(tool_stamp, file_path, function_name, str(exc))

    if result.errors:
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=list(result.errors),
            rule_id=tool_stamp,
            raw_output=(result.raw_output or "")[:2000],
        )

    facts = _parse_guard_output(result.raw_output or "", nonce)

    if facts["function_found"] is None:
        return _error(
            tool_stamp, file_path, function_name,
            "guard-dominance query produced no protocol output",
        )
    if facts["function_found"] is False:
        return _inconclusive(
            tool_stamp, file_path, function_name,
            f"function {function_name!r} not in CPG (no coverage — "
            "cannot refute or confirm)",
        )
    if not facts["sink_count"]:
        return _inconclusive(
            tool_stamp, file_path, function_name,
            f"no call to {sink_bare!r} passing {identifier!r} in "
            f"{function_name!r} — hypothesis identifiers did not bind "
            "(identifier-consistency control)",
            details={"sink": sink_bare, "identifier": identifier},
        )

    if facts["unguarded"]:
        # Negative control: only confirm when the matched sink code
        # actually mentions the hypothesis identifier.
        consistent = [
            u for u in facts["unguarded"]
            if _word_in(identifier, u.get("code", ""))
        ]
        if not consistent:
            return _inconclusive(
                tool_stamp, file_path, function_name,
                "unguarded sink matched but its code does not mention "
                f"{identifier!r} — refusing to confirm",
                details={"unguarded": facts["unguarded"]},
            )
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="confirmed",
            matches=[
                {
                    "line": u["line"],
                    "code": u["code"],
                    "sink": sink_bare,
                    "identifier": identifier,
                    "kind": "unguarded_sink",
                }
                for u in consistent
            ],
            rule_id=tool_stamp,
            raw_output=(result.raw_output or "")[:2000],
            details={"guarded": facts["guarded"]},
        )

    if facts["unguarded_total"] != 0:
        # Evidence lines are emission-capped; the refutation is a
        # universal quantifier over EVERY sink, so it may only book
        # when the uncapped count says zero. A missing count (partial
        # protocol) refuses to refute rather than trusting the capped
        # evidence view.
        return _inconclusive(
            tool_stamp, file_path, function_name,
            "guard protocol did not establish a zero unguarded-sink "
            "count — refusing to refute on capped evidence",
            details={"unguarded_total": facts["unguarded_total"]},
        )

    if check_kind is not None:
        # Kind-bind the refutation: the query collects EVERY
        # condition mentioning the identifier, so a mere USE
        # dominating the sink (live-verified: `while (ptr->next)`
        # dominating `free(ptr)`) is not the check the hypothesis
        # asserts is missing. The query reports one dominator per
        # sink; another, kind-matched condition may also dominate —
        # unknowable from here, so abstain rather than confirm.
        mismatched = [
            g for g in facts["guarded"]
            if not _guard_matches_kind(
                g.get("guard_code", ""), identifier, check_kind)
        ]
        if mismatched:
            return _inconclusive(
                tool_stamp, file_path, function_name,
                f"every {sink_bare!r} site is dominated by a "
                f"condition mentioning {identifier!r}, but a "
                f"dominator is not a {check_kind} check "
                f"({mismatched[0].get('guard_code', '')!r}) — "
                "domination by an unrelated condition cannot refute "
                f"a missing-{check_kind}-check hypothesis",
                details={"dominators": facts["guarded"],
                         "kind_mismatched": mismatched},
            )

    # Every matched sink is dominated by a check on the identifier:
    # the "missing check" hypothesis is mechanically refuted.
    return SweepResult(
        tool="joern",
        file_path=file_path,
        function_name=function_name,
        outcome="refuted",
        rule_id=tool_stamp,
        raw_output=(result.raw_output or "")[:2000],
        details={
            "dominators": facts["guarded"],
            "reason": (
                f"a check on {identifier!r} dominates every "
                f"{sink_bare!r} call site in {function_name!r}"
            ),
        },
    )


def run_flow_reachability_check(
    *,
    target_path: Path,
    file_path: str,
    function_name: str,
    source_id: str,
    sink_call: str,
    server: Any = None,
    timeout: int | None = None,
    max_call_depth: int = 2,
    sanitizer_names: Sequence[str] = (),
) -> SweepResult:
    """Flow-reachability verdict for a taint-style hypothesis.

    Outcomes:
      * ``confirmed`` — a dataflow from *source_id* to an argument of
        *sink_call* exists (evidence: the flow path).
      * ``refuted`` — CPG covers the function, both endpoints exist,
        and no flow was found.
      * ``inconclusive`` — function not in the CPG, or either endpoint
        absent (vacuity guard: an empty-source query "finding no flow"
        proves nothing).
      * ``error`` — Joern unavailable, invalid input, or query error.

    ``sanitizer_names`` arms the sanitizer-aware lane (the CWE-116
    encoding families): flows whose path steps call one of the names
    do not confirm — when EVERY returned flow is sanitized the outcome
    is ``inconclusive`` (a name match proves neither correct encoding
    nor its absence, so it is not a refutation either), and confirms
    from the remaining flows carry the detection-grade
    :data:`FLOW_ENCODING_STAMP` instead of :data:`FLOW_STAMP`. The
    zero-flow refutation lane is unchanged.
    """
    tool_stamp = FLOW_ENCODING_STAMP if sanitizer_names else FLOW_STAMP
    sink_bare = sink_call.rsplit(".", maxsplit=1)[-1]
    pre = _validate_common(
        tool_stamp, target_path, file_path, function_name, server,
        {"source_id": source_id, "sink_call": sink_bare},
    )
    if pre:
        return pre
    if not is_valid_identifier(source_id):
        return _error(
            tool_stamp, file_path, function_name,
            f"invalid source_id: {source_id!r}",
        )

    if timeout is None:
        timeout = default_query_timeout()

    nonce = _mint_nonce()
    query = build_flow_query(
        function_name, source_id, sink_bare,
        max_call_depth=max_call_depth, nonce=nonce,
    )
    try:
        result = server.query(query, timeout=timeout, check_length=False)
    except Exception as exc:  # noqa: BLE001 — degrade to outcome=error, never crash
        return _error(tool_stamp, file_path, function_name, str(exc))

    if result.errors:
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="error",
            errors=list(result.errors),
            rule_id=tool_stamp,
            raw_output=(result.raw_output or "")[:2000],
        )

    facts = _parse_flow_facts(result.raw_output or "", nonce)

    if facts["function_found"] is None:
        return _error(
            tool_stamp, file_path, function_name,
            "flow query produced no protocol output",
        )
    if facts["function_found"] is False:
        return _inconclusive(
            tool_stamp, file_path, function_name,
            f"function {function_name!r} not in CPG (vacuity guard: "
            "cannot refute what was never analysed)",
        )

    flows = list(getattr(result, "flows", []) or [])

    # Consistency belt: the count record says the engine FOUND flows
    # but no flow record decoded. A whole JOERN_FLOW line lost
    # without a marker fragment leaves no parse error, and the empty
    # flow list would otherwise ride the refutation lane — the same
    # partial-protocol rule the guard channel applies to its
    # unguarded count. One-directional on purpose: decoded flows
    # fewer than the count is server-side dedup of identical rendered
    # paths, not damage.
    if not flows and (facts["flow_count"] or 0) > 0:
        return _error(
            tool_stamp, file_path, function_name,
            f"flow protocol damage: count record reports "
            f"{facts['flow_count']} flow(s) but no flow record "
            "decoded",
        )

    if flows:
        # Identifier-consistency: some step of some flow must mention
        # the named source, and the flow must end in the named sink's
        # argument (the query already constrains the sink; check the
        # source binding on the returned path).
        consistent = []
        for flow in flows:
            steps = getattr(flow, "steps", []) or []
            texts = " ".join(
                f"{getattr(s, 'code', '')} {getattr(s, 'variable', '')}"
                for s in steps
            )
            if _word_in(source_id, texts):
                consistent.append(flow)
        if not consistent:
            return _inconclusive(
                tool_stamp, file_path, function_name,
                f"flows returned but none mentions {source_id!r} — "
                "refusing to confirm (identifier-consistency control)",
            )
        sanitized_count = 0
        if sanitizer_names:
            consistent, sanitized = _partition_sanitized_flows(
                consistent, sanitizer_names,
            )
            sanitized_count = len(sanitized)
            if not consistent:
                # Every returned flow passes a required-class
                # sanitizer name: the "reaches the sink unencoded"
                # premise failed, so no confirm — and a name match
                # proves nothing about encoding correctness for the
                # context, so no refutation either.
                return _inconclusive(
                    tool_stamp, file_path, function_name,
                    f"every flow from {source_id!r} to {sink_bare!r} "
                    "passes a required-class sanitizer name — "
                    "refusing to confirm (encoding residual not "
                    "shown); not a refutation (a sanitizer name does "
                    "not prove correct encoding for the context)",
                    details={"sanitized_flow_count": sanitized_count},
                )
        details: dict[str, Any] = {"source": source_id, "sink": sink_bare}
        if sanitizer_names:
            details["sanitized_flow_count"] = sanitized_count
            details["sanitizer_names_checked"] = list(sanitizer_names)
        return SweepResult(
            tool="joern",
            file_path=file_path,
            function_name=function_name,
            outcome="confirmed",
            matches=[f.to_dict() for f in consistent],
            rule_id=tool_stamp,
            raw_output=(result.raw_output or "")[:2000],
            details=details,
        )

    if not facts["source_count"] or not facts["sink_count"]:
        return _inconclusive(
            tool_stamp, file_path, function_name,
            f"endpoint missing in CPG (source {source_id!r}: "
            f"{facts['source_count'] or 0}, sink {sink_bare!r}: "
            f"{facts['sink_count'] or 0}) — query was vacuous",
            details={
                "source_count": facts["source_count"] or 0,
                "sink_count": facts["sink_count"] or 0,
            },
        )

    # Depth-bound witness: zero flows is only a refutation WITHIN the
    # engine's maxCallDepth. When the static call tree descends past
    # that horizon (or the probe failed), a genuine flow threaded
    # through deeper helper calls would produce the same silence —
    # inconclusive, never refuted. Confirm-direction is unaffected.
    deep = facts.get("deep_callee_count")
    if deep is None or deep < 0 or deep > 0:
        why = (
            f"call tree descends beyond the engine depth bound "
            f"({deep} internal method(s) past maxCallDepth="
            f"{max_call_depth})"
            if deep is not None and deep > 0
            else "depth-bound probe unavailable"
        )
        return _inconclusive(
            tool_stamp, file_path, function_name,
            f"no dataflow from {source_id!r} to {sink_bare!r} within "
            f"engine depth {max_call_depth}, but {why} — depth-bounded "
            f"silence cannot refute",
            details={
                "source_count": facts["source_count"],
                "sink_count": facts["sink_count"],
                "max_call_depth": max_call_depth,
                "deep_callee_count": deep,
            },
        )
    return SweepResult(
        tool="joern",
        file_path=file_path,
        function_name=function_name,
        outcome="refuted",
        rule_id=tool_stamp,
        raw_output=(result.raw_output or "")[:2000],
        details={
            "reason": (
                f"no dataflow from {source_id!r} to {sink_bare!r} in "
                f"{function_name!r} (both endpoints present in CPG; "
                f"call tree fully covered within maxCallDepth="
                f"{max_call_depth})"
            ),
            "source_count": facts["source_count"],
            "sink_count": facts["sink_count"],
            "max_call_depth": max_call_depth,
            "deep_callee_count": deep,
        },
    )
