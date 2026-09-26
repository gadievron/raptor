"""Taint spec-pack format and fail-closed loader.

One JSON pack file declares sources, sinks, sanitizers, and
propagators for one language/framework. The same rows configure the
native cross-file propagator and (where expressible — see
:mod:`core.taint.mad_matrix`) CodeQL models-as-data emission, so a
row is written once and consumed by both backends.

Trust posture (the load boundary of this module):

* Packs load from the IN-TREE packs directory
  (``core/taint/data/packs/``) and operator-supplied config
  directories ONLY — never from the scanned repository. A model file
  read from the target tree would be attacker-controlled detection
  steering: it could declare the repo's real sinks "sanitized" or
  bury signal under noise sources. :func:`load_packs` therefore takes
  repo-relative pack NAMES (``python/web-injection-core``), never
  target paths, and refuses any pack directory or resolved pack file
  inside ``target_root``.
* Validation is FAIL-CLOSED per file: any schema violation refuses
  the whole pack with a precise error naming the entry and field.
  A silently-skipped row would be an invisible detection gap.
* Matching vocabulary is exact dotted-name / structural — every
  match field is charset-validated at load; there is no regex-over-
  target-text surface in the format.
* The only target-derived spec channel is the learned intake
  (:mod:`core.taint.learned_intake`), which is bounded and
  tier-tagged separately.

Format summary (``schema_version`` 1):

* ``sources``: ``module_attribute`` (expressions rooted at an import
  binding of the dotted name), ``call_return`` (call results),
  ``route_param`` (binds to route-model records — no ``match``), and
  the reserved ``stored_read`` (a read API whose return carries
  stored taint under a ``store_key`` pairing label).
* ``sinks``: ``dotted_callee`` (import-table-resolved dotted callee;
  tainted values in the declared ``args``/``kwargs`` fire),
  ``method_name`` (bare-name equality with an optional
  ``receiver_hint`` — ALWAYS ``confidence: "heuristic"``, enforced),
  and the reserved ``stored_write`` (``store_key``-paired write API,
  the second-order storage half). ``unless_kwargs`` suppresses a hit
  only when the kwarg value is a LITERAL as written at the call site
  (``shell=False``); a computed value never suppresses — degradation
  is toward the sink firing, not away from it.
* ``sanitizers``: ``semantics: "kill"`` drops taint tags for the
  named sink classes; ``semantics: "tag"`` keeps taint flowing and
  records the sanitizer hop for downstream classification. Kill is
  reserved for transform-style calls whose RETURN VALUE is the safe
  value; validate-style guards tag only (kill-on-validate needs
  dominance analysis the consumer does not have). The curated table
  (:mod:`core.dataflow.known_safe_calls`) is auto-imported at load
  with exactly that split; packs ADD to it and may never restate or
  shadow a curated callee (load error).
* ``propagators``: flow edges in the access-path grammar shared with
  :mod:`core.dataflow.extension_pack` (``Argument[n]``,
  ``Argument[*]``, ``ReturnValue``) so one row emits both a native
  propagator and a models-as-data summary row without translation.
  ``"narrowing": true`` marks an entry that REDUCES the assumed
  propagation floor — legal only in these operator-controlled pack
  files (and flagged so review can see it); the learned channel is
  additive-only and can never mint it.

The reserved kinds (``stored_read`` / ``stored_write``) are
parse-valid now and engine-consumed later: a stored-taint pack is
pure data through this loader today, which is the acceptance test of
the format's extension story.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from dataclasses import fields as dataclass_fields
from pathlib import Path
from collections.abc import Iterable, Sequence

from core.dataflow.extension_pack import (
    ACCEPTED_PROVENANCE,
    # Access-path cell grammar shared with the models-as-data emitter
    # (same convention as route_models importing the callgraph's
    # dotted-form helpers): the two consumers of a propagator row must
    # agree byte-for-byte on what a valid cell is, so the validator is
    # imported rather than twinned.
    _valid_access,
)
from core.dataflow.known_safe_calls import KnownSafeCall, all_entries
from core.security.log_sanitisation import escape_nonprintable, has_nonprintable
from core.source.gated import read_text_gated

SCHEMA_VERSION = 1

#: The in-tree pack root. Trusted by identity — it ships with the
#: tool, not with any scanned target.
DEFAULT_PACKS_DIR = Path(__file__).resolve().parent / "data" / "packs"

# ── named caps ───────────────────────────────────────────────────────
# Every cap refuses loudly (PackLoadError) — a pack is operator
# configuration, so over-cap is a config error to fix, never data to
# silently truncate.

#: Byte budget per pack file, checked by stat() before any read.
#: Higher admits machine-generated mega-catalogs; lower bounds what a
#: hostile or accidental blob in a config directory can make the
#: loader parse (the seed packs are ~10 KiB; refusal on an oversize
#: file is O(1)).
MAX_PACK_BYTES = 1 * 1024 * 1024

#: Entries per role per pack. Higher admits harvested catalogs;
#: lower keeps a flooded config pack from becoming an unbounded
#: matching table (curated seed discipline is <= 9 exemplars per role
#: per class; 256 leaves generated-pack headroom without open-ending
#: the per-call matching cost downstream).
MAX_ENTRIES_PER_ROLE = 256

#: Length bound on dotted-name / identifier match fields. Higher
#: admits deeply nested module paths; lower bounds the per-call
#: string-compare cost and refuses degenerate megabyte "names".
MAX_MATCH_LEN = 200

#: Length bound on the free-text rationale. Higher admits fuller
#: soundness notes; lower keeps the one prose field from becoming a
#: smuggling channel into logs and prompts (rationale is also
#: printable-only, refused otherwise).
MAX_RATIONALE_LEN = 500

#: Structural per-entry list bounds — generous for real APIs, small
#: enough that a pathological entry cannot fan out matching state.
MAX_TAINT_CLASSES_PER_ENTRY = 8
MAX_FLOWS_PER_PROPAGATOR = 8
MAX_UNLESS_KWARGS = 8
MAX_SINK_ARGS = 16
MAX_UNLESS_VALUE_LEN = 64

#: How many violations one refusal message lists before eliding —
#: precise errors for real mistakes, bounded output for a hostile
#: file that is wrong ten thousand ways.
_MAX_ERRORS_LISTED = 20

# ── vocabulary constants ─────────────────────────────────────────────

SOURCE_KIND_MODULE_ATTRIBUTE = "module_attribute"
SOURCE_KIND_CALL_RETURN = "call_return"
SOURCE_KIND_ROUTE_PARAM = "route_param"
SOURCE_KIND_STORED_READ = "stored_read"
SOURCE_KINDS = frozenset({
    SOURCE_KIND_MODULE_ATTRIBUTE,
    SOURCE_KIND_CALL_RETURN,
    SOURCE_KIND_ROUTE_PARAM,
    SOURCE_KIND_STORED_READ,
})

SINK_KIND_DOTTED_CALLEE = "dotted_callee"
SINK_KIND_METHOD_NAME = "method_name"
SINK_KIND_STORED_WRITE = "stored_write"
SINK_KINDS = frozenset({
    SINK_KIND_DOTTED_CALLEE,
    SINK_KIND_METHOD_NAME,
    SINK_KIND_STORED_WRITE,
})

SANITIZER_KINDS = frozenset({"dotted_callee"})
PROPAGATOR_KINDS = frozenset({"dotted_callee"})

SEMANTICS_KILL = "kill"
SEMANTICS_TAG = "tag"
SANITIZER_SEMANTICS = frozenset({SEMANTICS_KILL, SEMANTICS_TAG})

CONFIDENCE_EXACT = "exact"
CONFIDENCE_HEURISTIC = "heuristic"
SINK_CONFIDENCES = frozenset({CONFIDENCE_EXACT, CONFIDENCE_HEURISTIC})

#: Provenance tiers a loaded entry carries. Ordering (weakest to
#: strongest binding for eviction/truncation purposes) is
#: learned < pack < curated.
TIER_CURATED = "curated"
TIER_PACK = "pack"
TIER_LEARNED = "learned"

#: Languages the pack FORMAT accepts. The native propagator consumes
#: python; javascript packs are parse-valid so the models-as-data
#: lane can grow without a format change. Anything else refuses.
SUPPORTED_PACK_LANGUAGES = frozenset({"python", "javascript"})

# ── grammars (charset-validated fields; no regex runs over target text,
#    these validate the pack's own operator-authored strings) ─────────
#
# All grammars anchor with \Z, never $: in Python re, $ also matches
# just BEFORE a trailing newline, so "os.system\n" would validate as
# "os.system" while remaining a distinct string — a visually identical
# twin that exact-match joins (curated-shadow detection, sink pairing,
# dedup) treat as a different name. A kill sanitizer "shlex.quote\n"
# would slip the curated-shadow load error that way. \Z anchors at the
# absolute end only.

_DOTTED_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)*\Z")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\Z")
# Taint / sink class grammar deliberately equals the models-as-data
# kind grammar so a class can ride into a kind cell unchanged.
_CLASS_RE = re.compile(r"^[a-z][a-z0-9-]*\Z")
_CWE_RE = re.compile(r"^CWE-[1-9][0-9]{0,4}\Z")
_STORE_KEY_RE = re.compile(r"^[a-z][a-z0-9_-]*\Z")
_FRAMEWORK_RE = re.compile(r"^[a-z][a-z0-9_-]*\Z")
# Pack-name segments carry no dots at all — the ``.json`` suffix is
# appended by the resolver, and a dotless grammar makes traversal
# spellings (``..``) unrepresentable rather than filtered.
_PACK_NAME_SEGMENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]*\Z")

_TOP_LEVEL_KEYS = frozenset({
    "schema_version", "language", "framework", "pack",
    "sources", "sinks", "sanitizers", "propagators",
})

#: Curated sink-class keys (:mod:`core.dataflow.known_safe_calls`)
#: translated to this format's class vocabulary. Unmapped curated
#: classes pass through unchanged when they already satisfy the class
#: grammar — a new curated class must never break pack loading; an
#: untranslated class only means pack sink classes will not pair with
#: it until the mapping row is added (recall-neutral).
_CURATED_SINK_CLASS = {
    "cmdi": "command-injection",
    "cmdi_argv": "argument-injection",
    "sqli": "sql-injection",
    "xss": "xss",
    "pathtrav": "path-traversal",
}


class PackLoadError(ValueError):
    """A pack failed to load. Fail-closed: the message names the pack
    and every violation (bounded), and the caller gets NO partial
    entry set — a half-loaded pack would be an invisible detection
    gap."""


# ── loaded-entry model ───────────────────────────────────────────────


@dataclass(frozen=True)
class FlowEdge:
    """One propagator flow in the shared access-path grammar."""

    src: str
    dst: str


@dataclass(frozen=True)
class SourceSpec:
    kind: str
    taint_classes: tuple[str, ...]
    match: str = ""
    store_key: str = ""
    provenance: str = ""
    rationale: str = ""
    tier: str = TIER_PACK
    pack: str = ""
    framework: str = ""


@dataclass(frozen=True)
class SinkSpec:
    kind: str
    sink_class: str
    cwe: str
    match: str = ""
    args: tuple[int, ...] = ()
    kwargs: tuple[str, ...] = ()
    receiver_hint: str = ""
    confidence: str = CONFIDENCE_EXACT
    #: (name, literal) pairs; a hit is suppressed only when the call
    #: site carries the kwarg as exactly this LITERAL token.
    unless_kwargs: tuple[tuple[str, str], ...] = ()
    store_key: str = ""
    provenance: str = ""
    rationale: str = ""
    tier: str = TIER_PACK
    pack: str = ""
    framework: str = ""


@dataclass(frozen=True)
class SanitizerSpec:
    kind: str
    match: str
    semantics: str
    sink_classes: tuple[str, ...]
    provenance: str = ""
    rationale: str = ""
    tier: str = TIER_PACK
    pack: str = ""
    framework: str = ""

    @property
    def is_wildcard(self) -> bool:
        return self.sink_classes == ("*",)


@dataclass(frozen=True)
class PropagatorSpec:
    kind: str
    match: str
    flows: tuple[FlowEdge, ...]
    #: True only for operator-controlled pack entries that REDUCE the
    #: assumed propagation floor. Deliberately absent from the
    #: learned-intake model — a learned spec cannot narrow flow.
    narrowing: bool = False
    provenance: str = ""
    rationale: str = ""
    tier: str = TIER_PACK
    pack: str = ""
    framework: str = ""


@dataclass(frozen=True)
class TaintPack:
    """One validated pack file."""

    name: str
    language: str
    framework: str
    schema_version: int
    path: Path
    sources: tuple[SourceSpec, ...] = ()
    sinks: tuple[SinkSpec, ...] = ()
    sanitizers: tuple[SanitizerSpec, ...] = ()
    propagators: tuple[PropagatorSpec, ...] = ()


# Allowed JSON keys per entry role, DERIVED from the loaded model so
# schema and dataclass cannot drift: an entry may carry exactly the
# spec's fields minus the loader-stamped metadata columns.
_ENTRY_META_FIELDS = frozenset({"tier", "pack", "framework"})


def _entry_keys(
    spec_type: type, rename: dict[str, str] | None = None,
) -> frozenset[str]:
    names = {f.name for f in dataclass_fields(spec_type)} - _ENTRY_META_FIELDS
    for field_name, json_key in (rename or {}).items():
        names.discard(field_name)
        names.add(json_key)
    return frozenset(names)


_SOURCE_KEYS = _entry_keys(SourceSpec)
_SINK_KEYS = _entry_keys(SinkSpec)
_SANITIZER_KEYS = _entry_keys(SanitizerSpec)
_PROPAGATOR_KEYS = _entry_keys(PropagatorSpec, rename={"flows": "flow"})


@dataclass(frozen=True)
class PackSet:
    """Merged view over loaded packs plus the curated sanitizer import.

    ``sanitizers`` already contains the curated entries (tier
    ``curated``) — consumers read one list and get the additive merge;
    ``curated_sanitizers`` is the same subset separately for audit
    rendering.
    """

    packs: tuple[TaintPack, ...]
    sources: tuple[SourceSpec, ...]
    sinks: tuple[SinkSpec, ...]
    sanitizers: tuple[SanitizerSpec, ...]
    propagators: tuple[PropagatorSpec, ...]
    curated_sanitizers: tuple[SanitizerSpec, ...] = field(default=())

    def taint_class_vocabulary(self) -> frozenset[str]:
        """The closed taint/sink-class vocabulary the packs declare.

        This is the membership gate for the learned channel: a
        learned spec naming a class outside this set is refused (a
        hostile project store cannot mint classes that bypass sink
        pairing). The wildcard sanitizer class is not vocabulary.
        """
        vocab: set[str] = set()
        for s in self.sources:
            vocab.update(s.taint_classes)
        for k in self.sinks:
            vocab.add(k.sink_class)
        for z in self.sanitizers:
            vocab.update(c for c in z.sink_classes if c != "*")
        return frozenset(vocab)


# ── error-message helpers ────────────────────────────────────────────


def _quote(value: object, *, max_len: int = 120) -> str:
    """Render a pack-file value inertly for an error message: escape
    non-printables and bound length. Pack files in a config directory
    are operator-controlled but still arbitrary bytes until validated
    — refusal messages must not relay terminal escapes."""
    text = escape_nonprintable(str(value))
    if len(text) > max_len:
        text = text[:max_len] + f"...[+{len(text) - max_len} chars]"
    return repr(text)


class _Errors:
    """Bounded violation collector for one pack file."""

    def __init__(self, label: str) -> None:
        self.label = label
        self.items: list[str] = []

    def add(self, where: str, message: str) -> None:
        self.items.append(f"{where}: {message}")

    def raise_if_any(self) -> None:
        if not self.items:
            return
        shown = self.items[:_MAX_ERRORS_LISTED]
        elided = len(self.items) - len(shown)
        suffix = f"; [+{elided} more violations]" if elided else ""
        msg = f"pack {self.label}: " + "; ".join(shown) + suffix
        raise PackLoadError(msg)


# ── field validators ─────────────────────────────────────────────────


def _check_str(
    errors: _Errors, where: str, entry: dict, key: str, pattern: re.Pattern[str],
    *, required: bool, max_len: int = MAX_MATCH_LEN, what: str = "",
) -> str:
    raw = entry.get(key)
    if raw is None or raw == "":
        if required:
            errors.add(where, f"{key} is required")
        return ""
    if not isinstance(raw, str):
        errors.add(where, f"{key} must be a string, got {_quote(raw)}")
        return ""
    if len(raw) > max_len:
        errors.add(where, f"{key} exceeds {max_len} chars")
        return ""
    if not pattern.match(raw):
        errors.add(where, f"{key} {_quote(raw)} fails {what or 'grammar'}")
        return ""
    return raw


def _check_rationale(errors: _Errors, where: str, entry: dict) -> str:
    raw = entry.get("rationale")
    if not isinstance(raw, str) or not raw.strip():
        errors.add(where, "rationale is required (why does this entry hold?)")
        return ""
    if len(raw) > MAX_RATIONALE_LEN:
        errors.add(where, f"rationale exceeds {MAX_RATIONALE_LEN} chars")
        return ""
    if has_nonprintable(raw):
        errors.add(where, "rationale contains non-printable characters")
        return ""
    return raw


def _check_provenance(errors: _Errors, where: str, entry: dict) -> str:
    raw = entry.get("provenance")
    if not isinstance(raw, str) or not raw:
        errors.add(where, "provenance is required")
        return ""
    if raw not in ACCEPTED_PROVENANCE:
        errors.add(
            where,
            f"provenance {_quote(raw)} not accepted; expected one of "
            f"{sorted(ACCEPTED_PROVENANCE)}",
        )
        return ""
    return raw


def _check_class_list(
    errors: _Errors, where: str, entry: dict, key: str,
    *, allow_wildcard: bool = False,
) -> tuple[str, ...]:
    raw = entry.get(key)
    if not isinstance(raw, list) or not raw:
        errors.add(where, f"{key} must be a non-empty list")
        return ()
    if len(raw) > MAX_TAINT_CLASSES_PER_ENTRY:
        errors.add(where, f"{key} exceeds {MAX_TAINT_CLASSES_PER_ENTRY} classes")
        return ()
    if allow_wildcard and raw == ["*"]:
        return ("*",)
    out: list[str] = []
    for c in raw:
        if not isinstance(c, str) or not _CLASS_RE.match(c) or len(c) > MAX_MATCH_LEN:
            hint = " ('*' is only valid alone)" if allow_wildcard and c == "*" else ""
            errors.add(where, f"{key} entry {_quote(c)} fails class grammar{hint}")
            return ()
        out.append(c)
    return tuple(out)


def _check_keys(
    errors: _Errors, where: str, entry: dict, allowed: frozenset[str],
) -> bool:
    unknown = set(entry) - allowed
    if unknown:
        listed = ", ".join(_quote(k) for k in sorted(map(str, unknown))[:5])
        errors.add(where, f"unknown key(s) {listed}; allowed: {sorted(allowed)}")
        return False
    return True


def _entries(
    errors: _Errors, data: dict, role: str,
) -> list[tuple[str, dict]]:
    raw = data.get(role)
    if raw is None:
        return []
    if not isinstance(raw, list):
        errors.add(role, "must be a list")
        return []
    if len(raw) > MAX_ENTRIES_PER_ROLE:
        errors.add(role, f"{len(raw)} entries exceed the {MAX_ENTRIES_PER_ROLE} cap")
        return []
    out: list[tuple[str, dict]] = []
    for i, entry in enumerate(raw):
        where = f"{role}[{i}]"
        if not isinstance(entry, dict):
            errors.add(where, "entry must be an object")
            continue
        out.append((where, entry))
    return out


# ── per-role parsers ─────────────────────────────────────────────────


def _parse_sources(
    errors: _Errors, data: dict, pack: str, framework: str,
) -> tuple[SourceSpec, ...]:
    out: list[SourceSpec] = []
    for where, entry in _entries(errors, data, "sources"):
        if not _check_keys(errors, where, entry, _SOURCE_KEYS):
            continue
        kind = entry.get("kind")
        if kind not in SOURCE_KINDS:
            errors.add(where, f"kind {_quote(kind)} not in {sorted(SOURCE_KINDS)}")
            continue
        before = len(errors.items)
        classes = _check_class_list(errors, where, entry, "taint_classes")
        needs_match = kind != SOURCE_KIND_ROUTE_PARAM
        match = _check_str(
            errors, where, entry, "match", _DOTTED_RE,
            required=needs_match, what="dotted-name grammar",
        )
        if kind == SOURCE_KIND_ROUTE_PARAM and entry.get("match"):
            errors.add(where, "route_param sources bind to route records and take no match")
        store_key = _check_str(
            errors, where, entry, "store_key", _STORE_KEY_RE,
            required=kind == SOURCE_KIND_STORED_READ, max_len=64,
            what="store-key grammar",
        )
        if kind != SOURCE_KIND_STORED_READ and entry.get("store_key"):
            errors.add(where, "store_key is only valid on stored_read sources")
        provenance = _check_provenance(errors, where, entry)
        rationale = _check_rationale(errors, where, entry)
        if len(errors.items) > before:
            continue
        out.append(SourceSpec(
            kind=kind, taint_classes=classes, match=match,
            store_key=store_key, provenance=provenance, rationale=rationale,
            tier=TIER_PACK, pack=pack, framework=framework,
        ))
    return tuple(out)


def _check_sink_args(
    errors: _Errors, where: str, entry: dict,
) -> tuple[tuple[int, ...], tuple[str, ...]]:
    args_raw = entry.get("args", [])
    kwargs_raw = entry.get("kwargs", [])
    args: tuple[int, ...] = ()
    kwargs: tuple[str, ...] = ()
    if not isinstance(args_raw, list) or len(args_raw) > MAX_SINK_ARGS:
        errors.add(where, f"args must be a list of at most {MAX_SINK_ARGS} positions")
    elif any(not isinstance(a, int) or isinstance(a, bool) or a < 0 or a > 63
             for a in args_raw):
        errors.add(where, "args entries must be integers in [0, 63]")
    elif len(set(args_raw)) != len(args_raw):
        errors.add(where, "args entries must be unique")
    else:
        args = tuple(args_raw)
    if not isinstance(kwargs_raw, list) or len(kwargs_raw) > MAX_SINK_ARGS:
        errors.add(where, f"kwargs must be a list of at most {MAX_SINK_ARGS} names")
    elif any(not isinstance(k, str) or not _IDENT_RE.match(k) or len(k) > MAX_MATCH_LEN
             for k in kwargs_raw):
        errors.add(where, "kwargs entries must be identifiers")
    else:
        kwargs = tuple(kwargs_raw)
    if not args and not kwargs:
        errors.add(where, "a sink needs at least one args position or kwargs name")
    return args, kwargs


def _check_unless_kwargs(
    errors: _Errors, where: str, entry: dict,
) -> tuple[tuple[str, str], ...]:
    raw = entry.get("unless_kwargs")
    if raw is None:
        return ()
    if not isinstance(raw, dict) or len(raw) > MAX_UNLESS_KWARGS:
        errors.add(
            where,
            f"unless_kwargs must be an object of at most {MAX_UNLESS_KWARGS} entries",
        )
        return ()
    out: list[tuple[str, str]] = []
    for k, v in raw.items():
        if not isinstance(k, str) or not _IDENT_RE.match(k):
            errors.add(where, f"unless_kwargs key {_quote(k)} must be an identifier")
            return ()
        # Values are literal TOKENS compared against source text as
        # written — strings only, bounded, printable. A non-string
        # here usually means the author expected evaluated semantics.
        if (not isinstance(v, str) or not v
                or len(v) > MAX_UNLESS_VALUE_LEN or has_nonprintable(v)):
            errors.add(
                where,
                f"unless_kwargs[{_quote(k)}] must be a printable literal token "
                f"string of at most {MAX_UNLESS_VALUE_LEN} chars (matched only "
                "against a literal as written at the call site)",
            )
            return ()
        out.append((k, v))
    return tuple(sorted(out))


def _parse_sinks(
    errors: _Errors, data: dict, pack: str, framework: str,
) -> tuple[SinkSpec, ...]:
    out: list[SinkSpec] = []
    for where, entry in _entries(errors, data, "sinks"):
        if not _check_keys(errors, where, entry, _SINK_KEYS):
            continue
        kind = entry.get("kind")
        if kind not in SINK_KINDS:
            errors.add(where, f"kind {_quote(kind)} not in {sorted(SINK_KINDS)}")
            continue
        before = len(errors.items)
        if kind == SINK_KIND_METHOD_NAME:
            match = _check_str(
                errors, where, entry, "match", _IDENT_RE,
                required=True, what="identifier grammar (bare method name)",
            )
        else:
            match = _check_str(
                errors, where, entry, "match", _DOTTED_RE,
                required=True, what="dotted-name grammar",
            )
        sink_class = _check_str(
            errors, where, entry, "sink_class", _CLASS_RE,
            required=True, what="class grammar",
        )
        # CWE is mandatory: downstream recall matching and classifier
        # routing key on it — a CWE-less sink would emit findings that
        # are invisible to both.
        cwe = _check_str(
            errors, where, entry, "cwe", _CWE_RE, required=True,
            max_len=12, what="CWE-id grammar",
        )
        args, kwargs = _check_sink_args(errors, where, entry)
        receiver_hint = _check_str(
            errors, where, entry, "receiver_hint", _IDENT_RE,
            required=False, what="identifier grammar",
        )
        if receiver_hint and kind != SINK_KIND_METHOD_NAME:
            errors.add(where, "receiver_hint is only valid on method_name sinks")
        confidence = entry.get(
            "confidence",
            CONFIDENCE_HEURISTIC if kind == SINK_KIND_METHOD_NAME
            else CONFIDENCE_EXACT,
        )
        if confidence not in SINK_CONFIDENCES:
            errors.add(
                where,
                f"confidence {_quote(confidence)} not in {sorted(SINK_CONFIDENCES)}",
            )
        elif kind == SINK_KIND_METHOD_NAME and confidence != CONFIDENCE_HEURISTIC:
            # Bare-name equality cannot be more than a heuristic — an
            # exact-confidence claim on it would overstate every hit.
            errors.add(where, "method_name sinks must declare confidence \"heuristic\"")
        unless_kwargs = _check_unless_kwargs(errors, where, entry)
        store_key = _check_str(
            errors, where, entry, "store_key", _STORE_KEY_RE,
            required=kind == SINK_KIND_STORED_WRITE, max_len=64,
            what="store-key grammar",
        )
        if kind != SINK_KIND_STORED_WRITE and entry.get("store_key"):
            errors.add(where, "store_key is only valid on stored_write sinks")
        provenance = _check_provenance(errors, where, entry)
        rationale = _check_rationale(errors, where, entry)
        if len(errors.items) > before:
            continue
        out.append(SinkSpec(
            kind=kind, match=match, sink_class=sink_class, cwe=cwe,
            args=args, kwargs=kwargs, receiver_hint=receiver_hint,
            confidence=str(confidence), unless_kwargs=unless_kwargs,
            store_key=store_key, provenance=provenance, rationale=rationale,
            tier=TIER_PACK, pack=pack, framework=framework,
        ))
    return tuple(out)


def _parse_sanitizers(
    errors: _Errors, data: dict, pack: str, framework: str,
    language: str,
) -> tuple[SanitizerSpec, ...]:
    curated_names = {
        e.library_call for e in all_entries() if language in e.languages
    }
    out: list[SanitizerSpec] = []
    for where, entry in _entries(errors, data, "sanitizers"):
        if not _check_keys(errors, where, entry, _SANITIZER_KEYS):
            continue
        kind = entry.get("kind")
        if kind not in SANITIZER_KINDS:
            errors.add(where, f"kind {_quote(kind)} not in {sorted(SANITIZER_KINDS)}")
            continue
        before = len(errors.items)
        match = _check_str(
            errors, where, entry, "match", _DOTTED_RE,
            required=True, what="dotted-name grammar",
        )
        if match and match in curated_names:
            # The curated table is the single source of truth for its
            # own callees; a pack restating one could silently widen a
            # kill to new sink classes or flip its semantics.
            errors.add(
                where,
                f"match {_quote(match)} is a curated known-safe callee; packs "
                "may only ADD sanitizers, never restate or shadow curated "
                "entries (edit core/dataflow/known_safe_calls.py instead)",
            )
        semantics = entry.get("semantics")
        if semantics not in SANITIZER_SEMANTICS:
            errors.add(
                where,
                f"semantics {_quote(semantics)} not in {sorted(SANITIZER_SEMANTICS)}",
            )
        classes = _check_class_list(
            errors, where, entry, "sink_classes", allow_wildcard=True,
        )
        if semantics == SEMANTICS_KILL and classes == ("*",):
            # A wildcard kill silences every class at once — the
            # highest-consequence row the format can express, so it
            # must name its classes explicitly to be reviewable.
            errors.add(where, "kill sanitizers must name explicit sink_classes, not \"*\"")
        provenance = _check_provenance(errors, where, entry)
        rationale = _check_rationale(errors, where, entry)
        if len(errors.items) > before:
            continue
        out.append(SanitizerSpec(
            kind=kind, match=match, semantics=str(semantics),
            sink_classes=classes, provenance=provenance, rationale=rationale,
            tier=TIER_PACK, pack=pack, framework=framework,
        ))
    return tuple(out)


def _parse_propagators(
    errors: _Errors, data: dict, pack: str, framework: str,
    *, in_tree: bool,
) -> tuple[PropagatorSpec, ...]:
    out: list[PropagatorSpec] = []
    for where, entry in _entries(errors, data, "propagators"):
        if not _check_keys(errors, where, entry, _PROPAGATOR_KEYS):
            continue
        kind = entry.get("kind")
        if kind not in PROPAGATOR_KINDS:
            errors.add(where, f"kind {_quote(kind)} not in {sorted(PROPAGATOR_KINDS)}")
            continue
        before = len(errors.items)
        match = _check_str(
            errors, where, entry, "match", _DOTTED_RE,
            required=True, what="dotted-name grammar",
        )
        flows_raw = entry.get("flow")
        flows: list[FlowEdge] = []
        if (not isinstance(flows_raw, list) or not flows_raw
                or len(flows_raw) > MAX_FLOWS_PER_PROPAGATOR):
            errors.add(
                where,
                f"flow must be a non-empty list of at most "
                f"{MAX_FLOWS_PER_PROPAGATOR} edges",
            )
        else:
            for j, edge in enumerate(flows_raw):
                if (not isinstance(edge, dict)
                        or set(edge) != {"from", "to"}):
                    errors.add(where, f"flow[{j}] must be an object with exactly 'from' and 'to'")
                    continue
                src, dst = edge["from"], edge["to"]
                for label, cell in (("from", src), ("to", dst)):
                    if (not isinstance(cell, str) or len(cell) > MAX_MATCH_LEN
                            or not _valid_access(cell)):
                        errors.add(
                            where,
                            f"flow[{j}].{label} {_quote(cell)} fails the "
                            "access-path grammar (Argument[n], Argument[*], "
                            "ReturnValue, ...)",
                        )
                        break
                else:
                    flows.append(FlowEdge(src=str(src), dst=str(dst)))
        narrowing = entry.get("narrowing", False)
        if not isinstance(narrowing, bool):
            errors.add(where, f"narrowing must be a boolean, got {_quote(narrowing)}")
        elif narrowing and not in_tree:
            # Narrowing reduces the assumed-propagation floor — a
            # suppression-direction claim reserved for packs shipped
            # in-tree, where it gets code review. Config-dir packs
            # (operator trust, but no review gate) may only widen.
            errors.add(
                where,
                "narrowing is reserved for packs shipped in-tree; a "
                "config-dir pack may only widen flow",
            )
        provenance = _check_provenance(errors, where, entry)
        rationale = _check_rationale(errors, where, entry)
        if len(errors.items) > before:
            continue
        out.append(PropagatorSpec(
            kind=kind, match=match, flows=tuple(flows),
            narrowing=bool(narrowing), provenance=provenance,
            rationale=rationale, tier=TIER_PACK, pack=pack,
            framework=framework,
        ))
    return tuple(out)


# ── curated sanitizer import ─────────────────────────────────────────


def _curated_rationale(entry: KnownSafeCall) -> str:
    note = entry.soundness_note.strip()
    if len(note) > MAX_RATIONALE_LEN:
        note = note[:MAX_RATIONALE_LEN - 16] + " ...[elided]"
    return note


def curated_sanitizers(language: str) -> tuple[SanitizerSpec, ...]:
    """The curated known-safe table as sanitizer specs for *language*.

    Semantics follow the table's transform-vs-validate split:
    transform entries KILL for their class (the return value is the
    safe value); validate entries TAG only (a guard that raises does
    not rewrite the value, and certifying the guarded path needs
    dominance analysis the consumer does not have). Entries are tier
    ``curated`` — packs add beside them, never over them.
    """
    out: list[SanitizerSpec] = []
    for entry in all_entries():
        if language not in entry.languages:
            continue
        mapped = _CURATED_SINK_CLASS.get(entry.sink_class, entry.sink_class)
        if not _CLASS_RE.match(mapped):
            # A curated key outside the class grammar cannot pair with
            # pack sink classes; skipping (loudly greppable here) is
            # recall-neutral — the entry never suppressed anything in
            # this lane to begin with.
            continue
        semantics = (
            SEMANTICS_KILL if entry.input_arg_kind == "transform"
            else SEMANTICS_TAG
        )
        out.append(SanitizerSpec(
            kind="dotted_callee",
            match=entry.library_call,
            semantics=semantics,
            sink_classes=(mapped,),
            provenance="framework_catalog",
            rationale=_curated_rationale(entry),
            tier=TIER_CURATED,
            pack="known-safe-calls",
            framework="",
        ))
    return tuple(out)


# ── name resolution + loading ────────────────────────────────────────


def _validate_pack_name(name: str) -> list[str]:
    segments = name.split("/")
    if not 1 <= len(segments) <= 2:
        return [f"pack name {_quote(name)} must be '<name>' or '<language>/<name>'"]
    bad = [s for s in segments if not _PACK_NAME_SEGMENT_RE.match(s)]
    if bad:
        return [
            f"pack name segment {_quote(s)} fails the pack-name grammar"
            for s in bad
        ]
    return []


def _resolve_pack(
    name: str,
    dirs: Sequence[Path],
    target_root: Path | None,
) -> tuple[Path, bool]:
    """Resolve *name* against *dirs* in order; returns ``(path,
    in_tree)`` where ``in_tree`` marks the shipped packs directory.

    Symlink targets and searched directories land in refusal messages
    — a symlink's target string is chosen by whoever wrote the link,
    so every interpolated path is escaped (:func:`_quote`)."""
    problems = _validate_pack_name(name)
    if problems:
        raise PackLoadError("; ".join(problems))
    resolved_target = target_root.resolve() if target_root is not None else None
    default_resolved = DEFAULT_PACKS_DIR.resolve()
    for base in dirs:
        base_resolved = base.resolve()
        candidate = base_resolved / f"{name}.json"
        if not candidate.is_file():
            continue
        candidate = candidate.resolve()
        if not candidate.is_relative_to(base_resolved):
            raise PackLoadError(
                f"pack {name}: resolves outside its pack directory "
                f"({_quote(candidate, max_len=240)}) — refusing "
                "(symlink escape)",
            )
        in_tree = base_resolved == default_resolved
        # Identity exemption: the shipped packs directory is trusted
        # because it ships with the tool, not because of where the
        # scan points — a self-scan (target_root = this checkout)
        # must still load its own packs. Operator config dirs get no
        # such identity and stay subject to the containment check.
        if (not in_tree and resolved_target is not None
                and candidate.is_relative_to(resolved_target)):
            raise PackLoadError(
                f"pack {name}: resolves inside the scanned tree "
                f"({_quote(candidate, max_len=240)}) — packs never load "
                "from a target repository (a target-shipped model file "
                "is detection steering)",
            )
        return candidate, in_tree
    searched = ", ".join(_quote(d, max_len=240) for d in dirs)
    raise PackLoadError(f"pack {name}: not found under [{searched}]")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    """object_pairs_hook: a duplicate JSON key parses last-wins, so a
    reviewed row could be silently replaced by a second spelling of
    the same key later in the file — refuse instead."""
    out: dict = {}
    for key, value in pairs:
        if key in out:
            msg = f"duplicate JSON key {_quote(key)}"
            raise ValueError(msg)
        out[key] = value
    return out


def _reject_non_finite(token: str) -> None:
    msg = f"non-finite JSON constant rejected: {token}"
    raise ValueError(msg)


def _load_pack_file(path: Path, name: str, *, in_tree: bool) -> TaintPack:
    errors = _Errors(name)
    try:
        # follow_symlinks=False (O_NOFOLLOW): *path* was fully
        # resolved during name resolution, so a final-component link
        # here means the entry was swapped after the resolve-time
        # checks — refuse rather than read whatever it points at now.
        text = read_text_gated(
            path, MAX_PACK_BYTES, follow_symlinks=False,
        )
    except (ValueError, OSError) as exc:
        raise PackLoadError(
            f"pack {name}: unreadable or over the {MAX_PACK_BYTES}-byte "
            f"budget ({escape_nonprintable(str(exc))})",
        ) from None
    try:
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_non_finite,
        )
    except RecursionError:
        raise PackLoadError(
            f"pack {name}: JSON nesting exceeds the parser depth budget",
        ) from None
    except ValueError as exc:
        raise PackLoadError(
            f"pack {name}: invalid JSON ({escape_nonprintable(str(exc))})",
        ) from None
    if not isinstance(data, dict):
        raise PackLoadError(f"pack {name}: top level must be an object")

    unknown = set(data) - _TOP_LEVEL_KEYS
    if unknown:
        listed = ", ".join(_quote(k) for k in sorted(map(str, unknown))[:5])
        errors.add("top-level", f"unknown key(s) {listed}")
    version = data.get("schema_version")
    if version != SCHEMA_VERSION:
        errors.add(
            "top-level",
            f"schema_version {_quote(version)} unsupported (this loader "
            f"reads exactly {SCHEMA_VERSION})",
        )
    language = data.get("language")
    if language not in SUPPORTED_PACK_LANGUAGES:
        errors.add(
            "top-level",
            f"language {_quote(language)} not in {sorted(SUPPORTED_PACK_LANGUAGES)}",
        )
    framework = data.get("framework")
    if not isinstance(framework, str) or not _FRAMEWORK_RE.match(framework or ""):
        errors.add("top-level", f"framework {_quote(framework)} fails grammar")
        framework = ""
    declared = data.get("pack")
    if declared != path.stem:
        errors.add(
            "top-level",
            f"pack field {_quote(declared)} must equal the file name "
            f"{_quote(path.stem)}",
        )
    errors.raise_if_any()
    language = str(language)  # membership in SUPPORTED_PACK_LANGUAGES held

    pack_label = str(declared)
    sources = _parse_sources(errors, data, pack_label, framework)
    sinks = _parse_sinks(errors, data, pack_label, framework)
    sanitizers = _parse_sanitizers(errors, data, pack_label, framework, language)
    propagators = _parse_propagators(
        errors, data, pack_label, framework, in_tree=in_tree,
    )
    errors.raise_if_any()

    return TaintPack(
        name=pack_label,
        language=language,
        framework=framework,
        schema_version=SCHEMA_VERSION,
        path=path,
        sources=sources,
        sinks=sinks,
        sanitizers=sanitizers,
        propagators=propagators,
    )


def load_packs(
    names: Iterable[str],
    *,
    extra_dirs: Sequence[Path | str] = (),
    target_root: Path | str | None = None,
) -> PackSet:
    """Load and merge the named packs, fail-closed.

    ``names`` are repo-relative pack names (``python/web-injection-core``)
    resolved against the in-tree packs directory first, then each
    operator-supplied ``extra_dirs`` entry in order. Any ``extra_dirs``
    directory inside ``target_root`` — and any resolved pack file
    inside it — refuses with :class:`PackLoadError`: the scanned tree
    is never a spec source. The in-tree directory is trusted by
    IDENTITY (it ships with the tool), so a self-scan whose
    ``target_root`` is this very checkout still loads the shipped
    packs; only operator config dirs are containment-checked.
    Narrowing propagator entries are in-tree-only — a config-dir pack
    may only widen flow.

    Raises :class:`PackLoadError` on the first pack that fails —
    partial pack sets are never returned.
    """
    dirs: list[Path] = [DEFAULT_PACKS_DIR]
    resolved_target = Path(target_root).resolve() if target_root is not None else None
    for extra in extra_dirs:
        extra_path = Path(extra).resolve()
        if resolved_target is not None and extra_path.is_relative_to(resolved_target):
            raise PackLoadError(
                f"pack directory {_quote(extra_path, max_len=240)} is "
                f"inside the scanned tree "
                f"({_quote(resolved_target, max_len=240)}) — refusing (a "
                "target-controlled pack directory is detection steering)",
            )
        dirs.append(extra_path)

    packs: list[TaintPack] = []
    seen: set[str] = set()
    for name in names:
        if name in seen:
            raise PackLoadError(f"pack {name}: listed twice")
        seen.add(name)
        path, in_tree = _resolve_pack(
            name, dirs,
            Path(target_root) if target_root is not None else None,
        )
        packs.append(_load_pack_file(path, name, in_tree=in_tree))

    curated: list[SanitizerSpec] = []
    seen_langs: set[str] = set()
    for pack in packs:
        if pack.language in seen_langs:
            continue
        seen_langs.add(pack.language)
        curated.extend(curated_sanitizers(pack.language))

    return PackSet(
        packs=tuple(packs),
        sources=tuple(s for p in packs for s in p.sources),
        sinks=tuple(s for p in packs for s in p.sinks),
        sanitizers=tuple(curated) + tuple(
            s for p in packs for s in p.sanitizers
        ),
        propagators=tuple(s for p in packs for s in p.propagators),
        curated_sanitizers=tuple(curated),
    )


def default_pack_names(language: str = "python") -> tuple[str, ...]:
    """The in-tree pack names shipped for *language*, sorted."""
    lang_dir = DEFAULT_PACKS_DIR / language
    if not _IDENT_RE.match(language) or not lang_dir.is_dir():
        return ()
    return tuple(
        f"{language}/{p.stem}" for p in sorted(lang_dir.glob("*.json"))
    )


__all__ = [
    "DEFAULT_PACKS_DIR",
    "MAX_ENTRIES_PER_ROLE",
    "MAX_PACK_BYTES",
    "MAX_RATIONALE_LEN",
    "SCHEMA_VERSION",
    "SUPPORTED_PACK_LANGUAGES",
    "FlowEdge",
    "PackLoadError",
    "PackSet",
    "PropagatorSpec",
    "SanitizerSpec",
    "SinkSpec",
    "SourceSpec",
    "TaintPack",
    "curated_sanitizers",
    "default_pack_names",
    "load_packs",
]
