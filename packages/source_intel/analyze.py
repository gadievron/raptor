"""Source intelligence analyzer — orchestrates cocci rules + alias
scanning to produce structured evidence per target.

Phase 2 (substrate) ships exactly one axis: ``axis 1 / attrs`` covering
``warn_unused_result``. Axes 2-7 plug in by adding rule directories
under ``engine/coccinelle/source_intel/`` and aggregators here.

The output is a :class:`SourceIntelResult` (frozen) keyed on target +
rule-set hash. The Stage D LLM consumer consumes it via
:mod:`packages.source_intel.render`; the corpus runner consumes it
via :mod:`packages.source_intel.adapter`.

Hard invariants (carried from design):
  * Strict sidecar — produces evidence, never overrides verdict.
  * ``--no-includes`` to spatch by default (untrusted-target posture
    matching PR-3 cocci scan + PR-4 prereqs).
  * Out-of-tree symbols never fabricated — `function_attrs_status`
    explicit when a symbol isn't found.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, FrozenSet, List, Optional, Tuple

from packages.source_intel.aliases import (
    ALL_WUR_ALIASES,
    wur_alias_in,
    wur_alias_origin,
)

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1


# =====================================================================
# Data shape
# =====================================================================


#: Recognised attribute kinds. Axis-N PRs add to this set; the cocci
#: rule's COCCIRESULT message prefix (``<kind>:<function>``) must match
#: one of these to be parsed.
KIND_WUR = "wur"
KIND_NONNULL = "nonnull"
KIND_ALLOC_SIZE = "alloc_size"
KIND_RETURNS_NONNULL = "returns_nonnull"
KIND_NORETURN = "noreturn"
KIND_MALLOC = "malloc"
KIND_NO_STACK_PROTECTOR = "no_stack_protector"
KIND_ACCESS = "access"

ALL_KINDS: Tuple[str, ...] = (
    KIND_WUR,
    KIND_NONNULL,
    KIND_ALLOC_SIZE,
    KIND_RETURNS_NONNULL,
    KIND_NORETURN,
    KIND_MALLOC,
    KIND_NO_STACK_PROTECTOR,
    KIND_ACCESS,
)


@dataclass(frozen=True)
class AttributeEvidence:
    """A single observation of a compiler attribute on a function.

    The ``kind`` field distinguishes evidence classes (``wur``,
    ``nonnull``, …). Axis-1-expansion adds more kinds; the data shape
    stays uniform so render / adapter code dispatches on ``kind``
    rather than carrying class-specific subtypes.

    ``conditional_on`` captures the innermost ``#if*`` condition
    enclosing the match (None when the match is unconditional). The
    Stage D consumer downweights matches whose condition wasn't
    confirmed-active in the actual build.
    """

    kind: str  # one of ``ALL_KINDS``
    function_name: str
    location: Tuple[str, int]  # (file_path, line)
    match_source: str  # "literal" | "known_alias" | "project_alias"
    raw_match: str  # actual spelling for provenance
    conditional_on: Optional[str] = None  # innermost enclosing #if* condition


def WurEvidence(  # noqa: N802 — back-compat factory for Phase 2 callers
    function_name: str,
    location: Tuple[str, int],
    match_source: str,
    raw_match: str,
    conditional_on: Optional[str] = None,
) -> AttributeEvidence:
    """Back-compat factory: returns an :class:`AttributeEvidence` with
    ``kind="wur"``. Phase 2 callers (tests, downstream code) used the
    name ``WurEvidence`` as a constructor; that name is preserved as a
    factory to avoid breaking imports.
    """
    return AttributeEvidence(
        kind=KIND_WUR,
        function_name=function_name,
        location=location,
        match_source=match_source,
        raw_match=raw_match,
        conditional_on=conditional_on,
    )


@dataclass(frozen=True)
class SourceIntelResult:
    """Per-target source-intelligence facts.

    Phase 2 shipped one evidence kind (``wur``); Phase 3 adds
    ``nonnull`` and lays the substrate for more kinds. The data shape
    is uniform — all attribute observations live in ``attributes`` and
    consumers filter / lookup by ``kind``.
    """

    schema_version: int = SCHEMA_VERSION
    target: str = ""
    rules_executed: Tuple[str, ...] = ()
    rules_failed: Tuple[Tuple[str, str], ...] = ()
    skipped_reason: Optional[str] = None
    spatch_version: Optional[str] = None

    #: All attribute observations across all kinds.
    attributes: Tuple[AttributeEvidence, ...] = ()

    #: Project-specific alias macros discovered in the target's
    #: headers, keyed by kind. Empty when discovery skipped (target
    #: had no headers or only the curated table was used).
    discovered_aliases: Tuple[Tuple[str, Tuple[str, ...]], ...] = ()

    @property
    def is_skipped(self) -> bool:
        return self.skipped_reason is not None

    @property
    def wur_functions(self) -> Tuple[AttributeEvidence, ...]:
        """Back-compat: WUR-only subset. Phase 2 callers / tests used
        this accessor; preserved by filtering ``attributes`` on kind.
        """
        return tuple(a for a in self.attributes if a.kind == KIND_WUR)

    def attrs_of_kind(self, kind: str) -> Tuple[AttributeEvidence, ...]:
        """Filter observations by attribute kind."""
        return tuple(a for a in self.attributes if a.kind == kind)

    def function_attrs(self, name: str) -> Tuple[AttributeEvidence, ...]:
        """All attribute observations for a given function name."""
        return tuple(a for a in self.attributes if a.function_name == name)

    def function_has_wur(self, name: str) -> Optional[AttributeEvidence]:
        """Lookup: is function ``name`` annotated WUR? Returns first
        observation or None. Back-compat from Phase 2."""
        for a in self.attributes:
            if a.kind == KIND_WUR and a.function_name == name:
                return a
        return None

    def function_has_kind(
        self, name: str, kind: str,
    ) -> Optional[AttributeEvidence]:
        """Generalised lookup — returns first observation of ``kind``
        on function ``name``, or None."""
        for a in self.attributes:
            if a.kind == kind and a.function_name == name:
                return a
        return None


# =====================================================================
# Shipped rule discovery
# =====================================================================


def _shipped_rules_root() -> Optional[Path]:
    """Return the in-tree shipped rules root, or None if absent
    (minimal install / packaging strip).

    Layout: ``engine/coccinelle/source_intel/<axis>/`` per-axis subdirs
    (``attrs/`` for axis 1; later axes get ``proximity/``,
    ``allocation/``, etc.). Each subdir contains one or more
    ``.cocci`` files; ``analyze`` iterates the subdirs and runs each
    in turn so the per-axis rule sets stay scoped.
    """
    # packages/source_intel/analyze.py -> repo root -> engine/...
    here = Path(__file__).resolve()
    candidate = here.parents[2] / "engine" / "coccinelle" / "source_intel"
    return candidate if candidate.is_dir() else None


# Back-compat alias for external test code that may import the old name.
_shipped_rules_dir = _shipped_rules_root


def _axis_dirs(rules_root: Path) -> List[Path]:
    """List of per-axis subdirectories under the rules root.

    Phase 2 ships ``attrs/`` only. Axes 2-7 add sibling dirs; this
    function picks all of them up automatically so adding an axis
    means dropping rules into a new subdir without touching analyze.
    Order is deterministic (sorted by name).
    """
    return sorted(d for d in rules_root.iterdir() if d.is_dir())


# =====================================================================
# Source-language heuristic (cocci is C-family only)
# =====================================================================


_C_CPP_EXTS: Tuple[str, ...] = (
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh",
)


def _has_c_cpp_source(target: Path, max_files: int = 200) -> bool:
    """Bounded rglob — same heuristic as PR-3 scan + PR-4 prereqs.
    Quick reject for pure-Python / pure-Go targets so we don't waste
    a spatch run.
    """
    if not target.is_dir():
        # Single-file target — accept if it's C-family.
        return target.suffix.lower() in _C_CPP_EXTS
    seen = 0
    for entry in target.rglob("*"):
        if not entry.is_file():
            continue
        seen += 1
        if entry.suffix.lower() in _C_CPP_EXTS:
            return True
        if seen >= max_files:
            return False
    return False


# =====================================================================
# Public API
# =====================================================================


def analyze(
    target: Path,
    rules_dir: Optional[Path] = None,
    timeout_per_rule: int = 60,
) -> SourceIntelResult:
    """Run shipped source_intel cocci rules against ``target``.

    Skip-silent semantics:
      * spatch not on PATH → ``skipped_reason="spatch_not_available"``
      * target has no C/C++ source → ``skipped_reason="no_c_cpp_source"``
      * shipped rules dir missing → ``skipped_reason="rules_dir_missing"``

    Returns a :class:`SourceIntelResult` with parsed evidence. Never
    raises — failures collapse to per-rule entries in ``rules_failed``
    or a global ``skipped_reason``.
    """
    target = Path(target)

    # Import locally so a packaging strip of packages/coccinelle
    # degrades to skipped rather than ImportError at module load.
    try:
        from packages.coccinelle.runner import (
            is_available as spatch_available,
            run_rules as spatch_run_rules,
            version as spatch_version,
        )
    except ImportError:
        return SourceIntelResult(
            target=str(target),
            skipped_reason="coccinelle_package_missing",
        )

    if not spatch_available():
        return SourceIntelResult(
            target=str(target),
            skipped_reason="spatch_not_available",
        )
    if not _has_c_cpp_source(target):
        return SourceIntelResult(
            target=str(target),
            skipped_reason="no_c_cpp_source",
        )

    effective_rules_root = (
        rules_dir if rules_dir else _shipped_rules_root()
    )
    if effective_rules_root is None:
        return SourceIntelResult(
            target=str(target),
            skipped_reason="rules_dir_missing",
        )

    # The shipped layout has per-axis subdirs (``attrs/`` etc.). When a
    # caller hands us a flat rules_dir (e.g. tests), accept that too —
    # if no subdirs are present, run rules from the dir directly.
    axis_dirs = _axis_dirs(effective_rules_root)
    rule_dirs = axis_dirs if axis_dirs else [effective_rules_root]

    rules_executed: List[str] = []
    rules_failed: List[Tuple[str, str]] = []
    observations: List[AttributeEvidence] = []

    # spatch invocation per axis. ``no_includes=True`` matches the
    # existing PR-3 scan + PR-4 prereqs untrusted-target posture;
    # trusted-mode opt-in is a future operator flag.
    for axis_dir in rule_dirs:
        spatch_results = spatch_run_rules(
            target=target,
            rules_dir=axis_dir,
            timeout_per_rule=timeout_per_rule,
            no_includes=True,
        )
        for result in spatch_results:
            rules_executed.append(result.rule)
            if result.errors:
                # Per-rule failure — collect but don't abort. Other rules
                # still contribute evidence.
                rules_failed.append(
                    (result.rule, "; ".join(result.errors)[:500])
                )
            for match in result.matches:
                observations.extend(_parse_match_to_attribute(match))

    # Project-specific alias discovery: walk target headers, classify
    # `#define MACRO __attribute__((...))` patterns by family, count
    # usage, cap per family.
    try:
        from packages.source_intel.discovery import discover_aliases
        discovery = discover_aliases(target)
        discovered_alias_tuple = tuple(
            (family, names)
            for family, names in sorted(discovery.aliases_by_family.items())
        )
    except ImportError:
        discovered_alias_tuple = ()

    # Augment cocci output with alias scanning. Phase 2 shipped curated
    # WUR aliases only; Phase 3c also scans for project-discovered
    # aliases (any kind) with provenance = "project_alias".
    observations.extend(_scan_alias_observations(target))
    observations.extend(
        _scan_project_alias_observations(
            target,
            discovered_alias_tuple,
        )
    )

    return SourceIntelResult(
        target=str(target),
        rules_executed=tuple(rules_executed),
        rules_failed=tuple(rules_failed),
        spatch_version=spatch_version(),
        attributes=tuple(observations),
        discovered_aliases=discovered_alias_tuple,
    )


# =====================================================================
# Internal — match parsing
# =====================================================================


#: Raw-match strings to record for each cocci-emitted kind. The cocci
#: rules match a small fixed set of literal spellings, so we map kind
#: → canonical provenance string once. (Per-spelling provenance lands
#: with axis-1-expansion's alias-discovery pass — projects that use
#: __must_check / __wur etc. would benefit from the exact spelling.)
_KIND_TO_RAW_MATCH: Dict[str, str] = {
    KIND_WUR: "__attribute__((warn_unused_result))",
    KIND_NONNULL: "__attribute__((nonnull))",
    KIND_ALLOC_SIZE: "__attribute__((alloc_size(...)))",
    KIND_RETURNS_NONNULL: "__attribute__((returns_nonnull))",
    KIND_NORETURN: "__attribute__((noreturn))",
    KIND_MALLOC: "__attribute__((malloc))",
    KIND_NO_STACK_PROTECTOR: "__attribute__((no_stack_protector))",
    KIND_ACCESS: "__attribute__((access(...)))",
}


def _parse_match_to_attribute(match: Any) -> List[AttributeEvidence]:
    """Convert a cocci :class:`SpatchMatch` into ``AttributeEvidence``
    records.

    The shipped attrs/*.cocci rules emit messages of the form
    ``<kind>:<function_name>`` where ``<kind>`` is one of ``ALL_KINDS``.
    Other message shapes are ignored (future-proof for non-attrs
    axes that may share this parser path).

    ``conditional_on`` is captured by looking up the innermost
    enclosing ``#if*`` block at the match's (file, line). The lookup
    is cached file-by-file; multiple matches in the same file share
    the parse cost.
    """
    msg = (getattr(match, "message", "") or "").strip()
    if ":" not in msg:
        return []
    kind, _, func_name = msg.partition(":")
    kind = kind.strip()
    func_name = func_name.strip()
    if not func_name or kind not in ALL_KINDS:
        return []
    file_path = getattr(match, "file", "")
    line_no = int(getattr(match, "line", 0))

    # Import locally to keep conditional capture optional — if the
    # module is stripped from a minimal install, evidence still emits.
    try:
        from packages.source_intel.conditional import enclosing_condition
        cond = enclosing_condition(file_path, line_no) if file_path else None
    except ImportError:
        cond = None

    return [AttributeEvidence(
        kind=kind,
        function_name=func_name,
        location=(file_path, line_no),
        match_source="literal",
        raw_match=_KIND_TO_RAW_MATCH.get(kind, ""),
        conditional_on=cond,
    )]


# Back-compat alias: tests that import the Phase 2 name keep working.
_parse_match_to_wur = _parse_match_to_attribute


def _scan_alias_observations(target: Path) -> List[AttributeEvidence]:
    """Curated-alias substring scan. Looks for known macro spellings
    in C/H files under ``target`` and emits one observation per file
    where any alias is seen.

    Limitations (documented; tightened in axis-1-expansion):
      * Function-name attribution is best-effort: we record an
        empty ``function_name`` because substring matching can't
        tell us which function the alias applied to.
      * Counted once per file; multiple aliases in one file produce
        one observation.

    These limitations are why the per-rule cocci approach is the
    primary evidence source — the alias scan is supplementary, not
    substitutive.
    """
    observations: List[AttributeEvidence] = []
    if not target.is_dir():
        # Single-file target — scan that file directly.
        if target.is_file() and target.suffix.lower() in _C_CPP_EXTS:
            return _scan_alias_in_file(target)
        return observations

    seen_files = 0
    for entry in target.rglob("*"):
        if seen_files >= 500:
            # Bound the scan; large kernel trees would overflow.
            break
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in _C_CPP_EXTS:
            continue
        seen_files += 1
        observations.extend(_scan_alias_in_file(entry))
    return observations


def _scan_project_alias_observations(
    target: Path,
    discovered_alias_tuple: Tuple[Tuple[str, Tuple[str, ...]], ...],
) -> List[AttributeEvidence]:
    """For each discovered project-specific alias macro, scan source
    files for occurrences and emit ``match_source="project_alias"``
    evidence.

    Limitations match the curated-alias scan: function-name attribution
    is best-effort (empty). The per-alias cocci rules planned for
    future axes will bind aliases to functions; this pass just records
    that the macro appears in a C source file.
    """
    observations: List[AttributeEvidence] = []
    if not target.is_dir():
        return observations

    # Build a flat list of (kind, alias_name) tuples for the scan.
    alias_pairs: List[Tuple[str, str]] = []
    for family, names in discovered_alias_tuple:
        for name in names:
            alias_pairs.append((family, name))
    if not alias_pairs:
        return observations

    seen_files = 0
    for entry in target.rglob("*"):
        if seen_files >= 500:
            break
        if not entry.is_file():
            continue
        if entry.suffix.lower() not in _C_CPP_EXTS:
            continue
        seen_files += 1
        try:
            text = entry.read_text(errors="replace")
        except OSError:
            continue
        for family, alias_name in alias_pairs:
            # Word-boundary check; substring would risk false positives
            # on prefix-overlap (FOO_CHECK vs MUST_CHECK).
            if not _is_word_present(text, alias_name):
                continue
            # First-occurrence line for prompt context.
            line_no = 0
            for n, line in enumerate(text.split("\n"), start=1):
                if _is_word_present(line, alias_name):
                    line_no = n
                    break
            observations.append(AttributeEvidence(
                kind=family,
                function_name="",  # see scan_alias_in_file docstring
                location=(str(entry), line_no),
                match_source="project_alias",
                raw_match=alias_name,
            ))
    return observations


def _is_word_present(text: str, word: str) -> bool:
    """Word-boundary substring check. Avoids false positives where
    one macro name is a prefix of another (e.g. ``CHECK`` matching in
    ``CHECK_RETURN``)."""
    import re as _re
    return bool(_re.search(r"\b" + _re.escape(word) + r"\b", text))


def _scan_alias_in_file(path: Path) -> List[AttributeEvidence]:
    """Best-effort: detect WUR alias spellings in a single C/H file.

    One observation per (file, alias_spelling) pair — multiple aliases
    in the same file produce multiple observations because each may
    apply to a different function. We can't bind the alias to a function
    name without parsing the C, which is exactly cocci's job; the
    alias-scan exists to surface that "this file has hardening intent"
    even when the cocci rule didn't fire (which it won't for non-literal
    spellings until per-alias rules ship).
    """
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return []

    observations: List[AttributeEvidence] = []
    for spelling in ALL_WUR_ALIASES:
        if spelling in text:
            # First occurrence line — for prompt rendering's sake.
            line_no = 0
            for n, line in enumerate(text.split("\n"), start=1):
                if spelling in line:
                    line_no = n
                    break
            observations.append(AttributeEvidence(
                kind=KIND_WUR,
                function_name="",  # see docstring — best-effort gap
                location=(str(path), line_no),
                match_source="known_alias",
                raw_match=spelling,
            ))
    return observations
