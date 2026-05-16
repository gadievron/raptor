""":class:`Validator` adapter — wires source_intel into the corpus runner.

Phase 2 substrate ships a minimal verdict policy: source_intel is
fundamentally a SIDECAR (evidence, not verdict), so the Validator
returns ``UNCERTAIN`` for findings where structural evidence is
inconclusive — which is most findings until axes 2-7 ship. Specific
explicit-verdict cases:

  * Finding's function annotated WUR (literal or known alias) AND
    finding cites an unchecked-return-class CWE (CWE-252/CWE-476):
    EXPLOITABLE — author intent supports the claim. (Build-flag
    enforcement caveats are recorded in evidence but don't gate
    the verdict.)
  * All other cases: UNCERTAIN.

This minimal policy intentionally leaves room for axes 2-7 to refine
the verdict via the same Validator. The corpus runner records the
UNCERTAIN bucket separately — it doesn't contribute to precision /
recall, so Phase 2 lands without harming the V2 baseline.

Wire via:
    libexec/raptor-corpus-run --output source_intel.csv \\
        --validator packages.source_intel.adapter:SourceIntelValidator
    libexec/raptor-corpus-metrics source_intel.csv
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, FrozenSet, Optional, Tuple

from core.dataflow.finding import Finding
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.analyze import (
    GRADE_DOMINATES,
    GRADE_SAME_FUNCTION,
    GRADE_SAME_PATH,
    KIND_ACCESS,
    KIND_ALLOC_SIZE,
    KIND_MALLOC,
    KIND_NO_STACK_PROTECTOR,
    KIND_NONNULL,
    KIND_NORETURN,
    KIND_RETURNS_NONNULL,
    KIND_WUR,
    AbortEvidence,
    AllocationEvidence,
    AttributeEvidence,
    CapabilityEvidence,
    HazardEvidence,
    SourceIntelResult,
    analyze,
)
from packages.source_intel.cache import SourceIntelCache

logger = logging.getLogger(__name__)


# Per-attribute-kind CWE relevance: only emit a verdict signal when
# the finding's rule_id is in the relevant set for the observed
# attribute. This keeps the verdict policy scoped — WUR evidence on
# a use-after-free finding does NOT support EXPLOITABLE.
_KIND_RELEVANT_RULE_PREFIXES: Dict[str, Tuple[str, ...]] = {
    KIND_WUR: (
        "cpp/null-dereference",
        "cpp/uncontrolled-",        # uncontrolled-allocation-size, etc.
        "cpp/unchecked-return",
        "cpp/unbounded-write",
        "c/null-dereference",
    ),
    KIND_NONNULL: (
        "cpp/null-dereference",
        "c/null-dereference",
    ),
    # alloc_size is mostly informational for memory-corruption findings:
    # tells the LLM "this function's return is a buffer of size N",
    # which is highly relevant when reasoning about CWE-120 / CWE-122
    # (where the bug is over-running an allocated buffer).
    KIND_ALLOC_SIZE: (
        "cpp/unbounded-write",
        "cpp/uncontrolled-",        # uncontrolled-allocation-size
    ),
    # returns_nonnull is relevant when the finding is about a NULL deref:
    # caller may have skipped a null check trusting the annotation; if
    # the annotation is wrong, the deref fires.
    KIND_RETURNS_NONNULL: (
        "cpp/null-dereference",
        "c/null-dereference",
    ),
    # noreturn is informational for the verdict policy — knowing a
    # function aborts on the path SUPPORTS a not-exploitable verdict
    # (DoS-only). But Phase 2-3 never emit NOT_EXPLOITABLE; we leave
    # noreturn evidence to surface via render strings only, with no
    # rule-id-relevance dispatch yet. Empty tuple → no verdict-relevant
    # rule prefixes.
    KIND_NORETURN: (),
    # malloc by itself is informational (mostly co-applied with
    # alloc_size). Leave verdict policy to alloc_size; malloc surfaces
    # via render strings only.
    KIND_MALLOC: (),
    # no_stack_protector marks a hardening hole. Relevant verdict
    # signal for stack-buffer-overflow CWE classes — finding gains
    # support when the buggy function explicitly opts out of canary
    # insertion.
    KIND_NO_STACK_PROTECTOR: (
        "cpp/unbounded-write",
        "cpp/uncontrolled-",
    ),
    # access declares pointer-parameter intent; relevant for CWE-120
    # / CWE-787 (the compiler may bounds-check operations against the
    # annotated parameter under FORTIFY_SOURCE).
    KIND_ACCESS: (
        "cpp/unbounded-write",
        "cpp/uncontrolled-",
    ),
}

# Back-compat — Phase 2 tests imported this name; preserved as the
# union over all kinds, which matches the Phase 2 single-kind
# semantics (Phase 2 dispatch was wur-only).
_WUR_RELEVANT_RULE_PREFIXES = _KIND_RELEVANT_RULE_PREFIXES[KIND_WUR]


# Repo-relative path prefixes that source_intel can scan; anything else
# (out-of-tree-fixture or absolute) is treated per the file's own path.
_DEFAULT_REPO_ROOT = Path(__file__).resolve().parents[2]


class SourceIntelValidator:
    """:class:`Validator` implementation driven by source_intel cocci
    evidence.

    Zero-arg construction works (for ``--validator`` import spec). The
    cache is shared across :meth:`validate` calls so repeated finding
    references to the same target tree amortize the cocci-run cost.
    """

    def __init__(
        self,
        repo_root: Optional[Path] = None,
        cache: Optional[SourceIntelCache] = None,
    ) -> None:
        self._repo_root = repo_root or _DEFAULT_REPO_ROOT
        self._cache = cache or SourceIntelCache()

    def validate(self, finding: Finding) -> ValidatorVerdict:
        """Return EXPLOITABLE when WUR-class evidence backs the claim;
        UNCERTAIN otherwise. NEVER NOT_EXPLOITABLE in Phase 2 — that
        would require axis 2 (proximity) or axis 4 (privilege gradient)
        evidence to support a confident refutation.
        """
        target = self._target_for_finding(finding)
        if target is None:
            return ValidatorVerdict.UNCERTAIN

        result = self._cache.get(target)
        if result is None:
            try:
                result = analyze(target)
            except Exception:  # noqa: BLE001 — never let analyze crash the runner
                logger.exception("source_intel analyze failed for %s", target)
                return ValidatorVerdict.UNCERTAIN
            self._cache.put(target, None, result)

        return self._verdict_from_result(finding, result)

    # -----------------------------------------------------------------
    # Internal
    # -----------------------------------------------------------------

    def _target_for_finding(self, finding: Finding) -> Optional[Path]:
        """Derive the target directory to scan from the finding's
        source file path.

        Heuristic: walk up from ``finding.source.file_path`` (resolved
        relative to repo root) to find a directory containing a build
        marker (``Makefile`` / ``compile_commands.json`` / ``.config``).
        Falls back to the file's immediate parent when no marker found.

        Returns None when the path can't be resolved — corpus replay
        on an unclonied out-of-tree fixture lands here.
        """
        file_path = (finding.source.file_path or "").strip()
        if not file_path:
            return None

        candidate = Path(file_path)
        if not candidate.is_absolute():
            candidate = (self._repo_root / candidate).resolve()

        if not candidate.exists():
            return None

        # If candidate is a file, walk up looking for build markers.
        if candidate.is_file():
            cur = candidate.parent
            for _ in range(8):  # bounded walk; kernel trees ~4 deep
                if (
                    (cur / "Makefile").is_file()
                    or (cur / "compile_commands.json").is_file()
                    or (cur / ".config").is_file()
                    or (cur / "Kbuild").is_file()
                ):
                    return cur
                if cur == cur.parent:
                    break
                cur = cur.parent
            return candidate.parent

        return candidate

    def _verdict_from_result(
        self,
        finding: Finding,
        result: SourceIntelResult,
    ) -> ValidatorVerdict:
        """Apply the verdict policy in four passes:

        1. **Dead-code check (Phase 7):** if PR-4's function_inventory
           reports the finding's enclosing function has zero callers
           in the target AND it's static, the bug is unreachable —
           return NOT_EXPLOITABLE with dead_code rationale.

        2. **Abort-dominance check (Phase 5a):** if an abort-class call
           sits in the same function as the finding's sink AND the
           finding's rule_id is memory-corruption-class, the bug
           primitive aborts before exploitation — return
           NOT_EXPLOITABLE.

        3. **Unchecked-allocation check (Phase 6a, axis 3):** if the
           finding's source line is at an allocator call site we
           emitted as `unchecked_alloc_*` AND the rule_id is
           null-deref-class, the structural unchecked-alloc evidence
           directly supports the finding — return EXPLOITABLE.

        4. **Attribute-evidence check (Phase 3-3d):** EXPLOITABLE when
           an attribute observation references a function named in the
           finding's snippet AND the rule_id is kind-relevant.

        Default: UNCERTAIN.
        """
        if result.is_skipped:
            return ValidatorVerdict.UNCERTAIN

        if _finding_in_dead_code(finding, self._repo_root):
            return ValidatorVerdict.NOT_EXPLOITABLE

        if _abort_dominates_finding(finding, result):
            return ValidatorVerdict.NOT_EXPLOITABLE

        if _privileged_capability_dominates(finding, result):
            return ValidatorVerdict.NOT_EXPLOITABLE

        if _fortify_source_blocks_finding(finding, result):
            return ValidatorVerdict.NOT_EXPLOITABLE

        if _downstream_check_suppresses_finding(finding):
            return ValidatorVerdict.NOT_EXPLOITABLE

        if _unchecked_alloc_supports_finding(finding, result):
            return ValidatorVerdict.EXPLOITABLE

        if _hazard_supports_finding(finding, result):
            return ValidatorVerdict.EXPLOITABLE

        snippet = (
            (finding.source.snippet or "")
            + " "
            + (finding.sink.snippet or "")
        )

        for ev in result.attributes:
            if not ev.function_name:
                continue
            if ev.function_name not in snippet:
                continue
            if _rule_id_is_relevant_for_kind(finding.rule_id, ev.kind):
                return ValidatorVerdict.EXPLOITABLE

        return ValidatorVerdict.UNCERTAIN


def _rule_id_is_relevant_for_kind(rule_id: str, kind: str) -> bool:
    """Check whether ``rule_id`` is in the relevance set for ``kind``."""
    return any(rule_id.startswith(prefix)
               for prefix in _KIND_RELEVANT_RULE_PREFIXES.get(kind, ()))


def _rule_id_is_wur_relevant(rule_id: str) -> bool:
    """Back-compat shim — Phase 2 callers / tests."""
    return _rule_id_is_relevant_for_kind(rule_id, KIND_WUR)


# Rule prefixes for which unchecked-allocation evidence directly
# supports the finding. Currently null-deref family — the typical
# manifestation of an unchecked alloc-result is a NULL deref.
_NULL_DEREF_RULE_PREFIXES: Tuple[str, ...] = (
    "cpp/null-dereference",
    "c/null-dereference",
)


def _finding_in_dead_code(finding: Finding, repo_root: Path) -> bool:
    """Compose with PR-4's ``packages.coccinelle.prereqs.gather_prereqs``
    to detect whether the finding's enclosing function is dead code
    (static, defined but not called anywhere in the target).

    Returns True iff:
      * the finding's sink file is C/C++ source
      * `_enclosing_function` resolves the sink to a function name F
      * F is declared `static` (file-local linkage)
      * PR-4 prereqs reports F as defined AND with zero callers

    The `static` requirement is critical: a non-static function whose
    callers happen to live in OTHER files (not in our target subset)
    would otherwise be wrongly flagged as dead. The classic example
    is a kernel driver entry-point function whose only caller is in
    a different translation unit. `static` linkage means the function
    is file-scoped — no callers in this file → genuinely unreachable.

    Skips silently when PR-4 isn't available (minimal install).
    """
    try:
        from packages.coccinelle.prereqs import gather_prereqs
    except ImportError:
        return False

    sink_path = finding.sink.file_path or ""
    sink_line = finding.sink.line or 0
    if not sink_path or not sink_line:
        return False

    # Resolve to absolute for the function-bounds heuristic + cache
    # comparison with PR-4 prereqs output.
    sink_path_abs = sink_path
    if not Path(sink_path).is_absolute():
        sink_path_abs = str((repo_root / sink_path).resolve())

    from packages.source_intel.analyze import _enclosing_function
    finding_fn = _enclosing_function(sink_path_abs, sink_line)
    if not finding_fn:
        return False

    if not _function_is_static(sink_path_abs, finding_fn):
        return False

    # Find the target directory (same heuristic as
    # _target_for_finding — file's parent or build-marker directory).
    target = Path(sink_path_abs).parent
    if not target.is_dir():
        return False

    facts = gather_prereqs(target)
    if facts.is_skipped:
        return False
    # Function must be defined AND have zero callers in the target.
    if not facts.function_exists(finding_fn):
        return False
    if facts.function_has_callers(finding_fn):
        return False
    # Final guard 1: PR-4's function_inventory.cocci only tracks direct
    # `funcname(args)` invocations. It misses function-pointer uses
    # (kernel struct ops vtables: `.mgmt_tx = brcmf_cfg80211_mgmt_tx,`,
    # callback registration: `register_handler(my_handler);`,
    # array-of-callbacks). A static function referenced as a pointer
    # IS reachable — skip the dead-code verdict.
    if _function_referenced_as_pointer(target, finding_fn):
        return False

    # Final guard 2: naming-convention. Kernel code routinely
    # registers handlers via macro concatenation
    # (`PANFROST_IOCTL(SUBMIT, submit, ...)` expands to reference
    # `panfrost_ioctl_submit`); the function name LITERALLY never
    # appears in the source so the pointer-ref guard misses it.
    # Real-target test on Linux 6.18 surfaced this on
    # panfrost_ioctl_submit. Functions whose names match common
    # vtable / callback naming conventions are highly likely to be
    # macro-registered handlers — defer to LLM Stage D rather than
    # claim dead-code.
    if _looks_like_macro_registered_handler(finding_fn):
        return False
    return True


# Naming-convention suffixes/infixes for functions that are commonly
# registered via macros and would have their name produced by token
# concatenation (so the literal name never appears in source).
# Conservative — only suppresses dead-code claim, doesn't change
# other axes.
_MACRO_REGISTERED_SUFFIXES: Tuple[str, ...] = (
    "_ioctl_submit", "_ioctl", "_ioctl_",
    "_show", "_store",
    "_open", "_release", "_read", "_write",
    "_init", "_exit",
    "_probe", "_remove",
    "_suspend", "_resume",
    "_attach", "_detach",
    "_get", "_set",
    "_alloc", "_free",
    "_create", "_destroy",
    "_handler", "_callback", "_op", "_ops",
)


def _looks_like_macro_registered_handler(fn_name: str) -> bool:
    """Heuristic: does the function name end with a suffix that
    suggests it's registered via a macro / ops vtable?

    Surfaced by real-target test on Linux 6.18: `panfrost_ioctl_submit`
    has its name produced by `panfrost_ioctl_##func` macro
    expansion — pointer-ref guard misses it. This is the common
    case across the kernel subsystem driver vocabulary.
    """
    if not fn_name:
        return False
    for suffix in _MACRO_REGISTERED_SUFFIXES:
        if fn_name.endswith(suffix):
            return True
    # Also infixes — common shapes like `*_ioctl_*`.
    for infix in ("_ioctl_", "_callback_", "_handler_"):
        if infix in fn_name:
            return True
    return False


def _function_referenced_as_pointer(
    target: Path, function_name: str
) -> bool:
    """Best-effort: scan ``target`` (file or dir) for non-call uses of
    ``function_name``. Returns True if the name appears in a context
    consistent with function-pointer use (vtable assignment, callback
    registration, address-of, array element).

    Patterns:
      * ``.field = funcname[,;}]``       — struct vtable assignment
      * ``= funcname[,;}]``              — bare initializer
      * ``& funcname\\b``                 — address-of
      * ``( funcname [,)]``              — passed as argument
      * ``\\bfuncname [,;]``              — array element / list

    Conservative file traversal: limited to ``.c`` / ``.h`` / ``.cc``
    / ``.cpp`` / ``.hpp`` to bound cost on noisy targets.
    """
    import re as _re
    fn = _re.escape(function_name)
    # Single regex covering the common pointer-use shapes. Each
    # alternative requires ``function_name`` is NOT followed by ``(``
    # — otherwise it is just a normal call PR-4 would have caught.
    pat = _re.compile(
        r"(?:[.=&,(]\s*" + fn + r"|^\s*" + fn + r")"
        r"(?!\s*\()"  # NOT a call
        r"(?:\s*[,;)}]|\s*$|\s+\w)",
        _re.MULTILINE,
    )
    EXTS = {".c", ".h", ".cc", ".cpp", ".hpp", ".cxx", ".hxx"}
    if target.is_file():
        files = [target]
    else:
        files = [p for p in target.rglob("*") if p.suffix in EXTS]
    for path in files:
        try:
            with open(path, "r", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        # Strip the function's own definition line so we don't
        # match it as a self-reference. Cheap heuristic: skip lines
        # containing both the name AND `(` AND `{` on same line, OR
        # a trailing `(` (signature line). Better: filter in pattern
        # via the `(?!\s*\()` negative lookahead — already done.
        if pat.search(text):
            return True
    return False


def _function_is_static(file_path: str, function_name: str) -> bool:
    """Best-effort: scan ``file_path`` for a line beginning with
    ``static`` and containing ``function_name(``.

    Conservative: returns False when uncertain. Static-detection
    failure ALWAYS keeps a non-static function from being marked
    dead, which is the safe direction (avoids false positives on
    cross-TU-callable functions).
    """
    try:
        with open(file_path, "r", errors="replace") as f:
            text = f.read()
    except OSError:
        return False
    # Match `static [optional return-type tokens] funcname(`
    import re as _re
    pat = _re.compile(
        r"^\s*static\s+(?:[A-Za-z_][A-Za-z0-9_]*\s+|\*\s*)*"
        + _re.escape(function_name) + r"\s*\(",
        _re.MULTILINE,
    )
    return bool(pat.search(text))


def _unchecked_alloc_supports_finding(
    finding: Finding,
    result: SourceIntelResult,
) -> bool:
    """Return True iff axis-3 evidence directly supports an EXPLOITABLE
    verdict on this finding:

    * finding's rule_id is null-deref-class, AND
    * an unchecked-allocation site sits at the finding's source line
      (within a small line-tolerance for column / multi-statement
      mismatches).

    Phase 6a only matches the field-assignment shape (cocci's
    ``unchecked_alloc_field`` rule). Local-variable and nested-field
    shapes wait for axis-3-expansion.
    """
    rid = finding.rule_id or ""
    if not any(rid.startswith(p) for p in _NULL_DEREF_RULE_PREFIXES):
        return False
    if not result.allocations:
        return False

    src_path = finding.source.file_path or ""
    src_line = finding.source.line or 0
    if not src_path or not src_line:
        return False

    src_path_abs = src_path
    if not Path(src_path).is_absolute():
        src_path_abs = str((_DEFAULT_REPO_ROOT / src_path).resolve())

    # Tight tolerance — the cocci match's line should be within a
    # handful of lines of the finding's source. The fixture path
    # (relative) and the cocci-emitted path (absolute) are normalised
    # via the path-resolution above.
    _SRC_LINE_TOLERANCE = 3

    sink_line = finding.sink.line or 0

    for ae in result.allocations:
        alloc_path, alloc_line = ae.location
        if alloc_path != src_path_abs:
            continue
        if abs(alloc_line - src_line) > _SRC_LINE_TOLERANCE:
            continue
        # Interprocedural-NULL-check guard: between the alloc line and
        # the deref line, look for `if (... <varname> ...)` that
        # branches out before the deref. Cocci's intraprocedural
        # `when != !local` clauses miss this shape (the check is via
        # a helper function, not a direct comparison). Suppress the
        # axis-3 EXPLOITABLE claim when we see it.
        var_name = _extract_local_var_from_snippet(finding.source.snippet)
        if var_name and sink_line > alloc_line + 1:
            if _has_interprocedural_check(
                alloc_path, alloc_line, sink_line, var_name,
            ):
                continue
        return True

    return False


_LOCAL_ASSIGN_RE = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z0-9_*\s]*\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*="
)


def _extract_local_var_from_snippet(snippet: Optional[str]) -> Optional[str]:
    """Best-effort: from `p = kstrdup(s, 0);` return `p`."""
    if not snippet:
        return None
    m = _LOCAL_ASSIGN_RE.match(snippet)
    return m.group(1) if m else None


def _has_interprocedural_check(
    file_path: str,
    alloc_line: int,
    sink_line: int,
    var_name: str,
) -> bool:
    """Best-effort: scan lines (alloc_line, sink_line) for
    `if (<expr involving var_name>)` followed by an early-exit
    statement (return/continue/break/goto) within 2 lines.

    This catches the interprocedural-NULL-check shape that cocci's
    intraprocedural `when !=` clauses miss:

        p = kstrdup(...);
        if (validate(p) < 0) return;   ← here
        use(p);

    AND the direct-check shape that survives cocci's `when` clauses
    in unusual layouts:

        p = kstrdup(...);
        if (something(p)) goto out;
        use(p);

    Conservative: only suppresses when the if-condition references
    ``var_name`` AND an early-exit follows within 2 lines. Pure data
    passes (printf(p), strlen(p)) don't match the if-condition
    constraint, so they don't trigger suppression.
    """
    if not file_path or sink_line <= alloc_line + 1:
        return False
    try:
        with open(file_path, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return False

    var_in_if = re.compile(
        r"\bif\s*\([^)]*\b" + re.escape(var_name) + r"\b"
    )
    early_exit = re.compile(r"\b(?:return\b|continue\b|break\b|goto\b)")

    # Lines are 0-indexed in the array; alloc_line/sink_line are 1-indexed.
    start_idx = alloc_line  # first line AFTER the alloc
    end_idx = min(sink_line - 1, len(lines))
    for i in range(start_idx, end_idx):
        if not var_in_if.search(lines[i]):
            continue
        # Found an if (... var ...) — look for early-exit within 2 lines.
        for j in range(i, min(i + 3, len(lines))):
            if early_exit.search(lines[j]):
                return True
    return False


# Memory-corruption rule_id prefixes — findings in these CWE classes
# may have their primitive aborted by an upstream abort-class call.
# CWE-78 / CWE-89 (injection) findings don't benefit from this signal
# because the exploitation primitive doesn't depend on continued
# execution of the C-language process state.
_MEMORY_CORRUPTION_RULE_PREFIXES: Tuple[str, ...] = (
    "cpp/null-dereference",
    "cpp/use-after-free",
    "cpp/double-free",
    "cpp/unbounded-write",
    "cpp/uncontrolled-",
    "c/null-dereference",
)


def _abort_dominates_finding(
    finding: Finding,
    result: SourceIntelResult,
) -> bool:
    """Return True iff axis-2 evidence supports NOT_EXPLOITABLE:

    * finding's rule_id is memory-corruption-class, AND
    * an abort-class call site sits in the same function as the
      finding's sink (Phase 5a same_function grade is enough;
      later phases will require same_path / dominates grade).

    The finding's enclosing function is derived from sink (file, line)
    via the same regex-based heuristic that ``analyze.py`` applies to
    abort sites — both sides use the same logic so attributions match
    when they exist.
    """
    rid = finding.rule_id or ""
    if not any(rid.startswith(p) for p in _MEMORY_CORRUPTION_RULE_PREFIXES):
        return False
    if not result.aborts:
        return False

    sink_path = finding.sink.file_path or ""
    sink_line = finding.sink.line or 0
    if not sink_path:
        return False

    # Normalise sink_path to absolute so it can be compared against
    # the abort's location (which carries the absolute path that
    # analyze passed to spatch). Relative paths in Finding records
    # are resolved against repo root.
    sink_path_abs = sink_path
    if not Path(sink_path).is_absolute():
        sink_path_abs = str((_DEFAULT_REPO_ROOT / sink_path).resolve())

    # Determine the finding's enclosing function (best-effort).
    from packages.source_intel.analyze import _enclosing_function
    finding_fn = _enclosing_function(sink_path_abs, sink_line) if sink_line else None

    # Phase 5a: NOT_EXPLOITABLE requires same-function AND tight line
    # proximity. `same_function` alone is too weak for big functions
    # (kernel functions routinely run 4000+ lines, so an abort
    # somewhere in the function doesn't dominate the bug primitive
    # 3000 lines later). Documented in the abort_proximate.cocci
    # rule header as a known limitation; later grades (`same_path`,
    # `dominates`) computed by axis-2-expansion will drop this
    # proximity requirement.
    _SAME_FUNCTION_LINE_PROXIMITY = 50

    for ab in result.aborts:
        # Require the abort to be in the same file as the finding's
        # sink (cross-file abort isn't proximate for our purposes).
        abort_path, abort_line = ab.location
        if abort_path != sink_path_abs:
            continue
        # Phase 5a grade gate — same_function with line proximity,
        # or any stronger grade (same_path / dominates) when those
        # ship in axis-2-expansion.
        if ab.grade == GRADE_SAME_FUNCTION:
            # Same-function + tight proximity → confident dominance.
            if not sink_line:
                continue
            if abs(abort_line - sink_line) > _SAME_FUNCTION_LINE_PROXIMITY:
                continue
            # Both function names known: must match exactly.
            if finding_fn and ab.enclosing_function:
                if ab.enclosing_function == finding_fn:
                    return True
                continue
            # At least one name unknown — accept on tight proximity
            # alone. The line check (≤50) already filters out the
            # mega-function false positives that motivated this gate.
            return True
        elif ab.grade in (GRADE_SAME_PATH, GRADE_DOMINATES):
            # Stronger grades — function-name check is sufficient
            # without the line-proximity gate (cocci has done the
            # path-dominance work).
            if finding_fn and ab.enclosing_function:
                if ab.enclosing_function == finding_fn:
                    return True

    return False


# =====================================================================
# Axis 4 — capability/privilege dominance
# =====================================================================


# Privileged-capability function names whose successful check implies
# the caller already holds privileges sufficient to do the harm
# directly. When such a check dominates a memory-corruption finding
# in the same function, the bug is reachable ONLY by an attacker who
# already has equivalent power, so the finding contributes nothing
# beyond what the attacker can already do — emit NOT_EXPLOITABLE.
#
# Conservative scope: ``capable``-family alone (Linux LSM check
# against the *current* task). ``ns_capable`` and friends are scoped
# to a namespace — an unprivileged userns admin can hold
# CAP_SYS_ADMIN inside their own ns without root, so they DON'T
# satisfy the "already root-equivalent" requirement.
_PRIVILEGED_CAP_FUNCTIONS: FrozenSet[str] = frozenset({
    "capable",
})

# Capability constants that grant root-equivalent power. Cocci emits
# the cap_function name only — the constant lives in the source line
# itself. We grep the abort site's source line for one of these
# constants.
#
# Membership criterion: hitting this cap MUST already let the attacker
# do arbitrary memory write / arbitrary code execution / kernel module
# load — i.e., subsume the memory-corruption primitive the finding
# claims. Bounded caps (CAP_NET_ADMIN, CAP_MAC_*, CAP_SYS_TIME, …) do
# NOT qualify — a memory-corruption primitive reachable from a bounded
# cap IS a privilege escalation that the finding correctly flags.
#
# Bug-survey lesson 2026-05-16: CAP_NET_ADMIN was originally in this
# set; removed after corpus fixture `cap_net_admin-gated-overflow`
# leaked as NOT_EXPLOITABLE when it should have stayed UNCERTAIN.
# CAP_NET_ADMIN grants network-stack admin only; doesn't let you
# load kernel modules or write arbitrary kmem.
_PRIVILEGED_CAP_CONSTANTS: FrozenSet[str] = frozenset({
    "CAP_SYS_ADMIN",      # nearly all FS / mount / namespace control
    "CAP_SYS_MODULE",     # arbitrary kernel-module load → arbitrary code
    "CAP_SYS_RAWIO",      # arbitrary device-mem access via /dev/mem
    "CAP_SYS_BOOT",       # kexec → arbitrary kernel boot
    "CAP_DAC_OVERRIDE",   # bypass file DAC — root-equivalent in practice
    "CAP_DAC_READ_SEARCH",  # similar bypass for reads
})


def _privileged_capability_dominates(
    finding: Finding,
    result: SourceIntelResult,
) -> bool:
    """Return True iff axis-4 evidence supports NOT_EXPLOITABLE:

    * finding's rule_id is memory-corruption-class, AND
    * a ``capable(CAP_X)`` call sits in the same function as the
      finding's sink (Phase 8 same_function grade is enough), AND
    * the capability constant on that line is in the privileged set
      (CAP_SYS_ADMIN / equivalent).

    Same proximity gate as axis-2 abort-dominance: ±50 lines from
    the finding's sink to filter mega-function false positives.
    """
    rid = finding.rule_id or ""
    if not any(rid.startswith(p) for p in _MEMORY_CORRUPTION_RULE_PREFIXES):
        return False
    if not result.capabilities:
        return False

    sink_path = finding.sink.file_path or ""
    sink_line = finding.sink.line or 0
    if not sink_path:
        return False

    sink_path_abs = sink_path
    if not Path(sink_path).is_absolute():
        sink_path_abs = str((_DEFAULT_REPO_ROOT / sink_path).resolve())

    from packages.source_intel.analyze import _enclosing_function
    finding_fn = (
        _enclosing_function(sink_path_abs, sink_line)
        if sink_line else None
    )

    _SAME_FUNCTION_LINE_PROXIMITY = 50

    for cap in result.capabilities:
        if cap.cap_function not in _PRIVILEGED_CAP_FUNCTIONS:
            continue
        cap_path, cap_line = cap.location
        if cap_path != sink_path_abs:
            continue
        if cap.grade == GRADE_SAME_FUNCTION:
            if not sink_line:
                continue
            if abs(cap_line - sink_line) > _SAME_FUNCTION_LINE_PROXIMITY:
                continue
            if finding_fn and cap.enclosing_function:
                if cap.enclosing_function != finding_fn:
                    continue
        elif cap.grade in (GRADE_SAME_PATH, GRADE_DOMINATES):
            if finding_fn and cap.enclosing_function:
                if cap.enclosing_function != finding_fn:
                    continue
        else:
            continue
        # Final filter: the capability constant on this line must be
        # privileged. We read the source line and look for one of the
        # privileged constants.
        if not _line_uses_privileged_cap(cap_path, cap_line):
            continue
        return True

    return False


def _line_uses_privileged_cap(file_path: str, line_no: int) -> bool:
    """Read ``file_path`` line ``line_no`` and check whether any
    privileged capability constant appears in it.

    Best-effort: capability checks under #ifdef may not reflect the
    actual build, and a mock capability constant in test code could
    spuriously match. Scope is bounded by upstream filters
    (function-name + memory-corruption rule_id + line proximity).
    """
    try:
        with open(file_path, "r", errors="replace") as f:
            for i, line in enumerate(f, 1):
                if i == line_no:
                    return any(c in line for c in _PRIVILEGED_CAP_CONSTANTS)
                if i > line_no:
                    return False
    except OSError:
        return False
    return False


# =====================================================================
# Axis 6 consumer — build flags
# =====================================================================


# glibc functions intercepted by FORTIFY_SOURCE: when level >= 2,
# the compiler/linker rewrites these to runtime-checked variants
# that abort() on bound violation. List drawn from glibc's
# bits/string_fortified.h, bits/stdio2.h, bits/unistd.h.
#
# Conservative set — covers the common write-class calls that
# CodeQL's cpp/unbounded-write rule typically flags. Known FORTIFY
# limitations:
#   * Only intercepts when destination size is compile-known
#     (e.g. fixed array `char buf[N]`). Variable-size dest passes
#     through unchecked. We don't try to reason about that — false
#     negatives only (we'd skip suppression when FORTIFY can't help).
#   * FORTIFY=3 (gcc 12+, glibc 2.34+) extends coverage; we treat
#     >=2 as "intercept" since the level-2 set is the stable union
#     covered by all 2/3 implementations.
_FORTIFIED_WRITE_CALLS: FrozenSet[str] = frozenset({
    "memcpy", "memmove", "memset", "mempcpy",
    "strcpy", "strncpy", "strcat", "strncat", "stpcpy", "stpncpy",
    "sprintf", "snprintf", "vsprintf", "vsnprintf",
    "gets", "fgets", "fgets_unlocked",
    "read", "pread", "recv", "recvfrom",
    "wcscpy", "wcsncpy", "wcscat", "wcsncat",
    "wmemcpy", "wmemmove", "wmemset",
    "swprintf", "vswprintf",
})


def _fortify_source_blocks_finding(
    finding: Finding,
    result: SourceIntelResult,
) -> bool:
    """Return True iff axis-6 evidence supports NOT_EXPLOITABLE:

    * build_flags has fortify_source_level >= 2, AND
    * finding's rule_id is unbounded-write-class, AND
    * the sink line names a FORTIFY-intercepted call.

    The sink-line snippet check uses a token boundary check to
    avoid spurious matches on substrings (e.g. ``my_strcpy`` would
    NOT match ``strcpy``).
    """
    bf = result.build_flags
    if bf is None:
        return False
    level = bf.fortify_source_level
    if level is None:
        return False
    # Source-aware threshold:
    #   * glibc: levels 1/2/3 distinct; level 1 only intercepts a
    #     subset (mostly read-class). Require >= 2 to assume the
    #     full intercept list applies.
    #   * kernel: CONFIG_FORTIFY_SOURCE doesn't tier — `_from_kconfig`
    #     maps "enabled" to level=1 by convention, but it intercepts
    #     the same write-class calls as glibc level 2. Accept level
    #     >= 1 when source is kconfig.
    if bf.source == "kconfig":
        if level < 1:
            return False
    elif level < 2:
        return False

    rid = finding.rule_id or ""
    if not rid.startswith(("cpp/unbounded-write", "c/unbounded-write")):
        return False

    snippet = (finding.sink.snippet or "")
    if not snippet:
        return False

    # Token-boundary scan: split on non-identifier chars.
    tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", snippet))
    if not (tokens & _FORTIFIED_WRITE_CALLS):
        return False

    # Destination-classifier guard: FORTIFY only intercepts when the
    # destination's size is compile-known via __builtin_object_size().
    # Static arrays (`char buf[N]`) qualify; pointers to dynamic memory
    # (`char *buf = malloc(want)`) DON'T — FORTIFY passes them through
    # unchecked. Without this guard the verdict policy over-suppresses
    # findings on malloc'd destinations, which is the common case in
    # most userspace.
    if _fortified_dest_is_variable_size(finding):
        return False
    return True


_DYNAMIC_ALLOCATORS_PATTERN = re.compile(
    r"\b(?:malloc|calloc|realloc|reallocarray|"
    r"kmalloc|kzalloc|kcalloc|kmalloc_array|krealloc|"
    r"kvmalloc|kvzalloc|kvmalloc_node|"
    r"vmalloc|vzalloc|vmalloc_node|"
    r"alloca|__builtin_alloca|"
    r"strdup|strndup|kstrdup|kstrdup_const|kstrndup|"
    r"kmemdup|kmemdup_nul)\s*\("
)


def _fortified_dest_is_variable_size(finding: Finding) -> bool:
    """Best-effort: extract the destination variable from the sink
    snippet (first identifier-argument of the fortified call) and
    scan the source file's enclosing function body for a line
    declaring or assigning ``dest = <dynamic-allocator>(...)``.

    Returns True iff such a line is found AND it lies between the
    function start and the sink — i.e., the destination IS pointer-to-
    heap, FORTIFY can't intercept it.

    Conservative on failure: returns False when we can't extract a
    dest var or read the file, leaving the verdict policy unchanged.
    """
    snippet = finding.sink.snippet or ""
    # Match the first identifier inside the call's argument list:
    # `strcpy(buf, src)` → "buf"; `memcpy(dst, src, n)` → "dst"
    m = re.search(
        r"[A-Za-z_][A-Za-z0-9_]*\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\b",
        snippet,
    )
    if not m:
        return False
    dest_var = m.group(1)

    sink_path = finding.sink.file_path or ""
    sink_line = finding.sink.line or 0
    if not sink_path or not sink_line:
        return False

    sink_path_abs = sink_path
    if not Path(sink_path).is_absolute():
        sink_path_abs = str((_DEFAULT_REPO_ROOT / sink_path).resolve())

    try:
        with open(sink_path_abs, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return False

    # Scope: scan up to 200 lines before the sink (typical function
    # body); we don't have function-bounds info here so use a bounded
    # window. Look for `dest_var = <dyn-alloc>(`.
    assign_pat = re.compile(
        r"\b" + re.escape(dest_var) + r"\s*=\s*\(?\s*[^=;]*?"
        + _DYNAMIC_ALLOCATORS_PATTERN.pattern[:-2] + r"\("
    )
    start = max(0, sink_line - 200)
    end = min(sink_line, len(lines))
    for i in range(start, end):
        if assign_pat.search(lines[i]):
            return True
    return False


# =====================================================================
# Axis 8 — validation-after-overflow (downstream-check suppressor)
# =====================================================================


# Rule prefixes where a downstream size/range check meaningfully
# suppresses the finding. Size-arithmetic CWEs (uncontrolled-alloc-
# size, unbounded-write) are correctly suppressed when a check on
# the size variable runs between bug-site and use-site, with an
# early-exit. NOT applicable to null-deref / UAF / double-free.
_DOWNSTREAM_CHECK_RULE_PREFIXES: Tuple[str, ...] = (
    "cpp/uncontrolled-",       # uncontrolled-allocation-size etc.
    "cpp/unbounded-write",
    "c/uncontrolled-",
    "c/unbounded-write",
)


def _downstream_check_suppresses_finding(finding: Finding) -> bool:
    """Return True iff axis-8 (validation-after-overflow) suppresses
    the finding.

    Pattern: the sink-line assigns a variable; a downstream
    ``if (...var...)`` with an early-exit (return/goto/continue/break)
    runs before any consumer of the var. The classic shape:

        int size = nex * sizeof(xfs_bmbt_rec_t);
        if (unlikely(size < 0 || size > MAX_OK)) return -ERR;
        memcpy(buf, src, size);

    Without this axis the verdict policy emits UNCERTAIN; with it
    the downstream guard is recognized and the verdict goes
    NOT_EXPLOITABLE (the surface arithmetic-overflow shape is
    real but mitigated by the in-function check).

    Real-target audit motivated this axis: 3 of 10 audited Linux
    int-overflow findings (xfs_inode_fork.c, hid-core.c, r100.c)
    have a downstream guard that source_intel was missing.
    """
    rid = finding.rule_id or ""
    if not any(rid.startswith(p) for p in _DOWNSTREAM_CHECK_RULE_PREFIXES):
        return False

    var_name = _extract_local_var_from_snippet(finding.sink.snippet)
    if not var_name:
        return False

    sink_path = finding.sink.file_path or ""
    sink_line = finding.sink.line or 0
    if not sink_path or not sink_line:
        return False

    sink_path_abs = sink_path
    if not Path(sink_path).is_absolute():
        sink_path_abs = str((_DEFAULT_REPO_ROOT / sink_path).resolve())

    try:
        with open(sink_path_abs, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return False

    # Scan forward up to 30 lines (typical alloc-then-validate-then-use
    # window). For each line containing `if (... var ...)`, look for an
    # early-exit within the next 5 lines. Require a relational
    # operator (`<`, `>`, `<=`, `>=`) on the same line — pure
    # `if (!var)` / `if (var == NULL)` is an allocator-success
    # check, not a size-overflow validation, and is handled by
    # axis 3 / axis 5 not by this axis.
    # Require the relational comparison to be on `var` itself, not
    # on a field of var (`var->field == 0` is checking the *value*
    # at the pointer, not the pointer's safety). Real-target test on
    # s390/kvm/interrupt.c:3337 surfaced this — axis-8 was wrongly
    # suppressing because `if (gaite->count == 0)` matched the
    # var-in-if regex.
    var_rel_re = re.compile(
        r"\b" + re.escape(var_name) + r"\s*(?:[<>]=?|==|!=)"
    )
    var_in_if = re.compile(
        r"\bif\s*\(.*?" + var_rel_re.pattern,
    )
    has_relational = re.compile(r"[<>](?!=)|[<>]=")
    early_exit = re.compile(r"\b(?:return\b|continue\b|break\b|goto\b)")

    start = sink_line  # next line after sink (0-indexed; sink_line itself excluded)
    end = min(sink_line + 30, len(lines))
    for i in range(start, end):
        if not var_in_if.search(lines[i]):
            continue
        # Require a relational comparison on this line. Pure-NULL
        # checks fall through to other axes.
        if not has_relational.search(lines[i]):
            continue
        # Look for early-exit INSIDE the if-body. Track brace depth
        # from the if-line. Stop scanning once the if-body closes —
        # a `return 0;` at function end is NOT an early-exit out of
        # the if. The xfs canonical case has 7 lines of warning
        # calls between `if (...)` and `return`, so use a generous
        # 20-line ceiling on the search.
        depth = 0
        seen_open_brace = False
        max_scan = min(i + 20, len(lines))
        for j in range(i, max_scan):
            line = lines[j]
            # Strip C-style comments before early-exit scanning —
            # otherwise `/* no return */` falsely matches `return`.
            stripped = _COMMENT_STRIP_RE.sub("", line)
            stripped = _LINE_COMMENT_STRIP_RE.sub("", stripped)
            # Single-line if shape: `if (cond) return -1;` — the
            # early-exit is on the same line, no `{` ever appears.
            # Match it before brace tracking advances.
            if early_exit.search(stripped):
                return True
            # Track brace depth ignoring chars inside strings/chars is
            # not done — depth may be slightly wrong on lines with
            # string literals containing braces. Acceptable for the
            # bug-class we're catching (kernel int-overflow guards
            # don't contain string-literal braces in practice).
            for ch in stripped:
                if ch == "{":
                    depth += 1
                    seen_open_brace = True
                elif ch == "}":
                    depth -= 1
            if seen_open_brace and depth <= 0:
                break
    return False


_COMMENT_STRIP_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_STRIP_RE = re.compile(r"//.*$", re.MULTILINE)


# =====================================================================
# Axis 7 — hazardous code patterns
# =====================================================================


# Hazard-kind → relevant CWE rule_id prefixes. Each kind only
# strengthens findings whose CWE class matches the hazard's
# threat-model fit.
_HAZARD_KIND_RELEVANT_RULES: Dict[str, Tuple[str, ...]] = {
    "deprecated_func": (
        "cpp/unbounded-write",
        "cpp/uncontrolled-",
        "c/unbounded-write",
    ),
    "signed_alloc": (
        "cpp/uncontrolled-allocation-size",
        "cpp/uncontrolled-",
        "c/uncontrolled-",
    ),
}


def _hazard_supports_finding(
    finding: Finding,
    result: SourceIntelResult,
) -> bool:
    """Return True iff axis-7 hazard evidence directly supports an
    EXPLOITABLE verdict on this finding.

    Required: a hazard call site at (or within ±3 lines of) the
    finding's sink AND the finding's rule_id is in the hazard
    kind's relevance set.

    Tight tolerance — the structural-hazard-then-bug-finding
    coincidence is strongest when both point to the same line; ±3
    line tolerance covers multi-line snippet shifts.
    """
    if not result.hazards:
        return False

    sink_path = finding.sink.file_path or ""
    sink_line = finding.sink.line or 0
    if not sink_path or not sink_line:
        return False

    sink_path_abs = sink_path
    if not Path(sink_path).is_absolute():
        sink_path_abs = str((_DEFAULT_REPO_ROOT / sink_path).resolve())

    rid = finding.rule_id or ""

    for hz in result.hazards:
        relevant = _HAZARD_KIND_RELEVANT_RULES.get(hz.kind, ())
        if not relevant or not any(rid.startswith(p) for p in relevant):
            continue
        hz_path, hz_line = hz.location
        if hz_path != sink_path_abs:
            continue
        if abs(hz_line - sink_line) > 3:
            continue
        return True

    return False
