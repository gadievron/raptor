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
from typing import Any, Dict, FrozenSet, Optional, Tuple

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

        if _privilege_back_walk_suppresses(
            finding, result, self._repo_root,
        ):
            return ValidatorVerdict.NOT_EXPLOITABLE

        if _fortify_source_blocks_finding(finding, result):
            return ValidatorVerdict.NOT_EXPLOITABLE

        if _stack_protector_suppresses_finding(finding, result):
            return ValidatorVerdict.NOT_EXPLOITABLE

        if _downstream_check_suppresses_finding(finding):
            return ValidatorVerdict.NOT_EXPLOITABLE

        if _unchecked_alloc_supports_finding(finding, result):
            return ValidatorVerdict.EXPLOITABLE

        if _hazard_supports_finding(finding, result):
            return ValidatorVerdict.EXPLOITABLE

        if _double_free_supports_finding(finding, result):
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
            if not _rule_id_is_relevant_for_kind(finding.rule_id, ev.kind):
                continue
            # Adversarial-tolerance guard for axis-1 WUR: refuse to
            # fire EXPLOITABLE if the annotated function's body is
            # trivial (no-op return-const) or returns the same
            # literal on every path. Catches planted-WUR shapes
            # the design's exit criterion identifies.
            #
            # Sophisticated adversaries with non-trivial bodies
            # returning varying-but-meaningless values aren't
            # detectable structurally — that's Stage D LLM's job.
            # See README adversarial-tolerance section.
            if ev.kind == KIND_WUR:
                if not _wur_annotation_trustworthy(
                    ev.location[0], ev.function_name,
                ):
                    continue
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
    # Two-line "separate err var" pattern:
    #   err = <call>(<...var...>);
    #   if (err) <early-exit>;
    # The if-cond contains `err`, not `var`, so the var_in_if
    # regex misses. Catch this shape by scanning for an assignment
    # whose RHS call references `var`, then checking subsequent
    # lines for `if (<assigned-id>) <exit>`.
    call_with_var = re.compile(
        r"^\s*([A-Za-z_]\w*)\s*=\s*\w+\s*\([^)]*\b"
        + re.escape(var_name) + r"\b"
    )

    # Lines are 0-indexed in the array; alloc_line/sink_line are 1-indexed.
    start_idx = alloc_line  # first line AFTER the alloc
    end_idx = min(sink_line - 1, len(lines))
    for i in range(start_idx, end_idx):
        if var_in_if.search(lines[i]):
            # Found an if (... var ...) — look for early-exit within 2 lines.
            for j in range(i, min(i + 3, len(lines))):
                if early_exit.search(lines[j]):
                    return True
        m = call_with_var.search(lines[i])
        if m:
            assigned = m.group(1)
            if_with_assigned = re.compile(
                r"\bif\s*\([^)]*\b" + re.escape(assigned) + r"\b"
            )
            # Look for `if (assigned ...)` within next 5 lines,
            # then early-exit within 3 lines after that.
            for j in range(i + 1, min(i + 6, len(lines))):
                if not if_with_assigned.search(lines[j]):
                    continue
                for k in range(j, min(j + 3, len(lines))):
                    if early_exit.search(lines[k]):
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

    # Per-grade proximity gate:
    #   * SAME_FUNCTION (default): ±50 line proximity — abort
    #     somewhere in the function isn't enough on its own (kernel
    #     functions routinely run thousands of lines).
    #   * SAME_PATH (abort inside a conditional branch at depth>1):
    #     ±300 line proximity — abort is provably on at least one
    #     path; could still be a different branch from the bug.
    #   * DOMINATES (abort at depth=1, no preceding return/goto):
    #     no proximity gate — abort runs on every path from
    #     function entry to its line, so anything in the same
    #     function after the abort line is dominated.
    _PROXIMITY_BY_GRADE: Dict[str, Optional[int]] = {
        GRADE_SAME_FUNCTION: 50,
        GRADE_SAME_PATH: 300,
        GRADE_DOMINATES: None,  # no proximity gate
    }

    for ab in result.aborts:
        # Require the abort to be in the same file as the finding's
        # sink (cross-file abort isn't proximate for our purposes).
        abort_path, abort_line = ab.location
        if abort_path != sink_path_abs:
            continue
        proximity_gate = _PROXIMITY_BY_GRADE.get(
            ab.grade, _SAME_FUNCTION_LINE_PROXIMITY_DEFAULT
        )
        if proximity_gate is not None:
            if not sink_line:
                continue
            if abs(abort_line - sink_line) > proximity_gate:
                continue
        # Function-name match — both must agree when both known.
        # DOMINATES grade further requires the abort to be ABOVE
        # the sink (an abort BELOW the bug can't dominate it).
        if finding_fn and ab.enclosing_function:
            if ab.enclosing_function != finding_fn:
                continue
        if ab.grade == GRADE_DOMINATES and sink_line:
            if abort_line >= sink_line:
                # Abort is at or below the sink → doesn't dominate.
                continue
        return True

    return False


_SAME_FUNCTION_LINE_PROXIMITY_DEFAULT = 50


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

    # Per-grade proximity gate — same shape as axis-2 abort:
    #   * SAME_FUNCTION (default): ±50 line proximity.
    #   * SAME_PATH (inside conditional branch): ±300 lines.
    #   * DOMINATES (depth=1, no preceding return): no gate;
    #     additionally requires cap_line < sink_line (a cap below
    #     the bug can't dominate it).
    proximity_by_grade: Dict[str, Optional[int]] = {
        GRADE_SAME_FUNCTION: 50,
        GRADE_SAME_PATH: 300,
        GRADE_DOMINATES: None,
    }

    for cap in result.capabilities:
        if cap.cap_function not in _PRIVILEGED_CAP_FUNCTIONS:
            continue
        cap_path, cap_line = cap.location
        if cap_path != sink_path_abs:
            continue
        proximity_gate = proximity_by_grade.get(cap.grade, 50)
        if proximity_gate is not None:
            if not sink_line:
                continue
            if abs(cap_line - sink_line) > proximity_gate:
                continue
        # Function-name match required when both known.
        if finding_fn and cap.enclosing_function:
            if cap.enclosing_function != finding_fn:
                continue
        # DOMINATES additionally requires cap_line < sink_line.
        if cap.grade == GRADE_DOMINATES and sink_line:
            if cap_line >= sink_line:
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


# =====================================================================
# Axis 4 expansion — 1-hop privilege back-walk
# =====================================================================


# Default depth limit for the privilege back-walk. 3 hops covers the
# common kernel call shapes (syscall → ioctl handler → subsystem
# helper → bug primitive); deeper walks bring diminishing returns and
# rising risk of over-suppression on dense call-graphs. Cap at 5 in
# the public API to keep walk cost bounded even with operator override.
_PRIV_BACK_WALK_DEFAULT_DEPTH = 3
_PRIV_BACK_WALK_MAX_DEPTH = 5


def _privilege_back_walk_suppresses(
    finding: Finding,
    result: SourceIntelResult,
    repo_root: Path,
    *,
    max_depth: int = _PRIV_BACK_WALK_DEFAULT_DEPTH,
) -> bool:
    """Return True iff every call path reaching the finding's
    enclosing function (within ``max_depth`` hops) passes through a
    privileged ``capable()`` check.

    Multi-hop scope (PR3 of Phase B): walks the inverted call graph
    via PR-4 prereqs (``packages.coccinelle.prereqs:function_inventory``);
    at each hop the caller's body is checked for a
    ``capable(CAP_<PRIVILEGED>)`` call. A path is "gated" when the
    walk encounters a privileged capability in some caller along the
    path before either depth-limit or a leaf is reached.

    Suppression requires **every** call path to be gated within
    ``max_depth``. If any path:
      * reaches a leaf (caller with no callers — likely an entry
        point) without seeing a gate, OR
      * exhausts ``max_depth`` without seeing a gate, OR
      * contains a caller whose enclosing function cannot be
        determined,
    the back-walk returns False (do NOT suppress; at least one
    unprivileged path exists, or we can't prove otherwise).

    ``max_depth`` is clamped at :data:`_PRIV_BACK_WALK_MAX_DEPTH`
    to bound walk cost on dense call-graphs.

    Cycle-safe: visited set prevents infinite recursion on mutually-
    recursive callers.

    Limitations:
      * No CFG-aware "call site is downstream of capable()" check —
        caller HAS capable() somewhere in its body is enough. Could
        over-suppress when the caller has multiple branches and only
        one is gated. Same limitation as the 1-hop version.
      * No support for indirect calls (function pointers / ops
        vtables / macro-registered handlers) — PR-4's
        ``function_inventory`` cocci doesn't see them.
      * Cap-set is the conservative root-equivalent set in
        :data:`_PRIVILEGED_CAP_CONSTANTS`; userspace namespace caps
        (CAP_NET_ADMIN, CAP_SYS_NICE, …) intentionally don't count.
    """
    rid = finding.rule_id or ""
    if not any(rid.startswith(p) for p in _MEMORY_CORRUPTION_RULE_PREFIXES):
        return False

    try:
        from packages.coccinelle.prereqs import gather_prereqs
    except ImportError:
        return False

    sink_path = finding.sink.file_path or ""
    sink_line = finding.sink.line or 0
    if not sink_path or not sink_line:
        return False

    sink_path_abs = sink_path
    if not Path(sink_path).is_absolute():
        sink_path_abs = str((_DEFAULT_REPO_ROOT / sink_path).resolve())

    from packages.source_intel.analyze import _enclosing_function
    finding_fn = _enclosing_function(sink_path_abs, sink_line)
    if not finding_fn:
        return False

    target = Path(sink_path_abs).parent
    if not target.is_dir():
        return False

    facts = gather_prereqs(target)
    if facts.is_skipped:
        return False

    callers = facts.callers_of(finding_fn)
    if not callers:
        # No callers seen — finding function may be a top-level
        # entry. In-function axis-4 handles entry-level checks.
        return False

    effective_depth = max(1, min(max_depth, _PRIV_BACK_WALK_MAX_DEPTH))

    # For each direct call site, find its enclosing function. The
    # path through that caller is "gated" iff the caller itself has
    # a privileged cap, OR (recursively) every path to that caller
    # within remaining depth is gated. If any direct caller's path
    # isn't gated, return False — at least one ungated path exists.
    visited = {finding_fn}
    for call_file, call_line in callers:
        caller_fn = _enclosing_function(call_file, call_line)
        if not caller_fn:
            return False
        if not _path_is_gated(
            caller_fn, facts, result,
            remaining_depth=effective_depth - 1,
            visited=visited,
        ):
            return False
    return True


def _path_is_gated(
    fn_name: str,
    facts: Any,
    result: SourceIntelResult,
    *,
    remaining_depth: int,
    visited: FrozenSet[str],
) -> bool:
    """Multi-hop helper: True iff every call path reaching ``fn_name``
    (within ``remaining_depth`` further hops) passes through a
    privileged capability check.

    Termination cases (visited in order):
      1. Cycle / already-visited (``fn_name in visited``) → False.
         Cycles can't be "gated" without an entry — bail.
      2. ``fn_name`` itself contains a privileged ``capable()`` →
         True. Gate found, stop expanding this branch.
      3. Depth exhausted (``remaining_depth == 0``) → False.
         Could not prove gating within budget; conservative.
      4. No callers (leaf) → False. ``fn_name`` is an entry point;
         path is ungated.
      5. Otherwise: recurse on every direct caller; True iff all
         caller paths are themselves gated.
    """
    if fn_name in visited:
        return False
    if _function_has_privileged_cap(fn_name, result):
        return True
    if remaining_depth <= 0:
        return False
    callers = facts.callers_of(fn_name)
    if not callers:
        return False
    next_visited = visited | {fn_name}
    from packages.source_intel.analyze import _enclosing_function
    for call_file, call_line in callers:
        caller_fn = _enclosing_function(call_file, call_line)
        if not caller_fn:
            return False
        if not _path_is_gated(
            caller_fn, facts, result,
            remaining_depth=remaining_depth - 1,
            visited=next_visited,
        ):
            return False
    return True


def _function_has_privileged_cap(
    fn_name: str,
    result: SourceIntelResult,
) -> bool:
    """Check if ``fn_name`` has a privileged ``capable(CAP_X)`` call
    site somewhere in its body.

    Uses ``result.capabilities`` (already-cocci-detected capability
    sites) + ``_line_uses_privileged_cap`` to verify the constant
    on the matched line is in ``_PRIVILEGED_CAP_CONSTANTS``.
    """
    for cap in result.capabilities:
        if cap.enclosing_function != fn_name:
            continue
        if cap.cap_function not in _PRIVILEGED_CAP_FUNCTIONS:
            continue
        cap_path, cap_line = cap.location
        if _line_uses_privileged_cap(cap_path, cap_line):
            return True
    return False


# =====================================================================
# Axis 1 adversarial-tolerance — WUR-annotation trust check
# =====================================================================


def _wur_annotation_trustworthy(file_path: str, function_name: str) -> bool:
    """Return True iff the WUR annotation on ``function_name`` is
    structurally trustworthy enough to drive an EXPLOITABLE verdict.

    Two-layer adversarial defense:

      1. **Triviality check** — locate the function's definition; if
         the body has ≤2 statements, the function is a no-op and the
         WUR annotation is suspect. Catches naive `return 0;` plants.

      2. **Return-value constancy** — scan all `return ...;` statements
         in the function body. If they're all the same literal
         constant (`return 0;`, `return -1;`, `return NULL;`), the
         return value carries no caller-actionable information.
         Catches medium-difficulty plants with dead branches.

    Returns False (annotation untrustworthy) when EITHER check fails;
    True (trust the annotation) when both pass.

    Conservative on failure: file unreadable or function definition
    not found → returns True (preserve existing verdict behavior).

    Known residual gap: sophisticated adversaries with non-trivial
    bodies returning varying-but-meaningless values aren't
    detectable structurally — that requires semantic understanding
    of what the return value MEANS to callers. Stage D LLM is the
    intended defense layer. Documented in README adversarial-
    tolerance section.
    """
    if not file_path or not function_name:
        return True

    # Tree-sitter-backed body extraction via inventory (preferred).
    # Falls back to the regex extractor when no inventory is cached
    # for the file's target dir (e.g. corpus-fixture lookups, tests
    # that pass synthetic file_paths). The regex path is robust on
    # standard ANSI C but historically misses pointer-return funcs,
    # split-type decls, and multi-line arg lists — all handled by
    # the inventory's tree-sitter parser.
    body_lines = _function_body_via_inventory(file_path, function_name)
    if body_lines is None:
        try:
            with open(file_path, "r", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return True

        fn_open_line = _find_function_definition_open(
            lines, function_name,
        )
        if fn_open_line is None:
            # No definition found — can't check body. Conservative: trust.
            return True

        body_lines, _ = _extract_function_body(lines, fn_open_line)
        if not body_lines:
            return True

    # Triviality check: count non-blank, non-comment, non-brace
    # statement-bearing lines.
    statement_count = _count_statements(body_lines)
    if statement_count <= 2:
        return False  # trivial body — don't trust WUR

    # Return-value constancy check: scan all `return X;` patterns.
    # Only suspect when EVERY return is a LITERAL (digit / NULL /
    # nullptr / hex) AND they're all the same. A return like
    # `return r;` (variable) is NOT a literal — caller might still
    # need to inspect it, so the WUR annotation could be legitimate.
    return_values = _extract_return_values(body_lines)
    if return_values:
        all_literal_same = (
            all(_is_literal_const(v) for v in return_values)
            and len(set(return_values)) == 1
        )
        if all_literal_same:
            return False

    return True


_LITERAL_CONST_RE = re.compile(
    r"^\s*(?:"
    r"-?\d+[uUlL]*"          # decimal int (signed/unsigned/long)
    r"|0[xX][0-9a-fA-F]+[uUlL]*"  # hex
    r"|NULL"
    r"|nullptr"
    r"|\(void\s*\*\s*\)\s*0"     # (void *)0
    r")\s*$"
)


def _is_literal_const(value: str) -> bool:
    """Return True if ``value`` (a stripped return-expression) is a
    literal constant — digit / hex / NULL / nullptr / (void *)0.
    `return r;` where r is a variable returns False.
    """
    return bool(_LITERAL_CONST_RE.match(value))


def _function_body_via_inventory(
    file_path: str, function_name: str,
) -> Optional[list]:
    """Tree-sitter-backed body extraction via the cached inventory
    populated by :func:`packages.source_intel.analyze.analyze`.

    Returns the body lines (``line_start .. line_end`` slice of the
    file, inclusive of signature) as a list of strings, or ``None``
    when:
      * no inventory is cached for the file's target dir, or
      * the inventory doesn't contain a function with this name in
        this file, or
      * the file can't be read.

    Caller falls back to the regex-based
    :func:`_find_function_definition_open` + :func:`_extract_function_body`
    pipeline on ``None``.

    Note: signature lines (e.g. ``static char *``, ``foo(args)``,
    ``{``) are included in the returned slice. The downstream
    triviality + return-value heuristics tolerate them — signature
    lines don't end in ``;`` and don't contain ``return`` so they
    contribute zero to the counts.
    """
    from packages.source_intel.analyze import _lookup_cached_inventory
    inv, target_dir = _lookup_cached_inventory(file_path)
    if inv is None:
        return None
    try:
        from pathlib import Path
        rel = str(Path(file_path).resolve().relative_to(target_dir))
    except (ValueError, OSError):
        return None
    # Find file record + named function item.
    file_record = None
    for fr in inv.get("files", []):
        if fr.get("path") == rel:
            file_record = fr
            break
    if file_record is None:
        return None
    for item in file_record.get("items") or []:
        if not isinstance(item, dict):
            continue
        if item.get("kind") not in (None, "function"):
            continue
        if item.get("name") != function_name:
            continue
        line_start = item.get("line_start")
        line_end = item.get("line_end")
        if not isinstance(line_start, int) or line_start <= 0:
            continue
        if not isinstance(line_end, int) or line_end < line_start:
            continue
        try:
            with open(file_path, "r", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return None
        # Convert inventory 1-indexed inclusive range → 0-indexed slice.
        if line_end > len(lines):
            line_end = len(lines)
        return lines[line_start - 1: line_end]
    return None


_FN_DEF_OPEN_RE = re.compile(
    r"^\s*(?:[A-Za-z_][A-Za-z_0-9*\s]*?\s+\*?\s*)?"  # optional return type
    r"(?P<name>[A-Za-z_][A-Za-z_0-9]*)\s*\("
)


def _find_function_definition_open(
    lines: list, function_name: str,
) -> Optional[int]:
    """Find the line where ``function_name``'s definition opens
    (line containing `func_name(args) {` or where `{` is on the
    next line). Returns 0-indexed line index, or None if not found.

    A definition is distinguished from a declaration by the presence
    of `{` on or after the function name (within a few lines). A
    declaration ends with `;` on the same line.
    """
    for i, line in enumerate(lines):
        m = _FN_DEF_OPEN_RE.match(line)
        if not m or m.group("name") != function_name:
            continue
        # Walk forward looking for `{` (definition) or `;` (declaration).
        # Strip comments first — `int foo(void) /* ... ; ... */` has `;`
        # in the comment but is still a definition.
        for j in range(i, min(i + 5, len(lines))):
            stripped = re.sub(r"/\*.*?\*/", "", lines[j], flags=re.DOTALL)
            stripped = re.sub(r"//.*$", "", stripped, flags=re.MULTILINE)
            if "{" in stripped:
                return j
            if ";" in stripped and "{" not in stripped:
                # Declaration, not definition — skip this match.
                break
    return None


def _extract_function_body(
    lines: list, fn_open_line: int,
) -> Tuple[list, int]:
    """Given the line index of a function-definition opener (line
    containing `{`), extract the body lines (between `{` and
    matching `}`). Returns (body_lines_list, close_line_index).
    """
    depth = 0
    body = []
    seen_open = False
    for i in range(fn_open_line, len(lines)):
        line = lines[i]
        for ch in line:
            if ch == "{":
                depth += 1
                seen_open = True
            elif ch == "}":
                depth -= 1
                if depth == 0 and seen_open:
                    return body, i
        if seen_open:
            body.append(line)
    return body, len(lines) - 1


def _count_statements(body_lines: list) -> int:
    """Count C statement-bearing lines in a function body.

    Heuristic: line is a statement if it ends in `;` after comment
    stripping AND isn't a preprocessor directive AND isn't pure
    declaration of a parameter. Doesn't try to be a parser.
    """
    count = 0
    for line in body_lines:
        stripped = re.sub(r"/\*.*?\*/", "", line, flags=re.DOTALL)
        stripped = re.sub(r"//.*$", "", stripped, flags=re.MULTILINE)
        stripped = stripped.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        if stripped in ("{", "}", "{}"):
            continue
        if stripped.endswith(";"):
            count += 1
    return count


_RETURN_VALUE_RE = re.compile(r"\breturn\s+([^;]+?)\s*;")


def _extract_return_values(body_lines: list) -> list:
    """Extract the right-hand side of every `return ...;` in the body.

    Returns a list of normalized (whitespace-collapsed) strings.
    Lines with bare `return;` (no value) are skipped — void-style
    returns don't speak to return-value semantics.
    """
    values = []
    for line in body_lines:
        stripped = re.sub(r"/\*.*?\*/", "", line, flags=re.DOTALL)
        stripped = re.sub(r"//.*$", "", stripped, flags=re.MULTILINE)
        m = _RETURN_VALUE_RE.search(stripped)
        if m:
            val = re.sub(r"\s+", " ", m.group(1).strip())
            values.append(val)
    return values


# =====================================================================
# Axis 3 expansion — double-free verdict
# =====================================================================


def _double_free_supports_finding(
    finding: Finding,
    result: SourceIntelResult,
) -> bool:
    """Return True iff axis-3 double-free evidence directly supports
    EXPLOITABLE on this finding.

    Required:
      * rule_id is `cpp/double-free` (or c/ variant)
      * a double-free evidence record sits at (or within ±3 lines
        of) the finding's source OR sink line.

    Both ROLE values count — finding may point to either the first
    or second kfree (CodeQL typically reports the second).
    """
    rid = finding.rule_id or ""
    if not (rid.startswith("cpp/double-free")
            or rid.startswith("c/double-free")):
        return False
    if not result.double_frees:
        return False

    sink_path = finding.sink.file_path or ""
    sink_line = finding.sink.line or 0
    src_line = finding.source.line or 0
    if not sink_path:
        return False

    sink_path_abs = sink_path
    if not Path(sink_path).is_absolute():
        sink_path_abs = str((_DEFAULT_REPO_ROOT / sink_path).resolve())

    for df in result.double_frees:
        df_path, df_line = df.location
        if df_path != sink_path_abs:
            continue
        for target_line in (sink_line, src_line):
            if not target_line:
                continue
            if abs(df_line - target_line) <= 3:
                return True
    return False


# =====================================================================
# Axis 6 consumer — stack_protector
# =====================================================================


def _stack_protector_suppresses_finding(
    finding: Finding,
    result: SourceIntelResult,
) -> bool:
    """Return True iff `-fstack-protector-{strong,all,explicit}` is
    active AND the finding is a stack-buffer-write class. Stack
    canaries don't prevent the bug — they convert code-execution
    primitives to abort()/SIGABRT, reducing the verdict from
    EXPLOITABLE to DoS-only.

    Tight scope:
      * stack_protector_level in {"strong", "all", "explicit"}
      * rule_id starts with `cpp/unbounded-write` or `cpp/uncontrolled-`
      * sink snippet names a fixed-size stack buffer (heuristic:
        contains `[<digit>]` array-size pattern in source line)

    The fixed-size check avoids over-suppressing on heap writes
    (malloc'd dst — stack canary doesn't apply). Sloppy heuristic;
    looks for `buf[<digit>]` or `[<digit>]` in the sink snippet OR
    one line above. Real CFG would do better; this is good enough
    for the kernel-buffer cases.

    NOT applicable to:
      * cpp/null-dereference (canary doesn't address null deref)
      * heap-buffer-write (canary is stack-only)
      * info-leak (canary doesn't prevent reads)
    """
    bf = result.build_flags
    if bf is None:
        return False
    if bf.stack_protector_level not in ("strong", "all", "explicit"):
        return False
    rid = finding.rule_id or ""
    if not rid.startswith((
        "cpp/unbounded-write", "c/unbounded-write",
        "cpp/uncontrolled-", "c/uncontrolled-",
    )):
        return False

    # Heuristic: sink snippet (or its surrounding lines) declares a
    # fixed-size stack array. Pattern: `<type> <ident>[<digit-or-const>];`
    # in the sink-line ±5 line window.
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
    # Search window: 10 lines back from sink (the buffer declaration
    # is typically near the top of the function).
    start = max(0, sink_line - 11)
    end = min(sink_line, len(lines))
    fixed_array_re = re.compile(
        r"\b[A-Za-z_][A-Za-z_0-9]*\s+[A-Za-z_][A-Za-z_0-9]*\s*\[\s*\d+\s*\]"
    )
    for i in range(start, end):
        if fixed_array_re.search(lines[i]):
            return True
    return False
