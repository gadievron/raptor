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
from pathlib import Path
from typing import Dict, Optional, Tuple

from core.dataflow.finding import Finding
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.analyze import (
    KIND_ACCESS,
    KIND_ALLOC_SIZE,
    KIND_MALLOC,
    KIND_NO_STACK_PROTECTOR,
    KIND_NONNULL,
    KIND_NORETURN,
    KIND_RETURNS_NONNULL,
    KIND_WUR,
    AttributeEvidence,
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
        """Apply the verdict policy: EXPLOITABLE only when a relevant
        attribute observation references a function named in the
        finding's snippet AND the rule_id is kind-relevant. Otherwise
        UNCERTAIN — Phase 2/3 never returns NOT_EXPLOITABLE."""
        if result.is_skipped:
            return ValidatorVerdict.UNCERTAIN

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
