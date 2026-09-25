"""Substrate-validity seam for refutation-capable audit tiers.

A mechanical tier's null result ("looked and found nothing") carries
verdict weight — it closes hypotheses, counts as class coverage in
gate resolution, and upgrades clean outcomes to tool-backed. That
weight is only honest when the tier's substrate (the model it
actually queries) can represent the language, file, and function the
hypothesis names: spatch parses every input as C and exits 0 with
zero matches on a PHP file, so silence from an unmodeled substrate is
not evidence.

This module is the single home for that invariant:

* :class:`Coverage` — the substrate evidence attached to a result.
* A per-tier predicate registry with declared evidence SCOPES
  (file / tree / binding) and a declared ``covered=None`` policy.
* :func:`substrate_covers` / :func:`file_substrate_coverage` — the
  pre-dispatch consult (chokepoint 1, in the tool-chain dispatcher)
  and the in-sweep consult (belt-and-braces: protects every caller,
  including refinement and replay paths that re-enter through the
  sweep functions).
* :func:`license_refutation` — the post-result license (chokepoint
  2, in the sweep layer): an unlicensed refuted demotes to
  ``skipped`` (provably unmodeled — did not look) or per the tier's
  declared unknown-policy; confirmations are never gated (a match is
  its own substrate proof).
* :func:`classify_sweep_outcome` — outcome normalizer for result
  consumers, so a ``skipped`` (or novel) outcome can never fall into
  a refuted counter through a bare ``else``.

The gate is mechanical by construction: coverage is proven by
language facts and tool receipts, never asserted by the LLM.
"""

from __future__ import annotations

import logging
import os
import stat
import threading
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from .sweep import SweepResult

logger = logging.getLogger(__name__)

# ── outcome vocabulary ───────────────────────────────────────────────

# The complete SweepResult outcome vocabulary. ``skipped`` means the
# tier never looked at a modeled substrate: excluded from the dispatch
# record, from gate-resolution class coverage, and from refuted
# counters — unlike ``inconclusive`` (substrate modeled, evidence
# indeterminate; stays dispatched) and ``error`` (tool malfunctioned;
# stays dispatched, feeds channel health).
SWEEP_OUTCOMES = frozenset(
    {"confirmed", "refuted", "error", "inconclusive", "skipped"},
)


def classify_sweep_outcome(result: Any) -> str:
    """Normalize a sweep/channel result's outcome for consumers.

    Returns exactly one of ``confirmed | refuted | error |
    inconclusive | skipped``. Anything outside that vocabulary maps
    to ``error``: a novel outcome string reaching an unadapted
    consumer must land in error accounting, never be miscounted as a
    refutation (the old bare-``else`` fall-throughs did exactly
    that).
    """
    outcome = getattr(result, "outcome", None)
    if outcome in SWEEP_OUTCOMES:
        return outcome
    return "error"


# ── coverage evidence ────────────────────────────────────────────────

# ``covered=None`` resolution policies, declared per registry entry:
#
# * ``fail-open`` — the coverage fact could not be established
#   (evidence infrastructure unavailable, language undetectable):
#   refuted stands, the receipt records the unknown. Chosen where
#   stripping refutation weight on a merely-unknown fact would
#   abolish the lane for targets it genuinely serves; the stated
#   price is that vacuous refutations survive in exactly that
#   degraded case — never below the tier's historic behavior.
# * ``inconclusive`` — the coverage evidence was computed but is
#   non-probative: the tool looked (stays dispatched) but may not
#   refute.
UNKNOWN_FAIL_OPEN = "fail-open"
UNKNOWN_INCONCLUSIVE = "inconclusive"

# Evidence scopes a registry entry can declare. A sentinel-pathed
# result (whole-tree ``"<codebase>"``, SMT ``"(path-check)"``) must
# never reach a file-scoped predicate: silently answering False would
# abolish the tier, True would license vacuity — so the mismatch
# raises instead (see :func:`substrate_covers`).
SCOPE_FILE = "file"
SCOPE_TREE = "tree"
SCOPE_BINDING = "binding"

# Sentinel file_path values minted by non-file-scoped producers.
SENTINEL_PATHS = frozenset({"<codebase>", "(path-check)"})


@dataclass(frozen=True)
class Coverage:
    """Substrate evidence for one (tier, subject) consult.

    ``covered`` is three-valued: True = substrate proven; False =
    provably not modeled; None = could not prove either way (resolved
    per the tier's declared ``unknown_policy``).
    """

    covered: bool | None
    # Evidence kind: "language" | "tree-language" | "unregistered" ...
    tier: str
    # Journal/report-facing prose, e.g.
    # "coccinelle: file language 'php' outside the C family".
    reason: str
    evidence: dict[str, Any] = field(default_factory=dict)
    # Resolution for covered=None, baked in from the registry entry.
    unknown_policy: str = UNKNOWN_FAIL_OPEN

    def as_receipt(self) -> dict[str, Any]:
        """JSON-safe receipt for result details / journal rows."""
        receipt: dict[str, Any] = {
            "covered": "unknown" if self.covered is None else self.covered,
            "tier": self.tier,
            "reason": self.reason,
        }
        if self.evidence:
            receipt["evidence"] = dict(self.evidence)
        return receipt


class SubstrateScopeError(TypeError):
    """A sentinel path reached a predicate of the wrong scope.

    Programming error by contract: the chokepoints must pass the
    real context a registry entry's declared scope requires.
    """


@dataclass(frozen=True)
class TierEntry:
    """One tier's registered substrate predicate."""

    scope: str
    predicate: Callable[..., Coverage]
    unknown_policy: str


# ── canonical language resolution ────────────────────────────────────

# The audit tree already carries several sibling detectors and three
# tool-vocabulary extension maps; this module consumes the CANONICAL
# inventory detector (detect/refine + content probe) and must never
# mint another extension map. Content is only read when it can change
# the answer (.h/.inc refinement, extensionless probe) — a bounded
# head, matching the inventory's own probe budgets.
_REFINE_HEAD_BYTES = 64 * 1024

# Per-run-stable memo: the sweep layer already treats the target tree
# as read-only for a run (see core.audit.sweep_memo), so a
# (target, file) language fact is stable. Bounded so hostile trees
# with unbounded distinct paths cannot grow it without limit; the
# miss cost is one dict lookup plus at most a bounded head read.
_LANG_CACHE_MAX = 4096
_LANG_CACHE: dict[tuple[str, str], str | None] = {}
_LANG_LOCK = threading.Lock()


def canonical_file_language(
    target_path: Path | str, file_path: str,
) -> str | None:
    """The canonical (inventory-vocabulary) language of one file.

    Extension detection first, refined by a bounded content read for
    the ambiguous classes (.h C/C++ split, .inc php/asm/c split), and
    content-probed (shebang / leading PHP tag) when the extension
    says nothing. None when no detector answers — never a guess.
    """
    key = (str(target_path), file_path)
    with _LANG_LOCK:
        if key in _LANG_CACHE:
            return _LANG_CACHE[key]

    from core.inventory.languages import (
        detect_language,
        detect_language_from_content,
        refine_language,
    )

    from core.inventory.languages import _read_probe_head

    language = detect_language(file_path)
    full = Path(target_path) / file_path
    if language is None:
        language = detect_language_from_content(str(full))
    elif language in ("c", "inc"):
        # Only these extension verdicts are content-refinable (.h may
        # be C++, .inc may be php/asm/c); everything else is final
        # without touching the file. The read goes through the
        # inventory's own probe primitive: O_NONBLOCK + fstat
        # S_ISREG + O_NOFOLLOW with a bounded single read — a plain
        # open()/read_bytes() here blocked forever on a FIFO named
        # like a header and buffered an attacker-sized file before
        # any slice applied.
        head_bytes = _read_probe_head(str(full), _REFINE_HEAD_BYTES)
        if head_bytes is None:
            # Unreadable, or present but not a regular file (FIFO,
            # device, symlink — the inventory's no-follow policy).
            # A MISSING path keeps the extension verdict: memoised
            # consults may ask about hypothetical paths, and there
            # is no object to contradict the extension. Anything
            # actually present that the probe refuses can prove
            # nothing about substrate — answer unknown, never a
            # language a refutation could be licensed on.
            if os.path.lexists(full):
                language = None
        else:
            language = refine_language(
                language, file_path,
                head_bytes.decode("utf-8", errors="replace"),
            )

    with _LANG_LOCK:
        if len(_LANG_CACHE) >= _LANG_CACHE_MAX:
            _LANG_CACHE.clear()
        _LANG_CACHE[key] = language
    return language


# Tree-language index per inventory "files" list, keyed on the list's
# identity + length (the lookup.py index-cache precedent: a fresh
# list is a fresh id; appends change the length). Small and bounded —
# one run works a handful of inventories.
_TREE_CACHE_MAX = 8
_TREE_CACHE: dict[tuple[int, int], tuple[list, frozenset[str]]] = {}
_TREE_LOCK = threading.Lock()


def tree_language_set(inventory: dict[str, Any] | None) -> frozenset[str] | None:
    """Canonical languages the inventory records for the target tree.

    None when there is no inventory to answer from (the caller's
    tier policy then decides — for coccinelle that is fail-open, so
    a run without an inventory keeps its historic behavior).
    """
    if not isinstance(inventory, dict):
        return None
    files = inventory.get("files")
    if not isinstance(files, list) or not files:
        return None
    key = (id(files), len(files))
    with _TREE_LOCK:
        cached = _TREE_CACHE.get(key)
        if cached is not None and cached[0] is files:
            return cached[1]
    langs = frozenset(
        entry.get("language")
        for entry in files
        if isinstance(entry, dict) and isinstance(entry.get("language"), str)
        and entry.get("language")
    )
    with _TREE_LOCK:
        if len(_TREE_CACHE) >= _TREE_CACHE_MAX:
            _TREE_CACHE.clear()
        _TREE_CACHE[key] = (files, langs)
    return langs


# ── per-tier predicates ──────────────────────────────────────────────

# spatch parses every input as C, unconditionally; only the C family
# is a real substrate for it. A C-parseable non-C dialect slipping
# through as 'c'/'cpp' stays covered (rare, visible in the receipt);
# a hostile .c-named non-C file also stays covered until the spatch
# parse-accounting receipt lands — a named, time-boxed residual, no
# worse than the historic behavior on every input.
_C_FAMILY = frozenset({"c", "cpp"})


def _coccinelle_file_predicate(
    *, language: str | None, file_path: str,
) -> Coverage:
    if language is None:
        # Undetectable language: fail open (policy declared on the
        # registry entry). Skipping here would abolish the lane for
        # unconventional-but-real C trees; the provably-wrong
        # direction (a detected non-C language) is what the seam
        # exists to close.
        return Coverage(
            covered=None,
            tier="language",
            reason=(
                "coccinelle: file language undetectable for "
                f"'{file_path}' — refutation weight kept (fail-open)"
            ),
        )
    if language in _C_FAMILY:
        return Coverage(
            covered=True,
            tier="language",
            reason=f"coccinelle: file language '{language}' in the C family",
            evidence={"language": language},
        )
    return Coverage(
        covered=False,
        tier="language",
        reason=(
            f"coccinelle: file language '{language}' outside the C family"
        ),
        evidence={"language": language},
    )


def _coccinelle_tree_predicate(
    *, tree_languages: frozenset[str] | None,
) -> Coverage:
    """Tree-scoped evidence for the whole-tree ``"<codebase>"`` result.

    Licenses only the chokepoint-2 RESULT: the dispatching chain leg
    still gates on the subject file's file-scoped predicate — the
    tree fact is a conjunct, never a replacement, or one stray C
    file would license a whole-tree refutation against a PHP-function
    hypothesis.
    """
    if tree_languages is None:
        return Coverage(
            covered=None,
            tier="tree-language",
            reason=(
                "coccinelle: no inventory language mix available — "
                "refutation weight kept (fail-open)"
            ),
        )
    present = sorted(tree_languages & _C_FAMILY)
    if present:
        return Coverage(
            covered=True,
            tier="tree-language",
            reason=(
                "coccinelle: target tree contains C-family source "
                f"({', '.join(present)})"
            ),
            evidence={"c_family_languages": present},
        )
    return Coverage(
        covered=False,
        tier="tree-language",
        reason="coccinelle: no C substrate in tree",
        evidence={"tree_languages": sorted(tree_languages)},
    )


def _sanwit_file_predicate(
    *, language: str | None, file_path: str,
) -> Coverage:
    """PHP is the sanitizer witness's only modeled substrate: the
    chain extractor and probe are PHP-specific, so dispatching against
    any other detected language could only mint not-executable noise.
    Unknown language fails OPEN (the channel's own extractor refuses
    non-chains with a reasoned receipt, and the channel emits no
    refutations for the license to matter)."""
    if language is None:
        return Coverage(
            covered=None,
            tier="language",
            reason=(
                "sanwit: file language undetectable for "
                f"'{file_path}' — dispatch kept (fail-open)"
            ),
        )
    if language == "php":
        return Coverage(
            covered=True,
            tier="language",
            reason="sanwit: file language 'php' is the modeled substrate",
            evidence={"language": language},
        )
    return Coverage(
        covered=False,
        tier="language",
        reason=f"sanwit: file language '{language}' is not php",
        evidence={"language": language},
    )


# Registry of tiers the seam adjudicates. A tier absent here is
# UNREGISTERED: the seam answers covered=None/fail-open for it — no
# behavior change until the tier migrates with its own predicate,
# scope, and unknown-policy declaration.
_REGISTRY: dict[str, TierEntry] = {
    # Both single-file coccinelle variants share the C-family
    # predicate (the one dispatch-site suffix gate, promoted to the
    # tier). Unknown language fails OPEN: the coverage fact itself
    # could not be established, and only a provably-unmodeled
    # substrate may strip refutation weight.
    "coccinelle": TierEntry(
        scope=SCOPE_FILE,
        predicate=_coccinelle_file_predicate,
        unknown_policy=UNKNOWN_FAIL_OPEN,
    ),
    "coccinelle_flow": TierEntry(
        scope=SCOPE_FILE,
        predicate=_coccinelle_file_predicate,
        unknown_policy=UNKNOWN_FAIL_OPEN,
    ),
    # Whole-tree cross-file sweep (SweepResult tool name): the result
    # is tree-scoped by construction (its file_path is the
    # "<codebase>" sentinel). No-inventory fails OPEN — direct
    # callers without an inventory keep historic behavior.
    "coccinelle_consistency": TierEntry(
        scope=SCOPE_TREE,
        predicate=_coccinelle_tree_predicate,
        unknown_policy=UNKNOWN_FAIL_OPEN,
    ),
    # Sanitizer-sufficiency witness: PHP-only substrate. The channel
    # never emits ``refuted``, so the unknown policy is moot for
    # licensing — registration exists for the pre-dispatch skip on
    # provably non-PHP files (and the registration tripwire).
    "sanwit": TierEntry(
        scope=SCOPE_FILE,
        predicate=_sanwit_file_predicate,
        unknown_policy=UNKNOWN_FAIL_OPEN,
    ),
}


def registered_scope(tool_type: str) -> str | None:
    """The declared evidence scope for *tool_type*, or None."""
    entry = _REGISTRY.get(tool_type)
    return entry.scope if entry is not None else None


def substrate_covers(
    tool_type: str,
    *,
    language: str | None = None,
    file_path: str = "",
    function_name: str = "",
    tree_languages: frozenset[str] | None = None,
) -> Coverage:
    """Consult the tier's registered predicate with the given facts.

    File-scoped entries answer from ``language``/``file_path``;
    tree-scoped entries from ``tree_languages``. An unregistered
    tool_type answers covered=None with fail-open — the seam never
    adjudicates a tier that has not declared its predicate.

    Raises:
        SubstrateScopeError: a sentinel ``file_path`` reached a
            file-scoped entry (the caller must pass the scope's real
            context, never the sentinel).
    """
    del function_name  # file/tree predicates need no function binding yet
    entry = _REGISTRY.get(tool_type)
    if entry is None:
        return Coverage(
            covered=None,
            tier="unregistered",
            reason=f"substrate: no registered predicate for '{tool_type}'",
        )
    if entry.scope == SCOPE_FILE:
        if file_path in SENTINEL_PATHS:
            msg = (
                f"sentinel path {file_path!r} reached the file-scoped "
                f"substrate predicate for '{tool_type}' — the caller "
                "must supply the scope's real context"
            )
            raise SubstrateScopeError(msg)
        cov = entry.predicate(language=language, file_path=file_path)
    elif entry.scope == SCOPE_TREE:
        cov = entry.predicate(tree_languages=tree_languages)
    else:
        # SCOPE_BINDING has no registered entries yet (the
        # validate-path receipt is a later phase); reaching it is a
        # registry bug.
        msg = f"unhandled substrate scope {entry.scope!r} for '{tool_type}'"
        raise SubstrateScopeError(msg)
    # The registry entry's declared policy is authoritative — a
    # predicate cannot silently pick its own None-resolution.
    if cov.unknown_policy != entry.unknown_policy:
        cov = replace(cov, unknown_policy=entry.unknown_policy)
    return cov


def _is_regular_subject_file(target_path: Path | str, file_path: str) -> bool:
    """Whether *file_path* names a regular file under the target.

    lstat (no follow), mirroring the inventory probe's no-symlink
    policy: only a plain regular file counts as a reviewable subject.
    """
    try:
        st = os.lstat(Path(target_path) / file_path)
    except (OSError, ValueError):
        return False
    return stat.S_ISREG(st.st_mode)


def file_substrate_coverage(
    tool_type: str,
    *,
    target_path: Path | str,
    file_path: str,
    language: str | None = None,
) -> Coverage | None:
    """File-scoped consult with canonical language resolution.

    Prefers the caller's *language* (the inventory-stamped value when
    the dispatcher has one), else resolves via the canonical
    detect/refine machinery. Returns None when *tool_type* has no
    file-scoped registry entry — chokepoint call sites no-op for
    unregistered tiers.

    Raises:
        SubstrateScopeError: *file_path* is a sentinel value that
            does NOT exist as a regular file under the target (a
            producer passed its result sentinel where the subject
            file belongs).
    """
    entry = _REGISTRY.get(tool_type)
    if entry is None or entry.scope != SCOPE_FILE:
        return None
    if file_path in SENTINEL_PATHS:
        # Sentinel NAMES are legal filenames: a tree can ship a real
        # file literally named "<codebase>" or "(path-check)", and
        # the inventory reviews it like any other subject. This
        # consult has the target context substrate_covers lacks, so
        # it adjudicates by existence: a regular file under the
        # target is a SUBJECT (raising here would let a hostile tree
        # suppress that file's findings by naming alone — the
        # dispatcher consults before its per-leg error handling, so
        # a raise kills every hypothesis on the file, where the base
        # behavior reviewed it normally). Only a sentinel that does
        # not exist as a regular file keeps the programming-error
        # raise.
        if not _is_regular_subject_file(target_path, file_path):
            msg = (
                f"sentinel path {file_path!r} reached the file-scoped "
                f"substrate consult for '{tool_type}' and no such "
                "subject file exists under the target — the caller "
                "must supply the scope's real context"
            )
            raise SubstrateScopeError(msg)
        if language is None:
            language = canonical_file_language(target_path, file_path)
        cov = entry.predicate(language=language, file_path=file_path)
        if cov.unknown_policy != entry.unknown_policy:
            cov = replace(cov, unknown_policy=entry.unknown_policy)
        return cov
    if language is None:
        language = canonical_file_language(target_path, file_path)
    return substrate_covers(
        tool_type, language=language, file_path=file_path,
    )


# ── chokepoint 2: the refutation license ─────────────────────────────


def license_refutation(result: "SweepResult", cov: Coverage) -> "SweepResult":
    """Demote an unlicensed null; confirmed/error pass through.

    * covered=True → refuted stands, carrying the receipt.
    * covered=False → ``skipped`` (did not look).
    * covered=None → per the tier's declared policy: fail-open keeps
      the refutation (receipt records the unknown), inconclusive
      demotes (the tool looked but may not refute).
    """
    if result.outcome != "refuted":
        return result
    if cov.covered is True or (
        cov.covered is None and cov.unknown_policy == UNKNOWN_FAIL_OPEN
    ):
        return replace(
            result,
            details={**(result.details or {}), "substrate": cov.as_receipt()},
        )
    demoted = "skipped" if cov.covered is False else "inconclusive"
    return replace(
        result,
        outcome=demoted,
        details={
            **(result.details or {}),
            "reason": cov.reason,
            "substrate": cov.as_receipt(),
        },
    )


def _reset_substrate_caches() -> None:
    """Test hook: drop the language/tree memos."""
    with _LANG_LOCK:
        _LANG_CACHE.clear()
    with _TREE_LOCK:
        _TREE_CACHE.clear()
