"""Gadget-oracle absence-precision measurement harness.

Cross-tabulates :func:`core.analysis.gadget_oracle.scan_tree` absence
tiers against ground-truth labels from PHP corpora to produce the
load-bearing number for the suppression follow-up: the **false-absence
rate for ``no_gadget_surface``** — the fraction of trees carrying a
documented gadget chain (or independently-censused POP surface) where
the oracle nonetheless emits the promotable tier. A false absence here
means a consumer trusting the tier would demote a real finding, so
this gates whether ``ABSENCE_EARNS_SUPPRESSION`` may ever flip.

Two corpus modes (binary-oracle precision precedent):

  ``synthetic``  Driver-GENERATED trees in the work dir (no PHP corpus
                 files live in the repo — the generators are the
                 corpus). Every row carries an expected ``absence_tier``
                 for the exact-match arm plus chain/surface labels.

  ``library``    Pinned public clones (tag + commit sha recorded in the
                 driver; cache under ``/var/tmp/gadget-corpus-cache``,
                 never the repo). Ground-truth labels are
                 phpggc-documented gadget chains (public provenance:
                 github.com/ambionics/phpggc, ``gadgetchains/``), plus
                 verified zero-surface packages for the usefulness
                 direction. Operator-run only — never a CI test.

Independent ground-truth arm: a REGEX-based, case-insensitive surface
census over ALL files regardless of extension — an independent
implementation that never calls the oracle. Any row where the oracle
censused zero surface but the regex arm saw surface is a FLAGGED MISS
(the dangerous direction) and is reported per-corpus. The regex arm
deliberately over-counts (comments, strings): its job is catching
files the oracle's walk missed, and over-count is the safe error for
that job.

Secondary (reported, not gating): chain-detection recall on documented
chains — expected to MISS most multi-hop chains, documenting the
``no_chains_found`` boundary empirically — and tier-fire rate on true
negatives (does the promotable tier actually fire when it should).

Output: ``out/gadget-oracle-precision/runs/<ts>/report.{json,md}``.

A completed run always exits 0 — even with false absences measured
(this is a measurement tool, not a gate) — so any CI gate over this
harness must assert on report content (the ``false_absence`` counts
in ``report.json`` / the stdout summary), never on the exit code.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol

from core.json import save_json

from .gadget_oracle import (
    MAX_FILE_BYTES,
    TIER_NO_CHAINS_FOUND,
    TIER_NO_GADGET_SURFACE,
    TIER_NONE,
    scan_tree,
)

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)

Mode = Literal["synthetic", "library"]

#: Library-clone cache (driver-owned; NEVER inside the repo — the
#: no-vendored-third-party-code rule).
LIBRARY_CACHE = Path("/var/tmp/gadget-corpus-cache")


# ---------------------------------------------------------------------------
# Independent regex ground-truth arm
# ---------------------------------------------------------------------------

#: The regex arm's OWN method list — deliberately duplicated from
#: ``gadget_oracle.POP_SURFACE_METHODS`` rather than imported, so the
#: two censuses stay independent implementations. A unit test pins the
#: two sets equal; divergence fails the test instead of silently
#: weakening the cross-check.
REGEX_POP_METHODS: tuple[str, ...] = (
    "__destruct", "__wakeup", "__unserialize", "__tostring",
    "__call", "__callstatic", "__get", "__set", "__isset",
    "__unset", "__invoke", "__clone", "__debuginfo", "__set_state",
)

_RE_METHOD_DEF = re.compile(
    rb"function\s+&?\s*("
    + b"|".join(m.encode() for m in REGEX_POP_METHODS)
    + rb")\s*\(",
    re.IGNORECASE,
)
_RE_SERIALIZABLE = re.compile(
    rb"implements[^;{]{0,400}?\bserializable\b", re.IGNORECASE,
)

#: Declared ``serialize``/``unserialize`` pair — Serializable trigger
#: surface even when no in-tree implements clause spells the
#: interface (the binding can ride an import alias, an in-tree
#: interface extending Serializable, or an out-of-tree interface).
#: The name must follow ``function`` immediately, so ``__unserialize``
#: (POP arm) and near-names like ``deserialize`` never match.
_RE_PAIR_DEF = re.compile(
    rb"function\s+&?\s*(?:un)?serialize\s*\(", re.IGNORECASE,
)

#: Trait-use adaptation targets the alias arm greps for — the POP
#: list plus Serializable's method pair (an alias landing on either
#: mints trigger surface). Duplicated from the oracle's
#: ``_SURFACE_CENSUS_NAMES`` on purpose (independence); a unit test
#: pins the sets equal.
REGEX_ALIAS_TARGETS: tuple[str, ...] = REGEX_POP_METHODS + (
    "serialize", "unserialize",
)

#: ``cleanup as __destruct;`` — a trait-use adaptation that mints a
#: magic method no ``function __destruct`` grep ever sees. The
#: optional visibility modifier rides between; the trailing ``;``
#: anchors the adaptation-statement shape.
_RE_TRAIT_ALIAS = re.compile(
    rb"\bas\s+(?:(?:public|protected|private)\s+)?("
    + b"|".join(m.encode() for m in REGEX_ALIAS_TARGETS)
    + rb")\s*;",
    re.IGNORECASE,
)

#: Autoload-family registration idioms — trigger surface in their own
#: right: ``unserialize()`` hands the attacker-chosen class-name
#: string to the autoload chain BEFORE any object method is
#: consulted, so an in-tree loader executes in-tree top-level code
#: with zero declared methods. Three registration mechanisms:
#: ``spl_autoload_register(...)``, a legacy ``function __autoload``
#: definition, and the ini ``unserialize_callback_func`` callback.
#: The ini mechanism is grepped as the bare option-name string —
#: over-matching comments/docs by design (safe direction for a
#: ground-truth arm); a DYNAMIC ini key whose value never spells the
#: option name anywhere in the tree is outside this arm's reach and
#: rides as a mandatory labeled corpus row instead
#: (autoload_ini_dynamic_key keeps the literal in an assignment
#: precisely so this arm stays non-vacuous on it). The
#: ``spl_autoload_register`` token is matched BARE (no call parens):
#: a registration can ride a string literal handed to a dynamic
#: dispatcher, a ``use function`` import, or a variable assignment —
#: the token anywhere in the tree is ground-truth surface for this
#: arm's purposes.
_RE_AUTOLOAD = re.compile(
    rb"\bspl_autoload_register\b"
    rb"|\bfunction\s+&?\s*__autoload\s*\("
    rb"|unserialize_callback_func",
    re.IGNORECASE,
)

#: Callable-passing builtins: ``call_user_func`` /
#: ``call_user_func_array`` invoke whatever callable their first
#: argument names — a registration idiom can hide behind either.
#: The bare token counts (over-matching docs/comments is the safe
#: direction); near-names (``call_user_func_custom``) stay outside
#: the word boundary.
_RE_CALLABLE_BUILTIN = re.compile(
    rb"\bcall_user_func(?:_array)?\b", re.IGNORECASE,
)

#: Variable-function invocation — ``$fn(...)`` calls whatever the
#: variable holds, including a name assembled at runtime that never
#: appears as a literal anywhere in the tree (concatenation,
#: ``str_rot13``, ...). Any such call site is surface for this arm:
#: no static census can bound what it invokes. Method calls
#: (``$this->x(``, ``$obj->x(``) do not match — the ``->`` breaks
#: the variable-then-paren adjacency.
_RE_VAR_INVOKE = re.compile(rb"\$\w+\s*\(")

#: DECLARED regex-arm boundary: parent-class RESOLUTION evasions
#: (namespace-relative, import-aliased, cross-namespace-aliased,
#: Unicode-casefold-colliding, and dead-branch-decoy ``extends`` /
#: trait-``use`` targets) are not independently checkable here.
#: Resolving a bare parent name needs the file's namespace + import
#: context — a parser's job — and a context-blind ``extends`` grep
#: would flag every internal-base parent (the extends_exception_only
#: guard and the psr library true negatives), destroying the
#: usefulness arm and the true-negative labels with it. Those shapes
#: are covered by mandatory labeled corpus rows
#: (namespace_relative_extends, use_alias_extends, the
#: alias_cross_namespace_* family, alias_before_declaration,
#: kelvin_casefold_extends, and the dead_branch_*_decoy family)
#: whose ground truth is the row label. The
#: ``<?xml``-smuggle shape needs no such carve-out: this arm reads
#: every file regardless of extension, so a smuggled method
#: definition is censused (xml_open_tag_smuggle relies on it).
#: Serializable-binding evasions (aliased / indirected / out-of-tree
#: implements clauses) need no carve-out either: the declared
#: ``serialize``/``unserialize`` pair itself is greppable
#: (``_RE_PAIR_DEF``), independent of how the binding is spelled.

#: VCS dirs skipped by the regex walk: packfiles/objects are
#: compressed (no plain-text matches to find) and are not part of the
#: tree the oracle claims anything about.
_REGEX_SKIP_DIRS = frozenset({".git", ".svn", ".hg"})

#: Per-file read cap for the regex arm — 4x the oracle's per-file cap,
#: so a file the oracle refused as oversized is still censused here.
_REGEX_MAX_READ = 4 * MAX_FILE_BYTES


def regex_surface_census(root: Path) -> dict[str, int]:
    """Case-insensitive POP-surface census over ALL files regardless
    of extension. Independent of the oracle by construction: no
    parsing, no extension filter, file symlinks read through.

    Returns ``{"method_defs": n, "serializable_impls": n,
    "pair_defs": n, "alias_defs": n, "autoload_regs": n,
    "callable_builtins": n, "var_invokes": n, "total": n}``.
    """
    method_defs = 0
    serializable = 0
    pair_defs = 0
    alias_defs = 0
    autoload_regs = 0
    callable_builtins = 0
    var_invokes = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames if d not in _REGEX_SKIP_DIRS)
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            if not os.path.isfile(full):
                continue
            try:
                with open(full, "rb") as fh:
                    data = fh.read(_REGEX_MAX_READ)
            except OSError:
                continue
            method_defs += len(_RE_METHOD_DEF.findall(data))
            serializable += len(_RE_SERIALIZABLE.findall(data))
            pair_defs += len(_RE_PAIR_DEF.findall(data))
            alias_defs += len(_RE_TRAIT_ALIAS.findall(data))
            autoload_regs += len(_RE_AUTOLOAD.findall(data))
            callable_builtins += len(
                _RE_CALLABLE_BUILTIN.findall(data))
            var_invokes += len(_RE_VAR_INVOKE.findall(data))
    return {
        "method_defs": method_defs,
        "serializable_impls": serializable,
        "pair_defs": pair_defs,
        "alias_defs": alias_defs,
        "autoload_regs": autoload_regs,
        "callable_builtins": callable_builtins,
        "var_invokes": var_invokes,
        "total": (method_defs + serializable + pair_defs + alias_defs
                  + autoload_regs + callable_builtins + var_invokes),
    }


# ---------------------------------------------------------------------------
# Row + corpus data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChainLabel:
    """One phpggc-documented gadget chain (public provenance)."""
    name: str          # phpggc chain id, e.g. "Guzzle/FW1"
    entry_class: str   # short name of the trigger-carrying class
    versions: str      # phpggc-documented target version range


@dataclass(frozen=True)
class PreparedRow:
    """One labeled tree ready to measure."""
    name: str
    tree: Path
    #: Synthetic exact-match arm: the tier the oracle MUST emit
    #: (``None`` on library rows — real trees earn no exact claim).
    expected_tier: str | None = None
    #: A chain the one-hop model is expected to FIND exists in-tree.
    expect_chain: bool = False
    #: Ground truth by construction/documentation: the tree carries
    #: POP surface or a documented chain (the regex arm extends this
    #: at measurement time).
    ground_truth_surface: bool = False
    #: Genuinely zero-surface tree — the usefulness direction (the
    #: promotable tier SHOULD fire here).
    true_negative: bool = False
    documented_chains: tuple[ChainLabel, ...] = ()
    notes: str = ""


@dataclass(frozen=True)
class RowMeasurement:
    """One measured row."""
    row: str
    emitted_tier: str
    chains_found: int
    chain_classes: tuple[str, ...]
    census_complete: bool
    incomplete_reasons: tuple[str, ...]
    oracle_surface_total: int
    regex_surface_total: int
    ground_truth_surface: bool
    flagged_miss: bool
    false_absence: bool
    expected_tier: str | None
    tier_match: bool | None
    expect_chain: bool
    chain_found_as_expected: bool | None
    true_negative: bool
    documented_chains: tuple[str, ...]
    entry_classes_found: tuple[str, ...]
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "row": self.row,
            "emitted_tier": self.emitted_tier,
            "chains_found": self.chains_found,
            "chain_classes": list(self.chain_classes),
            "census_complete": self.census_complete,
            "incomplete_reasons": list(self.incomplete_reasons),
            "oracle_surface_total": self.oracle_surface_total,
            "regex_surface_total": self.regex_surface_total,
            "ground_truth_surface": self.ground_truth_surface,
            "flagged_miss": self.flagged_miss,
            "false_absence": self.false_absence,
            "expected_tier": self.expected_tier,
            "tier_match": self.tier_match,
            "expect_chain": self.expect_chain,
            "chain_found_as_expected": self.chain_found_as_expected,
            "true_negative": self.true_negative,
            "documented_chains": list(self.documented_chains),
            "entry_classes_found": list(self.entry_classes_found),
            "notes": self.notes,
        }


@dataclass
class CorpusReport:
    """Per-corpus measurement result."""
    corpus_name: str
    corpus_mode: Mode
    n_rows: int
    rows: list[RowMeasurement] = field(default_factory=list)
    tier_counts: dict[str, int] = field(default_factory=dict)
    #: ``cross_tab[emitted_tier][gt_label]`` where gt_label is
    #: ``surface`` (documented chain / constructed surface / regex arm
    #: saw surface) or ``no_surface``.
    cross_tab: dict[str, dict[str, int]] = field(default_factory=dict)

    # The load-bearing direction.
    false_absence_denominator: int = 0
    false_absence_count: int = 0
    false_absence_rows: list[str] = field(default_factory=list)
    flagged_misses: list[str] = field(default_factory=list)

    # Synthetic exact-match arm.
    exact_match: float | None = None
    mismatches: list[dict[str, str]] = field(default_factory=list)

    # Secondary, non-gating.
    documented_chain_rows: int = 0
    chains_found_on_documented: int = 0
    chain_recall: float | None = None
    expected_findable_rows: int = 0
    expected_findable_found: int = 0
    true_negative_rows: int = 0
    tier_fired_on_negatives: int = 0
    tier_fire_rate: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus_name,
            "mode": self.corpus_mode,
            "n_rows": self.n_rows,
            "tier_counts": self.tier_counts,
            "cross_tab": self.cross_tab,
            "false_absence_denominator": self.false_absence_denominator,
            "false_absence_count": self.false_absence_count,
            "false_absence_rows": self.false_absence_rows,
            "flagged_misses": self.flagged_misses,
            "exact_match": self.exact_match,
            "mismatches": self.mismatches,
            "documented_chain_rows": self.documented_chain_rows,
            "chains_found_on_documented": self.chains_found_on_documented,
            "chain_recall": self.chain_recall,
            "expected_findable_rows": self.expected_findable_rows,
            "expected_findable_found": self.expected_findable_found,
            "true_negative_rows": self.true_negative_rows,
            "tier_fired_on_negatives": self.tier_fired_on_negatives,
            "tier_fire_rate": self.tier_fire_rate,
            "rows": [r.to_dict() for r in self.rows],
        }


class CorpusDriver(Protocol):
    """A corpus the harness can measure. Drivers own generation /
    cloning; the harness only consumes prepared rows."""
    name: str
    description: str
    mode: Mode

    def prepare(self, work_dir: Path) -> list[PreparedRow]:
        """Generate or fetch the corpus trees; return labeled rows."""
        ...


# ---------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------


def _oracle_surface_total(report: dict[str, Any]) -> int:
    """Total blocker count the oracle censused (methods +
    Serializable + dynamic-definition sites + autoload-family
    registrations; anonymous-class methods are already inside the
    method total). Autoload sites count so the flagged-miss
    cross-check compares like with like: the regex arm greps the
    registration idioms, and a registration the oracle DID record
    must not read as an oracle miss."""
    surface = report.get("pop_surface")
    if not isinstance(surface, dict):
        return 0
    total = 0
    for key in ("total_methods", "serializable_impls",
                "dynamic_definition_sites"):
        v = surface.get(key)
        if isinstance(v, int) and not isinstance(v, bool) and v > 0:
            total += v
    autoload = report.get("autoload")
    if isinstance(autoload, dict) and autoload.get("registered") is True:
        sites = autoload.get("sites")
        n_sites = len(sites) if isinstance(sites, list) else 0
        total += max(1, n_sites)
    return total


def measure_row(row: PreparedRow) -> RowMeasurement:
    """Scan one tree with the oracle AND the independent regex arm;
    cross-tabulate against the row's labels."""
    report = scan_tree(row.tree)
    emitted = report.get("absence_tier")
    if emitted not in (TIER_NO_GADGET_SURFACE, TIER_NO_CHAINS_FOUND,
                       TIER_NONE):
        emitted = TIER_NONE
    chains = [c for c in (report.get("chains") or [])
              if isinstance(c, dict)]
    chain_classes = tuple(sorted({
        str(c.get("class") or "") for c in chains}))
    census = report.get("census") or {}
    complete = census.get("complete") is True
    reasons = tuple(
        str(r) for r in (census.get("incomplete_reasons") or []))
    oracle_total = _oracle_surface_total(report)
    regex = regex_surface_census(row.tree)
    regex_total = regex["total"]
    gt_surface = row.ground_truth_surface or regex_total > 0
    flagged_miss = oracle_total == 0 and regex_total > 0
    false_absence = gt_surface and emitted == TIER_NO_GADGET_SURFACE
    tier_match = (emitted == row.expected_tier
                  if row.expected_tier is not None else None)
    chain_ok = (bool(chains) == row.expect_chain
                if row.expected_tier is not None else None)
    # Full-Unicode .lower() is fine HERE (recall bookkeeping only —
    # matching documented chain labels to emitted class names, both
    # ASCII in practice); name-IDENTITY decisions inside the oracle
    # use ASCII-only casefolding and never route through this.
    found_lower = {c.lower() for c in chain_classes}
    entry_found = tuple(sorted({
        lbl.entry_class for lbl in row.documented_chains
        if lbl.entry_class.lower() in found_lower}))
    return RowMeasurement(
        row=row.name,
        emitted_tier=str(emitted),
        chains_found=len(chains),
        chain_classes=chain_classes,
        census_complete=complete,
        incomplete_reasons=reasons,
        oracle_surface_total=oracle_total,
        regex_surface_total=regex_total,
        ground_truth_surface=gt_surface,
        flagged_miss=flagged_miss,
        false_absence=false_absence,
        expected_tier=row.expected_tier,
        tier_match=tier_match,
        expect_chain=row.expect_chain,
        chain_found_as_expected=chain_ok,
        true_negative=row.true_negative,
        documented_chains=tuple(
            lbl.name for lbl in row.documented_chains),
        entry_classes_found=entry_found,
        notes=row.notes,
    )


def cross_tab_rows(
    name: str, mode: Mode, measurements: Sequence[RowMeasurement],
) -> CorpusReport:
    """Fold row measurements into a per-corpus report."""
    rep = CorpusReport(corpus_name=name, corpus_mode=mode,
                       n_rows=len(measurements))
    exact_n = 0
    exact_ok = 0
    for m in measurements:
        rep.rows.append(m)
        rep.tier_counts[m.emitted_tier] = (
            rep.tier_counts.get(m.emitted_tier, 0) + 1)
        gt = "surface" if m.ground_truth_surface else "no_surface"
        rep.cross_tab.setdefault(m.emitted_tier, {}).setdefault(gt, 0)
        rep.cross_tab[m.emitted_tier][gt] += 1
        if m.ground_truth_surface:
            rep.false_absence_denominator += 1
            if m.false_absence:
                rep.false_absence_count += 1
                rep.false_absence_rows.append(m.row)
        if m.flagged_miss:
            rep.flagged_misses.append(m.row)
        if m.expected_tier is not None:
            exact_n += 1
            if m.tier_match and m.chain_found_as_expected:
                exact_ok += 1
            else:
                rep.mismatches.append({
                    "row": m.row,
                    "expected_tier": str(m.expected_tier),
                    "emitted_tier": m.emitted_tier,
                    "expected_chain": str(m.expect_chain),
                    "chains_found": str(m.chains_found),
                })
        if m.documented_chains:
            rep.documented_chain_rows += 1
            if m.chains_found:
                rep.chains_found_on_documented += 1
        if m.expect_chain:
            rep.expected_findable_rows += 1
            if m.chains_found:
                rep.expected_findable_found += 1
        if m.true_negative:
            rep.true_negative_rows += 1
            if m.emitted_tier == TIER_NO_GADGET_SURFACE:
                rep.tier_fired_on_negatives += 1
    if exact_n:
        rep.exact_match = exact_ok / exact_n
    if rep.documented_chain_rows:
        rep.chain_recall = (rep.chains_found_on_documented
                            / rep.documented_chain_rows)
    if rep.true_negative_rows:
        rep.tier_fire_rate = (rep.tier_fired_on_negatives
                              / rep.true_negative_rows)
    return rep


def run_corpus(driver: CorpusDriver, work_dir: Path) -> CorpusReport:
    """Drive one corpus end-to-end: prepare -> measure -> cross-tab."""
    work_dir.mkdir(parents=True, exist_ok=True)
    rows = driver.prepare(work_dir)
    measurements = [measure_row(row) for row in rows]
    return cross_tab_rows(driver.name, driver.mode, measurements)


# ---------------------------------------------------------------------------
# Aggregation + reporting
# ---------------------------------------------------------------------------


def aggregate(reports: Sequence[CorpusReport]) -> dict[str, Any]:
    """Cross-corpus aggregate — the headline the promotion decision
    reads. Rule-of-three is only a valid 95% upper bound when ZERO
    false absences were observed; with misses present it would
    understate the plausible rate, so ``None`` is reported instead."""
    denom = 0
    misses = 0
    tn_rows = 0
    tn_fired = 0
    doc_rows = 0
    doc_found = 0
    per_corpus: list[dict[str, Any]] = []
    for r in reports:
        denom += r.false_absence_denominator
        misses += r.false_absence_count
        tn_rows += r.true_negative_rows
        tn_fired += r.tier_fired_on_negatives
        doc_rows += r.documented_chain_rows
        doc_found += r.chains_found_on_documented
        per_corpus.append({
            "corpus": r.corpus_name,
            "mode": r.corpus_mode,
            "n_rows": r.n_rows,
            "false_absence_denominator": r.false_absence_denominator,
            "false_absence_count": r.false_absence_count,
            "flagged_misses": len(r.flagged_misses),
            "exact_match": r.exact_match,
            # Tier-fire counts ride here too so the aggregate block
            # answers the usefulness question per corpus without
            # re-deriving from the row dumps.
            "tier_counts": dict(r.tier_counts),
            "true_negative_rows": r.true_negative_rows,
            "tier_fired_on_negatives": r.tier_fired_on_negatives,
        })
    rule_of_three_ub = (3.0 / denom) if denom and misses == 0 else None
    return {
        "false_absence_denominator_total": denom,
        "false_absence_count_total": misses,
        "false_absence_rate": (misses / denom) if denom else None,
        "rule_of_three_95_upper_bound": rule_of_three_ub,
        "true_negative_rows_total": tn_rows,
        "tier_fired_on_negatives_total": tn_fired,
        "tier_fire_rate": (tn_fired / tn_rows) if tn_rows else None,
        "documented_chain_rows_total": doc_rows,
        "chains_found_on_documented_total": doc_found,
        "chain_recall": (doc_found / doc_rows) if doc_rows else None,
        "per_corpus": per_corpus,
    }


def _format_markdown(reports: Sequence[CorpusReport]) -> str:
    lines = ["# Gadget-oracle absence-precision report", ""]
    for r in reports:
        lines.append(f"## {r.corpus_name} ({r.corpus_mode})")
        lines.append("")
        lines.append(f"- rows: {r.n_rows}")
        lines.append(f"- tiers emitted: {r.tier_counts}")
        if r.exact_match is not None:
            lines.append(f"- exact tier+chain match: {r.exact_match:.1%}")
        if r.mismatches:
            lines.append(f"- mismatches ({len(r.mismatches)}):")
            lines.extend(
                f"  - `{m['row']}`: expected tier={m['expected_tier']}"
                f" got={m['emitted_tier']}; expected_chain="
                f"{m['expected_chain']} chains_found={m['chains_found']}"
                for m in r.mismatches)
        lines.append(
            f"- false absences (no_gadget_surface on a surfaced tree):"
            f" {r.false_absence_count}/{r.false_absence_denominator}")
        if r.false_absence_rows:
            lines.append(
                f"  - rows: {', '.join(r.false_absence_rows)}")
        if r.flagged_misses:
            lines.append(
                f"- flagged misses (oracle-surface=0, regex-surface>0):"
                f" {len(r.flagged_misses)}: "
                + ", ".join(r.flagged_misses))
        else:
            lines.append("- flagged misses: none")
        if r.chain_recall is not None:
            lines.append(
                f"- chain recall on documented-chain rows: "
                f"{r.chains_found_on_documented}/"
                f"{r.documented_chain_rows} = {r.chain_recall:.1%}")
        if r.expected_findable_rows:
            lines.append(
                f"- expected-findable chains found: "
                f"{r.expected_findable_found}/{r.expected_findable_rows}")
        if r.tier_fire_rate is not None:
            lines.append(
                f"- promotable tier fired on true negatives: "
                f"{r.tier_fired_on_negatives}/{r.true_negative_rows}"
                f" = {r.tier_fire_rate:.1%}")
        lines.append("")
        lines.append("Cross-tab (emitted tier x ground truth):")
        lines.append("")
        lines.append("| emitted tier | surface | no_surface |")
        lines.append("|---|---:|---:|")
        for k in (TIER_NO_GADGET_SURFACE, TIER_NO_CHAINS_FOUND,
                  TIER_NONE):
            row = r.cross_tab.get(k)
            if not row:
                continue
            lines.append(
                f"| {k} | {row.get('surface', 0)} "
                f"| {row.get('no_surface', 0)} |")
        lines.append("")
        rows_with_details = [m for m in r.rows
                             if m.documented_chains or m.flagged_miss
                             or m.false_absence]
        if rows_with_details:
            lines.append("Row detail:")
            lines.append("")
            for m in rows_with_details:
                doc = (", ".join(m.documented_chains)
                       if m.documented_chains else "-")
                entry = (", ".join(m.entry_classes_found)
                         if m.entry_classes_found else "-")
                lines.append(
                    f"- `{m.row}`: tier={m.emitted_tier}, "
                    f"chains={m.chains_found}, census_complete="
                    f"{m.census_complete}, oracle_surface="
                    f"{m.oracle_surface_total}, regex_surface="
                    f"{m.regex_surface_total}, documented=[{doc}], "
                    f"entry_classes_found=[{entry}]")
            lines.append("")
    agg = aggregate(reports)
    lines.append("## Aggregate")
    lines.append("")
    rate = agg["false_absence_rate"]
    lines.append(
        f"- false-absence rate (no_gadget_surface, dangerous "
        f"direction): {agg['false_absence_count_total']}/"
        f"{agg['false_absence_denominator_total']}"
        + (f" = {rate:.2%}" if rate is not None else ""))
    ub = agg["rule_of_three_95_upper_bound"]
    if ub is not None:
        lines.append(
            f"- rule-of-three 95% upper bound on false-absence rate: "
            f"{ub:.2%}")
    if agg["tier_fire_rate"] is not None:
        lines.append(
            f"- tier-fire rate on true negatives (usefulness): "
            f"{agg['tier_fired_on_negatives_total']}/"
            f"{agg['true_negative_rows_total']}"
            f" = {agg['tier_fire_rate']:.1%}")
    if agg["chain_recall"] is not None:
        lines.append(
            f"- chain recall on documented chains (documents the "
            f"no_chains_found boundary; NOT gating): "
            f"{agg['chains_found_on_documented_total']}/"
            f"{agg['documented_chain_rows_total']}"
            f" = {agg['chain_recall']:.1%}")
    lines.append("")
    lines.append(
        "Methodology note: `no_chains_found` is depth-limited by "
        "design — multi-hop / cross-class chains are EXPECTED misses "
        "for the one-hop model, which is exactly why that tier is "
        "never promotable. The only number that can earn the "
        "`no_gadget_surface` promotion is the false-absence rate "
        "above, and it must be zero."
    )
    lines.append("")
    return "\n".join(lines)


def write_report(reports: Sequence[CorpusReport], out_dir: Path) -> Path:
    """Write ``report.json`` and ``report.md`` into ``out_dir``."""
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "corpora": [r.to_dict() for r in reports],
        "aggregate": aggregate(reports),
    }
    save_json(json_path, payload)
    (out_dir / "report.md").write_text(
        _format_markdown(reports), encoding="utf-8")
    return json_path


# ---------------------------------------------------------------------------
# Synthetic corpus driver
# ---------------------------------------------------------------------------


def _write_tree(root: Path, files: dict[str, str | bytes]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            p.write_bytes(content)
        else:
            p.write_text(content)
    return root


_GADGET_CLASS = """<?php
class TempLogger {
    public $path;
    function __destruct() {
        unlink($this->path);
    }
}
"""

#: Chain-modeled trigger methods (the oracle's one-hop search follows
#: these); the rest of the POP set is census-only surface. Canonical
#: spellings for the generated source.
_CHAIN_MODELED = frozenset({
    "__destruct", "__wakeup", "__unserialize",
    "__toString", "__call", "__get", "__set",
})

_CANONICAL_POP: tuple[str, ...] = (
    "__destruct", "__wakeup", "__unserialize", "__toString",
    "__call", "__callStatic", "__get", "__set", "__isset",
    "__unset", "__invoke", "__clone", "__debugInfo", "__set_state",
)


class SyntheticCorpusDriver:
    """Generated labeled trees covering the recorded miss-classes,
    every census blocker, every census-degradation shape, and true
    negatives. No PHP corpus files live in the repo — this class IS
    the corpus."""

    name = "synthetic"
    description = ("generated PHP trees: miss-classes, census "
                   "blockers, degradations, true negatives")
    mode: Mode = "synthetic"

    def prepare(self, work_dir: Path) -> list[PreparedRow]:
        base = work_dir / "trees"
        if base.exists():
            shutil.rmtree(base)
        rows: list[PreparedRow] = []

        def add(name: str, files: dict[str, str | bytes],
                **labels: Any) -> Path:
            tree = _write_tree(base / name / "tree", files)
            rows.append(PreparedRow(name=name, tree=tree, **labels))
            return tree

        # -- recorded miss-classes ------------------------------------
        add("case_variant_destruct", {"g.php": (
            "<?php\nclass CaseGadget {\n    public $cmd;\n"
            "    function __DESTRUCT() {\n"
            "        SYSTEM($this->cmd);\n    }\n}\n")},
            expected_tier=TIER_NONE, expect_chain=True,
            ground_truth_surface=True,
            notes="miss-class: case-variant magic name")
        add("qualified_global_sink", {"g.php": (
            "<?php\nclass NsGadget {\n    public $cmd;\n"
            "    function __destruct() {\n"
            "        \\system($this->cmd);\n    }\n}\n")},
            expected_tier=TIER_NONE, expect_chain=True,
            ground_truth_surface=True,
            notes="miss-class: leading-backslash global sink")
        add("trait_destruct_same_file", {"g.php": (
            "<?php\ntrait Evil {\n    public function __destruct() {\n"
            "        system($this->cmd);\n    }\n}\n"
            "class TraitGadget {\n    use Evil;\n    public $cmd;\n}\n")},
            expected_tier=TIER_NONE, expect_chain=True,
            ground_truth_surface=True,
            notes="miss-class: trait-provided __destruct, same file")
        add("trait_destruct_cross_file", {
            "traits.php": (
                "<?php\ntrait Evil {\n"
                "    public function __destruct() {\n"
                "        system($this->cmd);\n    }\n}\n"),
            "user.php": (
                "<?php\nclass Uses {\n    use Evil;\n"
                "    public $cmd;\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("miss-class: cross-file trait — unresolved trait "
                   "use degrades the census, tier withheld"))

        # -- Serializable variants (surface the chain search never
        #    models: the census is what blocks the tier) --------------
        ser_body = (
            "    public function serialize() { return ''; }\n"
            "    public function unserialize($data) {\n"
            "        system($this->cmd);\n    }\n")
        add("serializable_plain", {"l.php": (
            "<?php\nclass Legacy implements Serializable {\n"
            "    public $cmd;\n" + ser_body + "}\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes="Serializable impl; sink inside unserialize()")
        add("serializable_backslash", {"l.php": (
            "<?php\nclass Legacy implements \\Serializable {\n"
            "    public $cmd;\n" + ser_body + "}\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes="\\Serializable variant")
        add("serializable_namespaced", {"l.php": (
            "<?php\nnamespace App;\n"
            "class Legacy implements \\Serializable {\n"
            "    public $cmd;\n" + ser_body + "}\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes="namespaced file, \\Serializable variant")
        add("serializable_alias_implements", {"l.php": (
            "<?php\nuse Serializable as Srl;\n"
            "class Legacy implements Srl {\n"
            "    public $cmd;\n" + ser_body + "}\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("implements clause rides an import alias — only "
                   "the declared serialize/unserialize pair census "
                   "sees the surface"))
        add("serializable_interface_indirection", {"l.php": (
            "<?php\ninterface Store extends Serializable {}\n"
            "class Legacy implements Store {\n"
            "    public $cmd;\n" + ser_body + "}\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("in-tree interface extends Serializable; the "
                   "class's own implements clause never spells it"))
        add("serializable_out_of_tree_interface", {"l.php": (
            "<?php\nclass Legacy implements \\Vendor\\Store {\n"
            "    public $cmd;\n" + ser_body + "}\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("interface autoloads from outside the tree; "
                   "nothing in-tree spells Serializable"))

        # -- dynamic definition ---------------------------------------
        add("eval_defined_class", {"boot.php": (
            "<?php\neval('class G { public $c; "
            "function __destruct() { system($this->c); } }');\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes="eval can define a class the static census never sees")

        # -- autoload-family trigger surface: unserialize() hands the
        #    attacker-chosen class-name string to the autoload chain
        #    BEFORE any object method is consulted, so an in-tree
        #    loader executes in-tree top-level code with ZERO declared
        #    methods. Execution-verified against the PHP engine for
        #    all three registration mechanisms. Registration alone
        #    demotes the tier (loader behavior is unmodelled). -------
        loaded = ("<?php\nfile_put_contents(__DIR__ . '/loaded.txt', "
                  "'side-effect');\n")
        add("autoload_spl_require", {
            "entry.php": (
                "<?php\nspl_autoload_register(function ($name) {\n"
                "    $f = __DIR__ . '/' . str_replace('\\\\', '/', "
                "$name) . '.php';\n"
                "    if (is_file($f)) { require $f; }\n});\n"
                "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("spl_autoload_register closure + require: the "
                   "class-name string reaches the loader before any "
                   "object method; in-tree top-level code executes"))
        add("autoload_legacy_function", {
            "entry.php": (
                "<?php\nfunction __autoload($name) {\n"
                "    $f = __DIR__ . '/' . $name . '.php';\n"
                "    if (is_file($f)) { require $f; }\n}\n"
                "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("legacy global __autoload hook (PHP <= 7.4) — "
                   "same trigger path as the SPL registration"))
        add("autoload_callback_ini", {
            "entry.php": (
                "<?php\nini_set('unserialize_callback_func', "
                "'loader');\n"
                "function loader($name) {\n"
                "    $f = __DIR__ . '/' . $name . '.php';\n"
                "    if (is_file($f)) { require $f; }\n}\n"
                "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("ini_set('unserialize_callback_func', ...) — the "
                   "registration mechanism no method census sees; "
                   "executes on PHP 7.4 AND 8.2"))
        add("autoload_callback_ini_alter", {
            "entry.php": (
                "<?php\nini_alter('unserialize_callback_func', "
                "'loader');\n"
                "function loader($name) {\n"
                "    $f = __DIR__ . '/' . $name . '.php';\n"
                "    if (is_file($f)) { require $f; }\n}\n"
                "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes="ini_alter is an ini_set alias — same registration")
        add("autoload_ini_dynamic_key", {
            "entry.php": (
                "<?php\n$key = 'unserialize_callback_func';\n"
                "ini_set($key, 'loader');\n"
                "function loader($name) {\n"
                "    $f = __DIR__ . '/' . $name . '.php';\n"
                "    if (is_file($f)) { require $f; }\n}\n"
                "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("dynamic ini_set key (a variable) — the census "
                   "cannot prove it is NOT the callback option, so "
                   "it fails closed as registration; the tree "
                   "genuinely registers at runtime"))
        add("autoload_spl_benign", {
            "entry.php": (
                "<?php\nspl_autoload_register(function ($name) {\n"
                "    error_log('autoload miss: ' . $name);\n});\n"
                "unserialize($_GET['x']);\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("control: registration whose loader body is "
                   "harmless — registration ALONE demotes (loader "
                   "behavior is unmodelled by design)"))
        add("unserialize_without_autoload", {
            "entry.php": "<?php\nunserialize($_GET['x']);\n"},
            expected_tier=TIER_NO_GADGET_SURFACE, true_negative=True,
            notes=("control: unserialize with no autoloader and no "
                   "classes — the tier must still fire"))
        add("ini_set_other_key", {
            "entry.php": (
                "<?php\nini_set('memory_limit', '1G');\n"
                "unserialize($_GET['x']);\n")},
            expected_tier=TIER_NO_GADGET_SURFACE, true_negative=True,
            notes=("control: a literal NON-callback ini key must not "
                   "read as autoload registration — pins the "
                   "literal-key discrimination"))

        # -- dynamic-invocation registrations: the SAME registrations
        #    as above, spelled so no direct-call census ever sees the
        #    callee name statically. Each tree genuinely registers at
        #    runtime (execution-verified against the PHP engine); the
        #    census fails closed on the dynamic callee / resolves the
        #    literal callable instead of trusting the spelling. ------
        loader_fn = (
            "function loader($name) {\n"
            "    $f = __DIR__ . '/' . $name . '.php';\n"
            "    if (is_file($f)) { require $f; }\n}\n")
        add("varfunc_autoload_register", {
            "entry.php": (
                "<?php\n$reg = 'spl_autoload_register';\n"
                "$reg('loader');\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("variable-function call $reg(...) registers the "
                   "loader — the callee name never appears as a "
                   "direct call spelling"))
        add("call_user_func_autoload_register", {
            "entry.php": (
                "<?php\ncall_user_func('spl_autoload_register', "
                "'loader');\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("call_user_func with a literal callable string — "
                   "the builtin forwards to the registration"))
        add("call_user_func_array_autoload_register", {
            "entry.php": (
                "<?php\ncall_user_func_array("
                "'spl_autoload_register', ['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("call_user_func_array variant — forwarded "
                   "arguments ride an opaque array"))
        add("parens_literal_autoload_register", {
            "entry.php": (
                "<?php\n('spl_autoload_register')('loader');\n"
                + loader_fn + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("parenthesized string literal invoked directly "
                   "(PHP 7+ callable syntax) — the callee expression "
                   "is not a static name node"))
        add("use_function_alias_autoload_register", {
            "entry.php": (
                "<?php\nuse function spl_autoload_register as "
                "registerLoader;\nregisterLoader('loader');\n"
                + loader_fn + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("use-function import rebinds a harmless-looking "
                   "name onto the registration builtin — the alias "
                   "must resolve back to the real callee"))
        add("varfunc_iniset_callback", {
            "entry.php": (
                "<?php\n$setter = 'ini_set';\n"
                "$setter('unserialize_callback_func', 'loader');\n"
                + loader_fn + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("variable-function ini_set sets the unserialize "
                   "callback — the ini registration rides a dynamic "
                   "callee"))
        add("concat_varfunc_autoload_register", {
            "entry.php": (
                "<?php\n$f = 'spl_autoload_' . 'register';\n"
                "$f('loader');\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("callee name assembled by concatenation — no "
                   "single literal in the tree spells the "
                   "registration; only the $f(...) call site is "
                   "visible"))
        add("iniset_spread_args", {
            "entry.php": (
                "<?php\n$args = ['unserialize_callback_func', "
                "'loader'];\nini_set(...$args);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("argument-spread ini_set — the key argument is "
                   "opaque, so the census cannot prove it is NOT the "
                   "callback option and fails closed; the tree "
                   "genuinely registers at runtime"))
        add("static_call_spellings", {
            "entry.php": (
                "<?php\nfunction fmt($v) {\n"
                "    return str_pad(trim($v), 8);\n}\n"
                "echo htmlspecialchars(fmt('x'));\n"
                "echo \\strtolower('ABC');\n"
                "unserialize($_GET['x']);\n")},
            expected_tier=TIER_NO_GADGET_SURFACE, true_negative=True,
            notes=("control: every call spells a static global "
                   "callee directly (bare and leading-backslash) — "
                   "the dynamic-invocation demotions must not touch "
                   "plain static call trees"))

        # -- forwarded-literal registrations: the callee is a plain
        #    static builtin the census has no rules for, and the
        #    family name rides as string-literal DATA the builtin
        #    invokes at runtime (documented PHP callable semantics) —
        #    as a direct argument here, and in the rows further down
        #    from every other storage position (default parameter,
        #    assignment, return, split concat, anonymous-class
        #    constructor, attribute). No callee-identity rule can see
        #    these; the family-literal-mention backstop must. --------
        add("arraymap_autoload_register", {
            "entry.php": (
                "<?php\narray_map('spl_autoload_register', "
                "['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("array_map invokes its callable argument — the "
                   "registration name never appears as a callee"))
        add("cuf_arraymap_autoload_register", {
            "entry.php": (
                "<?php\ncall_user_func('array_map', "
                "'spl_autoload_register', ['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("the dispatch resolves the literal 'array_map' "
                   "target (not a censused name) — the family name "
                   "it forwards must still block"))
        add("arraywalk_autoload_register", {
            "entry.php": (
                "<?php\n$cbs = ['loader'];\n"
                "array_walk($cbs, 'spl_autoload_register');\n"
                + loader_fn + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("array_walk applies the family-name callable to "
                   "each element"))
        add("arrayfilter_autoload_register", {
            "entry.php": (
                "<?php\narray_filter(['loader'], "
                "'spl_autoload_register');\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("array_filter invokes the family-name callable "
                   "as its predicate — the return value is "
                   "irrelevant, the registration side effect is "
                   "real"))
        add("shutdown_autoload_register", {
            "entry.php": (
                "<?php\nregister_shutdown_function("
                "'spl_autoload_register', 'loader');\n"
                "register_shutdown_function(function () {\n"
                "    unserialize($_GET['x']);\n});\n" + loader_fn),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("shutdown-deferred registration: the loader is "
                   "armed before a later shutdown callback "
                   "deserializes"))
        add("cuf_nested_arraymap_autoload_register", {
            "entry.php": (
                "<?php\ncall_user_func('call_user_func', "
                "'array_map', 'spl_autoload_register', "
                "['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("nested dispatch hops end on a non-censused "
                   "forwarder — the family literal past the resolved "
                   "hops must still block"))
        add("iterator_apply_autoload_register", {
            "entry.php": (
                "<?php\niterator_apply(new ArrayIterator([1]), "
                "'spl_autoload_register', ['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("iterator_apply invokes the family-name callable "
                   "per element; the constructor argument beside it "
                   "must not confuse the scan"))
        add("arraymap_iniset_callback", {
            "entry.php": (
                "<?php\n" + loader_fn
                + "array_map('ini_set', "
                "['unserialize_callback_func'], ['loader']);\n"
                "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("ini_set forwarded through array_map with the "
                   "callback key riding in a data array — the "
                   "ini-key rules never see the call, the forwarded "
                   "'ini_set' literal must"))
        add("arraymap_literal_payload_autoload", {
            "entry.php": (
                "<?php\narray_map('spl_autoload_register', "
                "['loader']);\n" + loader_fn
                + "unserialize('O:6:\"Absent\":0:{}');\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("forwarded registration with a LITERAL payload "
                   "naming an undeclared class — the loader runs on "
                   "the payload's class name with no request "
                   "superglobal anywhere"))
        add("arrayfilter_literal_payload_autoload", {
            "entry.php": (
                "<?php\narray_filter(['loader'], "
                "'spl_autoload_register');\n" + loader_fn
                + "unserialize('O:6:\"Absent\":0:{}');\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("array_filter variant of the literal-payload "
                   "shape"))
        add("defparam_forward_autoload_register", {
            "entry.php": (
                "<?php\n"
                "function boot($cb = 'spl_autoload_register') {\n"
                "    array_map($cb, ['loader']);\n}\nboot();\n"
                + loader_fn + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("the intact family name is stored as a DEFAULT "
                   "PARAMETER VALUE, never as a call argument — the "
                   "zero-argument invocation forwards it and the "
                   "registration is real"))
        add("assigned_literal_forward_autoload_register", {
            "entry.php": (
                "<?php\n$cb = 'spl_autoload_register';\n"
                "array_map($cb, ['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("plain assignment two lines above the forwarder — "
                   "at the call site the argument is a variable, so "
                   "only the position-independent mention sees the "
                   "name"))
        add("returned_literal_forward_autoload_register", {
            "entry.php": (
                "<?php\nfunction get_cb() { "
                "return 'spl_autoload_register'; }\n"
                "array_map(get_cb(), ['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("the forwarding argument is a nested CALL — no "
                   "argument-subtree or variable-tracking reading "
                   "reaches the stored return literal"))
        add("defparam_array_static_forward_autoload_register", {
            "entry.php": (
                "<?php\nclass Cfg {\n"
                "    public static function cbs("
                "$cbs = ['spl_autoload_register']) {\n"
                "        return $cbs;\n    }\n}\n"
                "$cbs = Cfg::cbs();\n"
                "array_map($cbs[0], ['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("array default parameter on a static method, "
                   "forwarded through a subscript — the literal "
                   "lives in declarative code only"))
        add("splitconcat_forward_autoload_register", {
            "entry.php": (
                "<?php\narray_map('spl_autoload' . '_register', "
                "['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("PHP compile-time-folds adjacent literal concat: "
                   "the split spelling IS the intact name to the "
                   "engine. ground_truth_surface is EXPLICIT here "
                   "because the regex arm's intact-token pattern "
                   "cannot see the split name — this row's truth "
                   "rides the marking, not the regex census, and a "
                   "regression here is invisible to flagged-miss "
                   "accounting by construction"))
        add("anonclass_ctor_autoload_register", {
            "entry.php": (
                "<?php\n$o = new class('spl_autoload_register') {\n"
                "    public $cb;\n"
                "    public function __construct($cb) {\n"
                "        $this->cb = $cb;\n"
                "        array_map($cb, ['loader']);\n    }\n};\n"
                + loader_fn + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("anonymous-class constructor argument — the "
                   "grammar nests the argument list under the "
                   "anonymous_class child, where a per-call-shape "
                   "scan missed it; the constructor runs at creation "
                   "and registers"))
        add("attribute_literal_autoload_register", {
            "entry.php": (
                "<?php\n#[Handler('spl_autoload_register')]\n"
                "class Job {}\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("attribute-argument literal — executes only "
                   "through a reflecting invoker, but the stored "
                   "callable string escapes the tree like any other "
                   "mention and is censused fail-closed"))
        add("heredoc_indented_whole_autoload_register", {
            "entry.php": (
                "<?php\n$cb = <<<EOT\n    spl_autoload_register\n"
                "    EOT;\narray_map($cb, ['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("PHP 7.3+ flexible heredoc: the closing marker's "
                   "indentation is stripped from every body line at "
                   "compile time, so the indented body IS the intact "
                   "family name at runtime — the census must dedent "
                   "before the whole-value match or the spelling "
                   "launders past it"))
        add("heredoc_indented_splitconcat_autoload_register", {
            "entry.php": (
                "<?php\n$cb = 'spl_' . <<<EOT\n    "
                "autoload_register\n    EOT;\n"
                "array_map($cb, ['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("pure-literal concat with an indented-closer "
                   "heredoc right operand — the chain fold reads "
                   "the same dedented leaf content; like the "
                   "split-concat row, the intact-token regex arm "
                   "cannot see this spelling, so ground truth rides "
                   "the explicit marking"))
        add("nowdoc_indented_splitconcat_autoload_register", {
            "entry.php": (
                "<?php\n$cb = 'spl_' . <<<'EOT'\n    "
                "autoload_register\n    EOT;\n"
                "array_map($cb, ['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("nowdoc variant of the indented split-concat "
                   "spelling — nowdoc bodies dedent identically "
                   "(only escape decoding differs); regex-blind "
                   "like its heredoc twin"))
        add("heredoc_cr_only_autoload_register", {
            "entry.php": (
                "<?php\r$cb = <<<EOT\r    spl_autoload_register\r"
                "    EOT;\rarray_map($cb, ['loader']);\r"
                + loader_fn.replace("\n", "\r")
                + "unserialize($_GET['x']);\r"),
            "loadme.php": loaded},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("bare-CR line endings throughout — PHP accepts "
                   "them and dedents the indented body to the "
                   "intact family name (execution-verified), so "
                   "the registration is live; the newline-anchored "
                   "indentation recovery fails closed today, and "
                   "this row keeps a one-sided CR-support edit "
                   "from earning on the executing spelling"))

        # -- census degradations (tier must be withheld) --------------
        add("inc_hidden_magic", {
            "safe.php": "<?php\nfunction ok() { return 1; }\n",
            "module.inc": _GADGET_CLASS},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes="gadget class in php-like-unscanned .inc file")
        symlink_tree = add("symlink_hidden_magic", {
            "ok.php": "<?php\nfunction ok() { return 1; }\n"},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes="gadget class behind an in-tree symlink")
        outside = symlink_tree.parent / "outside.php"
        outside.write_text(_GADGET_CLASS)
        (symlink_tree / "alias.php").symlink_to(outside)
        add("parse_error_file", {
            "ok.php": "<?php\nfunction ok() { return 1; }\n",
            "broken.php": (
                "<?php\nclass Broken {\n"
                "    function __destruct( {\n        unlink($this->x\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes="magic method inside a parse-error file")
        add("binary_prefix_heredoc_autoload_register", {
            "entry.php": (
                "<?php\n$cb = b<<<EOT\n    spl_autoload_register\n"
                "    EOT;\narray_map($cb, ['loader']);\n" + loader_fn
                + "unserialize($_GET['x']);\n"),
            "loadme.php": loaded},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("b-prefixed binary-string heredoc — valid "
                   "executing PHP (execution-verified) the grammar "
                   "cannot parse: the file censuses as a parse "
                   "error and completeness breaks, so the tier is "
                   "withheld tree-wide; pins the completeness gate "
                   "against a grammar upgrade that starts "
                   "half-parsing the construct while the live "
                   "registration stays invisible"))
        pad = "// " + "x" * 61 + "\n"
        oversized = ("<?php\n"
                     + pad * (MAX_FILE_BYTES // len(pad) + 2)
                     + _GADGET_CLASS.removeprefix("<?php\n"))
        add("oversized_file", {
            "ok.php": "<?php\nfunction ok() { return 1; }\n",
            "big.php": oversized},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes="gadget class beyond the per-file size cap")

        # -- anonymous class ------------------------------------------
        add("anon_class_destruct", {"h.php": (
            "<?php\n$h = new class {\n    public $p;\n"
            "    public function __destruct() {\n"
            "        unlink($this->p);\n    }\n};\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes="anonymous-class __destruct (not chain-modeled)")

        # -- adversarial false-absence shapes (each one a live-fired
        #    repro: a working POP trigger the census once missed) -----
        entry = "<?php\nunserialize($_GET['x']);\n"
        add("trait_alias_destruct", {"entry.php": entry, "g.php": (
            "<?php\ntrait Helper {\n"
            "    public function cleanup() {\n"
            "        system($this->cmd);\n    }\n}\n"
            "class Evil {\n    public $cmd;\n"
            "    use Helper { cleanup as __destruct; }\n}\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("trait-use adaptation mints __destruct — fires on "
                   "unserialize on PHP 7.4 and 8.2"))
        add("trait_alias_call", {"entry.php": entry, "g.php": (
            "<?php\ntrait Helper {\n"
            "    public function fire($m, $a) {\n"
            "        system($this->cmd);\n    }\n}\n"
            "class Evil {\n    public $cmd;\n"
            "    use Helper { fire as __call; }\n}\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes="trait-use adaptation mints __call")
        add("uppercase_open_tag_inc", {
            "entry.php": entry,
            "lib.inc": ("<?PHP\nclass Evil {\n    public $cmd;\n"
                        "    function __destruct() {\n"
                        "        system($this->cmd);\n    }\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("<?PHP open tag is valid PHP (case-insensitive) — "
                   "the .inc must census as php-like-unscanned"))
        add("short_open_tag_inc", {
            "entry.php": entry,
            "lib.inc": ("<?\nclass Evil {\n    public $cmd;\n"
                        "    function __destruct() {\n"
                        "        system($this->cmd);\n    }\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("<? short tag is live on compiled-default builds "
                   "(short_open_tag=1) — php-like-unscanned"))
        add("xml_decl_not_php", {
            "entry.php": entry,
            "feed.xml": "<?xml version=\"1.0\"?>\n<root/>\n",
            "conf.xml": ("<?xml   version=\"1.0\" "
                         "encoding=\"UTF-8\"?>\n<cfg/>\n")},
            expected_tier=TIER_NO_GADGET_SURFACE, true_negative=True,
            notes=("guard: a REAL XML declaration (<?xml + whitespace "
                   "+ version) must NOT count as php-like — the tier "
                   "still fires; every other <?xml-prefixed shape "
                   "over-counts fail-closed (see xml_open_tag_smuggle)"))
        add("xml_open_tag_smuggle", {
            "entry.php": entry,
            "payload.xml": ("<?xml;\nclass Evil {\n    public $cmd;\n"
                            "    function __destruct() {\n"
                            "        system($this->cmd);\n    }\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("<?xml; is LIVE short-tag PHP — the class "
                   "declaration is compile-hoisted even on 8.x where "
                   "the bare xml constant then errors (7.x warns) — "
                   "the .xml must census as php-like-unscanned"))
        add("unresolved_extends", {
            "entry.php": entry,
            "g.php": ("<?php\nclass SessionCache extends "
                      "Vendor\\Framework\\BufferedHandler {\n"
                      "    public $cmd;\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("out-of-tree parent hands the child its inherited "
                   "__destruct — census must break on "
                   "unresolved-parents"))
        add("extends_exception_only", {
            "entry.php": entry,
            "e.php": ("<?php\nclass ParseFailure extends Exception "
                      "{\n}\n"
                      "class LimitHit extends \\RuntimeException "
                      "{\n}\n")},
            expected_tier=TIER_NO_GADGET_SURFACE, true_negative=True,
            notes=("guard: GLOBAL-context bare and leading-backslash "
                   "PHP-internal bases carry no in-tree trigger code "
                   "— the tier still fires; a namespaced or "
                   "import-aliased bare name never takes this path "
                   "(see namespace_relative_extends / "
                   "use_alias_extends)"))
        add("namespace_relative_extends", {
            "entry.php": entry,
            "g.php": ("<?php\nnamespace App;\n"
                      "class SessionCache extends Exception {\n"
                      "    public $cmd;\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("inside a namespace the bare parent means "
                   "App\\Exception (PHP classes have no global "
                   "fallback) — an out-of-tree parent, not the "
                   "internal Exception; census must break on "
                   "unresolved-parents"))
        add("use_alias_extends", {
            "entry.php": entry,
            "g.php": ("<?php\nuse OtherNS\\Evil as Exception;\n"
                      "class SessionCache extends Exception {\n"
                      "    public $cmd;\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("the use import rebinds the bare name Exception "
                   "to OtherNS\\Evil — an out-of-tree parent; census "
                   "must break on unresolved-parents"))
        add("alias_cross_namespace_unbraced", {
            "entry.php": entry,
            "decoy.php": "<?php\nnamespace Some;\nclass Benign { }\n",
            "g.php": ("<?php\nnamespace A;\n"
                      "use Some\\Benign as Exception;\n"
                      "namespace B;\n"
                      "class SessionCache extends Exception {\n"
                      "    public $cmd;\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("namespace A's import must not resolve namespace "
                   "B's bare parent onto the in-tree decoy — PHP "
                   "resolves B\\Exception and autoloads it out of "
                   "tree; census must break on unresolved-parents"))
        add("alias_cross_namespace_braced", {
            "entry.php": entry,
            "decoy.php": "<?php\nnamespace Some;\nclass Benign { }\n",
            "g.php": ("<?php\nnamespace A {\n"
                      "    use Some\\Benign as Exception;\n}\n"
                      "namespace B {\n"
                      "    class SessionCache extends Exception {\n"
                      "        public $cmd;\n    }\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("braced form of alias_cross_namespace_unbraced; "
                   "census must break on unresolved-parents"))
        add("alias_cross_namespace_trait", {
            "entry.php": entry,
            "g.php": ("<?php\nnamespace Some;\n"
                      "trait Benign { public function h() { } }\n"
                      "namespace A;\n"
                      "use Some\\Benign as Helper;\n"
                      "namespace B;\n"
                      "class SessionCache {\n"
                      "    use Helper;\n    public $cmd;\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("namespace A's import must not resolve namespace "
                   "B's trait use onto the same-file decoy trait — "
                   "PHP resolves B\\Helper and autoloads it out of "
                   "tree; census must break on unresolved-traits"))
        add("alias_before_declaration", {
            "entry.php": entry,
            "g.php": ("<?php\nnamespace Some {\n"
                      "    class Benign { }\n}\n"
                      "namespace {\n"
                      "    class SessionCache extends VendorBase {\n"
                      "        public $cmd;\n    }\n"
                      "    use Some\\Benign as VendorBase;\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("an import applies from its declaration point "
                   "onward — the earlier reference resolves under "
                   "the namespace alone (global VendorBase, out of "
                   "tree); census must break on unresolved-parents"))
        add("kelvin_casefold_extends", {
            "entry.php": entry,
            "decoy.php": "<?php\nclass Khelper { }\n",
            "g.php": ("<?php\nclass SessionCache extends "
                      "\u212ahelper {\n    public $cmd;\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("U+212A KELVIN SIGN parent: full-Unicode "
                   "casefolding would match the in-tree ASCII "
                   "Khelper decoy, but PHP folds ASCII only and "
                   "autoloads the Kelvin-named class out of tree; "
                   "census must break on unresolved-parents"))
        add("dead_branch_class_decoy", {
            "entry.php": entry,
            "decoy.php": ("<?php\nif (PHP_VERSION_ID < 0) {\n"
                          "    class VendorBase { }\n}\n"),
            "g.php": ("<?php\nclass SessionCache extends VendorBase "
                      "{\n    public $cmd;\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("decoy parent inside a never-true if body — PHP "
                   "does not compile-hoist it, so the real parent is "
                   "autoloaded out of tree; census must break on "
                   "unresolved-parents"))
        add("dead_branch_function_class_decoy", {
            "entry.php": entry,
            "decoy.php": ("<?php\nfunction never_called() {\n"
                          "    class VendorBase { }\n}\n"),
            "g.php": ("<?php\nclass SessionCache extends VendorBase "
                      "{\n    public $cmd;\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("decoy parent inside an uncalled function — same "
                   "non-hoisting rule as dead_branch_class_decoy; "
                   "census must break on unresolved-parents"))
        add("dead_branch_trait_decoy", {
            "entry.php": entry,
            "g.php": ("<?php\nif (PHP_VERSION_ID < 0) {\n"
                      "    trait VendorTrait {\n"
                      "        public function h() { }\n    }\n}\n"
                      "class SessionCache {\n"
                      "    use VendorTrait;\n    public $cmd;\n}\n")},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("same-file decoy trait inside a never-true if "
                   "body — PHP does not compile-hoist it; census "
                   "must break on unresolved-traits"))
        add("resolved_parent_in_tree", {
            "parent.php": ("<?php\nclass BaseHandler {\n"
                           "    public function __destruct() {\n"
                           "        error_log('bye');\n    }\n}\n"),
            "child.php": ("<?php\nclass Child extends BaseHandler "
                          "{\n}\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("in-tree parent resolves: census complete, the "
                   "parent's own __destruct is counted surface"))
        add("node_modules_hidden", {
            "entry.php": entry,
            "node_modules/pkg/gadget.php": _GADGET_CLASS},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("gadget parked in a walk-skipped dir — census "
                   "must break on walk-skipped-dirs"))
        add("git_hidden", {
            "entry.php": entry,
            ".git/hooks/post-checkout.php": _GADGET_CLASS},
            expected_tier=TIER_NONE,
            ground_truth_surface=True,
            notes=("gadget in .git/hooks/ — the regex arm skips .git "
                   "by design, so ground truth here is the row label"))
        add("skipped_dir_without_php", {
            "entry.php": entry,
            "node_modules/pkg/index.js": "console.log(1);\n",
            "node_modules/pkg/package.json": "{}\n"},
            expected_tier=TIER_NO_GADGET_SURFACE, true_negative=True,
            notes=("guard: a PHP-free node_modules must not block "
                   "the tier"))
        add("create_function_class", {"d.php": (
            "<?php\ncreate_function('', 'class Evil { public $c; "
            "function __destruct() { system($this->c); } } "
            "return 1;');\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("create_function body is eval'd (PHP <= 7.4) and "
                   "can define a class"))
        add("preg_replace_eval_modifier", {"d.php": (
            "<?php\npreg_replace('/x/e', $_GET['r'], "
            "$_GET['s']);\n")},
            expected_tier=TIER_NO_CHAINS_FOUND,
            ground_truth_surface=True,
            notes=("/e-modified preg_replace evaluates the "
                   "replacement (PHP <= 5.4)"))

        # -- per-method surface family: one row per POP-surface
        #    method, each with a direct property sink. Pins every
        #    member of the census set individually. -------------------
        for canonical in _CANONICAL_POP:
            modeled = canonical in _CHAIN_MODELED
            add(f"surface_{canonical.lower().lstrip('_')}", {"m.php": (
                "<?php\nclass Carrier {\n    public $cmd;\n"
                f"    public function {canonical}() {{\n"
                "        system($this->cmd);\n    }\n}\n")},
                expected_tier=(TIER_NONE if modeled
                               else TIER_NO_CHAINS_FOUND),
                expect_chain=modeled,
                ground_truth_surface=True,
                notes=("chain-modeled trigger" if modeled
                       else "census-only surface (not chain-modeled)"))

        # -- true negatives (the usefulness direction) ----------------
        add("procedural_only", {"f.php": (
            "<?php\nfunction handle($input) {\n"
            "    return htmlspecialchars($input);\n}\n"
            "handle($_GET['x']);\n")},
            expected_tier=TIER_NO_GADGET_SURFACE, true_negative=True,
            notes="true negative: no classes at all")
        add("classes_without_magic", {"c.php": (
            "<?php\nclass Repo {\n    private $rows = [];\n"
            "    public function add($row) { $this->rows[] = $row; }\n"
            "    public function all() { return $this->rows; }\n}\n"
            "class Mapper {\n"
            "    public function map($x) { return trim($x); }\n}\n")},
            expected_tier=TIER_NO_GADGET_SURFACE, true_negative=True,
            notes="true negative: classes, zero magic methods")
        add("interface_only", {"i.php": (
            "<?php\ninterface Storage {\n"
            "    public function fetch($key);\n"
            "    public function store($key, $value);\n}\n")},
            expected_tier=TIER_NO_GADGET_SURFACE, true_negative=True,
            notes="true negative: interface-only tree")
        add("construct_only", {"p.php": (
            "<?php\nclass Plain {\n    public $x;\n"
            "    public function __construct($x) {\n"
            "        $this->x = $x;\n    }\n}\n")},
            expected_tier=TIER_NO_GADGET_SURFACE, true_negative=True,
            notes=("true negative: __construct is not POP surface — "
                   "pins the census is not naively __-prefixed"))
        return rows


# ---------------------------------------------------------------------------
# Library corpus driver
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LibrarySpec:
    """One pinned public clone. ``chains`` are phpggc-documented
    (github.com/ambionics/phpggc, ``gadgetchains/`` — catalog commit
    f8aebde3a1abb88b02042fd12a71b4c61d6cfe2c)."""
    row: str
    repo: str
    tag: str
    commit: str
    chains: tuple[ChainLabel, ...] = ()
    true_negative: bool = False
    notes: str = ""


#: The measured roster. Version ranges are the phpggc chain.php
#: version strings; entry classes are the trigger-carrying gadget
#: class (short name) from each chain's gadgets.php.
LIBRARY_ROSTER: tuple[LibrarySpec, ...] = (
    LibrarySpec(
        row="guzzle-6.3.2",
        repo="https://github.com/guzzle/guzzle",
        tag="6.3.2",
        commit="68d0ea14d5a3f42a20e87632a5f84931e2709c90",
        chains=(
            ChainLabel("Guzzle/FW1", "FileCookieJar",
                       "4.0.0-rc.2 <= 7.5.0+"),
            ChainLabel("Guzzle/RCE1", "FnStream", "6.0.0 <= 6.3.2"),
        ),
        notes=("Guzzle/FW1 is the one-hop shape: FileCookieJar::"
               "__destruct -> save($this->filename) -> "
               "file_put_contents — the findable-chain candidate"),
    ),
    LibrarySpec(
        row="monolog-1.18.0",
        repo="https://github.com/Seldaek/monolog",
        tag="1.18.0",
        commit="e19b764b5c855580e8ffa7e615f72c10fd2f99cc",
        chains=(
            ChainLabel("Monolog/RCE1", "SyslogUdpHandler",
                       "1.4.1 <= 1.6.0 / 1.17.2 <= 2.7.0+"),
            ChainLabel("Monolog/RCE2", "SyslogUdpHandler",
                       "1.4.1 <= 2.7.0+"),
        ),
    ),
    LibrarySpec(
        row="swiftmailer-5.4.1",
        repo="https://github.com/swiftmailer/swiftmailer",
        tag="v5.4.1",
        commit="0697e6aa65c83edf97bb0f23d8763f94e3f11421",
        chains=(
            ChainLabel("SwiftMailer/FW1", "Swift_Message",
                       "5.1.0 <= 5.4.8"),
        ),
    ),
    LibrarySpec(
        row="slim-3.8.1",
        repo="https://github.com/slimphp/Slim",
        tag="3.8.1",
        commit="5385302707530b2bccee1769613ad769859b826d",
        chains=(
            ChainLabel("Slim/RCE1", "Response", "3.8.1"),
        ),
    ),
    LibrarySpec(
        row="yii2-2.0.16",
        repo="https://github.com/yiisoft/yii2",
        tag="2.0.16",
        commit="ed64d6588630f9a1df92041fd5ca4087e786f3fb",
        chains=(
            ChainLabel("Yii2/RCE1", "BatchQueryResult", "<2.0.38"),
            ChainLabel("Yii2/RCE2", "BatchQueryResult", "<2.0.38"),
        ),
    ),
    LibrarySpec(
        row="laravel-5.4.27",
        repo="https://github.com/laravel/framework",
        tag="v5.4.27",
        commit="66f5e1b37cbd66e730ea18850ded6dc0ad570404",
        chains=(
            ChainLabel("Laravel/RCE1", "PendingBroadcast", "5.4.27"),
            ChainLabel("Laravel/RCE4", "PendingBroadcast",
                       "5.4.0 <= 8.6.9+"),
        ),
    ),
    LibrarySpec(
        row="psr-log-1.1.4",
        repo="https://github.com/php-fig/log",
        tag="1.1.4",
        commit="d49695b909c3b7628b6289db5479a1c204601f11",
        notes=("looks zero-surface but is NOT: __toString/__call in "
               "Psr/Log/Test helpers — documents that real interface "
               "packages carry surprise surface; tier must not fire"),
    ),
    LibrarySpec(
        row="psr-container-1.1.1",
        repo="https://github.com/php-fig/container",
        tag="1.1.1",
        commit="8622567409010282b7aeebe4bb841fe98b58dcaf",
        true_negative=True,
        notes="verified zero-surface interface package",
    ),
    LibrarySpec(
        row="psr-event-dispatcher-1.0.0",
        repo="https://github.com/php-fig/event-dispatcher",
        tag="1.0.0",
        commit="dbefd12671e8a14ec7f180cab83036ed26714bb0",
        true_negative=True,
        notes="verified zero-surface interface package",
    ),
)


def _git(args: list[str], cwd: Path | None = None) -> str:
    """Run one git command (list-args only; never a shell string)."""
    result = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True,
        timeout=600, check=True,
    )
    return result.stdout.strip()


class LibraryCorpusDriver:
    """Pinned public clones under :data:`LIBRARY_CACHE`. Every clone
    is verified against its pinned commit sha — a cache dir at the
    wrong commit is a hard error, never a silent measurement of the
    wrong tree. Operator-run only (network); never a CI test."""

    name = "library"
    description = ("pinned public clones labeled with phpggc-"
                   "documented chains + zero-surface packages")
    mode: Mode = "library"

    def __init__(self, cache: Path = LIBRARY_CACHE,
                 roster: tuple[LibrarySpec, ...] = LIBRARY_ROSTER):
        self.cache = cache
        self.roster = roster

    def _ensure_clone(self, spec: LibrarySpec) -> Path:
        dest = self.cache / spec.row
        if not dest.is_dir():
            self.cache.mkdir(parents=True, exist_ok=True)
            logger.info("cloning %s @ %s ...", spec.repo, spec.tag)
            _git(["clone", "--quiet", "--depth", "1", "--branch",
                  spec.tag, spec.repo, str(dest)])
        head = _git(["rev-parse", "HEAD"], cwd=dest)
        if head != spec.commit:
            raise RuntimeError(
                f"{spec.row}: cache at {dest} is at commit {head}, "
                f"pinned {spec.commit} — refusing to measure the "
                f"wrong tree (delete the dir to re-clone)")
        return dest

    def prepare(self, work_dir: Path) -> list[PreparedRow]:
        rows: list[PreparedRow] = []
        for spec in self.roster:
            tree = self._ensure_clone(spec)
            rows.append(PreparedRow(
                name=spec.row,
                tree=tree,
                expected_tier=None,
                expect_chain=False,
                ground_truth_surface=bool(spec.chains) or (
                    not spec.true_negative and bool(spec.notes)),
                true_negative=spec.true_negative,
                documented_chains=spec.chains,
                notes=spec.notes,
            ))
        return rows


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def registry() -> dict[str, CorpusDriver]:
    """Known corpora."""
    return {
        "synthetic": SyntheticCorpusDriver(),
        "library": LibraryCorpusDriver(),
    }


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. A completed run always exits 0 — even when
    false absences were measured: this is a measurement tool, not a
    gate. The miss count lands in the printed summary and the report
    artifact; consumers deciding on the numbers read those, never
    the exit code (non-zero exits mark only unusable invocations)."""
    p = argparse.ArgumentParser(
        prog="gadget-oracle-precision",
        description=(
            "Measure gadget-oracle absence-tier precision against "
            "labeled PHP corpora. The load-bearing number is the "
            "false-absence rate for no_gadget_surface — it gates "
            "whether ABSENCE_EARNS_SUPPRESSION may ever flip."
        ),
    )
    p.add_argument("--corpus", action="append", default=[],
                   help="corpus name (repeatable). Default: synthetic.")
    p.add_argument("--list", action="store_true",
                   help="list known corpora and exit")
    p.add_argument("--out", type=Path, default=None,
                   help=("output dir (default: "
                         "out/gadget-oracle-precision/runs/<ts>)"))
    args = p.parse_args(argv)

    reg = registry()
    if args.list:
        for name, drv in sorted(reg.items()):
            print(f"  {name:12}  {drv.description}")
        return 0

    names: list[str] = args.corpus or ["synthetic"]
    unknown = [n for n in names if n not in reg]
    if unknown:
        print(f"unknown corpora: {unknown}; --list to see options",
              file=sys.stderr)
        return 2

    # Anchor outputs to RAPTOR's out dir (binary-oracle precedent) so
    # reports never land cwd-relative.
    from core.config import RaptorConfig
    out_dir: Path
    if args.out is None:
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_dir = (Path(RaptorConfig.BASE_OUT_DIR)
                   / "gadget-oracle-precision" / "runs" / ts)
    else:
        out_dir = args.out
    cache_root = (Path(RaptorConfig.BASE_OUT_DIR)
                  / "gadget-oracle-precision" / "cache")

    reports: list[CorpusReport] = []
    for name in names:
        logger.info("measuring corpus %s ...", name)
        reports.append(run_corpus(reg[name], cache_root / name))

    json_path = write_report(reports, out_dir)
    agg = aggregate(reports)
    print(
        f"false-absence: {agg['false_absence_count_total']}/"
        f"{agg['false_absence_denominator_total']}"
    )
    if agg["true_negative_rows_total"]:
        print(
            f"tier-fire on true negatives: "
            f"{agg['tier_fired_on_negatives_total']}/"
            f"{agg['true_negative_rows_total']}"
        )
    print(f"report: {json_path}")
    return 0


__all__ = [
    "LIBRARY_CACHE",
    "LIBRARY_ROSTER",
    "REGEX_POP_METHODS",
    "ChainLabel",
    "CorpusDriver",
    "CorpusReport",
    "LibraryCorpusDriver",
    "LibrarySpec",
    "Mode",
    "PreparedRow",
    "RowMeasurement",
    "SyntheticCorpusDriver",
    "aggregate",
    "cross_tab_rows",
    "main",
    "measure_row",
    "regex_surface_census",
    "registry",
    "run_corpus",
    "write_report",
]


if __name__ == "__main__":
    sys.exit(main())
