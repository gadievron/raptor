"""Expanded-view (fidelity-3) semgrep for macro-hidden sink coverage.

Pattern rules match the source AS WRITTEN — anything hidden behind a
macro (``LIST_FOREACH`` wrappers, lock macros, allocator wrappers) is
invisible to them.  This module runs semgrep against the fidelity-3
preprocessor-expanded view built by
:mod:`core.audit.preprocessor_view` and translates match line numbers
back through the linemarker line map to ORIGINAL file coordinates.

Two consumers:

* :func:`core.audit.sweep.run_semgrep_sweep` — second pass when the
  plain pass produced no in-range match and the function's source
  shows macro invocations (cheap textual gate).  A confirmed match is
  evidence-stamped distinctly (``semgrep:<rule>:expanded``) so
  downstream review can see it came from the expanded view.
* the ``--expanded-semgrep`` /scan stage — re-runs the loaded ruleset
  over expanded views of macro-heavy TUs, emitting findings with
  original-coordinate locations and an ``expanded_view`` marker.

Noise policy: ONLY matches whose expanded line maps back to a line
inside the file being examined are kept.  System-header expansion has
``None`` map entries and other-file (header) expansion maps elsewhere
— both are dropped with a debug log, never surfaced as findings.

Failure policy: preprocess failure (missing generated headers, exotic
dialects) is a degraded result with a reason — never an exception that
kills the caller and never a fabricated view.

Bounds: expansion reuses preprocessor_view's per-run budget convention
(``_AUGMENT_FILE_CAP`` preprocessor runs); views are cached per file so
repeated hypotheses against the same TU pay the preprocessor once.
The semgrep invocation reuses ``packages.semgrep.runner.run_rule`` —
the same path :mod:`core.audit.sweep` uses.
"""

from __future__ import annotations

import logging
import os
import re
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._util import safe_join
from .preprocessor_view import (
    _AUGMENT_FILE_CAP,
    _CXX_SUFFIXES,
    ExpandedView,
    expand_translation_unit,
)

logger = logging.getLogger(__name__)

# C-family suffixes eligible for expansion. Headers included for the
# audit-side second pass (a .h preprocesses fine as a lone TU); the
# scan-side corpus walks proper TUs only (headers are covered through
# the TUs that include them).
_C_FAMILY_SUFFIXES = frozenset({".c", ".h"}) | _CXX_SUFFIXES
_TU_SUFFIXES = frozenset({".c"}) | (_CXX_SUFFIXES - {".hh", ".hpp", ".hxx"})

_SEMGREP_TIMEOUT_S = 120

# Cheap textual gate: an ALL_CAPS function-like macro invocation.
# preprocessor_view's prefilter (``_MACRO_INVOCATION_RE``) anchors to
# column 0 because it hunts DEFINE_HANDLER-style definition
# generators; here the interesting shapes are also *inside* function
# bodies (``LIST_FOREACH(...)``, ``SPIN_LOCK(...)``), so the same
# heuristic is relaxed to a word boundary anywhere on the line.
_MACRO_USE_RE = re.compile(r"\b[A-Z_][A-Z0-9_]{2,}\s*\(")


def is_c_family(file_path: str) -> bool:
    """Is *file_path* a C/C++ source or header (expandable)?"""
    return Path(file_path).suffix in _C_FAMILY_SUFFIXES


def has_macro_invocation(text: str) -> bool:
    """Does *text* contain a function-like ALL_CAPS macro invocation?"""
    return bool(_MACRO_USE_RE.search(text or ""))


# ---------------------------------------------------------------------------
# Per-run expansion budget (preprocessor_view's cap convention) + view cache
# ---------------------------------------------------------------------------


class ExpansionBudget:
    """Bounded, cached access to fidelity-3 views.

    At most *max_expansions* preprocessor runs are charged; views are
    cached per ``(target, file)`` so re-examining the same TU is free.
    Failed views are cached too — a TU that will not preprocess should
    not be retried on every hypothesis.  Thread-safe (the orchestrator
    sweeps concurrently).
    """

    def __init__(self, max_expansions: int = _AUGMENT_FILE_CAP):
        self.max_expansions = max_expansions
        self.used = 0
        self._views: dict[tuple[str, str], ExpandedView] = {}
        self._lock = threading.Lock()

    def view_for(
        self,
        target_path: Path,
        file_path: str,
        *,
        macro_config: Any = None,
        out_dir: Path | None = None,
    ) -> ExpandedView | None:
        """Cached fidelity-3 view, or None when the budget is spent.

        Cached entries (ok or degraded) never re-charge the budget.
        """
        key = (str(target_path), file_path)
        with self._lock:
            if key in self._views:
                return self._views[key]
            if self.used >= self.max_expansions:
                return None
            self.used += 1
        view = expand_translation_unit(
            target_path=Path(target_path),
            file_path=file_path,
            macro_config=macro_config,
            out_dir=out_dir,
        )
        with self._lock:
            self._views[key] = view
        return view


# Process-level budget for the audit-side second pass: one orchestrator
# run is one process, so this bounds the pass exactly the way
# preprocessor_view's checklist augmentation bounds itself.
_PROCESS_BUDGET = ExpansionBudget()


def _reset_process_budget(max_expansions: int = _AUGMENT_FILE_CAP) -> None:
    """Test hook: replace the process budget."""
    global _PROCESS_BUDGET
    _PROCESS_BUDGET = ExpansionBudget(max_expansions)


# ---------------------------------------------------------------------------
# Audit-side: one (target, file, rule) expanded pass
# ---------------------------------------------------------------------------


@dataclass
class ExpandedRuleResult:
    """Result of running one semgrep rule against one expanded TU.

    ``matches`` carry ORIGINAL coordinates (``line`` in *file_path*);
    ``dropped_out_of_file`` counts matches whose origin was a system
    header / another file (noise, excluded by policy).  ``ok=False``
    with *reason* is the graceful degradation shape — preprocess
    failure, budget exhaustion, semgrep failure — never an exception.
    """

    ok: bool
    file_path: str
    rule_config: str = ""
    matches: list[dict[str, Any]] = field(default_factory=list)
    dropped_out_of_file: int = 0
    reason: str = ""


def run_expanded_semgrep_rule(
    *,
    target_path: Path,
    file_path: str,
    rule_config: str,
    line_start: int = 0,
    line_end: int = 0,
    macro_config: Any = None,
    out_dir: Path | None = None,
    budget: ExpansionBudget | None = None,
    timeout: int = _SEMGREP_TIMEOUT_S,
) -> ExpandedRuleResult:
    """Run *rule_config* against the fidelity-3 view of *file_path*.

    Produces the expanded view via preprocessor_view (budgeted,
    cached), writes it to a scratch file with the original suffix
    (semgrep language detection), runs semgrep on it via the same
    ``packages.semgrep.runner.run_rule`` path the sweep engine uses,
    then translates match lines back through the line map.  Only
    matches mapping to lines inside *file_path* (and inside
    ``[line_start, line_end]`` when given) are kept.
    """

    def _degraded(reason: str) -> ExpandedRuleResult:
        logger.debug(
            "expanded_semgrep degraded for %s: %s", file_path, reason,
        )
        return ExpandedRuleResult(
            ok=False, file_path=file_path, rule_config=rule_config,
            reason=reason,
        )

    if not is_c_family(file_path):
        return _degraded(f"not a C/C++ file: {file_path}")
    if safe_join(Path(target_path), file_path) is None:
        return _degraded(f"path escapes target: {file_path}")

    budget = budget if budget is not None else _PROCESS_BUDGET
    view = budget.view_for(
        Path(target_path), file_path,
        macro_config=macro_config, out_dir=out_dir,
    )
    if view is None:
        return _degraded(
            f"expansion budget exhausted "
            f"({budget.max_expansions} preprocessor runs)",
        )
    if not view.ok:
        return _degraded(
            "no fidelity-3 view: " + "; ".join(str(e) for e in view.errors),
        )

    try:
        from packages.semgrep.runner import is_available, run_rule
    except ImportError as exc:
        return _degraded(f"semgrep runner unavailable: {exc}")
    if not is_available():
        return _degraded("semgrep not installed")

    suffix = Path(file_path).suffix or ".c"
    scratch = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", prefix="expanded_", suffix=suffix,
            delete=False, encoding="utf-8", errors="replace",
        ) as f:
            f.write(view.text)
            scratch = Path(f.name)

        try:
            result = run_rule(scratch, rule_config, timeout=timeout)
        except Exception as exc:  # noqa: BLE001 — degrade, never kill the caller
            return _degraded(f"semgrep on expanded view failed: {exc}")

        if result.errors and not result.findings:
            return _degraded(
                "semgrep errors on expanded view: "
                + "; ".join(result.errors[:3]),
            )

        tu_rel = file_path.replace(os.sep, "/")
        matches: list[dict[str, Any]] = []
        dropped = 0
        for finding in result.findings:
            exp_line = getattr(finding, "line", 0) or 0
            origin = view.origin_of(exp_line)
            if origin is None or origin[0] != tu_rel:
                # System-header / other-file expansion — noise by policy.
                dropped += 1
                logger.debug(
                    "expanded_semgrep: dropping match at expanded line %d "
                    "of %s (origin %s — outside the target file)",
                    exp_line, file_path,
                    origin[0] if origin else "<unattributable>",
                )
                continue
            orig_line = origin[1]
            if line_start and orig_line < line_start:
                continue
            if line_end and orig_line > line_end:
                continue
            matches.append({
                "line": orig_line,
                "expanded_line": exp_line,
                "rule_id": getattr(finding, "rule_id", "") or "",
                "message": getattr(finding, "message", "") or "",
                "file": tu_rel,
                "expanded_view": True,
            })

        return ExpandedRuleResult(
            ok=True, file_path=file_path, rule_config=rule_config,
            matches=matches, dropped_out_of_file=dropped,
        )
    finally:
        if scratch is not None:
            try:
                os.unlink(scratch)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Scan-side: expanded corpus of macro-heavy TUs
# ---------------------------------------------------------------------------


@dataclass
class ExpandedTu:
    """One TU's expanded copy in the scan corpus.

    Expanded copies deliberately preserve the original relative layout
    inside the scratch root, so ``original_rel`` doubles as the
    corpus-relative path.
    """

    original_rel: str
    view: ExpandedView


@dataclass
class ExpandedCorpus:
    """Scratch directory of expanded views for the /scan stage."""

    root: Path
    tus: dict[str, ExpandedTu] = field(default_factory=dict)  # original_rel →
    candidates_total: int = 0   # macro-heavy TUs discovered
    expanded: int = 0
    skipped_budget: int = 0
    failed: int = 0

    def summary_line(self) -> str:
        parts = [
            (
                f"expanded-semgrep: {self.expanded}/{self.candidates_total} "
                f"macro-heavy TU(s) expanded"
            )
        ]
        if self.failed:
            parts.append(f"{self.failed} failed to preprocess")
        if self.skipped_budget:
            parts.append(
                f"⚠️  {self.skipped_budget} TU(s) SKIPPED by the expansion "
                f"budget — no silent coverage claim for them"
            )
        return "; ".join(parts)


def _iter_candidate_tus(target_path: Path) -> list[str]:
    """Sorted repo-relative C/C++ TU paths, inventory exclusions applied."""
    from core.inventory.exclusions import DEFAULT_EXCLUDES, should_exclude

    target_path = Path(target_path)
    tus: list[str] = []
    for root, subdirs, files in os.walk(target_path, followlinks=False):
        subdirs[:] = sorted(d for d in subdirs if not d.startswith("."))
        for name in sorted(files):
            if Path(name).suffix not in _TU_SUFFIXES:
                continue
            rel = os.path.relpath(os.path.join(root, name), target_path)
            if should_exclude(rel, DEFAULT_EXCLUDES):
                continue
            tus.append(rel.replace(os.sep, "/"))
    return sorted(tus)


def build_expanded_corpus(
    target_path: Path,
    scratch_root: Path,
    *,
    max_tus: int = _AUGMENT_FILE_CAP,
    macro_config: Any = None,
    out_dir: Path | None = None,
) -> ExpandedCorpus:
    """Expand macro-heavy TUs into *scratch_root* for a corpus scan.

    Walks the target's C/C++ TUs (inventory exclusion rules reused),
    keeps files passing the macro-invocation gate, and expands up to
    *max_tus* of them (preprocessor_view's per-run budget convention).
    Expanded copies preserve the relative layout and suffix so semgrep
    language detection and result paths stay predictable.  Best-effort
    per file; preprocess failures are counted, never raised.
    """
    target_path = Path(target_path)
    scratch_root = Path(scratch_root)
    scratch_root.mkdir(parents=True, exist_ok=True)
    corpus = ExpandedCorpus(root=scratch_root)

    budget = max_tus
    for rel in _iter_candidate_tus(target_path):
        resolved = safe_join(target_path, rel)
        if resolved is None or not resolved.is_file():
            continue
        try:
            raw = resolved.read_text(errors="replace")
        except OSError:
            continue
        if not has_macro_invocation(raw):
            continue
        corpus.candidates_total += 1
        if budget <= 0:
            corpus.skipped_budget += 1
            continue
        budget -= 1
        view = expand_translation_unit(
            target_path=target_path,
            file_path=rel,
            macro_config=macro_config,
            out_dir=out_dir,
        )
        if not view.ok:
            corpus.failed += 1
            logger.debug(
                "expanded corpus: %s failed to preprocess: %s",
                rel, "; ".join(str(e) for e in view.errors),
            )
            continue
        dest = scratch_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            dest.write_text(view.text, encoding="utf-8", errors="replace")
        except OSError as exc:
            corpus.failed += 1
            logger.debug("expanded corpus: could not write %s: %s", dest, exc)
            continue
        corpus.expanded += 1
        corpus.tus[rel] = ExpandedTu(original_rel=rel, view=view)

    if corpus.skipped_budget:
        logger.warning(
            "expanded-semgrep: expansion budget reached — %d of %d "
            "macro-heavy TU(s) expanded; %d SKIPPED",
            corpus.expanded, corpus.candidates_total, corpus.skipped_budget,
        )
    return corpus


def _rel_in_corpus(root: Path, finding_file: str) -> str | None:
    """Corpus-relative path for a semgrep finding location, or None.

    Semgrep spells result paths differently across versions and
    invocation shapes (absolute, relative to the scanned dir, relative
    to the cwd) — resolve all three against the corpus root.
    """
    if not finding_file:
        return None
    try:
        root_real = os.path.realpath(root)
    except OSError:
        return None
    p = Path(finding_file)
    candidates = [p] if p.is_absolute() else [root / p, Path.cwd() / p]
    for cand in candidates:
        try:
            real = os.path.realpath(cand)
        except OSError:
            continue
        if real.startswith(root_real + os.sep) and os.path.isfile(real):
            return os.path.relpath(real, root_real).replace(os.sep, "/")
    return None


def translate_corpus_findings(
    corpus: ExpandedCorpus,
    findings: list[Any],
) -> tuple[list[dict[str, Any]], int]:
    """Translate corpus-scan findings back to original coordinates.

    Returns ``(translated, dropped)``.  Kept findings are dicts with
    ``file`` (original repo-relative path), ``line`` (original line),
    ``expanded_line``, ``rule_id``, ``message`` and the
    ``expanded_view`` marker.  Matches in unattributable regions
    (system headers) or mapping into a different file than the TU that
    pulled them in are dropped with a debug log.  Duplicate
    (rule, file, line) hits are collapsed.
    """
    translated: list[dict[str, Any]] = []
    dropped = 0
    seen: set[tuple[str, str, int]] = set()
    for finding in findings:
        f_file = getattr(finding, "file", "") or ""
        rel = _rel_in_corpus(corpus.root, f_file)
        tu = corpus.tus.get(rel) if rel else None
        if tu is None:
            dropped += 1
            logger.debug(
                "expanded-semgrep: dropping match in %r (not a corpus TU)",
                f_file,
            )
            continue
        exp_line = getattr(finding, "line", 0) or 0
        origin = tu.view.origin_of(exp_line)
        if origin is None or origin[0] != tu.original_rel:
            dropped += 1
            logger.debug(
                "expanded-semgrep: dropping match at expanded line %d of "
                "%s (origin %s — outside the target file)",
                exp_line, tu.original_rel,
                origin[0] if origin else "<unattributable>",
            )
            continue
        rule_id = getattr(finding, "rule_id", "") or ""
        key = (rule_id, tu.original_rel, origin[1])
        if key in seen:
            continue
        seen.add(key)
        translated.append({
            "file": tu.original_rel,
            "line": origin[1],
            "expanded_line": exp_line,
            "rule_id": rule_id,
            "message": getattr(finding, "message", "") or "",
            "expanded_view": True,
        })
    return translated, dropped


# ---------------------------------------------------------------------------
# SARIF for the /scan stage
# ---------------------------------------------------------------------------

_SARIF_SCHEMA_URI = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master"
    "/Documents/CommitteeSpecifications/2.1.0/sarif-schema-2.1.0.json"
)
_TOOL_NAME = "semgrep-expanded"


def findings_to_sarif(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """SARIF 2.1.0 document for translated expanded-view findings.

    Distinct ``tool.driver.name`` (``semgrep-expanded``) keeps these
    results a separate run in combined.sarif — downstream review sees
    the marker instead of silently mixing expanded-view hits into the
    plain semgrep run.  Every result carries
    ``properties.expanded_view: true`` and original coordinates.
    """
    rule_defs: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    results: list[dict[str, Any]] = []
    for f in findings:
        rule_id = f.get("rule_id") or "(unnamed)"
        if rule_id not in seen_rules:
            rule_defs.append({
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": rule_id},
                "defaultConfiguration": {"level": "warning"},
            })
            seen_rules.add(rule_id)
        results.append({
            "ruleId": rule_id,
            "level": "warning",
            "message": {
                "text": f.get("message") or f"{rule_id} matched "
                        "(fidelity-3 expanded view)",
            },
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.get("file", "")},
                    "region": {"startLine": f.get("line", 0)},
                },
            }],
            "properties": {
                "expanded_view": True,
                "expanded_line": f.get("expanded_line", 0),
            },
        })
    return {
        "$schema": _SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": _TOOL_NAME,
                    "fullName": "Semgrep over fidelity-3 preprocessor-"
                                "expanded views (macro-hidden sinks)",
                    "rules": rule_defs,
                },
            },
            "results": results,
        }],
    }
