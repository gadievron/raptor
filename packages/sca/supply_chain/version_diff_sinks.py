"""Mechanical sink annotation for version diffs.

Given source file contents from two versions of a dependency, this
module identifies:

  - Sinks ADDED in the new version (new dangerous call sites)
  - Sinks REMOVED from the new version
  - Guard changes around existing sinks (guard added/removed/weakened)

Tree-sitter only — no Joern dependency. Designed as a pre-LLM
enrichment step for ``llm/version_diff_review.py``: the mechanical
sink diff focuses the LLM reviewer on security-relevant changes and
provides structured evidence that the LLM's verdict can reference.

Primary consumer: ``packages/sca/llm/version_diff_review.py``
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .sink_vocab import SHARED_SUPPLY_CHAIN_SINKS, VERSION_DIFF_EXTRA_SINKS

logger = logging.getLogger(__name__)

# Composed from the shared supply-chain authority plus the
# version-diff-specific extras (see sink_vocab.py for the rationale).
_DIFF_SINKS: frozenset[str] = (
    SHARED_SUPPLY_CHAIN_SINKS | VERSION_DIFF_EXTRA_SINKS
)


@dataclass
class SinkChange:
    """One sink that changed between versions."""

    file_path: str
    sink_api: str
    line: int
    change_type: str  # "added" | "removed" | "guard_added" | "guard_removed"
    guard_count_old: int = 0
    guard_count_new: int = 0
    was_unconditional: bool | None = None
    is_unconditional: bool | None = None
    guard_categories: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "file": self.file_path,
            "sink_api": self.sink_api,
            "line": self.line,
            "change_type": self.change_type,
        }
        if self.change_type in ("guard_added", "guard_removed"):
            d["guard_count_old"] = self.guard_count_old
            d["guard_count_new"] = self.guard_count_new
        if self.was_unconditional is not None:
            d["was_unconditional"] = self.was_unconditional
        if self.is_unconditional is not None:
            d["is_unconditional"] = self.is_unconditional
        if self.guard_categories:
            d["guard_categories"] = self.guard_categories
        return d


@dataclass
class VersionDiffSinkResult:
    """Aggregate sink changes between two versions."""

    added_sinks: list[SinkChange]
    removed_sinks: list[SinkChange]
    guard_changes: list[SinkChange]

    @property
    def total_changes(self) -> int:
        return (
            len(self.added_sinks)
            + len(self.removed_sinks)
            + len(self.guard_changes)
        )

    @property
    def has_new_unconditional_sinks(self) -> bool:
        return any(
            s.is_unconditional for s in self.added_sinks
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "added_sinks": [s.to_dict() for s in self.added_sinks],
            "removed_sinks": [s.to_dict() for s in self.removed_sinks],
            "guard_changes": [s.to_dict() for s in self.guard_changes],
            "total_changes": self.total_changes,
            "has_new_unconditional_sinks": self.has_new_unconditional_sinks,
        }

    def summary_line(self) -> str:
        """One-line summary for the LLM prompt context."""
        parts: list[str] = []
        if self.added_sinks:
            n_uncond = sum(
                1 for s in self.added_sinks if s.is_unconditional
            )
            parts.append(
                f"{len(self.added_sinks)} sink(s) added"
                + (f" ({n_uncond} unconditional)" if n_uncond else "")
            )
        if self.removed_sinks:
            parts.append(f"{len(self.removed_sinks)} sink(s) removed")
        if self.guard_changes:
            added = sum(
                1 for g in self.guard_changes
                if g.change_type == "guard_added"
            )
            removed = len(self.guard_changes) - added
            if added:
                parts.append(f"{added} guard(s) added")
            if removed:
                parts.append(f"{removed} guard(s) removed")
        return "; ".join(parts) if parts else "no sink changes detected"


def analyze_version_diff_sinks(
    old_files: dict[str, str],
    new_files: dict[str, str],
    *,
    sink_names: frozenset[str] | None = None,
    changed_files_only: bool = True,
    out_dir: Any | None = None,
) -> VersionDiffSinkResult:
    """Compare sinks between two versions of a dependency.

    Args:
        old_files: filepath -> source text for old version
        new_files: filepath -> source text for new version
        sink_names: override the default sink set
        changed_files_only: when True (default), only analyze files
            that differ between versions
        out_dir: run output dir for loading IRIS project sinks.
            When provided, IRIS-confirmed sinks are merged with
            the default set. ``None`` is safe — stock sinks only.

    Returns:
        VersionDiffSinkResult with added/removed sinks and guard
        changes. Returns an empty result when the condition stack
        is unavailable.
    """
    try:
        from core.audit.condition_extraction import (
            extract_sink_guards,
            language_for_file,
        )
    except ImportError:
        logger.debug(
            "version_diff_sinks: condition stack not importable"
        )
        return VersionDiffSinkResult([], [], [])

    sinks = sink_names if sink_names is not None else _DIFF_SINKS

    # Merge IRIS project sinks when available (graceful: no-op on failure)
    if out_dir is not None and sink_names is None:
        try:
            from core.iris.api import get_project_sinks
            iris_sinks = get_project_sinks(out_dir=out_dir)
            if iris_sinks:
                sinks = sinks | iris_sinks
        except Exception:  # graceful: IRIS enrichment is a no-op on failure
            logger.debug(
                "version_diff_sinks: IRIS sink merge failed", exc_info=True,
            )

    if changed_files_only:
        files_to_check = _changed_files(old_files, new_files)
    else:
        files_to_check = set(old_files) | set(new_files)

    parseable = {
        f for f in files_to_check if language_for_file(f) is not None
    }

    old_sinks: dict[str, list] = {}
    new_sinks: dict[str, list] = {}

    for fp in parseable:
        if fp in old_files:
            old_sinks[fp] = extract_sink_guards(
                old_files[fp], fp, sink_names=sinks,
            )
        if fp in new_files:
            new_sinks[fp] = extract_sink_guards(
                new_files[fp], fp, sink_names=sinks,
            )

    added: list[SinkChange] = []
    removed: list[SinkChange] = []
    guard_changes: list[SinkChange] = []

    for fp in parseable:
        old_guards = old_sinks.get(fp, [])
        new_guards = new_sinks.get(fp, [])

        old_by_api = _group_by_api(old_guards)
        new_by_api = _group_by_api(new_guards)

        all_apis: set[str] = set(old_by_api) | set(new_by_api)
        for api in all_apis:
            old_count = len(old_by_api.get(api, []))
            new_count = len(new_by_api.get(api, []))

            if old_count == 0 and new_count > 0:
                for sg in new_by_api[api]:
                    categories = sorted(
                        {g.category for g in sg.guards}
                    )
                    added.append(SinkChange(
                        file_path=fp,
                        sink_api=api,
                        line=sg.sink_line,
                        change_type="added",
                        guard_count_new=sg.guard_count,
                        is_unconditional=sg.unconditional,
                        guard_categories=categories,
                    ))
            elif old_count > 0 and new_count == 0:
                for sg in old_by_api[api]:
                    removed.append(SinkChange(
                        file_path=fp,
                        sink_api=api,
                        line=sg.sink_line,
                        change_type="removed",
                        guard_count_old=sg.guard_count,
                        was_unconditional=sg.unconditional,
                    ))
            elif old_count > 0 and new_count > 0:
                _detect_guard_changes(
                    fp, api,
                    old_by_api[api], new_by_api[api],
                    guard_changes,
                )

    return VersionDiffSinkResult(
        added_sinks=added,
        removed_sinks=removed,
        guard_changes=guard_changes,
    )


def _changed_files(
    old_files: dict[str, str],
    new_files: dict[str, str],
) -> set[str]:
    """Return files that differ between versions."""
    changed: set[str] = set()
    for fp in set(old_files) | set(new_files):
        old_src = old_files.get(fp)
        new_src = new_files.get(fp)
        if old_src != new_src:
            changed.add(fp)
    return changed


def _group_by_api(guards: list) -> dict[str, list]:
    """Group SinkGuard objects by sink_api."""
    by_api: dict[str, list] = {}
    for sg in guards:
        by_api.setdefault(sg.sink_api, []).append(sg)
    return by_api


def _detect_guard_changes(
    file_path: str,
    api: str,
    old_guards: list,
    new_guards: list,
    out: list[SinkChange],
) -> None:
    """Detect guard additions/removals for sinks present in both."""
    old_total = sum(sg.guard_count for sg in old_guards)
    new_total = sum(sg.guard_count for sg in new_guards)
    old_uncond = sum(1 for sg in old_guards if sg.unconditional)
    new_uncond = sum(1 for sg in new_guards if sg.unconditional)

    if old_total == new_total and old_uncond == new_uncond:
        return

    # Unconditional-count movement outranks raw guard totals: a call
    # site losing its sole guard is a removal even when another
    # (guarded) call site pushes the aggregate guard count up, and
    # vice versa for a site gaining its first guard.
    if new_uncond > old_uncond:
        change_type = "guard_removed"
    elif new_uncond < old_uncond:
        change_type = "guard_added"
    elif new_total > old_total:
        change_type = "guard_added"
    else:
        change_type = "guard_removed"

    representative = new_guards[0]
    categories: list[str] = []
    if change_type == "guard_added":
        categories = sorted(
            {g.category for sg in new_guards for g in sg.guards}
        )
    out.append(SinkChange(
        file_path=file_path,
        sink_api=api,
        line=representative.sink_line,
        change_type=change_type,
        guard_count_old=old_total,
        guard_count_new=new_total,
        was_unconditional=old_uncond > 0,
        is_unconditional=new_uncond > 0,
        guard_categories=categories,
    ))


__all__ = [
    "SinkChange",
    "VersionDiffSinkResult",
    "analyze_version_diff_sinks",
]
