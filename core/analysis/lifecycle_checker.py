"""Check read sites against write-site preconditions.

For each read site of a state field, checks whether the read site's
dominating guards cover the preconditions established at write sites.
A read site that lacks coverage for one or more write-site guards
is a potential context-drift bug.
"""

from __future__ import annotations

import logging
import re

from .lifecycle_model import Guard, LifecycleFinding, StateField

logger = logging.getLogger(__name__)


def _normalize_condition(cond: str) -> str:
    """Normalize a condition string for comparison.

    Strips whitespace, lowercases, removes pointer-style variations
    so 'task->mm != NULL' matches 'task->mm'.
    """
    s = cond.strip().lower()
    s = re.sub(r"\s+", " ", s)
    # Flip Yoda-style comparisons (e.g. "null != x" → "x != null")
    s = re.sub(r"\b(null|0)\s*(!=|==)\s*(\S+)", r"\3 \2 \1", s)
    s = re.sub(r"\s*!=\s*null\b", "", s)
    s = re.sub(r"\s*!=\s*0\b", "", s)
    s = re.sub(r"\s*==\s*null\b", " == null", s)
    return re.sub(r"\s*==\s*0\b", " == 0", s)


def _guard_covers(read_guard: Guard, write_guard: Guard) -> bool:
    """Check if a read-site guard semantically covers a write-site guard.

    Conservative: returns True only when the normalized conditions
    match textually. LLM-assisted classification can provide a
    richer equivalence check.
    """
    return (
        _normalize_condition(read_guard.condition)
        == _normalize_condition(write_guard.condition)
        and read_guard.polarity == write_guard.polarity
    )


def _read_site_covers_guard(
    read_guards: frozenset[Guard],
    write_guard: Guard,
) -> bool:
    """Check if any read-site guard covers a write-site guard."""
    return any(_guard_covers(rg, write_guard) for rg in read_guards)


def check_coverage(
    field: StateField,
) -> list[LifecycleFinding]:
    """Check all read sites against all write-site preconditions.

    For each read site, computes the set of write-site guards that
    are NOT covered by any of the read site's dominating guards.
    If any write-site guard is missing at a read site, emits a
    LifecycleFinding.
    """
    findings: list[LifecycleFinding] = []

    all_write_guards: set[Guard] = set()
    for ws in field.write_sites:
        all_write_guards.update(ws.guards)

    if not all_write_guards:
        return findings

    for rs in field.read_sites:
        if not rs.security_relevant:
            continue

        missing: set[str] = set()
        for wg in all_write_guards:
            if not _read_site_covers_guard(rs.guards, wg):
                missing.add(wg.condition)

        if missing:
            confidence = "high" if len(missing) == len(all_write_guards) else "medium"
            findings.append(LifecycleFinding(
                state_field=field,
                read_site=rs,
                missing_guards=frozenset(missing),
                confidence=confidence,
            ))

    return findings


def check_coverage_with_cfg(
    field: StateField,
    cfg,
    *,
    cfg_file: str = "",
) -> list[LifecycleFinding]:
    """Check read sites using the structured guard-bypass query.

    When a CFG is available, uses path enumeration from entry to
    read site to determine whether write-site guards dominate all
    paths. Falls back to textual check_coverage() if the guard-bypass
    module isn't available or the CFG lacks the expected interface.

    When *cfg_file* is set, only read sites in that file are checked
    (the CFG is file-specific, so applying it to lines from other
    files produces wrong results).
    """
    try:
        from core.analysis.guard_bypass import check_guard_coverage
    except ImportError:
        return check_coverage(field)

    if not hasattr(cfg, "entry") or not hasattr(cfg, "nodes"):
        return check_coverage(field)

    findings: list[LifecycleFinding] = []

    all_write_guards: set[Guard] = set()
    for ws in field.write_sites:
        all_write_guards.update(ws.guards)

    if not all_write_guards:
        return findings

    for rs in field.read_sites:
        if cfg_file and rs.file != cfg_file:
            continue
        if not rs.security_relevant:
            continue

        missing: set[str] = set()
        for wg in all_write_guards:
            covered_structurally = check_guard_coverage(
                cfg, rs.line, wg.condition,
            )
            if not covered_structurally:
                if not _read_site_covers_guard(rs.guards, wg):
                    missing.add(wg.condition)

        if missing:
            confidence = "high" if len(missing) == len(all_write_guards) else "medium"
            findings.append(LifecycleFinding(
                state_field=field,
                read_site=rs,
                missing_guards=frozenset(missing),
                confidence=confidence,
            ))

    return findings


def check_all_fields(
    fields: list[StateField],
    cfgs=None,
) -> list[LifecycleFinding]:
    """Check all state fields and return all findings.

    When cfgs is provided (dict mapping file_path to CFG), uses
    structural guard-bypass queries for read sites in those files.
    """
    all_findings: list[LifecycleFinding] = []
    for field in fields:
        if cfgs:
            checked_sites: set = set()
            covered_files: set = set()
            for rs in field.read_sites:
                if rs.file in cfgs and rs.file not in covered_files:
                    cfg_findings = check_coverage_with_cfg(
                        field, cfgs[rs.file], cfg_file=rs.file,
                    )
                    all_findings.extend(cfg_findings)
                    covered_files.add(rs.file)
                    # Track read sites handled by CFG to avoid duplicates
                    for f in cfg_findings:
                        checked_sites.add(
                            (f.read_site.file, f.read_site.line),
                        )
                    # Also mark all read sites in this file as checked
                    for rs2 in field.read_sites:
                        if rs2.file == rs.file:
                            checked_sites.add((rs2.file, rs2.line))
            has_uncovered = any(
                rs.file not in covered_files
                for rs in field.read_sites
            )
            if not covered_files or has_uncovered:
                for f in check_coverage(field):
                    site_key = (f.read_site.file, f.read_site.line)
                    if site_key not in checked_sites:
                        all_findings.append(f)
        else:
            all_findings.extend(check_coverage(field))
    return all_findings
