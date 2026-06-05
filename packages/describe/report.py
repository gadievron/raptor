"""Top-level ``/describe`` report — composes target shape +
tool readiness + catalog defaults preview + cost estimate
into a single operator-facing description (``DescribeReport``)
plus renderers (text + JSON).

**Scope contract — read-only describe, no execution.**

/describe deliberately does NOT recommend operator-typed shell
commands (``./configure``, ``make``, ``apt install``). The
earlier ``recommended_pipeline`` section did, and that
conflated RAPTOR's sandboxed execution (``raptor.py X``) with
operator-typed arbitrary code execution of the target's
Makefile / configure script. A Makefile can do ``rm -rf /``,
exfiltrate data, run anything — recommending the operator
type ``make`` is a security boundary RAPTOR shouldn't cross.

What /describe DOES surface:

* Target shape — language mix, build system, size, catalog
  target type
* Target-type defaults preview — what packs, what preferred
  dirs, what RAPTOR pipeline names the catalog will apply
  when the operator runs analysis. NO runnable commands.
* Target-specific tool gaps — CodeQL build deps, coccinelle
  language applicability, binary-oracle artefact presence.
  Per-target. Host-level checks live in /doctor.
* Cost estimate — from #21 estimator.

When the operator is ready to act, they run ``raptor.py
agentic`` / ``codeql`` / ``scan`` etc. — those commands have
their own lifecycles and (when builds are needed) run them
inside RAPTOR's sandbox. The dangerous-build problem belongs
where building actually happens (in /codeql's DB step,
specifically), not in a "here, type these into your shell"
recommendation surface.

``core/build/recipe.py`` is still here as the build-command
substrate — /codeql will consume it when it gains sandboxed
build (separate arc).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from packages.describe.recommendations import recommend_next
from packages.describe.target_shape import TargetShape, infer_target_shape
from packages.describe.tool_readiness import ToolCheck, check_tool_readiness


@dataclass(frozen=True)
class TargetTypeDefaults:
    """What the matched catalog entry will drive when the
    operator runs analysis. Read-only preview — no
    runnable commands, just data.

    Empty fields are dropped from the renderer (target with
    no specific catalog defaults shows nothing here)."""
    semgrep_packs: List[str]
    high_priority_dirs: List[str]
    pipeline_names: List[str]   # catalog-label names, not runnable commands


@dataclass(frozen=True)
class DescribeReport:
    """Top-level ``/describe`` result. Pure data; renderers
    consume this. Crucially does NOT contain runnable
    operator-typed commands — see module docstring for the
    scope rationale."""
    target_shape: TargetShape
    tool_checks: List[ToolCheck]
    target_type_defaults: Optional[TargetTypeDefaults]
    estimate_summary: Optional[str]  # one-line "$X-Y, N-M min" or None
    # Original archive basename when the operator pointed at a
    # tarball/zip (extracted on the fly into a temp dir before
    # inference). None when the target was a plain directory.
    archive_label: Optional[str] = None


def build_describe_report(
    target_path: Path,
    archive_label: Optional[str] = None,
) -> DescribeReport:
    """Compose the substrates: target shape (#17 catalog +
    language/build detectors), tool readiness, catalog
    defaults preview, cost estimate.

    ``archive_label`` is the original archive basename when the
    caller extracted an archive to ``target_path`` before
    calling here. None for plain-directory targets.
    """
    shape = infer_target_shape(target_path)
    checks = check_tool_readiness(shape)
    preview = _target_type_defaults(shape)
    estimate = _estimate_summary(target_path)
    return DescribeReport(
        target_shape=shape,
        tool_checks=checks,
        target_type_defaults=preview,
        estimate_summary=estimate,
        archive_label=archive_label,
    )


# ---------------------------------------------------------------------------
# Target-type defaults preview — read-only data, no commands
# ---------------------------------------------------------------------------


def _target_type_defaults(
    shape: TargetShape,
) -> Optional[TargetTypeDefaults]:
    """Read the matched target-type entry and surface what it'll
    apply at analysis time. None when no matched entry OR when
    all preview fields are empty (no useful defaults to show —
    today the ``generic`` fallback has empty arrays for all
    three fields, but the check is field-based not name-based
    so a future generic entry that gains real defaults would
    surface here automatically)."""
    if not shape.target_type:
        return None
    try:
        from core.run.target_types import load_by_name
        entry = load_by_name(shape.target_type)
    except Exception:  # noqa: BLE001
        return None
    if entry is None:
        return None
    packs = list(entry.semgrep_packs_default)
    dirs = list(entry.attack_surface_high)
    pipeline = list(entry.pipeline_recommended)
    # Suppress preview when EVERY field is empty — nothing
    # useful to show. A future entry with any non-empty field
    # will surface (even if it's only the pipeline list, etc).
    if not packs and not dirs and not pipeline:
        return None
    return TargetTypeDefaults(
        semgrep_packs=packs,
        high_priority_dirs=dirs,
        pipeline_names=pipeline,
    )


def _estimate_summary(target_path: Path) -> Optional[str]:
    """One-line cost+time estimate from the existing #21
    estimator. None when no catalog match / estimator data."""
    try:
        from core.run.estimator import estimate_run, format_estimate
        est = estimate_run(target_path)
        if est is None:
            return None
        full = format_estimate(est)
        if not full:
            return None
        # Strip the estimator's "Expected: " prefix and "(target
        # type: ...)" suffix — the /describe renderer wraps the
        # value in "Cost estimate: ..." and the target type is
        # already named in the header.
        full = full.removeprefix("Expected: ")
        return full.split(" (target type:", 1)[0]
    except Exception:  # noqa: BLE001
        return None


# ---------------------------------------------------------------------------
# Renderers — text (operator-facing) + JSON (machine-readable)
# ---------------------------------------------------------------------------


_STATUS_SYMBOL = {"ok": "✓", "warn": "⚠", "fail": "✗", "unknown": "?"}


# Shared with packages/static-analysis/scanner.py — single
# source of truth lives in core.inventory.languages.
from core.inventory.languages import display_lang as _display_lang  # noqa: E402


def format_text(report: DescribeReport) -> str:
    """Operator-facing block. Single source of truth for what a
    human sees when they run ``raptor describe``."""
    s = report.target_shape
    lines: List[str] = ["Target analysis:"]

    # Pre-flight: when /describe extracted an archive on the
    # fly, surface that fact first so the operator knows the
    # rest of the block describes the extracted tree (not a
    # mystery binary blob).
    if report.archive_label:
        lines.append(f"  Source: archive {report.archive_label}")

    # Languages — "C++ (95%, 47k LOC), Python (5%, 2k LOC)".
    # File-share % alone over-represents languages with many
    # tiny files (Java's one-class-per-file convention can
    # dwarf a much larger C++ kernel by file count alone), so
    # we surface per-language LOC alongside the share.
    if s.language_breakdown:
        sorted_langs = sorted(
            s.language_breakdown.items(), key=lambda x: -x[1],
        )
        parts = []
        for lang, pct in sorted_langs:
            loc = s.language_lines.get(lang)
            if loc is None or loc <= 0:
                parts.append(f"{_display_lang(lang)} ({pct:g}%)")
            else:
                parts.append(
                    f"{_display_lang(lang)} ({pct:g}%, "
                    f"{_short_int(loc)} LOC)"
                )
        lines.append(f"  Languages: {', '.join(parts)}")
    else:
        # "none detected" rather than "unknown": we DID run the
        # language detector and it returned no signal. Whether
        # that's "really no source files" or "source files we
        # don't recognise" is something the operator can
        # distinguish by looking at the tree — we honestly
        # report what the detector saw.
        lines.append("  Languages: none detected")

    # Build system from primary language. Same "none detected"
    # vs "unknown" reasoning: BuildDetector ran and reported
    # no match. Could be "no build system at all" (loose source
    # collection, header-only library) OR "build system we
    # don't recognise" (custom build script, Bazel before we
    # added it, etc.). "none detected" is the honest report;
    # operator can investigate if surprised.
    if s.primary_language and s.primary_language in s.build_systems:
        lines.append(f"  Build system: {s.build_systems[s.primary_language]}")
    else:
        lines.append("  Build system: none detected")

    # Size.
    if s.total_files > 0:
        lines.append(
            f"  Size: ~{_short_int(s.total_lines)} LOC, "
            f"{s.total_files} source file"
            f"{'s' if s.total_files != 1 else ''}"
        )

    if s.target_type:
        lines.append(f"  Detected type: {s.target_type}")

    # License — from core.license (same detector that fires at
    # run lifecycle start). Surfaces SPDX id when known
    # ("MIT", "Apache-2.0"), classification only when SPDX
    # missing ("oss" / "proprietary"). "missing" → "License:
    # none detected" so the operator sees we DID look. We
    # never gate on the result — operator may have a CodeQL
    # commercial license, may be authorised on first-party
    # code, etc.
    if s.license is not None:
        if s.license.classification == "missing":
            lines.append("  License: none detected")
        elif s.license.spdx_id:
            line = f"  License: {s.license.spdx_id}"
            # Surface additional license files when present —
            # dual-licensed projects (libgcrypt: COPYING +
            # COPYING.LIB; NetworkManager: COPYING +
            # COPYING.LGPL; many GNU projects) carry meaningful
            # secondary licenses the operator should know about.
            # Keep the list short (≤3 file names) so the line
            # stays compact; truncate with "+N more" otherwise.
            if s.license.additional_files:
                names = list(s.license.additional_files)
                shown = names[:3]
                suffix = (
                    f", +{len(names) - 3} more"
                    if len(names) > 3 else ""
                )
                line += (
                    f"  (also: {', '.join(shown)}{suffix})"
                )
            lines.append(line)
        elif s.license.source_file:
            # "unknown" classification + a source file means the
            # detector found a LICENSE-named file but couldn't
            # classify the content (Firefox's LICENSE is a 7-line
            # pointer to toolkit/content/license.html, not the
            # actual MPL text). Be explicit so the operator
            # doesn't read "License: unknown" as "no license".
            lines.append(
                f"  License: present in {s.license.source_file} "
                f"(couldn't classify — check manually)"
            )
        else:
            lines.append(f"  License: {s.license.classification}")

    # Direct-dep counts per ecosystem. Lockfiles excluded —
    # this is the "what is the operator on the hook for
    # maintaining" view, not the transitive-tree size.
    # /sca is the natural next command when this is non-empty.
    if s.deps is not None and s.deps.by_ecosystem:
        # Sort by count desc so the dominant ecosystem leads.
        parts = [
            f"{count} {eco}"
            for eco, count in sorted(
                s.deps.by_ecosystem.items(), key=lambda x: -x[1],
            )
        ]
        suffix = " (parser cap hit; counts partial)" if s.deps.truncated else ""
        lines.append(f"  Dependencies: {', '.join(parts)}{suffix}")

    # Git provenance — branch / commit / dirty / last commit date.
    # All-None GitProvenance is "not a git checkout" — render
    # "Git: none detected" for honesty (we DID look). Partial
    # state (e.g. detached HEAD: branch=None but commit set)
    # renders what we got.
    if s.git is not None:
        if s.git.commit_short is None:
            lines.append("  Git: none detected")
        else:
            parts = []
            if s.git.branch:
                parts.append(s.git.branch)
            parts.append(f"@ {s.git.commit_short}")
            tail = []
            if s.git.dirty is True:
                tail.append("dirty")
            elif s.git.dirty is False:
                tail.append("clean")
            if s.git.last_commit_date:
                # Strip TZ for compact render — operator can
                # read the JSON if they need millisecond
                # precision. Date portion is the action-changer
                # ("is this code from yesterday or 2017?").
                tail.append(f"last commit {s.git.last_commit_date[:10]}")
            if tail:
                parts.append(f"({', '.join(tail)})")
            lines.append(f"  Git: {' '.join(parts)}")

    # Target-type defaults preview — data, not commands.
    if report.target_type_defaults is not None:
        cp = report.target_type_defaults
        lines.append("")
        lines.append("Defaults for this target type:")
        if cp.semgrep_packs:
            lines.append(
                f"  /scan baseline packs: {', '.join(cp.semgrep_packs)}"
            )
        if cp.high_priority_dirs:
            lines.append(
                f"  /agentic preferred dirs: "
                f"{', '.join(cp.high_priority_dirs)}"
            )
        if cp.pipeline_names:
            lines.append(
                f"  Pipeline: {' → '.join(cp.pipeline_names)}"
            )

    # Signal-based "Recommended next:" — augments the catalog's
    # static Pipeline line above with picks derived from what
    # we actually detected on this tree (dep counts, build
    # system, CI scanners already running). Two-layer: catalog
    # template + signal refinement.
    recs = recommend_next(s)
    if recs:
        lines.append("")
        lines.append("Recommended next (based on signals):")
        cmd_w = max(len(r.command) for r in recs)
        for r in recs:
            lines.append(f"  {r.command:<{cmd_w}}  — {r.reason}")

    # Tool applicability — target-level signals only. Host-level
    # checks (binary presence, LLM keys, env) live in /doctor.
    # Header says ``checks`` not ``gaps`` because the section
    # surfaces both ok and warn lines; "gaps" misled operators
    # who saw ✓ entries here and thought they were problems.
    lines.append("")
    lines.append("Target-specific checks:")
    if not report.tool_checks:
        lines.append("  (no target-specific checks ran)")
    else:
        name_w = max(len(c.name) for c in report.tool_checks)
        for c in report.tool_checks:
            sym = _STATUS_SYMBOL.get(c.status, "?")
            ver = f" ({c.version})" if c.version else ""
            head = f"  {sym} {c.name:<{name_w}}{ver}"
            lines.append(f"{head:<40} — {c.detail}")
            if c.hint:
                lines.append(f"      hint: {c.hint}")

    # Cost estimate.
    if report.estimate_summary:
        lines.append("")
        lines.append(
            f"Cost estimate (when running /agentic): "
            f"{report.estimate_summary}"
        )

    # Pointers — explicitly NO runnable build/install commands.
    # ``--repo`` value substituted with the resolved target path
    # so operators can copy the line directly (rather than the
    # pre-fix ``<target>`` placeholder which forced them to
    # substitute by hand).
    lines.append("")
    lines.append("For host-level setup, run `raptor doctor`.")
    lines.append(
        f"To start analysis, run `raptor.py agentic --repo "
        f"{s.target_path}` (prints same estimate at start; "
        f"runs sandboxed)."
    )

    return "\n".join(lines)


def format_json(report: DescribeReport) -> str:
    """Machine-readable serialisation — for CI / dashboards /
    downstream tools. Field names match the dataclass shape so
    consumers can mirror the schema."""
    s = report.target_shape
    doc: Dict[str, Any] = {
        "target_path": str(s.target_path),
        "languages": s.languages,
        "language_breakdown": s.language_breakdown,
        "primary_language": s.primary_language,
        "build_systems": s.build_systems,
        "target_type": s.target_type,
        "total_files": s.total_files,
        "total_lines": s.total_lines,
        "file_extensions": s.file_extensions,
        "language_lines": s.language_lines,
        "git": (
            None if s.git is None or s.git.commit_short is None else {
                "branch": s.git.branch,
                "commit_short": s.git.commit_short,
                "dirty": s.git.dirty,
                "last_commit_date": s.git.last_commit_date,
            }
        ),
        # Dep counts per ecosystem. None when detection didn't
        # run; empty by_ecosystem when no manifests / nothing
        # parseable. truncated=True flags the parser cap was hit.
        "deps": (
            None if s.deps is None else {
                "by_ecosystem": s.deps.by_ecosystem,
                "truncated": s.deps.truncated,
            }
        ),
        # License from core.license — serialise the full TargetLicense
        # shape (.to_dict() preserves it) so JSON consumers get the
        # SPDX id + classification + source file + confidence + any
        # additional dual-license files. None when detection failed.
        "license": (
            None if s.license is None else s.license.to_dict()
        ),
        "tool_checks": [
            {
                "name": c.name,
                "status": c.status,
                "version": c.version,
                "detail": c.detail,
                "hint": c.hint,
            }
            for c in report.tool_checks
        ],
        "target_type_defaults": (
            None if report.target_type_defaults is None else {
                "semgrep_packs": report.target_type_defaults.semgrep_packs,
                "high_priority_dirs": report.target_type_defaults.high_priority_dirs,
                "pipeline_names": report.target_type_defaults.pipeline_names,
            }
        ),
        "estimate_summary": report.estimate_summary,
        "archive_label": report.archive_label,
        # Signal-based recommendations — sibling to the catalog's
        # static "pipeline_names" (in target_type_defaults) but
        # derived from THIS tree's detected signals. RAPTOR
        # commands only (sandboxed) — never shell commands; the
        # scope guardrail in this module's docstring still holds.
        "recommended_next": [
            {"command": r.command, "reason": r.reason}
            for r in recommend_next(s)
        ],
    }
    return json.dumps(doc, indent=2)


def _short_int(n: int) -> str:
    """52000 → '52k'; 1500000 → '1.5M'."""
    if n >= 1_000_000:
        return f"{n / 1_000_000:.1f}M"
    if n >= 1_000:
        return f"{n // 1_000}k"
    return str(n)


__all__ = [
    "TargetTypeDefaults",
    "DescribeReport",
    "build_describe_report",
    "format_text",
    "format_json",
]
