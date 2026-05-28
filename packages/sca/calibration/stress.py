"""Stress-test sweep — scans every sample in PROJECT_SAMPLES and
diffs against a committed baseline.

Catches the silent-regression class of bug. The OSV ``Cargo →
crates.io`` ecosystem-name fix landed in commit 4b0d40f5; before
the fix every Rust crate's CVE lookup quietly returned zero. Nothing
in the test suite or the validate/refit pipelines noticed —
``alacritty-0.13`` legitimately had 0 vuln findings, but so did
every Cargo project in the corpus, and the validation passed
because Cargo was already 0% signal density.

A baseline-driven stress sweep would have flagged this immediately:
"alacritty-0.13 vuln findings 6 → 0 (-100%)". The calibration
pipeline is metric-driven (precision / ρ); the stress sweep is
*invariant*-driven (these scans should produce ROUGHLY these
counts).

## Exit codes (when called from the GHA workflow or a script)

    0 — every project within tolerance
    1 — at least one warn (small drift; investigate)
    2 — at least one fail (large drift or new error)

## What's measured

Per project:
  * elapsed_seconds (wall-clock for run_sca)
  * deps_analysed (resolved + transitive)
  * vuln_findings (sca:vulnerable_dependency count)
  * eco_breakdown (per-finding-ecosystem distribution)

What's deliberately NOT measured:
  * Cache hit ratio (fluctuates with TTL eviction)
  * SCA total runtime when including supply-chain / hygiene checks
    that depend on registry HTTP responsiveness — those calls are
    cached but sometimes refresh
  * Memory usage — operator's local resources, not SCA-controlled

## Baseline format

    {
      "_source": {
        "name": "RAPTOR SCA stress-test baseline",
        "license": "MIT (RAPTOR-generated)",
        "captured_at": "2026-05-10T...",
        "captured_with_commit": "a9ad1b74",
        "sample_count": 41,
        ...
      },
      "projects": {
        "alacritty-0.13": {
          "ecosystem": "Cargo",
          "deps_analysed": 331,
          "vuln_findings": 6,
          "eco_breakdown": {"Cargo": 5, "Inline": 1},
          "elapsed_seconds_p50": 12.3
        },
        ...
      }
    }

When a baseline doesn't exist for a sample, that sample is reported
``new`` (informational, not a regression). When a baseline exists
but the corresponding sample no longer does, that's reported
``orphan``.
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .project_samples import PROJECT_SAMPLES, ProjectSample

logger = logging.getLogger(__name__)


# Tolerance bands. Operators can override per-call.
DEFAULT_VULN_WARN_PCT = 0.25       # ±25% → warn
DEFAULT_VULN_FAIL_PCT = 0.50       # ±50% → fail
DEFAULT_DEPS_WARN_PCT = 0.10       # ±10% → warn (parsers shift)
DEFAULT_DEPS_FAIL_PCT = 0.30       # ±30% → fail
DEFAULT_ELAPSED_WARN_X = 3.0       # 3× slower → warn
DEFAULT_ELAPSED_FAIL_X = 5.0       # 5× slower → fail


@dataclass(frozen=True)
class StressResult:
    """Per-project scan diagnostics captured during the sweep."""

    project: str
    ecosystem: str
    elapsed_seconds: float
    deps_analysed: int
    vuln_findings: int
    eco_breakdown: Dict[str, int]
    error: Optional[str] = None  # populated when the scan itself failed


@dataclass(frozen=True)
class StressDiff:
    """Per-project comparison vs baseline."""

    project: str
    ecosystem: str
    severity: str           # "ok" / "warn" / "fail" / "new" / "orphan"
    issues: List[str] = field(default_factory=list)
    current: Optional[StressResult] = None


def run_stress_sweep(
    *,
    samples: Optional[Sequence[ProjectSample]] = None,
    out_root: Optional[Path] = None,
    git_clone_timeout: int = 300,
    sca_timeout: int = 600,
    max_workers: int = 4,
    use_existing_clones: bool = False,
) -> List[StressResult]:
    """Walk samples, scan each, return per-sample diagnostics.

    Scans run in parallel (``max_workers`` threads). Each scan is
    bounded by ``sca_timeout`` — if ``run_sca`` hasn't returned by
    then, the result is recorded as an error and the sweep continues.
    The underlying thread may linger until process exit, but won't
    block other scans.

    ``out_root`` defaults to a STABLE per-machine path under
    ``~/.raptor/cache/sca/stress/clones/``. Stable so that the
    per-target inventory cache (``core/inventory/builder.default_cache_dir``)
    finds matching SHA-256 entries across sweep runs and short-
    circuits the inventory build. The clone subdir for each sample
    gets ``rm -rf``'d before re-cloning to avoid ``git clone:
    destination already exists`` — so the source files are fresh
    every run, but the resolved path stays the same, which is what
    the inventory cache keys on.

    Tests + one-shot callers that want a fresh tempdir pass an
    explicit ``out_root``. The tempdir+cleanup path triggers when
    the caller explicitly passes ``out_root=None`` AND sets the
    environment variable ``RAPTOR_SCA_STRESS_EPHEMERAL=1`` — the
    rare "I want zero state across runs" mode for diagnosing
    cache-pollution bugs.

    ``use_existing_clones`` is a no-op today (every scan re-clones).
    Reserved for a future caching mode that would skip the clone
    when the existing checkout matches ``sample.git_ref``.
    """
    if samples is None:
        samples = PROJECT_SAMPLES

    cleanup_dir: Optional[Path] = None
    if out_root is None:
        if os.environ.get("RAPTOR_SCA_STRESS_EPHEMERAL"):
            cleanup_dir = Path(tempfile.mkdtemp(prefix="raptor-sca-stress-"))
            out_root = cleanup_dir
        else:
            from packages.sca import SCA_CACHE_ROOT
            out_root = SCA_CACHE_ROOT / "stress" / "clones"
    out_root.mkdir(parents=True, exist_ok=True)

    per_scan_budget = sca_timeout + git_clone_timeout
    results: List[StressResult] = []
    try:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers,
        ) as executor:
            future_to_sample = {
                executor.submit(
                    _scan_one, sample, out_root,
                    git_clone_timeout=git_clone_timeout,
                ): sample
                for sample in samples
            }
            completed: set = set()
            try:
                for future in concurrent.futures.as_completed(
                    future_to_sample, timeout=per_scan_budget,
                ):
                    completed.add(future)
                    sample = future_to_sample[future]
                    try:
                        result = future.result()
                    except Exception as e:  # noqa: BLE001
                        result = StressResult(
                            project=sample.name,
                            ecosystem=sample.ecosystem,
                            elapsed_seconds=0.0,
                            deps_analysed=0, vuln_findings=0,
                            eco_breakdown={},
                            error=f"unexpected: {str(e)[:200]}",
                        )
                    results.append(result)
                    logger.info(
                        "[%d/%d] %s/%s%s",
                        len(results), len(future_to_sample),
                        sample.ecosystem, sample.name,
                        " (error)" if result.error else "",
                    )
            except concurrent.futures.TimeoutError:
                pass
            for future, sample in future_to_sample.items():
                if future not in completed:
                    results.append(StressResult(
                        project=sample.name,
                        ecosystem=sample.ecosystem,
                        elapsed_seconds=float(per_scan_budget),
                        deps_analysed=0, vuln_findings=0,
                        eco_breakdown={},
                        error=(
                            f"scan timed out (>{per_scan_budget}s budget)"
                        ),
                    ))
    finally:
        if cleanup_dir is not None:
            try:
                _rmtree(cleanup_dir)
            except OSError:
                pass
    return results


def _scan_one(
    sample: ProjectSample,
    out_root: Path,
    *,
    git_clone_timeout: int,
) -> StressResult:
    proj_out = out_root / f"{sample.ecosystem}-{sample.name}"
    proj_out.mkdir(parents=True, exist_ok=True)
    clone_root = proj_out / "src"
    sca_out = proj_out / "out"

    # Clean residue from prior runs. The ``out_root`` stays stable
    # across sweeps (so the inventory cache's resolved-abs-path key
    # finds its checklist), but the clone itself must be fresh —
    # ``git clone`` refuses to write into an existing directory.
    # The previous run's ``sca_out`` is also cleaned so a stale
    # findings.json from a different ref doesn't get mixed in.
    if clone_root.exists():
        _rmtree(clone_root)
    if sca_out.exists():
        _rmtree(sca_out)

    try:
        subprocess.run(
            [
                "git", "clone", "--depth", "1",
                "--branch", sample.git_ref,
                sample.repo_url, str(clone_root),
            ],
            check=True, capture_output=True, text=True,
            timeout=git_clone_timeout,
        )
    except (subprocess.TimeoutExpired,
            subprocess.CalledProcessError) as e:
        err = (
            e.stderr if isinstance(e, subprocess.CalledProcessError)
            else f"clone timed out after {git_clone_timeout}s"
        )
        return StressResult(
            project=sample.name, ecosystem=sample.ecosystem,
            elapsed_seconds=0.0, deps_analysed=0,
            vuln_findings=0, eco_breakdown={},
            error=f"git clone failed: {str(err)[:200]}",
        )

    t0 = time.monotonic()
    try:
        from packages.sca.pipeline import run_sca, RunOptions
        run_result = run_sca(
            target=clone_root, output_dir=sca_out,
            options=RunOptions(
                enable_llm_review=False, enable_triage=False,
                # Stress sweeps run dozens of scans back-to-back; the
                # per-stage progress output noise dwarfs the actual
                # diagnostics. Auto-disable would already kick in for
                # non-TTY but explicit is safer.
                enable_progress=False,
            ),
        )
    except Exception as e:                                  # noqa: BLE001
        return StressResult(
            project=sample.name, ecosystem=sample.ecosystem,
            elapsed_seconds=time.monotonic() - t0,
            deps_analysed=0, vuln_findings=0, eco_breakdown={},
            error=f"run_sca failed: {str(e)[:200]}",
        )
    elapsed = time.monotonic() - t0

    eco_breakdown = _read_eco_breakdown(sca_out / "findings.json")

    return StressResult(
        project=sample.name, ecosystem=sample.ecosystem,
        elapsed_seconds=elapsed,
        deps_analysed=run_result.deps_analysed,
        vuln_findings=run_result.vuln_findings,
        eco_breakdown=eco_breakdown,
    )


def _read_eco_breakdown(findings_path: Path) -> Dict[str, int]:
    """Extract per-finding-ecosystem distribution of vuln findings.

    Returns ``{}`` on missing / unreadable file — the scan layer
    above already captures that as the ``error`` string.
    """
    breakdown: Dict[str, int] = {}
    try:
        data = json.loads(findings_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return breakdown
    if not isinstance(data, list):
        return breakdown
    for f in data:
        if not isinstance(f, dict):
            continue
        if f.get("vuln_type") != "sca:vulnerable_dependency":
            continue
        sca = f.get("sca") or {}
        if not isinstance(sca, dict):
            continue
        eco = sca.get("ecosystem") or "?"
        breakdown[eco] = breakdown.get(eco, 0) + 1
    return breakdown


def compare_to_baseline(
    results: Sequence[StressResult],
    baseline_path: Path,
    *,
    vuln_warn_pct: float = DEFAULT_VULN_WARN_PCT,
    vuln_fail_pct: float = DEFAULT_VULN_FAIL_PCT,
    deps_warn_pct: float = DEFAULT_DEPS_WARN_PCT,
    deps_fail_pct: float = DEFAULT_DEPS_FAIL_PCT,
    elapsed_warn_x: float = DEFAULT_ELAPSED_WARN_X,
    elapsed_fail_x: float = DEFAULT_ELAPSED_FAIL_X,
) -> List[StressDiff]:
    """Compare current sweep results against the baseline file.

    Missing baseline ⇒ every project reported ``new`` (informational).
    Missing project in current ⇒ ``orphan`` in the diff list.
    """
    baseline = _load_baseline(baseline_path)
    baseline_projects: Dict[str, Dict[str, Any]] = (
        baseline.get("projects") or {}
    )
    diffs: List[StressDiff] = []
    seen_in_current: set = set()

    for result in results:
        seen_in_current.add(result.project)
        # Errored scans are always fail.
        if result.error:
            diffs.append(StressDiff(
                project=result.project,
                ecosystem=result.ecosystem,
                severity="fail",
                issues=[f"scan error: {result.error}"],
                current=result,
            ))
            continue
        baseline_entry = baseline_projects.get(result.project)
        if baseline_entry is None:
            diffs.append(StressDiff(
                project=result.project,
                ecosystem=result.ecosystem,
                severity="new",
                issues=[
                    f"new project (vuln_findings={result.vuln_findings}, "
                    f"deps={result.deps_analysed}); update baseline "
                    f"to commit"
                ],
                current=result,
            ))
            continue
        issues, severity = _diff_one(
            baseline_entry, result,
            vuln_warn_pct=vuln_warn_pct, vuln_fail_pct=vuln_fail_pct,
            deps_warn_pct=deps_warn_pct, deps_fail_pct=deps_fail_pct,
            elapsed_warn_x=elapsed_warn_x,
            elapsed_fail_x=elapsed_fail_x,
        )
        diffs.append(StressDiff(
            project=result.project,
            ecosystem=result.ecosystem,
            severity=severity,
            issues=issues,
            current=result,
        ))

    # Orphans — projects in baseline but not in current sweep.
    for proj, entry in baseline_projects.items():
        if proj in seen_in_current:
            continue
        diffs.append(StressDiff(
            project=proj,
            ecosystem=entry.get("ecosystem", "?"),
            severity="orphan",
            issues=[
                "in baseline but not in current sweep — sample "
                "was removed?"
            ],
            current=None,
        ))
    return diffs


def _diff_one(
    baseline: Dict[str, Any],
    current: StressResult,
    *,
    vuln_warn_pct: float, vuln_fail_pct: float,
    deps_warn_pct: float, deps_fail_pct: float,
    elapsed_warn_x: float, elapsed_fail_x: float,
) -> Tuple[List[str], str]:
    issues: List[str] = []
    severity = "ok"

    # Vuln-finding count drift.
    bv = int(baseline.get("vuln_findings", 0) or 0)
    if bv > 0:
        signed_pct = (current.vuln_findings - bv) / bv
        abs_pct = abs(signed_pct)
        if abs_pct >= vuln_fail_pct:
            severity = "fail"
            issues.append(
                f"vuln_findings {bv} → {current.vuln_findings} "
                f"({signed_pct*100:+.0f}%, ≥ {vuln_fail_pct*100:.0f}% fail)"
            )
        elif abs_pct >= vuln_warn_pct:
            if severity == "ok":
                severity = "warn"
            issues.append(
                f"vuln_findings {bv} → {current.vuln_findings} "
                f"({signed_pct*100:+.0f}%, ≥ {vuln_warn_pct*100:.0f}% warn)"
            )
    else:
        # Baseline was 0 vuln_findings; flag any non-zero current as
        # warn so an OSV-Cargo-shaped fix that suddenly STARTS finding
        # vulns is loud.
        if current.vuln_findings > 0:
            if severity == "ok":
                severity = "warn"
            issues.append(
                f"vuln_findings 0 → {current.vuln_findings} "
                f"(baseline was 0; intentional? update baseline)"
            )

    # Deps-analysed drift (parser regressions).
    bd = int(baseline.get("deps_analysed", 0) or 0)
    if bd > 0:
        signed_pct = (current.deps_analysed - bd) / bd
        abs_pct = abs(signed_pct)
        if abs_pct >= deps_fail_pct:
            severity = "fail"
            issues.append(
                f"deps_analysed {bd} → {current.deps_analysed} "
                f"({signed_pct*100:+.0f}%, ≥ {deps_fail_pct*100:.0f}% fail)"
            )
        elif abs_pct >= deps_warn_pct:
            if severity == "ok":
                severity = "warn"
            issues.append(
                f"deps_analysed {bd} → {current.deps_analysed} "
                f"({signed_pct*100:+.0f}%, ≥ {deps_warn_pct*100:.0f}% warn)"
            )

    # Eco-breakdown drift — flag NEW eco categories appearing
    # (interesting but not failure-worthy unless huge).
    base_ecos = set((baseline.get("eco_breakdown") or {}).keys())
    new_ecos = set(current.eco_breakdown.keys()) - base_ecos
    missing_ecos = base_ecos - set(current.eco_breakdown.keys())
    if new_ecos:
        if severity == "ok":
            severity = "warn"
        issues.append(f"new eco categories: {sorted(new_ecos)}")
    if missing_ecos:
        if severity == "ok":
            severity = "warn"
        issues.append(f"eco categories disappeared: {sorted(missing_ecos)}")

    # Elapsed-time drift. Use generous bounds — single-run timing
    # noise is normal; only flag obvious regressions.
    be = float(baseline.get("elapsed_seconds_p50", 0.0) or 0.0)
    if be > 0:
        ratio = current.elapsed_seconds / be
        if ratio >= elapsed_fail_x:
            severity = "fail"
            issues.append(
                f"elapsed {be:.1f}s → {current.elapsed_seconds:.1f}s "
                f"({ratio:.1f}× ≥ {elapsed_fail_x:.0f}× fail)"
            )
        elif ratio >= elapsed_warn_x:
            if severity == "ok":
                severity = "warn"
            issues.append(
                f"elapsed {be:.1f}s → {current.elapsed_seconds:.1f}s "
                f"({ratio:.1f}× ≥ {elapsed_warn_x:.0f}× warn)"
            )

    return issues, severity


def write_baseline(
    results: Sequence[StressResult],
    baseline_path: Path,
    *,
    captured_with_commit: Optional[str] = None,
) -> None:
    """Capture current sweep results as the new baseline file."""
    projects: Dict[str, Dict[str, Any]] = {}
    for r in results:
        if r.error:
            # Don't bake error states into the baseline — that would
            # silently green-light a regression-by-error.
            continue
        projects[r.project] = {
            "ecosystem": r.ecosystem,
            "deps_analysed": r.deps_analysed,
            "vuln_findings": r.vuln_findings,
            "eco_breakdown": dict(sorted(r.eco_breakdown.items())),
            "elapsed_seconds_p50": round(r.elapsed_seconds, 1),
        }
    output = {
        # ``_source`` (rather than the originally-planned ``_meta``)
        # to satisfy the calibration corpus's license-check
        # convention — every JSON under ``data/calibration/`` carries
        # a ``_source`` block declaring its license + provenance.
        # Stress-baseline data is RAPTOR-generated (no third-party
        # content embedded), MIT-licensed, regenerated locally.
        "_source": {
            "name": "RAPTOR SCA stress-test baseline",
            "url": "internal — packages.sca.calibration.stress",
            "license": (
                "MIT (RAPTOR-generated). Captured per-sample "
                "diagnostics (deps_analysed, vuln_findings, "
                "eco_breakdown, elapsed_seconds_p50) for "
                "regression detection — no third-party content."
            ),
            "captured_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ",
            ),
            "captured_with_commit": captured_with_commit or "unknown",
            "sample_count": len(projects),
            "provenance": (
                "Output of ``run_stress_sweep`` against "
                "``project_samples`` in the calibration corpus. "
                "Re-generated by an operator calling "
                "``write_baseline()`` after intentional changes "
                "to the samples list, parser logic, or scoring "
                "formula."
            ),
        },
        "projects": dict(sorted(projects.items())),
    }
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps(output, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_baseline(path: Path) -> Dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning(
            "sca.calibration.stress: baseline read failed (%s); "
            "treating as empty", e,
        )
        return {}


def _rmtree(path: Path) -> None:
    """Recursive rm — avoids importing shutil at module top, since
    a stress sweep that doesn't pass through this code path
    (e.g., caller-supplied out_root) shouldn't pay the import."""
    import shutil
    shutil.rmtree(path, ignore_errors=True)


def render_diffs(diffs: Sequence[StressDiff]) -> str:
    """Render diff results as a human-readable text block."""
    lines: List[str] = []
    counts = {"ok": 0, "warn": 0, "fail": 0, "new": 0, "orphan": 0}
    for d in diffs:
        counts[d.severity] = counts.get(d.severity, 0) + 1

    lines.append(
        f"summary: {len(diffs)} project(s); "
        f"ok={counts['ok']} warn={counts['warn']} "
        f"fail={counts['fail']} new={counts['new']} "
        f"orphan={counts['orphan']}"
    )

    # Order diffs: fail > warn > new > orphan > ok
    severity_rank = {"fail": 0, "warn": 1, "new": 2, "orphan": 3, "ok": 4}
    for d in sorted(diffs, key=lambda x: (
        severity_rank.get(x.severity, 9), x.project,
    )):
        prefix = f"  [{d.severity:^6s}] {d.ecosystem}/{d.project}"
        if not d.issues:
            lines.append(prefix)
            continue
        lines.append(prefix + ":")
        for issue in d.issues:
            lines.append(f"             {issue}")
    return "\n".join(lines)


def diffs_to_exit_code(diffs: Sequence[StressDiff]) -> int:
    """0 ok / 1 warn / 2 fail. ``new`` and ``orphan`` are
    informational and don't affect the exit code."""
    if any(d.severity == "fail" for d in diffs):
        return 2
    if any(d.severity == "warn" for d in diffs):
        return 1
    return 0


__all__ = [
    "DEFAULT_DEPS_FAIL_PCT", "DEFAULT_DEPS_WARN_PCT",
    "DEFAULT_ELAPSED_FAIL_X", "DEFAULT_ELAPSED_WARN_X",
    "DEFAULT_VULN_FAIL_PCT", "DEFAULT_VULN_WARN_PCT",
    "StressDiff", "StressResult",
    "compare_to_baseline", "diffs_to_exit_code",
    "render_diffs", "run_stress_sweep", "write_baseline",
]
