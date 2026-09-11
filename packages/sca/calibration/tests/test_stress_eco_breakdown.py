"""In-process eco-breakdown plumbing in the stress sweep.

The sweep must never learn the per-ecosystem distribution by
re-reading the findings.json a scan just wrote: any size-capped
re-read eventually meets a legitimate artifact bigger than the cap
(large projects produce findings files of hundreds of MB) and
degrades to an empty breakdown — indistinguishable from a genuinely
clean scan, reported as "eco categories disappeared", and, worst,
baked into the baseline by a re-capture. The breakdown therefore
travels in-process on ``RunResult.eco_breakdown``.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import packages.sca.pipeline as pipeline_mod
from packages.sca.calibration import stress as stress_mod
from packages.sca.calibration.project_samples import ProjectSample
from packages.sca.calibration.stress import (
    StressResult,
    compare_to_baseline,
    write_baseline,
)
from packages.sca.pipeline import RunResult


def _sample(name: str = "proj") -> ProjectSample:
    return ProjectSample(
        name=name, ecosystem="PyPI",
        repo_url="https://example.invalid/x.git",
        git_ref="v1", license_spdx="MIT",
    )


def _run_result(out: Path, *, vulns: int,
                eco_breakdown: dict[str, int]) -> RunResult:
    return RunResult(
        target=out / "src", output_dir=out,
        findings_path=out / "findings.json",
        report_path=out / "report.md",
        sbom_path=out / "sbom.json",
        sarif_path=out / "findings.sarif",
        deps_analysed=5, vuln_findings=vulns,
        hygiene_findings=0, supply_chain_findings=0,
        suppressed_findings=0, in_kev=0,
        cache_hits=0, cache_misses=0,
        eco_breakdown=eco_breakdown,
    )


def _baseline(tmp_path: Path, projects: dict[str, Any]) -> Path:
    p = tmp_path / "baseline.json"
    p.write_text(json.dumps({"_source": {}, "projects": projects}))
    return p


def test_breakdown_comes_from_run_result_not_findings_json_reread(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The scan result's breakdown is the pipeline's in-process one;
    the findings.json on disk contributes nothing. The on-disk
    artifact here is unparseable — exactly what a capped or failed
    re-read would see — and the breakdown must still be populated."""
    expected = {"PyPI": 2, "npm": 1}

    def fake_clone(cmd: Any, **kwargs: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def fake_run_sca(*, target: Path, output_dir: Path,
                     options: Any) -> RunResult:
        output_dir.mkdir(parents=True, exist_ok=True)
        # Stand-in for an artifact the old re-read path could not
        # load (over its byte budget / unparseable): if anything
        # still re-read it, the breakdown would come back empty.
        (output_dir / "findings.json").write_bytes(b"\x00not-json")
        return _run_result(output_dir, vulns=3, eco_breakdown=expected)

    # Patches the stdlib subprocess module (stress.py imports it at
    # module level) — broad, but bounded by monkeypatch teardown and
    # the only subprocess call on this test's path is the git clone.
    monkeypatch.setattr(stress_mod.subprocess, "run", fake_clone)
    monkeypatch.setattr(pipeline_mod, "run_sca", fake_run_sca)

    result = stress_mod._scan_one(_sample(), tmp_path,
                                  git_clone_timeout=5.0)

    assert result.error is None
    assert result.eco_breakdown == expected
    assert sum(result.eco_breakdown.values()) == result.vuln_findings


def test_write_baseline_persists_in_process_breakdown(
    tmp_path: Path,
) -> None:
    """The captured baseline carries each project's in-process
    breakdown; errored scans never reach it (an empty breakdown from
    a failed scan must not be baked in as truth); a genuinely
    zero-finding project honestly persists ``{}``."""
    results = [
        StressResult(
            project="big", ecosystem="npm", elapsed_seconds=30.0,
            deps_analysed=100, vuln_findings=3,
            eco_breakdown={"npm": 2, "PyPI": 1},
        ),
        StressResult(
            project="clean", ecosystem="Cargo", elapsed_seconds=5.0,
            deps_analysed=40, vuln_findings=0, eco_breakdown={},
        ),
        StressResult(
            project="broken", ecosystem="Go", elapsed_seconds=1.0,
            deps_analysed=0, vuln_findings=0, eco_breakdown={},
            error="run_sca failed: boom",
        ),
    ]
    out = tmp_path / "baseline.json"
    write_baseline(results, out, captured_with_commit="deadbeef")

    data = json.loads(out.read_text(encoding="utf-8"))
    projects = data["projects"]
    assert set(projects) == {"big", "clean"}   # errored scan excluded
    assert projects["big"]["eco_breakdown"] == {"PyPI": 1, "npm": 2}
    assert projects["big"]["vuln_findings"] == 3
    assert projects["clean"]["eco_breakdown"] == {}


def test_failed_scan_reports_scan_error_not_eco_disappearance(
    tmp_path: Path,
) -> None:
    """A scan that failed carries an empty breakdown as a side
    effect; the diff must attribute that to the scan error, never
    render it as baseline eco categories 'disappearing'."""
    baseline = _baseline(tmp_path, {
        "proj": {"ecosystem": "PyPI", "deps_analysed": 50,
                 "vuln_findings": 10, "eco_breakdown": {"PyPI": 10},
                 "elapsed_seconds_p50": 20.0},
    })
    failed = StressResult(
        project="proj", ecosystem="PyPI", elapsed_seconds=1.0,
        deps_analysed=0, vuln_findings=0, eco_breakdown={},
        error="run_sca failed: boom",
    )
    diffs = compare_to_baseline([failed], baseline)
    assert len(diffs) == 1
    assert diffs[0].severity == "fail"
    assert diffs[0].issues == ["scan error: run_sca failed: boom"]
    assert not any("disappeared" in i for i in diffs[0].issues)


def test_genuinely_empty_breakdown_still_reports_disappearance(
    tmp_path: Path,
) -> None:
    """The other direction: a HEALTHY scan whose breakdown really
    lost a category keeps the 'disappeared' issue — the message is
    reserved for real data, not read failures."""
    baseline = _baseline(tmp_path, {
        "proj": {"ecosystem": "PyPI", "deps_analysed": 50,
                 "vuln_findings": 10, "eco_breakdown": {"PyPI": 10},
                 "elapsed_seconds_p50": 20.0},
    })
    empty = StressResult(
        project="proj", ecosystem="PyPI", elapsed_seconds=18.0,
        deps_analysed=50, vuln_findings=0, eco_breakdown={},
    )
    diffs = compare_to_baseline([empty], baseline)
    assert len(diffs) == 1
    assert any("eco categories disappeared: ['PyPI']" in i
               for i in diffs[0].issues)
