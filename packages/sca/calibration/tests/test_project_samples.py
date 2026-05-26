"""Tests for project-sample collection — clone, scan, sanitise.

Network-dependent operations (git clone + run_sca) are mocked so
the tests run offline and deterministically. The collector's
sanitisation + error-handling logic is what matters for unit
tests; live clone-and-scan is exercised by an integration smoke
test that's gated behind ``RAPTOR_SCA_LIVE_NETWORK`` (operator
opts in).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List
from unittest.mock import patch


from packages.sca.calibration.project_samples import (
    PROJECT_SAMPLES,
    CollectResult,
    ProjectSample,
    _sanitise_findings,
    collect_project_samples,
)


def _fake_findings(sample_root: Path):
    """Build the canonical fake-findings list rooted under the
    caller's hermetic sample dir. The vulnerable-dependency entry
    must have its ``file`` under ``sample_root`` so the path-strip
    tests can verify the prefix is removed."""
    return [
        {
            "vuln_type": "sca:vulnerable_dependency",
            "finding_id": "sca:vulnerable_dependency:PyPI:django:CVE-X",
            "severity": "high",
            "file": str(sample_root / "django" / "setup.py"),
            "sca": {
                "ecosystem": "PyPI",
                "name": "django",
                "version": "4.2.0",
                "purl": "pkg:pypi/django@4.2.0",
                "advisory": {"osv_id": "GHSA-x"},
                "in_kev": False,
                "epss": 0.05,
                "cvss_score": 7.5,
                "reachability": {"verdict": "imported"},
                "raptor_risk_estimate": 0.65,
                "risk_components": {"calibration_status": "unverified"},
            },
        },
        {
            "vuln_type": "sca:hygiene:loose_pin",   # filtered out
            "finding_id": "sca:hygiene:loose_pin:django",
            "severity": "low",
            "sca": {"ecosystem": "PyPI", "name": "django"},
        },
        {
            "vuln_type": "sca:license:warned",      # filtered out
            "finding_id": "sca:license:warned:PyPI:django",
            "severity": "medium",
            "sca": {"ecosystem": "PyPI", "name": "django",
                     "spdx": "GPL-3.0"},
        },
    ]


# ---------------------------------------------------------------------------
# _sanitise_findings — schema + path stripping
# ---------------------------------------------------------------------------


def test_sanitise_keeps_only_vuln_findings(tmp_path):
    sample_root = tmp_path / "sample"
    out = _sanitise_findings(_fake_findings(sample_root), sample_root)
    assert len(out) == 1
    assert out[0]["finding_id"] == "sca:vulnerable_dependency:PyPI:django:CVE-X"


def test_sanitise_strips_tempdir_paths(tmp_path):
    """The output must NOT contain any file path under the
    discarded clone dir — second runs would have different
    tempdir suffixes and we don't want path leakage."""
    sample_root = tmp_path / "sample"
    out = _sanitise_findings(_fake_findings(sample_root), sample_root)
    serialised = json.dumps(out)
    assert str(sample_root) not in serialised
    assert "setup.py" not in serialised


def test_sanitise_preserves_validation_relevant_fields(tmp_path):
    sample_root = tmp_path / "sample"
    out = _sanitise_findings(_fake_findings(sample_root), sample_root)
    f = out[0]
    # Fields needed for validation: score, severity, kev/epss
    # signals, advisory id.
    assert f["raptor_risk_estimate"] == 0.65
    assert f["severity"] == "high"
    assert f["in_kev"] is False
    assert f["epss"] == 0.05
    assert f["cvss_score"] == 7.5
    assert f["dep_name"] == "django"
    assert f["dep_version"] == "4.2.0"
    assert f["purl"] == "pkg:pypi/django@4.2.0"
    assert f["advisory"] == {"osv_id": "GHSA-x"}


def test_sanitise_empty_input(tmp_path):
    assert _sanitise_findings([], tmp_path) == []


def test_sanitise_skips_malformed_entries(tmp_path):
    bad = [None, "string", 42, {"vuln_type": "sca:vulnerable_dependency"}]
    out = _sanitise_findings(bad, tmp_path)
    # The dict-without-sca survives but with mostly None fields.
    assert len(out) == 1


# ---------------------------------------------------------------------------
# collect_project_samples — orchestrator + license filter
# ---------------------------------------------------------------------------


def test_only_licenses_filter(tmp_path: Path):
    """Operators concerned about license-touch can restrict
    collection to specific SPDX IDs."""
    samples = [
        ProjectSample(name="x", ecosystem="PyPI",
                       repo_url="https://x/", git_ref="v1",
                       license_spdx="GPL-3.0"),
        ProjectSample(name="y", ecosystem="PyPI",
                       repo_url="https://y/", git_ref="v1",
                       license_spdx="MIT"),
    ]
    # Mock _collect_one so no network. Just record which samples
    # got through the filter.
    called_with: List[ProjectSample] = []
    with patch(
        "packages.sca.calibration.project_samples._collect_one"
    ) as mock_collect:
        mock_collect.side_effect = lambda s, *args, **kw: (
            called_with.append(s),
            CollectResult(
                project=s.name, ecosystem=s.ecosystem,
                written=True, error=None, finding_count=0,
            ),
        )[1]
        collect_project_samples(
            out_dir=tmp_path, samples=samples,
            only_licenses=["MIT"],
        )
    assert [s.name for s in called_with] == ["y"]


def test_one_sample_failing_doesnt_abort_others(tmp_path: Path):
    """A failure on one project doesn't stop the rest."""
    samples = [
        ProjectSample(name="ok", ecosystem="PyPI",
                       repo_url="https://ok/", git_ref="v1",
                       license_spdx="MIT"),
        ProjectSample(name="bad", ecosystem="PyPI",
                       repo_url="https://bad/", git_ref="v1",
                       license_spdx="MIT"),
    ]
    def _fake(s, *args, **kw):
        if s.name == "bad":
            raise RuntimeError("simulated clone failure")
        return CollectResult(
            project=s.name, ecosystem=s.ecosystem,
            written=True, error=None, finding_count=2,
        )
    with patch(
        "packages.sca.calibration.project_samples._collect_one",
        side_effect=_fake,
    ):
        results = collect_project_samples(
            out_dir=tmp_path, samples=samples,
        )
    by_name = {r.project: r for r in results}
    assert by_name["ok"].written is True
    assert by_name["bad"].error is not None
    assert "simulated clone failure" in by_name["bad"].error


def test_parallel_collects_all_samples_input_order(tmp_path: Path):
    """jobs>1 runs projects across a process pool and returns one result
    per sample in INPUT order (not completion order), with per-project
    failures isolated. Uses the ``fork`` start method so the patched
    ``_collect_one`` is inherited by the worker processes."""
    samples = [
        ProjectSample(name=f"p{i}", ecosystem="PyPI",
                       repo_url=f"https://p{i}/", git_ref="v1",
                       license_spdx="MIT")
        for i in range(5)
    ]

    def _fake(s, *args, **kw):
        # Emit to stdout so the worker's fd-level capture is exercised.
        print(f"scanning {s.name}")
        if s.name == "p3":
            raise RuntimeError("boom p3")
        return CollectResult(
            project=s.name, ecosystem=s.ecosystem,
            written=True, error=None, finding_count=len(s.name),
        )

    with patch(
        "packages.sca.calibration.project_samples._collect_one",
        side_effect=_fake,
    ):
        results = collect_project_samples(
            out_dir=tmp_path, samples=samples,
            jobs=3, prewarm=False, _mp_start_method="fork",
        )

    assert [r.project for r in results] == [f"p{i}" for i in range(5)]
    by = {r.project: r for r in results}
    assert by["p0"].written is True
    assert by["p3"].error is not None and "boom p3" in by["p3"].error
    # The four non-failing projects all produced a result.
    assert sum(1 for r in results if r.written) == 4


def test_prewarm_global_feeds_is_best_effort(monkeypatch):
    """The KEV pre-warm must never raise — a fetch/import failure just
    leaves workers to load the catalog themselves."""
    from packages.sca.calibration import project_samples as ps

    def _boom():
        raise RuntimeError("network down")

    monkeypatch.setattr("core.http.default_client", _boom)
    # Should swallow the error, not propagate.
    ps._prewarm_global_feeds()


def test_default_samples_all_have_licenses():
    """The curated list ships with declared licenses — sanity-
    check the data file."""
    for s in PROJECT_SAMPLES:
        assert s.license_spdx, f"{s.name} missing license"
        assert s.repo_url.startswith("https://"), s.name
        assert s.git_ref, f"{s.name} missing git_ref pin"


def test_default_samples_only_permissive_or_dual():
    """Bootstrap policy: don't pull in copyleft-only projects.
    Tightens the collection's license footprint to OSI-permissive
    or dual-licensed (e.g. ``MIT OR Apache-2.0``)."""
    permissive = {"MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause", "ISC"}
    for s in PROJECT_SAMPLES:
        # Either single-permissive or dual-licensed with at least
        # one permissive choice.
        choices = {c.strip() for c in s.license_spdx.replace(
            " AND ", " OR ").split(" OR ")}
        assert choices & permissive, (
            f"{s.name} license {s.license_spdx!r} has no permissive "
            f"choice; expand the policy or remove from PROJECT_SAMPLES"
        )
