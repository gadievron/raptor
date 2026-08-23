"""Tests for packages/cve_env/scripts/raptor-cve-env-bench — the A/B harness.

The subprocess boundary is stubbed; the harness's own logic (CVE list
handling, record shaping, sidecar/stdout outcome recovery, timeout
accounting, aggregation, disagreement detection, resume) is exercised
for real.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
SCRIPT = (REPO_ROOT / "packages" / "cve_env" / "scripts"
          / "raptor-cve-env-bench")


def _load():
    loader = SourceFileLoader("raptor_cve_env_bench", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def bench():
    return _load()


def _args(**kw):
    base = {
        "model": None, "max_turns": 96, "max_cost_usd": 1.80,
        "wall_seconds": 1800.0, "cve_ids": [], "cves": None,
    }
    base.update(kw)
    return SimpleNamespace(**base)


# ── CVE list handling ─────────────────────────────────────────────────


def test_load_cves_dedupes_validates_and_uppercases(bench, tmp_path) -> None:
    listing = tmp_path / "cves.txt"
    listing.write_text(
        "CVE-2018-7600  # drupalgeddon\n\n# comment line\ncve-2021-41773\n"
    )
    args = _args(cve_ids=["CVE-2018-7600"], cves=str(listing))
    assert bench.load_cves(args) == ["CVE-2018-7600", "CVE-2021-41773"]


def test_load_cves_rejects_bogus_id(bench) -> None:
    with pytest.raises(SystemExit):
        bench.load_cves(_args(cve_ids=["CVE-123"]))


def test_parse_args_rejects_unknown_backend(bench) -> None:
    with pytest.raises(SystemExit):
        bench.parse_args(["--backends", "sdk,quantum", "CVE-2018-7600"])


# ── run_one record shapes ─────────────────────────────────────────────


def _fake_runner(*, sidecar: dict | None = None, stdout: str = "",
                 rc: int = 0, timeout: bool = False):
    """Runner double: optionally writes the outcome sidecar the child
    would have written into the --audit-root it was given."""

    def runner(cmd, **kw):
        if timeout:
            raise subprocess.TimeoutExpired(cmd=cmd, timeout=kw["timeout"])
        audit_root = Path(cmd[cmd.index("--audit-root") + 1])
        cve = cmd[cmd.index("build") + 1]
        if sidecar is not None:
            (audit_root / f"{cve}.outcome.json").write_text(
                json.dumps(sidecar))
        return SimpleNamespace(returncode=rc, stdout=stdout, stderr="err")

    return runner


def test_run_one_reads_sidecar_fields(bench, tmp_path) -> None:
    outcome = {
        "cve_id": "CVE-2018-7600", "status": "success",
        "verify_passed": True, "num_turns": 12, "total_cost_usd": 0.42,
        "refusals": 0, "method": "vulhub-image", "give_up_reason": "",
    }
    rec = bench.run_one(
        "CVE-2018-7600", "core", 1, tmp_path, _args(),
        runner=_fake_runner(sidecar=outcome),
    )
    assert rec["backend"] == "core" and rec["bench_rc"] == 0
    assert rec["status"] == "success" and rec["verify_passed"] is True
    assert rec["total_cost_usd"] == 0.42 and rec["method"] == "vulhub-image"


def test_run_one_falls_back_to_stdout_json(bench, tmp_path) -> None:
    stdout = "noise\n" + json.dumps(
        {"cve_id": "CVE-2018-7600", "status": "unresolvable",
         "give_up_reason": "no_image"})
    rec = bench.run_one(
        "CVE-2018-7600", "sdk", 1, tmp_path, _args(),
        runner=_fake_runner(sidecar=None, stdout=stdout, rc=1),
    )
    assert rec["status"] == "unresolvable"
    assert rec["give_up_reason"] == "no_image"


def test_run_one_marks_missing_outcome(bench, tmp_path) -> None:
    rec = bench.run_one(
        "CVE-2018-7600", "sdk", 1, tmp_path, _args(),
        runner=_fake_runner(sidecar=None, stdout="", rc=1),
    )
    assert rec["status"] == "bench_no_outcome"
    assert "stderr_tail" in rec


def test_run_one_timeout_is_a_recorded_status(bench, tmp_path,
                                              monkeypatch) -> None:
    cleaned: list[str] = []
    monkeypatch.setattr(bench, "_cleanup_after_kill", cleaned.append)
    rec = bench.run_one(
        "CVE-2018-7600", "core", 1, tmp_path, _args(wall_seconds=1.0),
        runner=_fake_runner(timeout=True),
    )
    assert rec["status"] == "bench_timeout"
    assert cleaned == ["CVE-2018-7600"]


def test_run_env_sets_backend_and_pythonpath(bench) -> None:
    env = bench._run_env("core", "some-model")
    assert env["CVE_ENV_AGENT_BACKEND"] == "core"
    assert env["CVE_ENV_MODEL"] == "some-model"
    assert str(bench.RAPTOR_DIR) in env["PYTHONPATH"]
    assert "cve_env" in env["PYTHONPATH"]


def test_build_cmd_uses_facade_not_lifecycle_shim(bench, tmp_path) -> None:
    """Bench runs must not feed the scorecard / verified outcomes — the
    lifecycle shim (libexec/raptor-cve-env) does; python -m cve_env does
    not."""
    cmd = bench._build_cmd("CVE-2018-7600", tmp_path, _args())
    assert "-m" in cmd and "cve_env" in cmd
    assert not any("raptor-cve-env" in str(c) for c in cmd)
    assert "--silent" in cmd and "--auto-cleanup-containers" in cmd


# ── aggregation / disagreements / report ─────────────────────────────


_RECORDS = [
    {"cve_id": "CVE-1000-0001", "backend": "sdk", "repeat": 1,
     "status": "success", "verify_passed": True, "num_turns": 10,
     "total_cost_usd": 0.5, "refusals": 0, "duration_s": 60},
    {"cve_id": "CVE-1000-0001", "backend": "core", "repeat": 1,
     "status": "verified_partial", "verify_passed": True, "num_turns": 14,
     "total_cost_usd": 0.7, "refusals": 1, "duration_s": 80},
    {"cve_id": "CVE-1000-0002", "backend": "sdk", "repeat": 1,
     "status": "unresolvable", "verify_passed": False, "num_turns": 30,
     "total_cost_usd": 1.1, "refusals": 0, "give_up_reason": "no_image",
     "duration_s": 200},
    {"cve_id": "CVE-1000-0002", "backend": "core", "repeat": 1,
     "status": "success", "verify_passed": True, "num_turns": 22,
     "total_cost_usd": 0.9, "refusals": 0, "duration_s": 150},
    {"cve_id": "CVE-1000-0003", "backend": "sdk", "repeat": 1,
     "status": "bench_timeout", "duration_s": 1800},
    {"cve_id": "CVE-1000-0003", "backend": "core", "repeat": 1,
     "status": "turn_cap", "verify_passed": False, "num_turns": 96,
     "total_cost_usd": 1.8, "refusals": 0, "duration_s": 900},
]


def test_aggregate_headline_numbers(bench) -> None:
    agg = bench.aggregate(_RECORDS)
    assert agg["sdk"]["runs"] == 3 and agg["core"]["runs"] == 3
    assert agg["sdk"]["success_family"] == 1
    assert agg["core"]["success_family"] == 2
    assert agg["sdk"]["bench_timeouts"] == 1
    assert agg["core"]["refusals"] == 1
    assert agg["core"]["total_cost_usd"] == pytest.approx(3.4)
    assert agg["sdk"]["statuses"]["unresolvable"] == 1


def test_disagreements_compare_success_family_on_repeat_one(bench) -> None:
    dis = bench.disagreements(_RECORDS)
    cves = [d["cve_id"] for d in dis]
    # 0001: both in the success family (success vs verified_partial) →
    # NOT a disagreement. 0003: both are misses (bench_timeout vs
    # turn_cap) → same family, surfaced in the per-run table instead.
    # Only 0002 crosses the family line.
    assert cves == ["CVE-1000-0002"]


def test_disagreements_ignore_repeat_variance(bench) -> None:
    records = list(_RECORDS) + [
        {"cve_id": "CVE-1000-0001", "backend": "core", "repeat": 2,
         "status": "unresolvable"},
    ]
    assert [d["cve_id"] for d in bench.disagreements(records)] == \
        ["CVE-1000-0002"]


def test_report_renders_tables_and_disagreements(bench) -> None:
    text = bench.render_report(_RECORDS, {"model": "m", "repeats": 1})
    assert "| backend | runs | success-family |" in text
    assert "CVE-1000-0002: core: success, sdk: unresolvable" in text
    assert "bench_timeout" in text
    assert "**model**: m" in text


# ── driver resume ─────────────────────────────────────────────────────


def test_main_resumes_from_results_jsonl(bench, tmp_path,
                                         monkeypatch) -> None:
    bench_dir = tmp_path / "bench"
    bench_dir.mkdir()
    prior = {"cve_id": "CVE-1000-0001", "backend": "sdk", "repeat": 1,
             "status": "success", "verify_passed": True}
    (bench_dir / "results.jsonl").write_text(json.dumps(prior) + "\n")

    ran: list[tuple[str, str]] = []

    def fake_run_one(cve, backend, repeat, _dir, _args, **_kw):
        ran.append((cve, backend))
        return {"cve_id": cve, "backend": backend, "repeat": repeat,
                "status": "unresolvable"}

    monkeypatch.setattr(bench, "run_one", fake_run_one)
    rc = bench.main(["CVE-1000-0001", "--out", str(bench_dir),
                     "--backends", "sdk,core"])
    assert rc == 0
    assert ran == [("CVE-1000-0001", "core")]  # sdk cell resumed, not re-run
    assert (bench_dir / "report.md").is_file()


def test_report_only_requires_results(bench, tmp_path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert bench.main(["--report-only", "--out", str(empty)]) == 1
    assert bench.main(["--report-only"]) == 2
