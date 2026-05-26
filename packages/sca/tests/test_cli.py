"""Tests for ``packages.sca.cli`` — exit codes, output paths, flag plumbing."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from packages.sca import cli, pipeline


@pytest.fixture
def offline_target(tmp_path: Path) -> Path:
    """Empty repo with one trivial manifest — runs without network."""
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "package.json").write_text('{"dependencies": {"x": "*"}}',
                                       encoding="utf-8")
    return repo


def test_main_returns_2_when_target_missing(tmp_path: Path) -> None:
    rc = cli.main([str(tmp_path / "nope")])
    assert rc == 2


def test_main_returns_2_when_target_not_a_directory(tmp_path: Path) -> None:
    f = tmp_path / "file"
    f.write_text("x")
    rc = cli.main([str(f)])
    assert rc == 2


def test_main_writes_findings_and_report(
    offline_target: Path, tmp_path: Path,
) -> None:
    out = tmp_path / "out"
    rc = cli.main([str(offline_target), "--out", str(out), "--offline"])
    assert rc == 0
    assert (out / "findings.json").exists()
    assert (out / "report.md").exists()
    rows = json.loads((out / "findings.json").read_text())
    assert isinstance(rows, list)


def test_main_default_out_dir_is_timestamped(
    offline_target: Path, tmp_path: Path, monkeypatch,
) -> None:
    """Without --out the run lands under ./out/sca-<ts>/."""
    monkeypatch.chdir(tmp_path)
    rc = cli.main([str(offline_target), "--offline"])
    assert rc == 0
    out_root = tmp_path / "out"
    assert out_root.exists()
    runs = list(out_root.iterdir())
    assert len(runs) == 1
    assert runs[0].name.startswith("sca-")
    assert (runs[0] / "findings.json").exists()


def test_main_runtime_error_returns_3(
    offline_target: Path, tmp_path: Path, monkeypatch,
) -> None:
    """If the pipeline raises, the CLI returns 3 rather than crashing."""
    def boom(**_):
        raise RuntimeError("synthetic pipeline failure")
    monkeypatch.setattr(pipeline, "run_sca", boom)
    monkeypatch.setattr(cli, "run_sca", boom)
    rc = cli.main([str(offline_target), "--out", str(tmp_path / "out"),
                   "--offline"])
    assert rc == 3


def test_flags_propagate_to_run_sca(
    offline_target: Path, tmp_path: Path, monkeypatch,
) -> None:
    captured: Dict[str, Any] = {}

    def fake_run_sca(*, target, output_dir, options):
        captured["target"] = target
        captured["options"] = options
        # Return a minimal RunResult-shaped object for _print_summary.
        from packages.sca.pipeline import RunResult
        return RunResult(
            target=target, output_dir=output_dir,
            findings_path=output_dir / "findings.json",
            report_path=output_dir / "report.md",
            sbom_path=output_dir / "sbom.cdx.json",
            sarif_path=output_dir / "findings.sarif",
            deps_analysed=0, vuln_findings=0, hygiene_findings=0,
            supply_chain_findings=0, suppressed_findings=0,
            in_kev=0, cache_hits=0, cache_misses=0,
        )

    monkeypatch.setattr(cli, "run_sca", fake_run_sca)
    rc = cli.main([
        str(offline_target),
        "--out", str(tmp_path / "out"),
        "--offline", "--no-cache",
        "--no-kev", "--no-epss",
        "--cache-root", str(tmp_path / "cache"),
    ])
    assert rc == 0
    options = captured["options"]
    assert options.offline is True
    assert options.no_cache is True
    assert options.enable_kev is False
    assert options.enable_epss is False
    assert options.cache_root == tmp_path / "cache"


def test_verbose_flag_lowers_log_level(
    offline_target: Path, tmp_path: Path,
) -> None:
    """``-v`` and ``-vv`` switch logging level; just verify CLI still
    succeeds end-to-end."""
    rc = cli.main([str(offline_target), "--out", str(tmp_path / "out"),
                   "--offline", "-vv"])
    assert rc == 0
