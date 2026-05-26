"""Tests for the programmatic SCA API (``packages.sca.api``)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from packages.sca.api import analyse, _summarise
from packages.sca.pipeline import RunResult


def _fake_run_result(output_dir: Path) -> RunResult:
    return RunResult(
        target=output_dir / "target",
        output_dir=output_dir,
        findings_path=output_dir / "findings.json",
        report_path=output_dir / "report.md",
        sbom_path=output_dir / "sbom.cdx.json",
        sarif_path=output_dir / "sca.sarif",
        deps_analysed=10,
        vuln_findings=3,
        hygiene_findings=2,
        supply_chain_findings=1,
        suppressed_findings=0,
        in_kev=1,
        cache_hits=5,
        cache_misses=5,
        llm_cost=0.42,
    )


def test_summarise_roundtrip(tmp_path: Path) -> None:
    result = _fake_run_result(tmp_path)
    summary = _summarise(result)
    assert summary["status"] == "ok"
    assert summary["vuln_findings"] == 3
    assert summary["llm_cost"] == 0.42
    assert summary["deps_analysed"] == 10


@patch("packages.sca.api.run_sca")
def test_analyse_returns_summary(mock_run_sca, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    mock_run_sca.return_value = _fake_run_result(out)

    summary = analyse(target=tmp_path, output_dir=out)
    assert summary["status"] == "ok"
    assert summary["vuln_findings"] == 3
    mock_run_sca.assert_called_once()


@patch("packages.sca.api.run_sca", side_effect=RuntimeError("boom"))
def test_analyse_returns_error_on_failure(mock_run_sca, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    summary = analyse(target=tmp_path, output_dir=out)
    assert summary["status"] == "error"
    assert "boom" in summary["error"]


@patch("packages.sca.api.run_sca")
def test_analyse_with_sarif_dirs_calls_linking(mock_run_sca, tmp_path: Path) -> None:
    out = tmp_path / "out"
    out.mkdir()
    mock_run_sca.return_value = _fake_run_result(out)

    # Write a minimal findings.json for cross-tool linking
    findings_path = out / "findings.json"
    findings_path.write_text("[]")

    sarif_dir = tmp_path / "semgrep"
    sarif_dir.mkdir()

    with patch("packages.sca.cross_tool.link_related_findings") as mock_link:
        summary = analyse(
            target=tmp_path, output_dir=out,
            sarif_dirs=[sarif_dir],
        )
    assert summary["status"] == "ok"
    mock_link.assert_called_once()


@patch("packages.sca.api.run_sca")
def test_analyse_cross_tool_failure_non_fatal(mock_run_sca, tmp_path: Path) -> None:
    """Cross-tool linking failure should not cause analyse() to fail."""
    out = tmp_path / "out"
    out.mkdir()
    mock_run_sca.return_value = _fake_run_result(out)

    sarif_dir = tmp_path / "semgrep"
    sarif_dir.mkdir()

    with patch("packages.sca.cross_tool.link_related_findings",
               side_effect=RuntimeError("link failed")):
        summary = analyse(
            target=tmp_path, output_dir=out,
            sarif_dirs=[sarif_dir],
        )
    assert summary["status"] == "ok"
