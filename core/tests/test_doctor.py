"""Unit tests for the RAPTOR doctor command."""

from __future__ import annotations

from pathlib import Path
import sys

from core.doctor import DoctorCheck, collect_checks, main, render_checks


def _minimal_repo(root: Path) -> None:
    for dirname in ("core", "packages", "libexec", "bin"):
        (root / dirname).mkdir(parents=True)


def test_collect_checks_reports_layout_and_writable_dirs(tmp_path: Path):
    _minimal_repo(tmp_path)

    checks = collect_checks(tmp_path)
    by_name = {check.name: check for check in checks}

    assert by_name["repo_layout"].status == "pass"
    assert by_name["output_dir"].status == "pass"
    assert by_name["state_tmp"].status == "pass"
    assert (tmp_path / "out").is_dir()
    assert (tmp_path / ".raptor" / "tmp").is_dir()


def test_collect_checks_fails_when_repo_layout_is_missing(tmp_path: Path):
    checks = collect_checks(tmp_path)
    by_name = {check.name: check for check in checks}

    assert by_name["repo_layout"].status == "fail"
    assert "missing required directories" in by_name["repo_layout"].detail


def test_render_checks_includes_summary():
    output = render_checks(
        [
            DoctorCheck("python", "pass", "ok"),
            DoctorCheck("tool:semgrep", "warn", "not found"),
            DoctorCheck("repo_layout", "fail", "missing"),
        ]
    )

    assert "RAPTOR doctor" in output
    assert "PASS python: ok" in output
    assert "WARN tool:semgrep: not found" in output
    assert "FAIL repo_layout: missing" in output
    assert "Summary: 1 failure(s), 1 warning(s)" in output


def test_main_rejects_unexpected_args(capsys):
    rc = main(["--json"])

    captured = capsys.readouterr()
    assert rc == 2
    assert "usage: raptor doctor" in captured.err


def test_main_exits_zero_without_failures(monkeypatch, capsys):
    monkeypatch.setattr(
        "core.doctor.collect_checks",
        lambda: [DoctorCheck("python", "pass", sys.version.split()[0])],
    )

    rc = main([])

    captured = capsys.readouterr()
    assert rc == 0
    assert "RAPTOR doctor" in captured.out
