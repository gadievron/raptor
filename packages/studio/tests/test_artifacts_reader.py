"""Tests for artifacts reader (exploits, patches, reports, activity)."""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from packages.studio.services.artifacts_reader import (
    list_exploits,
    list_patches,
    list_reports,
    tail_activity,
)
from packages.studio.services.raptor_writer import create_project


def _seed_run(output_dir: Path, name: str, command: str) -> Path:
    run = output_dir / name
    run.mkdir(parents=True)
    (run / ".raptor-run.json").write_text(json.dumps({
        "version": 1,
        "command": command,
        "timestamp": "2026-04-23T12:00:00Z",
        "status": "completed",
        "extra": {},
    }))
    return run


@pytest.fixture
def seeded_project(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    output_base = tmp_path / "out"
    proj = create_project(
        "fixture-proj",
        str(tmp_path / "target"),
        projects_dir=projects_dir,
        output_base=output_base,
    )
    run_dir = _seed_run(Path(proj.output_dir), "scan_demo_20260423_120000", "raptor scan --repo /tmp/x")
    exp_dir = run_dir / "exploits"
    exp_dir.mkdir()
    (exp_dir / "cmd_injection_poc.py").write_text("# exploit")
    (exp_dir / "sqli_poc.py").write_text("# exploit")

    patch_dir = run_dir / "patches"
    patch_dir.mkdir()
    (patch_dir / "fix-cmd.patch").write_text("--- a\n+++ b\n")

    (run_dir / "validation-report.md").write_text("# Validation Report")
    return proj


def test_list_exploits(seeded_project):
    exploits = list_exploits(seeded_project)
    names = sorted(e.filename for e in exploits)
    assert names == ["cmd_injection_poc.py", "sqli_poc.py"]
    for e in exploits:
        assert e.run_name == "scan_demo_20260423_120000"
        assert e.size_bytes > 0


def test_list_patches(seeded_project):
    patches = list_patches(seeded_project)
    assert [p.filename for p in patches] == ["fix-cmd.patch"]


def test_list_reports_finds_known_md(seeded_project):
    reports = list_reports(seeded_project)
    assert any(r.filename == "validation-report.md" for r in reports)


def test_list_exploits_also_reads_fuzzing_subdirs(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    output_base = tmp_path / "out"
    proj = create_project(
        "fuzz-proj",
        str(tmp_path / "target"),
        projects_dir=projects_dir,
        output_base=output_base,
    )
    fuzz_run = _seed_run(Path(proj.output_dir), "fuzz_bin_20260423_130000", "python raptor_fuzzing.py --binary /tmp/bin")
    analysis_exploits = fuzz_run / "analysis" / "exploits"
    analysis_exploits.mkdir(parents=True)
    (analysis_exploits / "crash_0001_exploit.c").write_text("int main(){}")

    exploits = list_exploits(proj)
    assert [e.filename for e in exploits] == ["crash_0001_exploit.c"]


def test_tail_activity_reads_jsonl(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    output_base = tmp_path / "out"
    proj = create_project(
        "log-proj",
        str(tmp_path / "target"),
        projects_dir=projects_dir,
        output_base=output_base,
    )
    logs_dir = Path(proj.output_dir) / "logs"
    logs_dir.mkdir()
    (logs_dir / "raptor_1.jsonl").write_text("\n".join([
        json.dumps({"timestamp": "2026-04-23 12:00:00,001", "level": "INFO", "message": "Started"}),
        json.dumps({"timestamp": "2026-04-23 12:00:05,123", "level": "ERROR", "message": "Something broke"}),
    ]) + "\n")

    entries = tail_activity(proj, limit=10)
    assert len(entries) == 2
    assert entries[0].level == "ERROR"  # newest first
    assert entries[1].message == "Started"


def test_tail_activity_skips_malformed_lines(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    output_base = tmp_path / "out"
    proj = create_project(
        "mal-proj",
        str(tmp_path / "target"),
        projects_dir=projects_dir,
        output_base=output_base,
    )
    logs_dir = Path(proj.output_dir) / "logs"
    logs_dir.mkdir()
    (logs_dir / "raptor.jsonl").write_text(
        "not json\n"
        + json.dumps({"timestamp": "2026-04-23 12:00:00,001", "level": "INFO", "message": "OK"}) + "\n"
        + "also not json\n"
    )
    entries = tail_activity(proj)
    assert [e.message for e in entries] == ["OK"]
