"""Tests for persona reader + finding → persona mapping."""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


@pytest.fixture
def fake_personas(tmp_path, monkeypatch):
    """Point RAPTOR_HOME at a tmp dir with synthetic persona files."""
    personas_dir = tmp_path / "tiers" / "personas"
    personas_dir.mkdir(parents=True)
    (personas_dir / "security_researcher.md").write_text("# security researcher brief")
    (personas_dir / "exploit_developer.md").write_text("# exploit dev brief")
    (personas_dir / "binary_exploitation_specialist.md").write_text("# binary spec brief")
    (personas_dir / "crash_analyst.md").write_text("# crash brief")
    (personas_dir / "penetration_tester.md").write_text("# pen tester brief")
    (personas_dir / "codeql_finding_analyst.md").write_text("# codeql finding")
    (personas_dir / "codeql_analyst.md").write_text("# codeql dataflow")
    (personas_dir / "patch_engineer.md").write_text("# patch brief")
    (personas_dir / "fuzzing_strategist.md").write_text("# fuzzing brief")

    monkeypatch.setenv("RAPTOR_HOME", str(tmp_path))
    from packages.studio import config
    importlib.reload(config)
    for mod in ("packages.studio.services.personas",):
        if mod in sys.modules:
            importlib.reload(sys.modules[mod])
    from packages.studio.services import personas
    personas.clear_cache()
    yield personas
    personas.clear_cache()


def test_all_personas_loaded(fake_personas):
    personas = fake_personas.all_personas()
    labels = {p.label for p in personas}
    assert "Security Researcher" in labels
    assert "Exploit Developer" in labels
    assert "Binary Exploitation Specialist" in labels
    # Every persona has metadata even if the file is missing.
    keys = {p.key for p in personas}
    assert "offensive_security_researcher" in keys


def test_memory_corruption_picks_binary_specialists(fake_personas):
    f = {"vuln_type": "stack_overflow"}
    results = fake_personas.personas_for_finding(f)
    keys = [p.key for p in results]
    assert "binary_exploitation_specialist" in keys
    assert "crash_analyst" in keys
    # Security researcher always present as baseline.
    assert "security_researcher" in keys


def test_web_vuln_picks_pen_tester(fake_personas):
    f = {"vuln_type": "sql_injection"}
    results = fake_personas.personas_for_finding(f)
    assert results[0].key == "penetration_tester"


def test_codeql_tool_picks_codeql_analyst(fake_personas):
    f = {"vuln_type": "xss", "tool": "codeql"}
    keys = [p.key for p in fake_personas.personas_for_finding(f)]
    assert "codeql_finding_analyst" in keys


def test_exploitable_finding_picks_exploit_dev_and_patch(fake_personas):
    f = {
        "vuln_type": "command_injection",
        "final_status": "exploitable",
    }
    keys = [p.key for p in fake_personas.personas_for_finding(f)]
    assert "exploit_developer" in keys
    assert "patch_engineer" in keys


def test_memory_corruption_finding_with_feasibility_also_picks_exploit_dev(fake_personas):
    f = {
        "vuln_type": "buffer_overflow",
        "feasibility": {"verdict": "likely_exploitable"},
    }
    keys = [p.key for p in fake_personas.personas_for_finding(f)]
    assert "binary_exploitation_specialist" in keys
    assert "exploit_developer" in keys


def test_crash_filename_picks_fuzzing_personas(fake_personas):
    f = {"vuln_type": "segfault", "file": "afl_output/main/crashes/id-000001"}
    keys = [p.key for p in fake_personas.personas_for_finding(f)]
    assert "fuzzing_strategist" in keys or "crash_analyst" in keys


def test_personas_for_finding_caps_results(fake_personas):
    f = {
        "vuln_type": "buffer_overflow",
        "tool": "codeql",
        "final_status": "exploitable",
        "feasibility": {"verdict": "exploitable"},
        "file": "src/crash.c",
    }
    results = fake_personas.personas_for_finding(f)
    assert 1 <= len(results) <= 4


def test_persona_content_loaded_when_file_exists(fake_personas):
    p = fake_personas.get_persona("exploit_developer")
    assert p is not None
    assert p.is_loaded
    assert p.content.startswith("# exploit dev")


def test_persona_content_empty_when_file_missing(fake_personas):
    # offensive_security_researcher file was NOT written in fixture
    p = fake_personas.get_persona("offensive_security_researcher")
    assert p is not None
    assert not p.is_loaded
    assert p.content == ""
