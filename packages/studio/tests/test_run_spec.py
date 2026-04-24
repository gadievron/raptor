"""Tests for run_spec command-building."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.studio.services.run_spec import (
    CLAUDE_ONLY_KINDS,
    RUNNABLE_KINDS,
    UnsupportedKind,
    build_command,
    claude_cli_hint,
    is_runnable,
)


def test_is_runnable_returns_true_for_pure_python_kinds():
    assert is_runnable("agentic")
    assert is_runnable("scan")
    assert is_runnable("codeql")
    assert is_runnable("fuzz")


def test_is_runnable_returns_true_for_claude_backed_kinds():
    # These shell out to `claude -p` under the hood.
    assert is_runnable("understand")
    assert is_runnable("validate")
    assert is_runnable("oss-forensics")
    assert is_runnable("crash-analysis")


def test_claude_backed_kinds_build_claude_wrapper(tmp_path: Path):
    argv = build_command("understand", "/tmp/app", tmp_path, {"mode": "map"},
                         project_name="myproj")
    assert argv[0] == "bash"
    assert argv[1] == "-c"
    assert "claude -p" in argv[2]
    assert "/understand --map /tmp/app" in argv[2]
    assert "project use myproj" in argv[2]


def test_oss_forensics_includes_focus_in_prompt(tmp_path: Path):
    argv = build_command(
        "oss-forensics",
        "https://github.com/owner/repo",
        tmp_path,
        {"focus": "July 13 incident"},
        project_name="p",
    )
    assert "/oss-forensics" in argv[2]
    assert "July 13 incident" in argv[2]
    assert "github.com/owner/repo" in argv[2]


def test_oss_forensics_appends_vendor_report_url(tmp_path: Path):
    argv = build_command(
        "oss-forensics",
        "https://github.com/owner/repo",
        tmp_path,
        {"focus": "incident", "vendor_report_url": "https://vendor/report.html"},
        project_name="p",
    )
    assert "validate claims in https://vendor/report.html" in argv[2]
    assert "github.com/owner/repo" in argv[2]


def test_oss_forensics_bare_url_when_no_focus_or_vendor(tmp_path: Path):
    argv = build_command(
        "oss-forensics",
        "https://github.com/owner/repo",
        tmp_path,
        {},
        project_name="p",
    )
    # When neither focus nor vendor, pass the URL bare (no quotes-with-dashes).
    assert "github.com/owner/repo" in argv[2]


def test_crash_analysis_requires_both_urls(tmp_path: Path):
    with pytest.raises(ValueError, match="bug_url"):
        build_command("crash-analysis", "", tmp_path, {}, project_name="p")


def test_build_command_agentic_minimal(tmp_path: Path):
    argv = build_command("agentic", "/tmp/myapp", tmp_path, {})
    assert argv[0] == "python3"
    assert argv[1].endswith("raptor_agentic.py")
    assert "--repo" in argv
    assert "/tmp/myapp" in argv


def test_build_command_agentic_with_flags(tmp_path: Path):
    argv = build_command("agentic", "/tmp/app", tmp_path, {
        "policy_groups": "owasp,secrets",
        "max_findings": "5",
        "mode": "fast",
        "no_exploits": "on",
    })
    assert "--policy-groups" in argv
    assert "owasp,secrets" in argv
    assert "--max-findings" in argv
    assert "5" in argv
    assert "--mode" in argv
    assert "fast" in argv
    assert "--no-exploits" in argv


def test_build_command_scan_adds_fast_flags(tmp_path: Path):
    argv = build_command("scan", "/tmp/app", tmp_path, {})
    assert "--mode" in argv and "fast" in argv
    assert "--no-exploits" in argv
    assert "--no-patches" in argv


def test_build_command_codeql_language(tmp_path: Path):
    argv = build_command("codeql", "/tmp/app", tmp_path, {
        "language": "python",
        "validate_dataflow": "on",
        "visualize": "on",
    })
    assert argv[1].endswith("raptor_codeql.py")
    assert "--language" in argv and "python" in argv
    assert "--validate-dataflow" in argv
    assert "--visualize" in argv


def test_build_command_fuzz_requires_duration(tmp_path: Path):
    with pytest.raises(ValueError, match="Duration is required"):
        build_command("fuzz", "/tmp/bin", tmp_path, {})


def test_build_command_fuzz_with_options(tmp_path: Path):
    argv = build_command("fuzz", "/tmp/bin", tmp_path, {
        "duration": "600",
        "parallel": "4",
        "max_crashes": "10",
        "autonomous": "on",
        "goal": "find heap overflow",
    })
    assert argv[1].endswith("raptor_fuzzing.py")
    assert "--binary" in argv and "/tmp/bin" in argv
    assert "--duration" in argv and "600" in argv
    assert "--parallel" in argv and "4" in argv
    assert "--autonomous" in argv
    assert "--goal" in argv and "find heap overflow" in argv


def test_build_command_unsupported_kind_raises(tmp_path: Path):
    with pytest.raises(UnsupportedKind):
        build_command("not-a-real-kind", "/tmp/app", tmp_path, {})


def test_claude_cli_hint_returns_string_for_claude_backed():
    hint = claude_cli_hint("validate", "/tmp/app", "myproj")
    assert hint is not None
    assert "raptor project use myproj" in hint
    assert "/validate" in hint


def test_claude_cli_hint_returns_none_for_python_entrypoint_kinds():
    assert claude_cli_hint("agentic", "/tmp/app", "myproj") is None
    assert claude_cli_hint("scan", "/tmp/app", "myproj") is None
    assert claude_cli_hint("fuzz", "/tmp/bin", "myproj") is None


def test_every_runnable_kind_has_fields():
    for kind, spec in RUNNABLE_KINDS.items():
        if spec.requires_claude:
            assert spec.slash_command.startswith("/")
        else:
            assert spec.script.endswith(".py")
            assert spec.target_arg in ("--repo", "--binary")
