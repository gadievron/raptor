"""Trust-gate coverage for Copilot ``--add-dir`` configuration."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.security.cc_trust import (
    check_repo_agent_cli_trust,
    is_trust_overridden,
    set_trust_override,
)


@pytest.fixture(autouse=True)
def _strict_trust():
    set_trust_override(False)
    yield
    set_trust_override(False)


def test_claude_mode_does_not_block_copilot_instruction_file(tmp_path):
    (tmp_path / "AGENTS.md").write_text("target instructions", encoding="utf-8")
    assert not check_repo_agent_cli_trust(
        str(tmp_path), agent_cli="claude",
    )


@pytest.mark.parametrize(
    "relative",
    [
        "AGENTS.md",
        "CLAUDE.md",
        "GEMINI.md",
        ".github/copilot-instructions.md",
        ".github/copilot-mcp.json",
        ".vscode/mcp.json",
    ],
)
def test_copilot_mode_blocks_trusted_config_files(
    tmp_path, relative, capsys,
):
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("target config", encoding="utf-8")
    assert check_repo_agent_cli_trust(str(tmp_path), agent_cli="copilot")
    assert relative in capsys.readouterr().out


@pytest.mark.parametrize(
    "relative",
    [
        ".github/agents",
        ".github/skills",
        ".github/hooks",
        ".claude/agents",
        ".claude/commands",
        ".claude/skills",
    ],
)
def test_copilot_mode_blocks_nonempty_trusted_config_dirs(
    tmp_path, relative, capsys,
):
    directory = tmp_path / relative
    directory.mkdir(parents=True)
    (directory / "config.md").write_text("instructions", encoding="utf-8")
    assert check_repo_agent_cli_trust(str(tmp_path), agent_cli="copilot")
    assert relative in capsys.readouterr().out


def test_empty_trusted_config_directory_is_inert(tmp_path):
    (tmp_path / ".github" / "skills").mkdir(parents=True)
    assert not check_repo_agent_cli_trust(str(tmp_path), agent_cli="copilot")


def test_symlinked_trusted_config_directory_blocks(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    github = tmp_path / ".github"
    github.mkdir()
    (github / "skills").symlink_to(outside, target_is_directory=True)
    assert check_repo_agent_cli_trust(str(tmp_path), agent_cli="copilot")


def test_explicit_trust_override_allows_copilot_config(tmp_path, capsys):
    (tmp_path / "AGENTS.md").write_text("trusted", encoding="utf-8")
    assert not check_repo_agent_cli_trust(
        str(tmp_path),
        agent_cli="copilot",
        trust_override=True,
    )
    assert "trust override active" in capsys.readouterr().out


def test_authenticated_session_trust_override_is_honoured(monkeypatch):
    set_trust_override(None)
    monkeypatch.setattr(
        "core.project.sessions.session_repo_trusted",
        lambda repo_path: True,
    )

    assert is_trust_overridden("/trusted")


def test_explicit_denial_overrides_authenticated_session(monkeypatch):
    monkeypatch.setattr(
        "core.project.sessions.session_repo_trusted",
        lambda repo_path: True,
    )
    set_trust_override(False)

    assert not is_trust_overridden("/trusted")


def test_raptor_self_scan_is_not_blocked():
    root = Path(__file__).resolve().parents[3]
    assert not check_repo_agent_cli_trust(str(root), agent_cli="copilot")
