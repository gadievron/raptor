from __future__ import annotations

import json
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _frontmatter(text: str) -> dict[str, str]:
    lines = text.splitlines()
    assert lines and lines[0] == "---"
    try:
        end = lines[1:].index("---") + 1
    except ValueError as exc:
        raise AssertionError("missing closing frontmatter marker") from exc

    data: dict[str, str] = {}
    for line in lines[1:end]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip().strip('"')
    return data


def test_codex_repo_guidance_files_exist() -> None:
    assert (ROOT / "AGENTS.md").is_file()
    assert (ROOT / ".agents" / "skills").is_dir()
    assert (ROOT / ".codex" / "config.toml").is_file()
    assert (ROOT / ".codex" / "hooks.json").is_file()


def test_agent_skills_have_required_frontmatter() -> None:
    skills = sorted((ROOT / ".agents" / "skills").rglob("SKILL.md"))
    assert skills, "expected Codex skills under .agents/skills"

    for skill in skills:
        metadata = _frontmatter(_read(skill))
        assert metadata.get("name"), f"{skill} is missing a skill name"
        assert metadata.get("description"), f"{skill} is missing a skill description"


def test_codex_agents_are_valid_toml() -> None:
    agents = sorted((ROOT / ".codex" / "agents").glob("*.toml"))
    assert agents, "expected Codex sub-agent definitions"

    for agent in agents:
        data = tomllib.loads(_read(agent))
        assert data.get("description"), f"{agent} is missing a description"
        assert data.get("developer_instructions"), f"{agent} is missing developer instructions"


def test_codex_startup_hook_uses_repo_relative_session_init() -> None:
    config = tomllib.loads(_read(ROOT / ".codex" / "config.toml"))
    env = config["shell_environment_policy"]["set"]
    assert env["RAPTOR_ENV_FILE"] == ".codex/raptor.env"
    assert "CLAUDE_ENV_FILE" not in env

    hooks = json.loads(_read(ROOT / ".codex" / "hooks.json"))
    command = hooks["hooks"]["SessionStart"][0]["hooks"][0]["command"]
    assert "_RAPTOR_TRUSTED=1" in command
    assert "libexec/raptor-session-init" in command
    assert "CLAUDE_PROJECT_DIR" not in command


def test_active_codex_docs_do_not_point_at_retired_skill_paths() -> None:
    paths = [
        ROOT / "AGENTS.md",
        ROOT / ".codex" / "config.toml",
        ROOT / ".codex" / "hooks.json",
        *sorted((ROOT / ".codex" / "agents").glob("*.toml")),
        *sorted((ROOT / ".agents" / "skills").glob("source-command-*/SKILL.md")),
        ROOT / ".agents" / "skills" / "code-understanding" / "SKILL.md",
        ROOT / ".agents" / "skills" / "exploitability-validation" / "SKILL.md",
        ROOT / ".agents" / "skills" / "coverage" / "SKILL.md",
    ]

    forbidden = [".Codex/skills", ".claude/skills", "CLAUDE_PROJECT_DIR"]
    for path in paths:
        text = _read(path)
        for marker in forbidden:
            assert marker not in text, f"{path} still references {marker}"
