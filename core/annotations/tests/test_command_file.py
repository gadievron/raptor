"""Lint-style smoke tests for the ``/annotate`` slash command file.

These don't exercise behaviour — they just verify the command file is
syntactically intact, references the correct libexec script, and
documents every subcommand the CLI implements. Catches accidental
deletion / link rot when the CLI evolves.
"""

from __future__ import annotations

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
COMMAND_FILE = REPO_ROOT / ".claude" / "commands" / "annotate.md"
CLI = REPO_ROOT / "libexec" / "raptor-annotate"
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"


def _command_text():
    return COMMAND_FILE.read_text(encoding="utf-8")


class TestCommandFileExists:
    def test_command_file_present(self):
        assert COMMAND_FILE.exists(), (
            f"slash command file missing: {COMMAND_FILE}"
        )

    def test_cli_target_exists_and_executable(self):
        assert CLI.exists(), f"libexec target missing: {CLI}"
        assert CLI.stat().st_mode & 0o100, (
            f"libexec target not executable: {CLI}"
        )


class TestFrontMatter:
    def test_has_frontmatter(self):
        text = _command_text()
        # YAML front matter must be the first thing.
        assert text.startswith("---\n"), (
            "command file must start with YAML front matter"
        )
        # And must close.
        body_start = text.find("\n---\n", 4)
        assert body_start > 0, "front matter must be closed with ---"

    def test_has_description(self):
        text = _command_text()
        assert "description:" in text.split("\n---\n", 1)[0], (
            "front matter needs a 'description:' field"
        )


class TestSubcommandsCovered:
    """Every CLI subcommand should be documented in the slash command
    file. Otherwise an operator types ``/annotate stale`` and Claude
    has no idea that's a real subcommand."""

    SUBCOMMANDS = ("add", "ls", "show", "edit", "rm", "stale")

    @pytest.mark.parametrize("sub", SUBCOMMANDS)
    def test_subcommand_documented(self, sub):
        text = _command_text()
        # Look for /annotate <sub> in usage block, or `<sub> ` (with
        # trailing space or args) in the subcommands table.
        assert (
            f"/annotate {sub}" in text
            or f"`{sub} " in text
            or f"`{sub}`" in text
        ), f"subcommand '{sub}' not documented in command file"


class TestExecutionTarget:
    def test_references_libexec_cli(self):
        text = _command_text()
        # The command file's Execution section must point Claude at
        # the right libexec script.
        assert "libexec/raptor-annotate" in text, (
            "command file does not reference libexec/raptor-annotate"
        )


class TestClaudeMdEntry:
    def test_command_listed_in_claude_md(self):
        """Operators reading CLAUDE.md should see /annotate in the
        commands list."""
        text = CLAUDE_MD.read_text(encoding="utf-8")
        assert "/annotate" in text, (
            "CLAUDE.md COMMANDS section does not mention /annotate"
        )


class TestKeyConventions:
    """Spot-check that the design conventions Claude needs to apply
    are present in the doc — otherwise operators get inconsistent
    behaviour across sessions."""

    def test_documents_source_human_default(self):
        text = _command_text()
        assert "source=human" in text or "`source` " in text or "human" in text, (
            "command file should document the source=human convention"
        )

    def test_documents_respect_manual(self):
        text = _command_text()
        assert "respect-manual" in text, (
            "command file should document overwrite=respect-manual"
        )

    def test_documents_base_resolution_order(self):
        text = _command_text()
        # Operators need to know how --base resolves.
        assert "--base" in text
        assert "active project" in text.lower()
