"""Unit tests for the commands.md exclusion-sentence parse.

The parity lint counts ONLY backticked names in the exclusion
sentence: a bare-word scrape used to count every English word that
collided with a command stem (the word "commands" in the sentence
itself matched commands.md), so renames and rewording flipped the
lint in confusing ways.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "check_command_metadata.py"


@pytest.fixture(scope="module")
def mod():
    spec = importlib.util.spec_from_file_location(
        "check_command_metadata", _SCRIPT)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_backticked_names_extracted(mod) -> None:
    sentence = (
        "internal/duplicate commands (`/commands` itself, "
        "`raptor-scan`, `raptor-fuzz`, `raptor-web`)"
    )
    assert mod._excluded_names(sentence) == {
        "commands", "raptor-scan", "raptor-fuzz", "raptor-web",
    }


def test_bare_prose_words_not_counted(mod) -> None:
    # "commands" appears as prose (and as a bare example name) — with
    # no backticks nothing may be counted, so accidental stem/word
    # collisions can't satisfy or trip the parity check.
    sentence = (
        "internal/duplicate commands (e.g., raptor-scan, raptor-fuzz, "
        "raptor-web)"
    )
    assert mod._excluded_names(sentence) == set()


def test_leading_slash_stripped(mod) -> None:
    assert mod._excluded_names("`/commands`") == {"commands"}


def test_repo_sentence_matches_frontmatter_set(mod) -> None:
    """The shipped commands.md sentence must parse to exactly the
    frontmatter-excluded set (the lint's end-to-end contract)."""
    text = mod.COMMANDS_INDEX.read_text(encoding="utf-8")
    m = mod._EXCL_SENTENCE_RE.search(text)
    assert m, "exclusion sentence missing from commands.md"
    names = mod._excluded_names(m.group(0))
    flagged = set()
    for md in mod.COMMANDS_DIR.glob("*.md"):
        fm, _ = mod._parse_frontmatter(md.read_text(encoding="utf-8"))
        if fm.get("exclude_from_listing", "").lower() == "true":
            flagged.add(md.stem)
    assert names == flagged


class TestDispatchContainment:
    """The dispatch target must stay inside the repository — absolute
    paths (``REPO / "/abs"`` discards the base entirely), ``..``
    traversal, and symlink escapes are all lint errors, and an escape
    attempt never crashes the lint."""

    def _repo(self, tmp_path: Path) -> Path:
        repo = tmp_path / "repo"
        (repo / "libexec").mkdir(parents=True)
        (repo / "libexec" / "raptor-x").write_text("#!/bin/sh\n")
        return repo

    def test_repo_relative_target_accepted(self, mod, monkeypatch, tmp_path) -> None:
        monkeypatch.setattr(mod, "REPO", self._repo(tmp_path))
        assert mod._check_dispatch("x", "libexec/raptor-x --flag") == []

    def test_absolute_existing_target_rejected(self, mod, monkeypatch, tmp_path) -> None:
        repo = self._repo(tmp_path)
        outside = tmp_path / "outside.sh"
        outside.write_text("#!/bin/sh\n")
        monkeypatch.setattr(mod, "REPO", repo)
        errs = mod._check_dispatch("x", f"bash {outside}")
        assert len(errs) == 1
        assert "absolute or parent traversal" in errs[0]

    def test_absolute_missing_target_reports_instead_of_crashing(
        self, mod, monkeypatch, tmp_path,
    ) -> None:
        # Previously ``target.relative_to(REPO)`` raised an unhandled
        # ValueError while FORMATTING the error for a missing absolute
        # target, crashing the lint instead of reporting.
        monkeypatch.setattr(mod, "REPO", self._repo(tmp_path))
        errs = mod._check_dispatch("x", "bash /nonexistent-zz/script.sh")
        assert len(errs) == 1
        assert "absolute or parent traversal" in errs[0]

    def test_parent_traversal_rejected(self, mod, monkeypatch, tmp_path) -> None:
        repo = self._repo(tmp_path)
        (tmp_path / "outside.sh").write_text("#!/bin/sh\n")
        monkeypatch.setattr(mod, "REPO", repo)
        errs = mod._check_dispatch("x", "libexec/../../outside.sh")
        assert len(errs) == 1
        assert "absolute or parent traversal" in errs[0]

    def test_symlink_escape_rejected(self, mod, monkeypatch, tmp_path) -> None:
        repo = self._repo(tmp_path)
        outside = tmp_path / "outside.sh"
        outside.write_text("#!/bin/sh\n")
        (repo / "libexec" / "raptor-link").symlink_to(outside)
        monkeypatch.setattr(mod, "REPO", repo)
        errs = mod._check_dispatch("x", "libexec/raptor-link")
        assert len(errs) == 1
        assert "resolves outside the repository" in errs[0]

    def test_missing_relative_target_still_reported(
        self, mod, monkeypatch, tmp_path,
    ) -> None:
        monkeypatch.setattr(mod, "REPO", self._repo(tmp_path))
        errs = mod._check_dispatch("x", "libexec/raptor-gone")
        assert len(errs) == 1
        assert "does not exist" in errs[0]


class TestDuplicateFrontmatterKeys:
    def test_duplicate_key_reported(self, mod) -> None:
        fm, duplicates = mod._parse_frontmatter(
            "---\n"
            "dispatch: skill\n"
            "description: d\n"
            "dispatch: libexec/raptor-x\n"
            "---\n"
            "body\n"
        )
        assert duplicates == ["dispatch"]
        assert fm["dispatch"] == "libexec/raptor-x"

    def test_unique_keys_report_no_duplicates(self, mod) -> None:
        fm, duplicates = mod._parse_frontmatter(
            "---\ndispatch: skill\ndescription: d\n---\nbody\n"
        )
        assert duplicates == []
        assert fm == {"dispatch": "skill", "description": "d"}
