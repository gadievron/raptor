"""Tests for the .gitmodules parser."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import PinStyle
from packages.sca.parsers.gitmodules import parse


def _write_gitmodules(tmp_path: Path, content: str) -> Path:
    """Create a fake repo root with .gitmodules + a .git/ directory."""
    p = tmp_path / ".gitmodules"
    p.write_text(content)
    (tmp_path / ".git").mkdir(exist_ok=True)
    return p


def _write_submodule_head(
    tmp_path: Path, submodule_name: str, sha: str,
) -> None:
    head_dir = tmp_path / ".git" / "modules" / submodule_name
    head_dir.mkdir(parents=True, exist_ok=True)
    (head_dir / "HEAD").write_text(sha + "\n")


# ---------------------------------------------------------------------------
# Section parsing
# ---------------------------------------------------------------------------


def test_single_github_submodule(tmp_path):
    p = _write_gitmodules(
        tmp_path,
        '[submodule "vendor/zlib"]\n'
        '\tpath = vendor/zlib\n'
        '\turl = https://github.com/madler/zlib.git\n',
    )
    [d] = parse(p)
    assert d.ecosystem == "GitHub"
    assert d.name == "madler/zlib"
    assert d.purl == "pkg:github/madler/zlib"
    assert d.pin_style == PinStyle.WILDCARD       # no SHA resolved
    assert d.source_kind == "git_submodule"
    assert d.source_extra["url"] == "https://github.com/madler/zlib.git"
    assert d.source_extra["path"] == "vendor/zlib"
    assert d.source_extra["submodule_name"] == "vendor/zlib"


def test_github_submodule_with_resolved_sha(tmp_path):
    sha = "a" * 40
    p = _write_gitmodules(
        tmp_path,
        '[submodule "vendor/zlib"]\n'
        '\tpath = vendor/zlib\n'
        '\turl = https://github.com/madler/zlib.git\n',
    )
    _write_submodule_head(tmp_path, "vendor/zlib", sha)
    [d] = parse(p)
    assert d.version == sha
    assert d.pin_style == PinStyle.GIT
    assert d.is_lockfile is True
    assert d.purl == f"pkg:github/madler/zlib@{sha}"


def test_head_with_ref_indirection(tmp_path):
    """``HEAD`` sometimes contains ``ref: refs/heads/<branch>``;
    follow the indirection one level."""
    sha = "b" * 40
    p = _write_gitmodules(
        tmp_path,
        '[submodule "vendor/foo"]\n'
        '\tpath = vendor/foo\n'
        '\turl = https://github.com/owner/foo.git\n',
    )
    head_dir = tmp_path / ".git" / "modules" / "vendor/foo"
    head_dir.mkdir(parents=True)
    (head_dir / "HEAD").write_text("ref: refs/heads/main\n")
    refs_dir = head_dir / "refs/heads"
    refs_dir.mkdir(parents=True)
    (refs_dir / "main").write_text(sha + "\n")
    [d] = parse(p)
    assert d.version == sha


def test_invalid_sha_in_head_falls_back_to_none(tmp_path):
    """A short / non-hex SHA isn't accepted — version stays None."""
    p = _write_gitmodules(
        tmp_path,
        '[submodule "x"]\n'
        '\tpath = x\n'
        '\turl = https://github.com/o/x.git\n',
    )
    _write_submodule_head(tmp_path, "x", "not-a-real-sha")
    [d] = parse(p)
    assert d.version is None


def test_missing_head_file(tmp_path):
    p = _write_gitmodules(
        tmp_path,
        '[submodule "x"]\n'
        '\tpath = x\n'
        '\turl = https://github.com/o/x.git\n',
    )
    [d] = parse(p)
    assert d.version is None


def test_missing_git_directory(tmp_path):
    """No ``.git`` ancestor at all — version unresolved, parser
    still emits the submodule with metadata."""
    p = tmp_path / ".gitmodules"
    p.write_text(
        '[submodule "x"]\n'
        '\tpath = x\n'
        '\turl = https://github.com/o/x.git\n',
    )
    [d] = parse(p)
    assert d.version is None


# ---------------------------------------------------------------------------
# URL classification
# ---------------------------------------------------------------------------


def test_ssh_style_github_url_normalised(tmp_path):
    p = _write_gitmodules(
        tmp_path,
        '[submodule "vendor/x"]\n'
        '\tpath = vendor/x\n'
        '\turl = git@github.com:owner/repo.git\n',
    )
    [d] = parse(p)
    assert d.ecosystem == "GitHub"
    assert d.purl == "pkg:github/owner/repo"


def test_non_github_url_falls_back_to_generic(tmp_path):
    p = _write_gitmodules(
        tmp_path,
        '[submodule "vendor/x"]\n'
        '\tpath = vendor/x\n'
        '\turl = https://gitlab.com/group/proj.git\n',
    )
    [d] = parse(p)
    assert d.ecosystem == "GitGeneric"
    assert d.purl == "pkg:generic/gitlab.com/group/proj"


def test_url_without_dotgit_suffix(tmp_path):
    p = _write_gitmodules(
        tmp_path,
        '[submodule "vendor/x"]\n'
        '\tpath = vendor/x\n'
        '\turl = https://github.com/owner/repo\n',
    )
    [d] = parse(p)
    assert d.purl == "pkg:github/owner/repo"


# ---------------------------------------------------------------------------
# Multiple sections
# ---------------------------------------------------------------------------


def test_multiple_submodules(tmp_path):
    p = _write_gitmodules(
        tmp_path,
        '[submodule "a"]\n'
        '\tpath = a\n'
        '\turl = https://github.com/o/a.git\n'
        '[submodule "b"]\n'
        '\tpath = b\n'
        '\turl = https://github.com/o/b.git\n',
    )
    deps = parse(p)
    assert {d.name for d in deps} == {"o/a", "o/b"}


def test_section_missing_url_skipped(tmp_path):
    """Malformed entry with no url field — skip silently."""
    p = _write_gitmodules(
        tmp_path,
        '[submodule "a"]\n'
        '\tpath = a\n'
        '[submodule "b"]\n'
        '\tpath = b\n'
        '\turl = https://github.com/o/b.git\n',
    )
    deps = parse(p)
    assert {d.name for d in deps} == {"o/b"}


def test_comments_and_blank_lines(tmp_path):
    p = _write_gitmodules(
        tmp_path,
        '# This is a comment\n'
        '\n'
        '[submodule "x"]\n'
        '; ini-style comment\n'
        '\tpath = x\n'
        '\turl = https://github.com/o/x.git\n',
    )
    [d] = parse(p)
    assert d.name == "o/x"


def test_unreadable_file(tmp_path):
    """Doesn't exist — parser returns []."""
    p = tmp_path / ".gitmodules"
    assert parse(p) == []


def test_empty_file(tmp_path):
    p = _write_gitmodules(tmp_path, "")
    assert parse(p) == []


def test_orphan_field_outside_section_ignored(tmp_path):
    p = _write_gitmodules(
        tmp_path,
        'path = orphan\n'
        '[submodule "x"]\n'
        '\tpath = x\n'
        '\turl = https://github.com/o/x.git\n',
    )
    deps = parse(p)
    assert {d.name for d in deps} == {"o/x"}
