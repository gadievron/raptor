"""Tests for the .gitmodules parser."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from packages.sca.models import PinStyle
from packages.sca.parsers.gitmodules import parse

# skip-or-hermetic: the ls-tree fallback tests build REAL git repos —
# on a git-less runner they must skip, not error.
_needs_git = pytest.mark.skipif(
    shutil.which("git") is None, reason="git binary not available",
)


def _git_env(tmp_path: Path) -> dict[str, str]:
    """Hermetic git env: neutralise global/system config and hooks so
    an operator's ~/.gitconfig (fsmonitor, hooksPath, templates) can't
    steer the fixture repos."""
    import os

    env = dict(os.environ)
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


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


# ---------------------------------------------------------------------------
# URL robustness
# ---------------------------------------------------------------------------

def test_bracketed_ipv6_scp_url_parses(tmp_path):
    # SCP-style refs may carry a bracketed IPv6 host; splitting on the
    # first colon produced ``https://[/...`` which urlparse rejects
    # with ``ValueError: Invalid IPv6 URL`` — and the exception killed
    # the parse of the WHOLE file.
    p = _write_gitmodules(
        tmp_path,
        '[submodule "v6"]\n'
        '\tpath = v6\n'
        '\turl = git@[2001:db8::1]:vendor/lib.git\n',
    )
    [d] = parse(p)
    assert d.name == "2001:db8::1/vendor/lib"


def test_unparseable_url_skips_row_not_file(tmp_path, caplog):
    # A hostile/malformed URL must drop only its own row; the sibling
    # submodule still parses.
    import logging
    p = _write_gitmodules(
        tmp_path,
        '[submodule "bad"]\n'
        '\tpath = bad\n'
        '\turl = https://[not-a-bracket-host\n'
        '[submodule "good"]\n'
        '\tpath = good\n'
        '\turl = https://github.com/o/r.git\n',
    )
    with caplog.at_level(logging.WARNING):
        deps = parse(p)
    assert [d.name for d in deps] == ["o/r"]
    assert any("unparseable submodule URL" in r.getMessage()
               for r in caplog.records)


# ---------------------------------------------------------------------------
# git ls-tree fallback (no .git/modules/ but tree object has the SHA)
# ---------------------------------------------------------------------------

@_needs_git
def test_ls_tree_fallback_resolves_sha(tmp_path):
    """When .git/modules/<name>/HEAD is absent, fall back to
    ``git ls-tree`` which reads the pinned SHA from the tree object."""
    import subprocess
    # Build a real git repo with a submodule-like tree entry.
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True,
                   env=_git_env(tmp_path))
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "t@t"],
        capture_output=True, env=_git_env(tmp_path),
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "t"],
        capture_output=True, env=_git_env(tmp_path),
    )
    # Create a .gitmodules file.
    gm = tmp_path / ".gitmodules"
    gm.write_text(
        '[submodule "ext/lib"]\n'
        '\tpath = ext/lib\n'
        '\turl = https://github.com/owner/lib.git\n',
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "add", ".gitmodules"],
        capture_output=True, env=_git_env(tmp_path),
    )
    # Manually insert a gitlink (160000 mode) for ext/lib.
    fake_sha = "a" * 40
    (tmp_path / "ext").mkdir()
    subprocess.run(
        ["git", "-C", str(tmp_path), "update-index", "--add",
         "--cacheinfo", f"160000,{fake_sha},ext/lib"],
        capture_output=True, env=_git_env(tmp_path),
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-m", "init",
         "--allow-empty"],
        capture_output=True, env=_git_env(tmp_path),
    )
    # No .git/modules/ directory — the submodule hasn't been cloned.
    assert not (tmp_path / ".git" / "modules").exists()
    [d] = parse(gm)
    assert d.version == fake_sha
    assert d.pin_style == PinStyle.GIT


@_needs_git
def test_ls_tree_fallback_no_commit(tmp_path):
    """When there's no commit at all, the fallback returns None
    gracefully (no crash)."""
    import subprocess
    subprocess.run(["git", "init", str(tmp_path)], capture_output=True,
                   env=_git_env(tmp_path))
    gm = tmp_path / ".gitmodules"
    gm.write_text(
        '[submodule "x"]\n\tpath = x\n'
        '\turl = https://github.com/o/x.git\n',
    )
    [d] = parse(gm)
    assert d.version is None


def test_ls_tree_runs_hardened_and_env_sanitised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ls-tree child runs inside an UNTRUSTED repo: it must get
    the strict read-only git overrides (committed config cannot pick
    core.fsmonitor / core.hooksPath / core.sshCommand commands) and
    the sanitised environment — never the operator's full env."""
    from packages.sca.parsers import gitmodules as gm

    seen: dict = {}

    class _Result:
        returncode = 0
        stdout = ("160000 commit "
                  "0123456789abcdef0123456789abcdef01234567\tlibs/x\n")
        stderr = ""

    def _fake_run(cmd, **kwargs):
        seen["cmd"] = cmd
        seen["kwargs"] = kwargs
        return _Result()

    monkeypatch.setattr(gm.subprocess, "run", _fake_run)
    monkeypatch.setenv("GITHUB_TOKEN", "hostile-must-not-leak")
    sha = gm._resolve_from_ls_tree(tmp_path, "libs/x")
    assert sha == "0123456789abcdef0123456789abcdef01234567"

    cmd = seen["cmd"]
    assert cmd[0] == "git"
    joined = " ".join(cmd)
    # Config-neutralising overrides present before the subcommand.
    assert "core.fsmonitor=" in joined
    assert "core.hooksPath=" in joined
    assert cmd.index("ls-tree") > cmd.index("-c")
    # Sanitised env passed explicitly; allowlist drops the token.
    env = seen["kwargs"].get("env")
    assert env is not None
    assert "GITHUB_TOKEN" not in env


# ---------------------------------------------------------------------------
# Repo-root walk-up is bounded
# ---------------------------------------------------------------------------


def test_repo_root_walk_stops_at_scan_root(tmp_path):
    """A target WITHOUT its own ``.git`` (extracted tarball, exported
    subtree) scanned under a directory that IS a git repo must NOT
    adopt that outer repo as the submodule-resolution root — git would
    then run (and ``.git/modules`` refs be read) in a repo above the
    scan target, at attacker-chosen submodule paths."""
    from packages.sca.parsers._safe_read import scan_root_context
    from packages.sca.parsers.gitmodules import _find_repo_root

    outer = tmp_path / "operator-repo"
    target = outer / "extracted" / "src"
    target.mkdir(parents=True)
    (outer / ".git").mkdir()
    gm = target / ".gitmodules"
    gm.write_text('[submodule "x"]\n  path = libs/x\n  url = u\n')
    with scan_root_context(target):
        assert _find_repo_root(gm) is None
    # Without a scan-root bound the .git boundary still stops the
    # walk AT the outer repo (the depth-capped legacy behaviour).
    assert _find_repo_root(gm) == outer.resolve()


def test_repo_root_walk_depth_capped(tmp_path):
    """No scan root, no ``.git`` anywhere near: the walk gives up at
    the shared depth cap instead of proceeding to ``/``."""
    from packages.sca.parsers.gitmodules import _find_repo_root

    deep = tmp_path
    for i in range(15):
        deep = deep / f"d{i}"
    deep.mkdir(parents=True)
    gm = deep / ".gitmodules"
    gm.write_text('[submodule "x"]\n  path = libs/x\n  url = u\n')
    # A .git thirteen-plus levels above the manifest is out of reach.
    (tmp_path / ".git").mkdir()
    assert _find_repo_root(gm) is None
