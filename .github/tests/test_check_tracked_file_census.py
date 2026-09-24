"""Tests for .github/scripts/check_tracked_file_census.py — the
per-subsystem tracked-file shape census."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / ".github" / "scripts"))

from check_tracked_file_census import (  # noqa: E402
    SUBSYSTEMS,
    census_violations,
    main,
    mode_violations,
    _glob_to_regex,
)


class TestGlobDialect:
    def _match(self, pattern: str, path: str) -> bool:
        return _glob_to_regex(pattern).fullmatch(path) is not None

    def test_star_does_not_cross_directories(self):
        assert self._match("rules/*.yaml", "rules/x.yaml")
        assert not self._match("rules/*.yaml", "rules/a/x.yaml")

    def test_doublestar_matches_zero_or_more_components(self):
        assert self._match("rules/**/*.yaml", "rules/x.yaml")
        assert self._match("rules/**/*.yaml", "rules/a/b/x.yaml")
        assert not self._match("rules/**/*.yaml", "rules/a/b/x.yml")

    def test_leading_doublestar_matches_at_root(self):
        assert self._match("**/README.md", "README.md")
        assert self._match("**/README.md", "a/b/README.md")
        assert not self._match("**/README.md", "a/xREADME.md")

    def test_literal_dots_are_escaped(self):
        # ``.`` in a pattern is a literal dot, not regex any-char —
        # otherwise "a.py" would also bless "aXpy".
        assert self._match("*.py", "a.py")
        assert not self._match("*.py", "aXpy")

    def test_trailing_doublestar_matches_any_suffix(self):
        assert self._match("tests/**", "tests/x")
        assert self._match("tests/**", "tests/a/b")
        assert not self._match("tests/**", "tests")

    def test_trailing_newline_does_not_match(self):
        # ``$``-anchored matching tolerates one string-final newline;
        # the translator must not (fullmatch semantics). The census
        # additionally rejects ANY control byte before patterns are
        # consulted — this pins the regex layer independently.
        assert not self._match("rules/**/*.yaml", "rules/x.yaml\n")
        assert not self._match("*.py", "a.py\n")

    def test_character_classes_are_rejected_loudly(self):
        # ``[ab]`` is outside the dialect; escaping it silently would
        # leave a dead pattern that matches nothing.
        with pytest.raises(ValueError):
            _glob_to_regex("rules/[ab].yaml")


def test_censused_root_set_is_pinned() -> None:
    # Deliberate-membership pin: the anti-vacuity test below iterates
    # the LIVE dict, so silently DELETING a root would leave every
    # census test green while its subsystem loses coverage. Editing
    # this list is the explicit act that removes (or adds) a censused
    # subsystem.
    assert sorted(SUBSYSTEMS) == [
        "core/audit/rules",
        "engine/coccinelle",
        "engine/codeql",
        "engine/negative_controls",
        "engine/semgrep",
    ]


class TestCensus:
    def test_planted_extensionless_stray_is_caught(self):
        # The motivating class: a one-line extensionless scratch file
        # beside a rule pack. No content gate opens it (ruff sees only
        # .py; the fixture suites glob rules/**/*.yaml), so shape is
        # the only tripwire.
        v = census_violations(["engine/semgrep/rules/scratch"])
        assert v == {
            "engine/semgrep": ["engine/semgrep/rules/scratch"],
        }

    # Violation-direction coverage for EVERY censused root — a root
    # whose shapes accidentally widen to "anything" must fail here.
    @pytest.mark.parametrize("stray", [
        "engine/semgrep/rules/notes.txt",
        "engine/coccinelle/rules/scratch",
        "engine/codeql/queries/cpp/extra.yml",  # non-manifest .yml must
                                                # not ride in as "a pack"
        "engine/negative_controls/notes",
        "core/audit/rules/decompiler/scratch",
    ])
    def test_planted_stray_per_root_is_caught(self, stray):
        root = next(r for r in SUBSYSTEMS if stray.startswith(r + "/"))
        assert census_violations([stray]) == {root: [stray]}

    @pytest.mark.parametrize("name", [
        "engine/semgrep/rules/x.yaml\n",       # shape-passing but for \n
        "engine/semgrep/rules/a/.gitkeep\n",   # payload-capable placeholder
        "engine/semgrep/tests/x\x1by.py",      # ESC mid-name
        # C1 CSI (valid UTF-8, terminal-live) and a bidi override
        # (renders as a different name) — spelled as escapes so no
        # live control/format character sits in this source file.
        "engine/semgrep/rules/x\u009b.yaml",
        "engine/semgrep/rules/x\u202e.yaml",
    ])
    def test_control_and_format_names_are_always_violations(self, name):
        v = census_violations([name])
        (lines,) = v.values()
        (line,) = lines
        assert "(control character in file name)" in line
        # The printed form is inert: escapes, never the live character.
        for live in ("\n", "\x1b", "\u009b", "\u202e"):
            assert live not in line

    def test_legitimate_shapes_pass(self):
        assert census_violations([
            "engine/semgrep/rules/python/injection/sqli.yaml",
            "engine/semgrep/rules/registry-cache/.gitkeep",
            "engine/semgrep/tests/java/Deserialize.java",
            "engine/semgrep/tools/cache-packs.py",
            "engine/coccinelle/rules/use_after_free.cocci",
            "engine/coccinelle/source_intel/crypto/packs/openssl.json",
            "engine/coccinelle/tests/.gitignore",
            "engine/coccinelle/api_pack_renderer.py",
            "engine/codeql/queries/cpp/UseAfterMove.ql",
            "engine/codeql/queries/cpp/qlpack.yml",
            "engine/codeql/suites/README.md",
            "engine/negative_controls/xxe.c",
            "core/audit/rules/decompiler/format-string.yaml",
        ]) == {}

    def test_paths_outside_censused_roots_are_ignored(self):
        # The gate only claims the subsystems it enumerates —
        # libexec/ shims are extensionless by design and must never
        # enter this census.
        assert census_violations([
            "libexec/raptor-run-lifecycle",
            "core/llm/client.py",
            "engine/semgrep-lookalike/scratch",  # sibling name, not the root
        ]) == {}

    def test_root_itself_needs_the_separator(self):
        # A file literally named like a censused root is not "under"
        # it (prefix match is on ``root + "/"``).
        assert census_violations(["engine/semgrepx"]) == {}


class TestModeCensus:
    def test_symlink_and_gitlink_are_violations(self):
        out = mode_violations([
            ("120000", "engine/semgrep/rules/link.yaml"),
            ("160000", "engine/codeql/queries/sub"),
        ])
        assert len(out) == 2
        assert any("symlink" in line for line in out)
        assert any("gitlink" in line for line in out)

    def test_regular_files_and_outside_paths_pass(self):
        assert mode_violations([
            ("100644", "engine/semgrep/rules/x.yaml"),
            ("100755", "engine/coccinelle/api_pack_renderer.py"),
            ("120000", "some/other/link"),  # outside the census
        ]) == []


@pytest.fixture()
def scratch_repo(tmp_path: Path) -> Path:
    """A minimal git repo with a clean censused population. Adds to
    the INDEX only (the gate reads the index), so no commit identity
    is needed. Skips when git is unavailable — same degrade as the
    gate itself."""
    if shutil.which("git") is None:
        pytest.skip("git unavailable")
    repo = tmp_path / "repo"
    rules = repo / "engine/semgrep/rules"
    rules.mkdir(parents=True)
    (rules / "ok.yaml").write_text("rules: []\n", encoding="utf-8")
    (rules / ".gitkeep").write_text("", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "init", "-q"], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
    return repo


class TestScratchRepoEndToEnd:
    """Planted-file integration: the whole pipeline (git parsing, mode
    and name validation, .gitkeep emptiness) against a throwaway index
    — never the real tree."""

    def _gate(self, repo: Path, capsys) -> tuple[int, str]:
        rc = main(["--root", str(repo)])
        return rc, capsys.readouterr().out

    def test_clean_scratch_repo_passes(self, scratch_repo, capsys):
        rc, out = self._gate(scratch_repo, capsys)
        assert rc == 0 and "[file-census] clean:" in out

    def test_trailing_newline_name_fails(self, scratch_repo, capsys):
        evil = scratch_repo / "engine/semgrep/rules/evil.yaml\n"
        evil.write_text("rules: []\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(scratch_repo), "add", "-A"],
                       check=True)
        rc, out = self._gate(scratch_repo, capsys)
        assert rc == 1
        assert "control character in file name" in out
        assert "evil.yaml\\x0a" in out  # escaped, never raw

    def test_content_bearing_gitkeep_fails(self, scratch_repo, capsys):
        keep = scratch_repo / "engine/semgrep/rules/.gitkeep"
        keep.write_text("#!/bin/sh\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(scratch_repo), "add", "-A"],
                       check=True)
        rc, out = self._gate(scratch_repo, capsys)
        assert rc == 1 and "content-bearing .gitkeep" in out

    def test_tracked_symlink_fails(self, scratch_repo, capsys):
        link = scratch_repo / "engine/semgrep/rules/link.yaml"
        link.symlink_to("ok.yaml")
        subprocess.run(["git", "-C", str(scratch_repo), "add", "-A"],
                       check=True)
        rc, out = self._gate(scratch_repo, capsys)
        assert rc == 1 and "symlink" in out

    def test_gitlink_entry_fails(self, scratch_repo, capsys):
        # A submodule pointer census-blessed as "some file" is the
        # worst shape; fabricate the 160000 index entry directly.
        subprocess.run(
            ["git", "-C", str(scratch_repo), "update-index", "--add",
             "--cacheinfo",
             "160000,0123456789012345678901234567890123456789,"
             "engine/semgrep/rules/sub.yaml"],
            check=True,
        )
        rc, out = self._gate(scratch_repo, capsys)
        assert rc == 1 and "gitlink" in out

    def test_non_utf8_name_fails_closed_without_traceback(
        self, scratch_repo, capsys,
    ):
        raw = os.path.join(
            os.fsencode(scratch_repo), b"engine/semgrep/rules/\xffx.yaml",
        )
        with open(raw, "wb") as fh:
            fh.write(b"rules: []\n")
        subprocess.run(["git", "-C", str(scratch_repo), "add", "-A"],
                       check=True)
        # Fail-closed direction pinned: this must stay a violation —
        # an errors="replace" style "fix" that normalises the name
        # into a matchable one turns undecodable paths into a pass.
        rc, out = self._gate(scratch_repo, capsys)
        assert rc == 1 and "not valid UTF-8" in out

    def test_c1_and_bidi_names_fail_with_inert_output(
        self, scratch_repo, capsys,
    ):
        # C1 CSI (U+009B) and a bidi override (U+202E) are valid
        # UTF-8, so they survive decode and would shape-match but for
        # the categorical Cc/Cf check.
        # Escape-spelled: no live control/format char in source.
        for fname in ("evil\u009b.yaml", "evil\u202e.yaml"):
            path = scratch_repo / "engine/semgrep/rules" / fname
            path.write_text("rules: []\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(scratch_repo), "add", "-A"],
                       check=True)
        rc, out = self._gate(scratch_repo, capsys)
        assert rc == 1
        assert "evil\\x9b.yaml" in out and "evil\\u202e.yaml" in out
        # Byte-clean output (LC_ALL=C style audit): no live control
        # or format character anywhere in the report.
        assert not any(
            ch for ch in out
            if ch != "\n" and (ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f
                               or ch == "\u202e")
        )

    def test_poisoned_git_env_is_scrubbed(
        self, scratch_repo, tmp_path, capsys, monkeypatch,
    ):
        # Inherited GIT_INDEX_FILE=<missing> makes git census an
        # EMPTY index as clean; GIT_DIR retargets another repository.
        # Both must be scrubbed from the gate's subprocesses.
        stray = scratch_repo / "engine/semgrep/rules/scratch"
        stray.write_text("x\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(scratch_repo), "add", "-A"],
                       check=True)
        other = tmp_path / "other-repo"
        other.mkdir()
        subprocess.run(["git", "-C", str(other), "init", "-q"],
                       check=True)
        monkeypatch.setenv("GIT_INDEX_FILE",
                           str(tmp_path / "no-such-index"))
        monkeypatch.setenv("GIT_DIR", str(other / ".git"))
        rc, out = self._gate(scratch_repo, capsys)
        assert rc == 1 and "engine/semgrep/rules/scratch" in out

    def test_require_git_fails_a_zero_entry_census(
        self, tmp_path, capsys,
    ):
        if shutil.which("git") is None:
            pytest.skip("git unavailable")
        empty = tmp_path / "empty-repo"
        empty.mkdir()
        subprocess.run(["git", "-C", str(empty), "init", "-q"],
                       check=True)
        # Tracking data present but zero censused files: vacuous —
        # always wrong where --require-git is set.
        assert main(["--root", str(empty), "--require-git"]) == 1
        assert "zero tracked files" in capsys.readouterr().out
        assert main(["--root", str(empty)]) == 0  # bare mode: visible
        assert "0 tracked files" in capsys.readouterr().out

    def test_require_git_makes_the_notice_arm_fail(
        self, tmp_path, capsys,
    ):
        if shutil.which("git") is None:
            pytest.skip("git unavailable")
        # tmp_path lives outside any repository on supported runners
        # (a GIT_CEILING guard would be scrubbed with the rest of the
        # GIT_* environment by design).
        bare = tmp_path / "not-a-repo"
        bare.mkdir()
        assert main(["--root", str(bare)]) == 0  # notice arm
        assert "notice" in capsys.readouterr().out
        assert main(["--root", str(bare), "--require-git"]) == 1
        assert "error" in capsys.readouterr().out


class TestRealTree:
    """Integration against the actual checkout (skipped without git,
    same degrade as the gate script itself)."""

    def _tracked(self) -> list[str]:
        proc = subprocess.run(
            ["git", "-C", str(REPO), "ls-files", "-z", "--",
             *sorted(SUBSYSTEMS)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode != 0 or not proc.stdout.strip("\0"):
            pytest.skip("not a git checkout (or git unavailable)")
        return [p for p in proc.stdout.split("\0") if p]

    def test_current_tree_is_clean(self):
        assert census_violations(self._tracked()) == {}

    def test_every_censused_root_is_populated(self):
        # Anti-vacuity: a renamed or moved subsystem root must fail
        # here, not leave the census silently covering nothing (root
        # DELETION from the dict is separately pinned by the
        # membership test above).
        tracked = self._tracked()
        empty = [
            root for root in SUBSYSTEMS
            if not any(p.startswith(root + "/") for p in tracked)
        ]
        assert empty == [], (
            f"censused root(s) with no tracked files: {empty} — "
            "update SUBSYSTEMS to the subsystem's new location"
        )

    def test_gate_main_reports_clean(self, capsys):
        assert main(["--root", str(REPO)]) == 0
        out = capsys.readouterr().out
        assert "[file-census] clean:" in out

    def test_gate_main_rejects_bad_root(self):
        assert main(["--root", str(REPO / "no-such-dir")]) == 2


def test_census_gate_is_wired_into_the_pr_gate() -> None:
    # PR-gate presence pin. Sweep parity is separately enforced by
    # test_ci_controls_docs (exact-set parity between lint.yml's
    # repo-invariants job and miswiring-scan.yml) — but that parity is
    # on script paths, not flags, so --require-git is pinned here for
    # BOTH invocations: without it a checkout failure mode degrades to
    # the exported-tree notice arm and CI goes green on a skipped
    # census.
    wired = "python3 .github/scripts/check_tracked_file_census.py --require-git"
    lint = (REPO / ".github/workflows/lint.yml").read_text(
        encoding="utf-8",
    )
    invariants = lint.split("\n  repo-invariants:", 1)[1]
    assert wired in invariants, (
        "tracked-file census (with --require-git) dropped from "
        "lint.yml's repo-invariants job"
    )
    sweep = (REPO / ".github/workflows/miswiring-scan.yml").read_text(
        encoding="utf-8",
    )
    assert wired in sweep, (
        "tracked-file census (with --require-git) dropped from the "
        "daily sweep"
    )
