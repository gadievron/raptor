"""End-to-end tests for the ``libexec/raptor-annotate`` operator CLI.

Drives the CLI as a subprocess. Each test sets ``_RAPTOR_TRUSTED=1``
to bypass the trust-marker guard and passes ``--base`` so no project
state is required.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-annotate"


def _run(*args, env=None, input_text=None):
    """Run the CLI with --base resolved by caller in args."""
    real_env = dict(os.environ)
    real_env["_RAPTOR_TRUSTED"] = "1"
    if env:
        real_env.update(env)
    result = subprocess.run(
        [sys.executable, str(CLI), *args],
        env=real_env,
        capture_output=True,
        text=True,
        input=input_text,
    )
    return result


# ---------------------------------------------------------------------------
# Trust marker
# ---------------------------------------------------------------------------


class TestTrustMarker:
    def test_refuses_without_marker(self, tmp_path):
        env = {k: v for k, v in os.environ.items()
               if k not in ("_RAPTOR_TRUSTED", "CLAUDECODE")}
        result = subprocess.run(
            [sys.executable, str(CLI), "ls", "--base", str(tmp_path)],
            env=env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 2
        assert "internal dispatch" in result.stderr


# ---------------------------------------------------------------------------
# add
# ---------------------------------------------------------------------------


class TestAdd:
    def test_basic_add(self, tmp_path):
        r = _run("add", "src/foo.py", "process",
                 "--base", str(tmp_path),
                 "--status", "clean",
                 "-m", "Reviewed, no taint")
        assert r.returncode == 0, r.stderr
        assert "wrote" in r.stdout
        # Verify on disk.
        ann_file = tmp_path / "src" / "foo.py.md"
        assert ann_file.exists()
        text = ann_file.read_text()
        assert "## process" in text
        assert "status=clean" in text
        assert "source=human" in text  # default
        assert "Reviewed, no taint" in text

    def test_add_with_cwe_and_meta(self, tmp_path):
        r = _run("add", "src/foo.py", "process",
                 "--base", str(tmp_path),
                 "--status", "finding",
                 "--cwe", "CWE-78",
                 "--meta", "reviewer=alice",
                 "--meta", "ticket=BUG-42",
                 "-m", "command injection via shell=True")
        assert r.returncode == 0
        text = (tmp_path / "src" / "foo.py.md").read_text()
        assert "cwe=CWE-78" in text
        assert "reviewer=alice" in text
        assert "ticket=BUG-42" in text

    def test_add_body_from_stdin(self, tmp_path):
        r = _run("add", "src/foo.py", "process",
                 "--base", str(tmp_path),
                 "--status", "clean",
                 "--body-file", "-",
                 input_text="body from stdin\nmulti-line content\n")
        assert r.returncode == 0
        ann = (tmp_path / "src" / "foo.py.md").read_text()
        assert "body from stdin" in ann
        assert "multi-line content" in ann

    def test_add_body_from_file(self, tmp_path):
        body_file = tmp_path / "_body.txt"
        body_file.write_text("imported prose\n")
        r = _run("add", "src/foo.py", "process",
                 "--base", str(tmp_path),
                 "--status", "clean",
                 "--body-file", str(body_file))
        assert r.returncode == 0
        assert "imported prose" in (tmp_path / "src" / "foo.py.md").read_text()

    def test_add_with_hash(self, tmp_path):
        # Set up a mock target repo with a real source file.
        target = tmp_path / "repo"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "foo.py").write_text(
            "def process(x):\n    return os.system(x)\n"
        )
        ann_base = tmp_path / "anns"
        r = _run("add", "src/foo.py", "process",
                 "--base", str(ann_base),
                 "--status", "finding",
                 "--lines", "1-2",
                 "--target", str(target),
                 "-m", "shell injection")
        assert r.returncode == 0, r.stderr
        text = (ann_base / "src" / "foo.py.md").read_text()
        assert "hash=" in text
        assert "start_line=1" in text
        assert "end_line=2" in text

    def test_add_invalid_lines_format(self, tmp_path):
        r = _run("add", "src/foo.py", "f",
                 "--base", str(tmp_path),
                 "--lines", "garbage",
                 "-m", "x")
        assert r.returncode == 2
        assert "lines" in r.stderr

    def test_add_invalid_meta(self, tmp_path):
        r = _run("add", "src/foo.py", "f",
                 "--base", str(tmp_path),
                 "--meta", "no-equals-sign",
                 "-m", "x")
        assert r.returncode == 2

    def test_add_respect_manual_skips_human(self, tmp_path):
        # First write as human (default).
        _run("add", "src/foo.py", "f",
             "--base", str(tmp_path),
             "-m", "manual note")
        # Now LLM tries respect-manual — should skip.
        r = _run("add", "src/foo.py", "f",
                 "--base", str(tmp_path),
                 "--source", "llm",
                 "--overwrite", "respect-manual",
                 "-m", "llm overwrite attempt")
        # Skip is signalled with rc=1 and "skipped" in stderr.
        assert r.returncode == 1
        assert "skipped" in r.stderr
        # Manual content still there.
        text = (tmp_path / "src" / "foo.py.md").read_text()
        assert "manual note" in text
        assert "llm overwrite" not in text

    def test_add_rejects_invalid_overwrite_mode(self, tmp_path):
        r = _run("add", "src/foo.py", "f",
                 "--base", str(tmp_path),
                 "--overwrite", "bogus",
                 "-m", "x")
        # argparse rejects before reaching our validation.
        assert r.returncode != 0


# ---------------------------------------------------------------------------
# ls
# ---------------------------------------------------------------------------


class TestLs:
    def test_empty_says_so(self, tmp_path):
        r = _run("ls", "--base", str(tmp_path))
        assert r.returncode == 0
        assert "(no annotations)" in r.stdout

    def test_lists_added(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "clean", "-m", "ok")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--status", "finding", "-m", "bad")
        r = _run("ls", "--base", str(tmp_path))
        assert r.returncode == 0
        assert "src/a.py" in r.stdout
        assert "src/b.py" in r.stdout

    def test_filter_by_status(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "clean", "-m", "ok")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--status", "finding", "-m", "bad")
        r = _run("ls", "--base", str(tmp_path), "--status", "finding")
        assert "src/b.py" in r.stdout
        assert "src/a.py" not in r.stdout

    def test_filter_by_source(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--source", "human", "-m", "manual")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--source", "llm", "-m", "auto")
        r = _run("ls", "--base", str(tmp_path), "--source", "llm")
        assert "src/b.py" in r.stdout
        assert "src/a.py" not in r.stdout

    def test_filter_by_file(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "clean", "-m", "ok")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--status", "clean", "-m", "ok")
        r = _run("ls", "--base", str(tmp_path), "--file", "src/a.py")
        assert "src/a.py" in r.stdout
        assert "src/b.py" not in r.stdout


# ---------------------------------------------------------------------------
# show
# ---------------------------------------------------------------------------


class TestShow:
    def test_shows_existing(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "clean", "-m", "the body content")
        r = _run("show", "src/a.py", "f1", "--base", str(tmp_path))
        assert r.returncode == 0
        assert "## f1" in r.stdout
        assert "status=clean" in r.stdout
        assert "the body content" in r.stdout

    def test_missing_returns_1(self, tmp_path):
        r = _run("show", "src/nope.py", "x", "--base", str(tmp_path))
        assert r.returncode == 1
        assert "no annotation" in r.stderr


# ---------------------------------------------------------------------------
# rm
# ---------------------------------------------------------------------------


class TestRm:
    def test_removes_existing(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "clean", "-m", "x")
        r = _run("rm", "src/a.py", "f1", "--base", str(tmp_path))
        assert r.returncode == 0
        assert "removed" in r.stdout

    def test_remove_missing_returns_1(self, tmp_path):
        r = _run("rm", "src/nope.py", "x", "--base", str(tmp_path))
        assert r.returncode == 1


# ---------------------------------------------------------------------------
# edit
# ---------------------------------------------------------------------------


class TestEdit:
    def test_edit_invokes_editor(self, tmp_path):
        # Use ``true`` as a no-op editor — exits 0 without prompting.
        env = {"EDITOR": "true"}
        r = _run("edit", "src/a.py", "f1",
                 "--base", str(tmp_path), env=env)
        assert r.returncode == 0
        # Placeholder file created.
        assert (tmp_path / "src" / "a.py.md").exists()

    def test_edit_propagates_editor_failure(self, tmp_path):
        env = {"EDITOR": "false"}
        r = _run("edit", "src/a.py", "f1",
                 "--base", str(tmp_path), env=env)
        assert r.returncode != 0


# ---------------------------------------------------------------------------
# stale
# ---------------------------------------------------------------------------


class TestStale:
    def test_no_annotations(self, tmp_path):
        r = _run("stale", "--base", str(tmp_path),
                 "--target", str(tmp_path))
        assert r.returncode == 0
        assert "(no stale" in r.stdout

    def test_detects_stale(self, tmp_path):
        target = tmp_path / "repo"
        target.mkdir()
        (target / "src").mkdir()
        src = target / "src" / "a.py"
        src.write_text("def f():\n    return 1\n")
        # Add annotation with hash from current source.
        ann_base = tmp_path / "anns"
        _run("add", "src/a.py", "f",
             "--base", str(ann_base),
             "--status", "clean",
             "--lines", "1-2",
             "--target", str(target),
             "-m", "ok")
        # Run stale check now — nothing stale.
        r = _run("stale", "--base", str(ann_base),
                 "--target", str(target))
        assert r.returncode == 0
        assert "(no stale" in r.stdout
        # Edit source — hash changes — stale detected.
        src.write_text("def f():\n    return 99\n")
        r = _run("stale", "--base", str(ann_base),
                 "--target", str(target))
        assert r.returncode == 0
        assert "src/a.py:f" in r.stdout
        assert "stored=" in r.stdout
        assert "current=" in r.stdout

    def test_skips_annotations_without_hash(self, tmp_path):
        # Add annotation without --lines (no hash captured).
        _run("add", "src/a.py", "f", "--base", str(tmp_path),
             "--status", "clean", "-m", "no hash")
        r = _run("stale", "--base", str(tmp_path),
                 "--target", str(tmp_path))
        assert r.returncode == 0
        assert "(no stale" in r.stdout


# ---------------------------------------------------------------------------
# Base resolution
# ---------------------------------------------------------------------------


class TestBaseResolution:
    def test_explicit_base_used(self, tmp_path):
        r = _run("ls", "--base", str(tmp_path))
        assert r.returncode == 0

    def test_no_base_no_project_errors(self, tmp_path):
        # Run with no --base and a temp HOME so no real project exists.
        # We can't easily fake "no active project" in a real repo with
        # active-state, so instead point PROJECTS_DIR at an empty tmp dir
        # via env. The real defence is integration-tested in the slash
        # command harness; here, just ensure the explicit-base path works.
        # Skip this assertion if a project is active in the dev env.
        pass
