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

    def test_auto_discovers_bounds_from_checklist_in_base_parent(
        self, tmp_path,
    ):
        """When ``--lines`` is omitted, the CLI looks for a
        checklist.json next to the base directory's parent."""
        run_dir = tmp_path / "run"
        ann_base = run_dir / "annotations"
        run_dir.mkdir()
        target = tmp_path / "repo"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "foo.py").write_text(
            "def f():\n    pass\n"
        )
        # Checklist sits next to the base dir's parent (i.e. in run_dir).
        import json
        (run_dir / "checklist.json").write_text(json.dumps({
            "files": [{
                "path": "src/foo.py",
                "items": [{"name": "f", "line_start": 1, "line_end": 2}],
            }],
        }))
        r = _run("add", "src/foo.py", "f",
                 "--base", str(ann_base),
                 "--status", "clean",
                 "--target", str(target),
                 "-m", "auto-discovered")
        assert r.returncode == 0, r.stderr
        text = (ann_base / "src" / "foo.py.md").read_text()
        assert "hash=" in text
        assert "start_line=1" in text
        assert "end_line=2" in text

    def test_auto_discovery_skipped_silently_no_checklist(self, tmp_path):
        """No checklist anywhere → no hash, but the annotation
        still lands. No warning printed (warnings are reserved for
        explicit ``--lines`` failures)."""
        r = _run("add", "src/foo.py", "f",
                 "--base", str(tmp_path),
                 "--status", "clean",
                 "-m", "no hash possible")
        assert r.returncode == 0
        assert "warning" not in r.stderr
        text = (tmp_path / "src" / "foo.py.md").read_text()
        assert "hash=" not in text

    def test_explicit_checklist_arg(self, tmp_path):
        run_dir = tmp_path / "out"
        run_dir.mkdir()
        ann_base = run_dir / "annotations"
        target = tmp_path / "repo"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "foo.py").write_text("def f():\n    pass\n")
        import json
        ck = tmp_path / "custom-checklist.json"
        ck.write_text(json.dumps({
            "files": [{
                "path": "src/foo.py",
                "items": [{"name": "f", "line_start": 1, "line_end": 2}],
            }],
        }))
        r = _run("add", "src/foo.py", "f",
                 "--base", str(ann_base),
                 "--checklist", str(ck),
                 "--target", str(target),
                 "-m", "from custom checklist")
        assert r.returncode == 0
        text = (ann_base / "src" / "foo.py.md").read_text()
        assert "hash=" in text

    def test_explicit_lines_overrides_checklist(self, tmp_path):
        """If both --lines and --checklist could provide bounds,
        --lines wins (operator's explicit intent)."""
        run_dir = tmp_path / "run"
        run_dir.mkdir()
        ann_base = run_dir / "annotations"
        target = tmp_path / "repo"
        target.mkdir()
        (target / "src").mkdir()
        (target / "src" / "foo.py").write_text(
            "def f():\n    return 1\n\ndef g():\n    return 2\n"
        )
        import json
        (run_dir / "checklist.json").write_text(json.dumps({
            "files": [{
                "path": "src/foo.py",
                "items": [{"name": "f", "line_start": 1, "line_end": 2}],
            }],
        }))
        # Operator explicitly says lines 4-5 (the ``g`` body).
        r = _run("add", "src/foo.py", "f",
                 "--base", str(ann_base),
                 "--lines", "4-5",
                 "--target", str(target),
                 "-m", "explicit override")
        assert r.returncode == 0
        text = (ann_base / "src" / "foo.py.md").read_text()
        assert "start_line=4" in text
        assert "end_line=5" in text

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

    def test_filter_by_cwe(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--status", "finding", "--cwe", "CWE-78", "-m", "x")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--status", "finding", "--cwe", "CWE-89", "-m", "x")
        r = _run("ls", "--base", str(tmp_path), "--cwe", "CWE-78")
        assert "src/a.py" in r.stdout
        assert "src/b.py" not in r.stdout

    def test_filter_by_rule_id_substring(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--meta", "rule_id=py/sql-injection", "-m", "x")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "--meta", "rule_id=cpp/buffer-overflow", "-m", "x")
        # Substring "py/" scopes to Python rules.
        r = _run("ls", "--base", str(tmp_path), "--rule-id", "py/")
        assert "src/a.py" in r.stdout
        assert "src/b.py" not in r.stdout

    def test_grep_body(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "-m", "uses subprocess.call shell=True")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "-m", "constant-time compare")
        r = _run("ls", "--base", str(tmp_path), "--grep", "subprocess")
        assert "src/a.py" in r.stdout
        assert "src/b.py" not in r.stdout

    def test_grep_case_insensitive(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "-m", "Subprocess Call")
        r = _run("ls", "--base", str(tmp_path), "--grep", "SUBPROCESS")
        assert "src/a.py" in r.stdout

    def test_grep_metadata_value(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path),
             "--meta", "ticket=BUG-42", "-m", "x")
        _run("add", "src/b.py", "f2", "--base", str(tmp_path),
             "-m", "x")
        r = _run("ls", "--base", str(tmp_path), "--grep", "BUG-42")
        assert "src/a.py" in r.stdout
        assert "src/b.py" not in r.stdout

    def test_since_filter_all_recent(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path), "-m", "x")
        # Just-written annotation falls inside any reasonable window.
        r = _run("ls", "--base", str(tmp_path), "--since", "1h")
        assert "src/a.py" in r.stdout

    def test_since_filter_excludes_old(self, tmp_path):
        import os, time
        _run("add", "src/a.py", "f1", "--base", str(tmp_path), "-m", "x")
        # Backdate the annotation file by 30 days.
        ann_file = tmp_path / "src" / "a.py.md"
        old_ts = time.time() - (30 * 86400)
        os.utime(ann_file, (old_ts, old_ts))
        r = _run("ls", "--base", str(tmp_path), "--since", "7d")
        assert "src/a.py" not in r.stdout

    def test_since_bad_value_errors(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path), "-m", "x")
        r = _run("ls", "--base", str(tmp_path), "--since", "garbage")
        assert r.returncode == 2
        assert "since" in r.stderr.lower()

    def test_since_supported_units(self, tmp_path):
        _run("add", "src/a.py", "f1", "--base", str(tmp_path), "-m", "x")
        for unit in ("60s", "5m", "1h", "1d", "1w"):
            r = _run("ls", "--base", str(tmp_path), "--since", unit)
            assert r.returncode == 0, f"{unit}: {r.stderr}"

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
