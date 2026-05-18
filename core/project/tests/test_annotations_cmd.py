"""Tests for ``/project annotations`` subcommand.

Builds a fake project with two run dirs each carrying annotations,
plus the project's top-level annotations dir, and verifies the
``annotations`` subcommand walks all three and prints a deduped /
filtered listing.
"""

from __future__ import annotations

import unittest
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from core.annotations import Annotation, write_annotation
from core.project.cli import _print_annotations


class _FakeProject:
    """Minimal Project shim — only the attributes _print_annotations
    actually touches."""

    def __init__(self, output_dir: Path, run_dirs):
        self.output_dir = str(output_dir)
        self._run_dirs = run_dirs

    def get_run_dirs(self, sweep=False):
        return list(self._run_dirs)


def _build_project(tmp_path: Path):
    """Create: two run dirs each with annotations, plus project-level
    annotations dir."""
    project_root = tmp_path / "myproject"
    project_root.mkdir()

    run_a = project_root / "run-a"
    run_a.mkdir()
    (run_a / ".raptor-run.json").write_text("{}")  # marker
    write_annotation(run_a / "annotations", Annotation(
        file="src/foo.py", function="login",
        body="LLM run-a body", metadata={
            "source": "llm", "status": "finding", "cwe": "CWE-89",
        },
    ))

    run_b = project_root / "run-b"
    run_b.mkdir()
    (run_b / ".raptor-run.json").write_text("{}")
    write_annotation(run_b / "annotations", Annotation(
        file="src/foo.py", function="logout",
        body="LLM run-b body", metadata={
            "source": "llm", "status": "clean",
        },
    ))

    # Project-level (operator notes).
    write_annotation(project_root / "annotations", Annotation(
        file="src/foo.py", function="login",
        body="Operator override: actually clean after manual review",
        metadata={"source": "human", "status": "clean"},
    ))

    return _FakeProject(project_root, [run_a, run_b])


class TestPrintAnnotations(unittest.TestCase):
    def test_lists_all_unique_pairs(self):
        with TemporaryDirectory() as d:
            project = _build_project(Path(d))
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project)
            output = buf.getvalue()
            # Two unique (file, function) pairs: (foo.py, login) +
            # (foo.py, logout). The login annotation from run-a is
            # superseded by the project-level human one.
            assert "2 annotation(s)" in output
            assert "src/foo.py" in output
            assert "login" in output
            assert "logout" in output

    def test_project_level_overrides_run_level(self):
        with TemporaryDirectory() as d:
            project = _build_project(Path(d))
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project)
            output = buf.getvalue()
            # The login row should show source=human (project-level),
            # not source=llm (run-a).
            login_line = [l for l in output.splitlines() if "login" in l][0]
            assert "human" in login_line

    def test_filter_by_status(self):
        with TemporaryDirectory() as d:
            project = _build_project(Path(d))
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project, status_filter="clean")
            output = buf.getvalue()
            # Both surviving rows are clean (logout=clean, login=clean
            # after override).
            assert "2 annotation(s)" in output
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project, status_filter="finding")
            output = buf.getvalue()
            # No finding rows survive the override.
            assert "No annotations match" in output

    def test_filter_by_source(self):
        with TemporaryDirectory() as d:
            project = _build_project(Path(d))
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project, source_filter="human")
            output = buf.getvalue()
            assert "1 annotation(s)" in output
            assert "login" in output

    def test_filter_by_file(self):
        with TemporaryDirectory() as d:
            project = _build_project(Path(d))
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project, file_filter="src/foo.py")
            output = buf.getvalue()
            assert "2 annotation(s)" in output
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project, file_filter="src/missing.py")
            output = buf.getvalue()
            assert "No annotations match" in output

    def test_filter_by_cwe(self):
        with TemporaryDirectory() as d:
            project = _build_project(Path(d))
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project, cwe_filter="CWE-89")
            output = buf.getvalue()
            # Only run-a's login had CWE-89, but it's overridden by
            # the project-level entry without a CWE — so no match.
            assert "No annotations match" in output

    def test_filter_by_rule_id_substring(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "p"
            out.mkdir()
            run = out / "run-x"
            run.mkdir()
            write_annotation(run / "annotations", Annotation(
                file="src/foo.py", function="a",
                metadata={"source": "llm", "rule_id": "py/sql-injection"},
            ))
            write_annotation(run / "annotations", Annotation(
                file="src/foo.py", function="b",
                metadata={"source": "llm", "rule_id": "cpp/buffer-overflow"},
            ))
            project = _FakeProject(out, [run])
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project, rule_id_filter="py/")
            output = buf.getvalue()
            assert "1 annotation(s)" in output
            assert "::a" in output or " a " in output  # function name
            assert "::b" not in output

    def test_grep(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "p"
            out.mkdir()
            run = out / "run-x"
            run.mkdir()
            write_annotation(run / "annotations", Annotation(
                file="src/foo.py", function="a",
                body="uses subprocess.call shell=True",
                metadata={"source": "llm"},
            ))
            write_annotation(run / "annotations", Annotation(
                file="src/foo.py", function="b",
                body="constant-time compare",
                metadata={"source": "llm"},
            ))
            project = _FakeProject(out, [run])
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project, grep="subprocess")
            output = buf.getvalue()
            assert "1 annotation(s)" in output
            assert " a " in output

    def test_since_filter_recent(self):
        """All freshly-written annotations are within a wide window."""
        with TemporaryDirectory() as d:
            project = _build_project(Path(d))
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project, since="7d")
            output = buf.getvalue()
            assert "2 annotation(s)" in output

    def test_since_filter_excludes_old(self):
        import os, time
        with TemporaryDirectory() as d:
            project = _build_project(Path(d))
            # Backdate the run-level annotation file by 30 days.
            for run in project._run_dirs:
                for md in (run / "annotations").rglob("*.md"):
                    old_ts = time.time() - (30 * 86400)
                    os.utime(md, (old_ts, old_ts))
            # Also backdate the project-level file.
            for md in (Path(project.output_dir) / "annotations").rglob("*.md"):
                old_ts = time.time() - (30 * 86400)
                os.utime(md, (old_ts, old_ts))
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project, since="7d")
            output = buf.getvalue()
            # All annotations are now older than 7d → filter shows
            # "no annotations match".
            assert "No annotations match" in output

    def test_since_bad_value_errors(self):
        with TemporaryDirectory() as d:
            project = _build_project(Path(d))
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project, since="garbage")
            output = buf.getvalue()
            assert "bad --since" in output

    def test_no_runs_no_project_annotations(self):
        with TemporaryDirectory() as d:
            project_root = Path(d) / "empty"
            project_root.mkdir()
            project = _FakeProject(project_root, [])
            with patch("sys.stdout", new_callable=StringIO) as buf:
                _print_annotations(project)
            output = buf.getvalue()
            assert "No annotations" in output


if __name__ == "__main__":
    unittest.main()
