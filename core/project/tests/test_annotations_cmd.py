"""Tests for ``/project annotations`` subcommand.

Builds a fake project with two run dirs each carrying annotations,
plus the project's top-level annotations dir, and verifies the
``annotations`` subcommand walks all three and prints a deduped /
filtered listing.
"""

from __future__ import annotations

import json
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
