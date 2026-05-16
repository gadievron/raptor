"""Tests for annotation handling in ``generate_project_report``.

Verifies the report includes annotation counts and writes
``annotations.json`` + ``annotations.md`` next to the merged
findings export.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.annotations import Annotation, write_annotation
from core.project.report import (
    gather_project_annotations,
    generate_project_report,
    render_annotations_markdown,
)


class _FakeProject:
    def __init__(self, output_dir: Path, run_dirs, name="test"):
        self.name = name
        self.output_path = output_dir
        self.output_dir = str(output_dir)
        self._run_dirs = run_dirs

    def get_run_dirs(self, sweep=False):
        return list(self._run_dirs)


def _build_project(tmp_path: Path):
    out = tmp_path / "myproj"
    out.mkdir()
    run_a = out / "run-a"
    run_a.mkdir()
    write_annotation(run_a / "annotations", Annotation(
        file="src/foo.py", function="login",
        body="LLM run-a body",
        metadata={"source": "llm", "status": "finding"},
    ))
    write_annotation(run_a / "annotations", Annotation(
        file="src/foo.py", function="logout",
        body="LLM run-a body 2",
        metadata={"source": "llm", "status": "clean"},
    ))
    # Project-level operator override on login.
    write_annotation(out / "annotations", Annotation(
        file="src/foo.py", function="login",
        body="Operator override",
        metadata={"source": "human", "status": "clean"},
    ))
    return _FakeProject(out, [run_a])


class TestGatherProjectAnnotations(unittest.TestCase):
    def test_dedupes_with_project_priority(self):
        with TemporaryDirectory() as d:
            project = _build_project(Path(d))
            recs = gather_project_annotations(project)
            assert len(recs) == 2  # login + logout
            login = next(r for r in recs if r["function"] == "login")
            assert login["source"] == "human"  # project-level wins
            assert "Operator override" in login["body"]

    def test_no_annotations_returns_empty(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "p"
            out.mkdir()
            project = _FakeProject(out, [])
            assert gather_project_annotations(project) == []


class TestRenderAnnotationsMarkdown(unittest.TestCase):
    def test_empty_renders_no_annotations(self):
        md = render_annotations_markdown([], "test")
        assert "No annotations" in md

    def test_includes_counts_and_per_function(self):
        records = [
            {"file": "a.py", "function": "f1",
             "status": "clean", "source": "human",
             "body": "ok", "metadata": {}},
            {"file": "a.py", "function": "f2",
             "status": "finding", "source": "llm",
             "body": "bad", "metadata": {}},
        ]
        md = render_annotations_markdown(records, "myproj")
        assert "Annotations — myproj" in md
        assert "2 unique annotation(s)" in md
        assert "clean=1" in md
        assert "finding=1" in md
        assert "human=1" in md
        assert "llm=1" in md
        assert "`a.py`" in md
        assert "`f1`" in md
        assert "`f2`" in md


class TestGenerateProjectReport(unittest.TestCase):
    def test_writes_annotations_json_and_md(self):
        with TemporaryDirectory() as d:
            project = _build_project(Path(d))
            # Add a run marker so get_run_dirs returns it via sweep.
            (project._run_dirs[0] / ".raptor-run.json").write_text("{}")
            stats = generate_project_report(project)
            assert stats["annotations"] == 2
            report_dir = Path(stats["report_dir"])
            assert (report_dir / "annotations.json").exists()
            assert (report_dir / "annotations.md").exists()
            data = json.loads((report_dir / "annotations.json").read_text())
            assert len(data["annotations"]) == 2
            md = (report_dir / "annotations.md").read_text()
            assert "login" in md
            assert "logout" in md

    def test_no_runs_returns_zero_annotations(self):
        with TemporaryDirectory() as d:
            out = Path(d) / "empty"
            out.mkdir()
            project = _FakeProject(out, [])
            stats = generate_project_report(project)
            assert stats == {"findings": 0, "runs": 0, "annotations": 0}


if __name__ == "__main__":
    unittest.main()
