"""Tests for ``core.project.annotations_diff``.

Builds two run dirs with overlapping annotation sets and asserts
the diff classifier puts each pair in the right bucket (added,
removed, changed, unchanged).
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.annotations import Annotation, write_annotation
from core.project.annotations_diff import (
    diff_annotations,
    format_diff,
)


class TestDiffAnnotations(unittest.TestCase):
    def _setup_runs(self, tmp_path: Path):
        run_a = tmp_path / "run-a"
        run_b = tmp_path / "run-b"
        run_a.mkdir()
        run_b.mkdir()

        # Same in both — unchanged.
        for run in (run_a, run_b):
            write_annotation(run / "annotations", Annotation(
                file="src/foo.py", function="same",
                body="identical body",
                metadata={"source": "llm", "status": "clean"},
            ))

        # In A only — removed.
        write_annotation(run_a / "annotations", Annotation(
            file="src/foo.py", function="dropped",
            body="x", metadata={"source": "llm", "status": "clean"},
        ))

        # In B only — added.
        write_annotation(run_b / "annotations", Annotation(
            file="src/foo.py", function="new",
            body="y", metadata={"source": "llm", "status": "finding"},
        ))

        # In both, status changed — changed.
        write_annotation(run_a / "annotations", Annotation(
            file="src/foo.py", function="status_flip",
            body="x", metadata={"source": "llm", "status": "finding"},
        ))
        write_annotation(run_b / "annotations", Annotation(
            file="src/foo.py", function="status_flip",
            body="x", metadata={"source": "llm", "status": "clean"},
        ))

        # In both, body changed — changed.
        write_annotation(run_a / "annotations", Annotation(
            file="src/foo.py", function="body_flip",
            body="initial reasoning",
            metadata={"source": "llm", "status": "clean"},
        ))
        write_annotation(run_b / "annotations", Annotation(
            file="src/foo.py", function="body_flip",
            body="updated reasoning after re-review",
            metadata={"source": "llm", "status": "clean"},
        ))

        return run_a, run_b

    def test_classification(self):
        with TemporaryDirectory() as d:
            run_a, run_b = self._setup_runs(Path(d))
            result = diff_annotations(run_a, run_b)
            assert len(result["added"]) == 1
            assert result["added"][0]["function"] == "new"
            assert len(result["removed"]) == 1
            assert result["removed"][0]["function"] == "dropped"
            assert len(result["changed"]) == 2
            changed_names = {c["after"]["function"] for c in result["changed"]}
            assert changed_names == {"status_flip", "body_flip"}
            assert len(result["unchanged"]) == 1
            assert result["unchanged"][0]["function"] == "same"

    def test_irrelevant_metadata_drift_is_unchanged(self):
        """Updating ``hash`` or ``rule_id`` doesn't count as changed
        — operators care about body + status, not file checksums."""
        with TemporaryDirectory() as d:
            run_a = Path(d) / "a"; run_a.mkdir()
            run_b = Path(d) / "b"; run_b.mkdir()
            write_annotation(run_a / "annotations", Annotation(
                file="src/x.py", function="f", body="same body",
                metadata={"source": "llm", "status": "clean",
                          "hash": "abc123"},
            ))
            write_annotation(run_b / "annotations", Annotation(
                file="src/x.py", function="f", body="same body",
                metadata={"source": "llm", "status": "clean",
                          "hash": "def456"},  # different hash
            ))
            result = diff_annotations(run_a, run_b)
            assert len(result["unchanged"]) == 1
            assert len(result["changed"]) == 0

    def test_empty_runs(self):
        with TemporaryDirectory() as d:
            run_a = Path(d) / "a"; run_a.mkdir()
            run_b = Path(d) / "b"; run_b.mkdir()
            result = diff_annotations(run_a, run_b)
            assert result["added"] == []
            assert result["removed"] == []
            assert result["changed"] == []
            assert result["unchanged"] == []

    def test_no_annotations_subdir(self):
        """Run dirs without ``annotations/`` subdirs treated as empty."""
        with TemporaryDirectory() as d:
            run_a = Path(d) / "a"; run_a.mkdir()
            run_b = Path(d) / "b"; run_b.mkdir()
            # No annotations/ in either.
            result = diff_annotations(run_a, run_b)
            assert all(len(result[k]) == 0
                       for k in ("added", "removed", "changed", "unchanged"))


class TestFormatDiff(unittest.TestCase):
    def test_includes_counts(self):
        with TemporaryDirectory() as d:
            run_a = Path(d) / "a"; run_a.mkdir()
            run_b = Path(d) / "b"; run_b.mkdir()
            write_annotation(run_b / "annotations", Annotation(
                file="src/x.py", function="new", body="x",
                metadata={"source": "llm", "status": "finding"},
            ))
            result = diff_annotations(run_a, run_b)
            text = format_diff(result)
            assert "added=1" in text
            assert "removed=0" in text
            assert "+ src/x.py::new" in text

    def test_status_change_rendered(self):
        with TemporaryDirectory() as d:
            run_a = Path(d) / "a"; run_a.mkdir()
            run_b = Path(d) / "b"; run_b.mkdir()
            write_annotation(run_a / "annotations", Annotation(
                file="src/x.py", function="f", body="x",
                metadata={"source": "llm", "status": "finding"},
            ))
            write_annotation(run_b / "annotations", Annotation(
                file="src/x.py", function="f", body="x",
                metadata={"source": "llm", "status": "clean"},
            ))
            result = diff_annotations(run_a, run_b)
            text = format_diff(result)
            assert "finding → clean" in text


if __name__ == "__main__":
    unittest.main()
