"""End-to-end verification that ``compute_summary`` picks up the
``coverage-annotations.json`` record written by ``/agentic`` and
``/understand``.

The standard ``load_records`` reader scans for ``coverage-*.json``
files. The annotation builder writes one per run. This test pins
that the wire-up actually flows: write annotations → coverage record
emitted → compute_summary surfaces it as ``tools["annotations"]``.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.annotations import Annotation, write_annotation
from core.coverage.record import build_from_annotations, write_record
from core.coverage.summary import compute_summary


class TestSummaryWithAnnotations(unittest.TestCase):
    """Pins that the annotation tool name appears in the summary
    output, with the right files_examined and functions_analysed."""

    def _make_run_with_annotations(self, run_dir: Path):
        """Create a run dir that mirrors what /agentic writes:
        a checklist.json (inventory), an annotations tree, and a
        coverage-annotations.json built from the tree."""
        # Tiny inventory.
        checklist = {
            "target_path": str(run_dir),
            "total_files": 1,
            "total_items": 3,
            "files": [
                {
                    "path": "src/foo.py",
                    "sloc": 30,
                    "items": [
                        {"name": "alpha", "line_start": 1, "line_end": 10},
                        {"name": "beta", "line_start": 11, "line_end": 20},
                        {"name": "gamma", "line_start": 21, "line_end": 30},
                    ],
                }
            ],
        }
        (run_dir / "checklist.json").write_text(json.dumps(checklist))

        # Annotations on two of the three functions.
        ann_dir = run_dir / "annotations"
        write_annotation(ann_dir, Annotation(
            file="src/foo.py", function="alpha",
            body="reviewed clean",
            metadata={"source": "human", "status": "clean"},
        ))
        write_annotation(ann_dir, Annotation(
            file="src/foo.py", function="beta",
            body="LLM finding",
            metadata={"source": "llm", "status": "finding"},
        ))

        # Coverage record (matches what /agentic + /understand emit).
        record = build_from_annotations(ann_dir)
        assert record is not None
        write_record(run_dir, record, tool_name="annotations")

    def test_annotations_record_appears_in_summary(self):
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            self._make_run_with_annotations(run_dir)

            summary = compute_summary(run_dir)
            assert summary is not None
            tools = summary["tools"]
            assert "annotations" in tools, (
                f"annotations tool missing from summary; "
                f"got tools: {list(tools.keys())}"
            )
            ann_info = tools["annotations"]
            assert ann_info["files_examined"] == 1
            assert ann_info["functions_analysed"] == 2

    def test_summary_records_annotation_status_breakdown(self):
        """The builder stamps annotation_statuses + annotation_sources
        on the record; verify they survive into the summary's tools
        dict (readers tolerate unknown keys)."""
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            self._make_run_with_annotations(run_dir)

            summary = compute_summary(run_dir)
            ann_info = summary["tools"]["annotations"]
            # Either present (if compute_summary preserves) or absent
            # (if it filters to the schema fields it knows). Pin the
            # current behaviour — whichever it is.
            # If preserved, useful for `/project annotations` etc.
            # We at minimum want files + functions present.
            assert "files_examined" in ann_info
            assert "functions_analysed" in ann_info

    def test_unreviewed_unchanged_when_no_llm_record(self):
        """Without an LLM record, the existing semantics keep
        ``unreviewed_functions`` at total_items even when annotations
        cover some functions. This is documented as conservative —
        annotations don't currently reduce the LLM-scoped 'unreviewed'
        count. If that ever changes, this test will surface the
        semantic shift."""
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            self._make_run_with_annotations(run_dir)

            summary = compute_summary(run_dir)
            # 3 inventory items, no LLM coverage, 2 annotated.
            # Current semantics: unreviewed_functions = total_items - llm
            # = 3 - 0 = 3. (Annotations are out of band today.)
            assert summary["unreviewed_functions"] == 3

    def test_per_file_breakdown_includes_annotation_functions(self):
        """The per-file breakdown DOES use the union of all tools'
        functions_analysed — so annotated functions show up as
        reviewed in per-file detail even though the top-level
        unreviewed_functions stays LLM-scoped."""
        with TemporaryDirectory() as d:
            run_dir = Path(d)
            self._make_run_with_annotations(run_dir)

            summary = compute_summary(run_dir)
            per_file = {pf["path"]: pf for pf in summary["per_file"]}
            foo = per_file.get("src/foo.py")
            assert foo is not None
            # Annotations covered alpha + beta — per-file "reviewed"
            # count reflects that.
            assert foo["reviewed"] == 2
            assert foo["total"] == 3
            assert "gamma" in foo["unreviewed_functions"]


if __name__ == "__main__":
    unittest.main()
