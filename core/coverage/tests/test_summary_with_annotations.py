"""Annotations flow into the unified coverage view two ways: the
``coverage-annotations.json`` record surfaces in the per-run execution detail,
and durable annotations become llm-category coverage in the store (so annotated
functions drop out of the LLM-review gap and a ``finding`` annotation reads
``open``).
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from core.annotations import Annotation, write_annotation
from core.coverage.record import build_from_annotations, write_record
from core.coverage.summary import execution_detail
from core.coverage.store import CoverageStore
from core.coverage.importer import backfill
from core.coverage.store_summary import store_view

_CHECKLIST = {"files": [{"path": "src/foo.py", "sloc": 30, "items": [
    {"name": "alpha", "line_start": 1, "line_end": 10},
    {"name": "beta", "line_start": 11, "line_end": 20},
    {"name": "gamma", "line_start": 21, "line_end": 30}]}]}


class TestAnnotationsInCoverage(unittest.TestCase):

    def _make(self, run_dir: Path):
        (run_dir / "checklist.json").write_text(json.dumps(_CHECKLIST))
        ann = run_dir / "annotations"
        # Interactive-TTY stamps: the shape a real operator add
        # records (stamp-less human notes demote — the date fence).
        write_annotation(ann, Annotation(
            file="src/foo.py", function="alpha", body="clean",
            metadata={"source": "human", "status": "clean",
                      "provenance": "interactive-tty", "tty": "stdin",
             "sid": "inherited", "envm": "trusted",
             "parents": "bash"}))
        write_annotation(ann, Annotation(
            file="src/foo.py", function="beta", body="bug",
            metadata={"source": "human", "status": "finding",
                      "provenance": "interactive-tty", "tty": "stdin",
             "sid": "inherited", "envm": "trusted",
             "parents": "bash"}))
        rec = build_from_annotations(ann)
        assert rec is not None
        write_record(run_dir, rec, tool_name="annotations")

    def test_annotations_record_in_execution_detail(self):
        with TemporaryDirectory() as d:
            run = Path(d)
            self._make(run)
            detail = execution_detail([run], _CHECKLIST)
            assert "annotations" in detail["tools"]
            assert detail["tools"]["annotations"]["files_examined"] == 1

    def test_annotations_become_llm_coverage_in_store(self):
        with TemporaryDirectory() as d:
            run = Path(d)
            self._make(run)
            store = CoverageStore(run / "coverage.json")
            backfill(store, [run], _CHECKLIST, annotations_base=run / "annotations")
            view = store_view(store, _CHECKLIST)
            # alpha (clean) + beta (finding) annotated → llm-examined; gamma not.
            assert view["functions_by_category"]["llm"] == 2
            gap = {g["function"] for g in view["llm_gap_functions"]}
            assert "gamma" in gap and "alpha" not in gap
            # The finding annotation makes beta read `open`.
            assert view["verdicts"]["open"] == 1

    def test_machine_annotations_do_not_clear_the_review_gap(self):
        # Agent-written notes are hint-tier: llm-extent examination
        # evidence, but never operator-grade review credit. A
        # human-grade note on alpha clears the gap; an agent note on
        # gamma must not (both directions).
        with TemporaryDirectory() as d:
            run = Path(d)
            (run / "checklist.json").write_text(json.dumps(_CHECKLIST))
            ann = run / "annotations"
            write_annotation(ann, Annotation(
                file="src/foo.py", function="alpha", body="clean",
                metadata={"source": "human", "status": "clean",
                          "provenance": "interactive-tty", "tty": "stdin",
             "sid": "inherited", "envm": "trusted",
             "parents": "bash"}))
            write_annotation(ann, Annotation(
                file="src/foo.py", function="gamma", body="agent note",
                metadata={"source": "agent", "status": "clean",
                          "provenance": "non-tty", "tty": "none"}))
            store = CoverageStore(run / "coverage.json")
            backfill(store, [run], _CHECKLIST,
                     annotations_base=run / "annotations")
            view = store_view(store, _CHECKLIST)
            # Both notes are llm-extent...
            assert view["functions_by_category"]["llm"] == 2
            # ...but only the human note counts as a review.
            gap = {g["function"] for g in view["llm_gap_functions"]}
            assert "alpha" not in gap
            assert "gamma" in gap


if __name__ == "__main__":
    unittest.main()
