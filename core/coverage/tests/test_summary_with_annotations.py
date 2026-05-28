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
        write_annotation(ann, Annotation(
            file="src/foo.py", function="alpha", body="clean",
            metadata={"source": "human", "status": "clean"}))
        write_annotation(ann, Annotation(
            file="src/foo.py", function="beta", body="bug",
            metadata={"source": "llm", "status": "finding"}))
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


if __name__ == "__main__":
    unittest.main()
