"""Aggregated artifact-layer robustness corners (rvw7 U03 group).

- path_feasibility: string-shaped per-step ``path_conditions``
  char-iterated into one-character PathConditions handed to the SMT
  verb; a ``steps: null`` trace raised.
- measurement: a present-but-null hypothesis crashed
  format_evaluation; fp_rate divided by ALL graded rows including
  clean/dormant (understated); a list-shaped graded findings file
  crashed _load_findings.
- pre_scan: scope labels collapsed ``/`` to ``_`` so scopes ``a/b``
  and ``a_b`` collided on one SARIF filename (last write wins).
"""

from __future__ import annotations

import json

from core.audit.path_feasibility import extract_conditions_from_flow_trace


class TestFlowTraceConditionShapes:
    def test_string_step_conditions_wrap_not_char_iterate(self):
        conds = extract_conditions_from_flow_trace(
            {"steps": [{"path_conditions": "size > 0", "file": "a.c"}]},
        )
        assert [c.text for c in conds] == ["size > 0"]

    def test_string_top_level_conditions_wrap(self):
        conds = extract_conditions_from_flow_trace(
            {"steps": [], "path_conditions": "n < len"},
        )
        assert [c.text for c in conds] == ["n < len"]

    def test_null_steps_tolerated(self):
        assert extract_conditions_from_flow_trace(
            {"steps": None, "path_conditions": []},
        ) == []

    def test_list_shapes_unchanged(self):
        conds = extract_conditions_from_flow_trace({
            "steps": [{"path_conditions": [
                "a > 0", {"text": "b != NULL", "negated": True},
            ]}],
        })
        assert [c.text for c in conds] == ["a > 0", "b != NULL"]
        assert conds[1].negated is True


class TestMeasurementRobustness:
    def _graded(self, tmp_path, rows):
        (tmp_path / "findings-graded.json").write_text(
            json.dumps({"findings": rows}),
        )

    def test_null_hypothesis_formats(self, tmp_path):
        from core.audit.measurement import evaluate_run, format_evaluation
        self._graded(tmp_path, [{
            "file": "a.c", "function": "f", "status": "finding",
            "hypothesis": None,
        }])
        result = evaluate_run(tmp_path, [])
        text = format_evaluation(result)
        assert "a.c:f" in text

    def test_fp_rate_denominator_is_verdict_rows(self, tmp_path):
        from core.audit.measurement import evaluate_run
        self._graded(tmp_path, [
            {"file": "a.c", "function": "f", "status": "finding",
             "hypothesis": "h"},
            {"file": "a.c", "function": "g", "status": "clean"},
            {"file": "a.c", "function": "h", "status": "dormant"},
            {"file": "a.c", "function": "i", "status": "suspicious",
             "hypothesis": "h2"},
        ])
        result = evaluate_run(tmp_path, [])
        # Both verdict rows are FPs against empty ground truth; clean
        # and dormant rows must not deflate the rate.
        assert result.total_findings == 2
        assert result.fp_rate == 1.0

    def test_list_shaped_graded_file_loads(self, tmp_path):
        from core.audit.measurement import evaluate_run
        (tmp_path / "findings-graded.json").write_text(
            json.dumps([{
                "file": "a.c", "function": "f", "status": "finding",
                "hypothesis": "h",
            }]),
        )
        result = evaluate_run(tmp_path, [])
        assert result.total_findings == 1


class TestPreScanScopeLabels:
    def test_slash_and_underscore_scopes_do_not_collide(self, tmp_path):
        from core.audit.pre_scan import _scan_targets
        (tmp_path / "a" / "b").mkdir(parents=True)
        (tmp_path / "a_b").mkdir()
        labels = [lab for lab, _ in _scan_targets(tmp_path, ["a/b", "a_b"])]
        assert len(set(labels)) == 2

    def test_plain_scope_label_stays_readable(self, tmp_path):
        from core.audit.pre_scan import _scan_targets
        (tmp_path / "src").mkdir()
        labels = [lab for lab, _ in _scan_targets(tmp_path, ["src"])]
        assert labels == ["src"]


class TestSharedPrepSourceTexts:
    def test_prep_reads_each_gap_file_through_one_map(self):
        # Five prep channels each built their own whole-tree
        # {file: text} dict (one retained run-long) — several
        # redundant in-memory copies of every gap file. The shared
        # read-through map is the only _contained_source_text caller
        # inside _compute_audit_prep.
        import ast as _ast
        from pathlib import Path as _Path
        orch = _Path(__file__).resolve().parents[1] / "orchestrator.py"
        tree = _ast.parse(orch.read_text())
        prep = next(
            n for n in tree.body
            if isinstance(n, _ast.FunctionDef)
            and n.name == "_compute_audit_prep"
        )
        def _calls_stopping_at_defs(fn):
            found = 0
            stack = list(fn.body)
            while stack:
                node = stack.pop()
                if isinstance(node, (_ast.FunctionDef,
                                     _ast.AsyncFunctionDef)):
                    continue  # nested defs counted separately
                if (
                    isinstance(node, _ast.Call)
                    and isinstance(node.func, _ast.Name)
                    and node.func.id == "_contained_source_text"
                ):
                    found += 1
                stack.extend(_ast.iter_child_nodes(node))
            return found

        assert _calls_stopping_at_defs(prep) == 0, \
            "a prep channel re-grew its own source-text loop"
        shared = next(
            n for n in _ast.walk(prep)
            if isinstance(n, _ast.FunctionDef)
            and n.name == "_gap_source_texts"
        )
        assert _calls_stopping_at_defs(shared) == 1
