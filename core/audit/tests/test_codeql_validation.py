"""Tests for core.audit.codeql_validation — IRIS-style dataflow verification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from core.audit.codeql_validation import (
    DataflowClaim,
    _count_codeflow_results,
    _guard_condition_on_line,
    _path_conditions,
    _sarif_result_paths,
    _smt_prune_sarif_matches,
    extract_claims_from_review,
    generate_taint_query,
    validate_dataflow_claim,
)


def _claim(src_fn="read_input", sink_fn="system"):
    return DataflowClaim(
        source_file="src/handler.c",
        source_function=src_fn,
        sink_file="src/exec.c",
        sink_function=sink_fn,
    )


class TestGenerateTaintQuery:
    def test_contains_source_and_sink(self):
        query = generate_taint_query(_claim("read_input", "system"))
        assert 'getName() = "read_input"' in query
        assert 'getName() = "system"' in query

    def test_is_valid_ql_structure(self):
        query = generate_taint_query(_claim())
        assert "@kind path-problem" in query
        assert "DataFlow::ConfigSig" in query
        assert "isSource" in query
        assert "isSink" in query

    def test_modern_dataflow_api_imports(self):
        # `import DataFlow::PathGraph` does not resolve against the
        # module-based (ConfigSig) API — every generated query failed
        # to compile ("could not resolve module DataFlow::PathGraph",
        # reproduced with codeql query compile) and the channel was
        # dead.  The flow module's own PathGraph is the modern shape.
        query = generate_taint_query(_claim())
        assert "semmle.code.cpp.dataflow.new.TaintTracking" in query
        assert "import AuditHypothesisFlow::PathGraph" in query
        assert "import DataFlow::PathGraph" not in query
        assert "@problem.severity" in query

    def test_handles_valid_identifiers(self):
        query = generate_taint_query(_claim("foo_bar", "baz_qux"))
        assert "foo_bar" in query
        assert "baz_qux" in query

    def test_rejects_injection_in_source(self):
        try:
            generate_taint_query(_claim('foo" or 1=1', "bar"))
            assert False, "should raise ValueError"
        except ValueError as exc:
            assert "identifier" in str(exc)

    def test_rejects_empty_function_name(self):
        try:
            generate_taint_query(_claim("", "bar"))
            assert False, "should raise ValueError"
        except ValueError as exc:
            assert "non-empty" in str(exc)

    def test_unsupported_language(self):
        try:
            generate_taint_query(_claim(), language="python")
            assert False, "should raise ValueError"
        except ValueError as exc:
            assert "unsupported" in str(exc)


class TestCountSarifResults:
    def test_empty_sarif(self):
        assert _count_codeflow_results({}) == 0

    def test_no_codeflows(self):
        sarif = {"runs": [{"results": [{"message": {"text": "found"}}]}]}
        assert _count_codeflow_results(sarif) == 0

    def test_with_codeflows(self):
        sarif = {
            "runs": [{
                "results": [
                    {"codeFlows": [{"threadFlows": []}]},
                    {"codeFlows": [{"threadFlows": []}]},
                    {"message": {"text": "no flow"}},
                ],
            }],
        }
        assert _count_codeflow_results(sarif) == 2


class TestValidateDataflowClaim:
    def test_no_db_path(self):
        result = validate_dataflow_claim(_claim())
        assert result.confirmed is None
        assert "no CodeQL database" in result.error

    def test_db_not_found(self, tmp_path: Path):
        result = validate_dataflow_claim(
            _claim(), db_path=tmp_path / "nonexistent",
        )
        assert result.confirmed is None
        assert "not found" in result.error

    def test_import_error(self, tmp_path: Path, monkeypatch):
        db = tmp_path / "db"
        db.mkdir()
        import builtins
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if "codeql_augmented_run" in name:
                raise ImportError("not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

        result = validate_dataflow_claim(_claim(), db_path=db)
        assert result.confirmed is None
        assert "not available" in result.error
        assert result.query_text  # query should still be generated

    def test_successful_run_with_matches(self, tmp_path: Path, monkeypatch):
        from dataclasses import dataclass as dc

        from core.audit import codeql_validation

        db = tmp_path / "db"
        db.mkdir()

        sarif_data = {
            "runs": [{"results": [
                {"codeFlows": [{"threadFlows": []}]},
            ]}],
        }

        @dc
        class FakeResult:
            sarif_path: Path
            queries: tuple = ()
            extension_pack: object = None
            elapsed_seconds: float = 0.1

        def mock_analyze(db_path, queries, output_path, **kwargs):
            output_path.write_text(json.dumps(sarif_data))
            return FakeResult(sarif_path=output_path)

        monkeypatch.setattr(
            codeql_validation, "validate_dataflow_claim",
            validate_dataflow_claim,
        )
        import core.dataflow.codeql_augmented_run as codeql_mod
        monkeypatch.setattr(codeql_mod, "analyze", mock_analyze)

        result = validate_dataflow_claim(_claim(), db_path=db)
        assert result.confirmed is True
        assert result.sarif_matches == 1

    def test_successful_run_no_matches(self, tmp_path: Path, monkeypatch):
        from dataclasses import dataclass as dc

        db = tmp_path / "db"
        db.mkdir()

        @dc
        class FakeResult:
            sarif_path: Path
            queries: tuple = ()
            extension_pack: object = None
            elapsed_seconds: float = 0.1

        def mock_analyze(db_path, queries, output_path, **kwargs):
            output_path.write_text(json.dumps({"runs": [{"results": []}]}))
            return FakeResult(sarif_path=output_path)

        import core.dataflow.codeql_augmented_run as codeql_mod
        monkeypatch.setattr(codeql_mod, "analyze", mock_analyze)

        result = validate_dataflow_claim(_claim(), db_path=db)
        assert result.confirmed is False
        assert result.sarif_matches == 0


class TestGuardConditionExtraction:
    def test_if_condition(self):
        assert _guard_condition_on_line("    if (len > 16) {") == "len > 16"

    def test_while_condition(self):
        assert _guard_condition_on_line("while (i < n)") == "i < n"

    def test_for_takes_middle_clause(self):
        assert (
            _guard_condition_on_line("for (i = 0; i < count; i++) {")
            == "i < count"
        )

    def test_nested_call_stays_balanced(self):
        assert (
            _guard_condition_on_line("if (check(x, y) && len > 0) {")
            == "check(x, y) && len > 0"
        )

    def test_plain_statement_returns_none(self):
        assert _guard_condition_on_line("    x = y + 1;") is None

    def test_unbalanced_multiline_returns_none(self):
        assert _guard_condition_on_line("if (a > b &&") is None


def _sarif_with_flow(steps, *, extra_result=None):
    """SARIF with one path-problem result whose thread flow hits steps."""
    locations = [
        {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                },
            },
        }
        for uri, line in steps
    ]
    results = [{
        "ruleId": "raptor/audit-hypothesis",
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": steps[-1][0]},
                "region": {"startLine": steps[-1][1]},
            },
        }],
        "codeFlows": [{"threadFlows": [{"locations": locations}]}],
    }]
    if extra_result is not None:
        results.append(extra_result)
    return {"runs": [{"results": results}]}


def _write_guarded_source(tmp_path: Path) -> Path:
    """Target tree with contradictory guards along the flow path."""
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "vuln.c").write_text(
        "int f(int len) {\n"          # 1
        "    if (len < 0) {\n"        # 2
        "        int x = len;\n"      # 3  <- step
        "        if (len > 0) {\n"    # 4
        "            sink(x);\n"      # 5  <- step
        "        }\n"                 # 6
        "    }\n"
        "    return 0;\n"
        "}\n",
    )
    return target


class TestSarifPathExtraction:
    def test_steps_extracted(self):
        sarif = _sarif_with_flow([("src/vuln.c", 3), ("src/vuln.c", 5)])
        result = sarif["runs"][0]["results"][0]
        paths = _sarif_result_paths(result)
        assert paths == [[("src/vuln.c", 3), ("src/vuln.c", 5)]]

    def test_path_conditions_harvested(self, tmp_path: Path):
        target = _write_guarded_source(tmp_path)
        conds = _path_conditions(
            [("src/vuln.c", 3), ("src/vuln.c", 5)], target, {},
        )
        texts = [c["text"] for c in conds]
        assert texts == ["len < 0", "len > 0"]

    def test_uri_escape_outside_target_ignored(self, tmp_path: Path):
        target = _write_guarded_source(tmp_path)
        (tmp_path / "outside.c").write_text("if (a > 0) {\n")
        conds = _path_conditions(
            [("../outside.c", 1)], target, {},
        )
        assert conds == []


def _write_early_exit_source(tmp_path: Path) -> Path:
    """The guard-clause-reject-then-positive-check idiom: trivially
    live for any ``len >= 0``."""
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "vuln.c").write_text(
        "void f(char *d, char *s, int len) {\n"  # 1
        "    if (len < 0)\n"                     # 2
        "        return;\n"                      # 3
        "    memcpy(d, s, len);\n"               # 4  <- step
        "    if (len >= 0) {\n"                  # 5
        "        memcpy(d, s, len);\n"           # 6  <- step
        "    }\n"
        "}\n",
    )
    return target


class TestGuardPolarity:
    """A refutation-grade receipt must never be mintable by asserting
    a guard with the wrong polarity: positive only when the step is
    provably inside the arm, negated for the exit-only ``if`` arm,
    dropped everywhere else."""

    def test_early_exit_guard_harvests_negated(self, tmp_path: Path):
        target = _write_early_exit_source(tmp_path)
        conds = _path_conditions(
            [("src/vuln.c", 4), ("src/vuln.c", 6)], target, {},
        )
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("len < 0", True),
            ("len >= 0", False),
        ]

    def test_braced_exit_only_arm_harvests_negated(self, tmp_path: Path):
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int len) {\n"                # 1
            "    if (len < 0) { return; }\n"     # 2
            "    sink(len);\n"                   # 3  <- step
            "}\n",
        )
        conds = _path_conditions([("src/vuln.c", 3)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("len < 0", True),
        ]

    def test_step_after_non_exit_arm_drops_condition(self, tmp_path: Path):
        # `if (c) x = 1; step` — the step is NOT bound by c in either
        # direction; asserting it would be a polarity guess.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int len) {\n"                # 1
            "    if (len < 0)\n"                 # 2
            "        len = 0;\n"                 # 3
            "    sink(len);\n"                   # 4  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 4)], target, {}) == []

    def test_guard_on_step_line_not_harvested(self, tmp_path: Path):
        # The step may be the condition expression itself, not the
        # arm — same-line guards are undecidable, never asserted.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int len) {\n"                # 1
            "    if (len < 0) sink(len);\n"      # 2  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 2)], target, {}) == []

    def test_loop_break_body_is_not_negated(self, tmp_path: Path):
        # Falling out of `while (c) { break; }` does not falsify c.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int len) {\n"                # 1
            "    while (len > 0) { break; }\n"   # 2
            "    sink(len);\n"                   # 3  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 3)], target, {}) == []

    def test_else_if_guard_never_asserted(self, tmp_path: Path):
        # Fall-through past an `else if` can come from an EARLIER
        # taken arm — neither polarity is assertable.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int a, int len) {\n"         # 1
            "    if (a) { log(); }\n"            # 2
            "    else if (len < 0)\n"            # 3
            "        return;\n"                  # 4
            "    sink(len);\n"                   # 5  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 5)], target, {}) == []

    def test_label_on_the_step_line_drops_condition(
        self, tmp_path: Path,
    ):
        # Reviewer repro shape: the goto target IS the step line —
        # `if (len < 0) goto out; return;` then `out: memcpy(...)`.
        # The path through the goto reaches the step with the guard
        # TRUE; asserting the negation falsely proved a live flow
        # "mutually exclusive" against a later positive guard.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) goto out;\n"            # 2
            "    return;\n"                           # 3
            "out: memcpy(d, s, len);\n"               # 4  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 4)], target, {}) == []

    def test_label_after_the_step_does_not_drop(self, tmp_path: Path):
        # Third direction: a label AFTER the step is unreachable
        # before it — the guard still binds normally.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int len) {\n"                     # 1
            "    if (len < 0)\n"                      # 2
            "        return;\n"                       # 3
            "    sink(len);\n"                        # 4  <- step
            "out:\n"                                  # 5
            "    log();\n"                            # 6
            "}\n",
        )
        conds = _path_conditions([("src/vuln.c", 4)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("len < 0", True),
        ]

    def test_live_goto_target_flow_survives_real_smt_prune(
        self, tmp_path: Path,
    ):
        pytest.importorskip("z3")
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) goto out;\n"            # 2
            "    return;\n"                           # 3
            "out: memcpy(d, s, len);\n"               # 4  <- step
            "    if (len < 0) {\n"                    # 5
            "        memcpy(d, s, len);\n"            # 6  <- step
            "    }\n"
            "}\n",
        )
        sarif = _sarif_with_flow([("src/vuln.c", 4), ("src/vuln.c", 6)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (1, 0)
        assert receipts == []

    def test_brace_sharing_exit_arm_harvests_negated(
        self, tmp_path: Path,
    ):
        # The arm's closing brace shares the STEP's line (K&R-compact
        # / minified / generated C): the step is the fall-through of
        # an exit-only arm, NOT its body.  Judging it "inside the
        # arm" asserted the guard with inverted polarity — with an
        # ordinary sibling guard on the flow, the pair proved unsat
        # and minted a proof-grade smt_path_infeasible on a
        # trivially-live path.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {\n"                    # 2
            "        return;\n"                       # 3
            "    } memcpy(d, s, len);\n"              # 4  <- step
            "}\n",
        )
        conds = _path_conditions([("src/vuln.c", 4)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("len < 0", True),
        ]

    def test_brace_sharing_non_exit_arm_drops_condition(
        self, tmp_path: Path,
    ):
        # Same brace-sharing shape, non-exit arm: whether the arm ran
        # is unknowable at the step — neither polarity is assertable.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int len) {\n"                     # 1
            "    if (len < 0) {\n"                    # 2
            "        len = 0;\n"                      # 3
            "    } sink(len);\n"                      # 4  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 4)], target, {}) == []

    def test_nested_close_on_step_line_still_positive(
        self, tmp_path: Path,
    ):
        # The step-line brace closes a NESTED block; the guard's own
        # arm is still open — the provable positive assertion (a true
        # prune input) must survive the brace-sharing defence.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int n) {\n"                       # 1
            "    if (n > 0) {\n"                      # 2
            "        {\n"                             # 3
            "            log(n);\n"                   # 4
            "        } sink(n);\n"                    # 5  <- step
            "    }\n"                                 # 6
            "}\n",
        )
        conds = _path_conditions([("src/vuln.c", 5)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("n > 0", False),
        ]

    def test_brace_prefixed_label_on_step_line_drops_condition(
        self, tmp_path: Path,
    ):
        # `} out: step;` — the label escapes a line-start label check
        # behind the brace prefix, but it is still a goto target: the
        # goto path reaches the step with the guard TRUE, so neither
        # polarity holds (the exit-only arm here ends in `goto`, the
        # shape that would otherwise earn the negation).
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {\n"                    # 2
            "        goto out;\n"                     # 3
            "    } out: memcpy(d, s, len);\n"         # 4  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 4)], target, {}) == []

    def test_literal_brace_in_arm_does_not_defeat_the_census(
        self, tmp_path: Path,
    ):
        # A `{` inside a string literal is data: counting it made the
        # brace-sharing step "nested" again and re-minted the
        # inverted-polarity positive assertion.  The census runs on
        # literal/comment-blanked text.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            'void g(char *d, char *s, int len) {\n'   # 1
            '    if (len < 0) {\n'                    # 2
            '        log("{");\n'                     # 3
            '        return;\n'                       # 4
            '    } memcpy(d, s, len);\n'              # 5  <- step
            '}\n',
        )
        conds = _path_conditions([("src/vuln.c", 5)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("len < 0", True),
        ]

    def test_comment_brace_on_guard_tail_does_not_defeat_the_census(
        self, tmp_path: Path,
    ):
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int len) {\n"                     # 1
            "    if (len < 0) { // sanity {\n"        # 2
            "        return;\n"                       # 3
            "    } sink(len);\n"                      # 4  <- step
            "}\n",
        )
        conds = _path_conditions([("src/vuln.c", 4)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("len < 0", True),
        ]

    def test_unblankable_region_abstains(self, tmp_path: Path):
        # A block comment running past the region (and a raw string,
        # whose delimiter grammar defeats a quote scanner) leave the
        # brace census unusable — the polarity abstains rather than
        # censusing data as code.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "open.c").write_text(
            "void f(int len) {\n"                     # 1
            "    if (len < 0) {\n"                    # 2
            "        return; /* trailing\n"           # 3
            "    } sink(len);\n"                      # 4  <- step
            "}\n",
        )
        assert _path_conditions([("src/open.c", 4)], target, {}) == []
        (target / "src" / "raw.c").write_text(
            'void f(int len) {\n'                     # 1
            '    if (len < 0) {\n'                    # 2
            '        log(R"({)");\n'                  # 3
            '        return;\n'                       # 4
            '    } sink(len);\n'                      # 5  <- step
            '}\n',
        )
        assert _path_conditions([("src/raw.c", 5)], target, {}) == []

    def test_live_brace_sharing_flow_survives_real_smt_prune(
        self, tmp_path: Path,
    ):
        # End-to-end regression pin: exit-only arm closing on the
        # step's line + an ordinary `len >= 0` guard downstream —
        # live for any len >= 0, and pruned pre-fix.
        pytest.importorskip("z3")
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {\n"                    # 2
            "        return;\n"                       # 3
            "    } memcpy(d, s, len);\n"              # 4  <- step
            "    if (len >= 0) {\n"                   # 5
            "        memcpy(d, s, len);\n"            # 6  <- step
            "    }\n"                                 # 7
            "}\n",
        )
        sarif = _sarif_with_flow([("src/vuln.c", 4), ("src/vuln.c", 6)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (1, 0)
        assert receipts == []

    def test_brace_sharing_negation_still_feeds_true_prunes(
        self, tmp_path: Path,
    ):
        # No over-correction: the fall-through NEGATION harvested at a
        # brace-sharing step still combines with a later positive
        # guard into a genuinely infeasible — prunable — path.
        pytest.importorskip("z3")
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {\n"                    # 2
            "        return;\n"                       # 3
            "    } log(len);\n"                       # 4  <- step
            "    if (len < 0) {\n"                    # 5
            "        memcpy(d, s, len);\n"            # 6  <- step
            "    }\n"                                 # 7
            "}\n",
        )
        sarif = _sarif_with_flow([("src/vuln.c", 4), ("src/vuln.c", 6)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (0, 1)
        assert receipts[0]["verdict"] == "smt_path_infeasible"

    def test_live_early_exit_flow_survives_real_smt_prune(
        self, tmp_path: Path,
    ):
        # Regression pin with the real solver: the two-step flow over
        # the early-exit idiom is live for any len >= 0 and must be
        # KEPT — the wrong-polarity harvest proved it "mutually
        # exclusive" and minted an smt_path_infeasible receipt.
        pytest.importorskip("z3")
        target = _write_early_exit_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 4), ("src/vuln.c", 6)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (1, 0)
        assert receipts == []

    def test_splice_hidden_open_brace_exit_arm_harvests_negated(
        self, tmp_path: Path,
    ):
        # C line splice (translation phase 2): the guard line ends in
        # `\` and the arm-opening `{` lands on the continuation line.
        # The physical tail's dangling `\` defeated startswith("{")
        # and the exit-statement match, so the exit-only arm's
        # negation was dropped; the window is judged from the joined
        # logical text.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) \\\n"                   # 2
            "    {\n"                                 # 3
            "        return;\n"                       # 4
            "    } memcpy(d, s, len);\n"              # 5  <- step
            "}\n",
        )
        conds = _path_conditions([("src/vuln.c", 5)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("len < 0", True),
        ]

    def test_splice_hidden_open_brace_step_inside_arm_positive(
        self, tmp_path: Path,
    ):
        # Inside-arm variant of the same splice: the step sits in the
        # still-open arm, and the provable positive assertion (a true
        # prune input) must survive the hidden `{`.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int n) {\n"                       # 1
            "    if (n > 0) \\\n"                     # 2
            "    {\n"                                 # 3
            "        sink(n);\n"                      # 4  <- step
            "    }\n"                                 # 5
            "}\n",
        )
        conds = _path_conditions([("src/vuln.c", 4)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("n > 0", False),
        ]

    def test_comment_splice_does_not_mint_negation(self, tmp_path: Path):
        # `// reject \` splices the next physical line INTO the
        # comment: the real arm is EMPTY and the step falls through
        # for ANY len.  Reading the commented-out `return;` as code
        # judged the arm exit-only and asserted len<0 NEGATED — the
        # false-suppression direction.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {  // reject \\\n"      # 2
            "        return;\n"                       # 3 (comment!)
            "    }\n"                                 # 4
            "    memcpy(d, s, len);\n"                # 5  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 5)], target, {}) == []

    def test_token_splitting_splice_does_not_mint_exit(
        self, tmp_path: Path,
    ):
        # `return\` + `_flag = 1;` is ONE token — an assignment, not
        # an exit.  The space-joined physical window read
        # `return\ _flag` and `^return\b` matched at the backslash
        # boundary, asserting a false negation.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "int return_flag;\n"                      # 1
            "void g(char *d, char *s, int len) {\n"   # 2
            "    if (len < 0) { return\\\n"           # 3
            "_flag = 1; }\n"                          # 4
            "    memcpy(d, s, len);\n"                # 5  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 5)], target, {}) == []

    def test_splice_crlf_variant_harvests_negated(self, tmp_path: Path):
        # CRLF source: the \n-model split leaves the `\r` on the
        # line, so the splice is `\` + `\r` at line end.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\r\n"  # 1
            "    if (len < 0) \\\r\n"                  # 2
            "    {\r\n"                                # 3
            "        return;\r\n"                      # 4
            "    } memcpy(d, s, len);\r\n"             # 5  <- step
            "}\r\n",
            newline="",
        )
        conds = _path_conditions([("src/vuln.c", 5)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("len < 0", True),
        ]

    def test_splice_with_trailing_blank_harvests_negated(
        self, tmp_path: Path,
    ):
        # Backslash + blanks + newline: not a splice to ISO C, but
        # GCC and Clang both join it (with a warning) — judge the
        # text the compiler actually built.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) \\ \n"                  # 2
            "    {\n"                                 # 3
            "        return;\n"                       # 4
            "    } memcpy(d, s, len);\n"              # 5  <- step
            "}\n",
        )
        conds = _path_conditions([("src/vuln.c", 5)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("len < 0", True),
        ]

    def test_splice_into_step_line_abstains(self, tmp_path: Path):
        # The window's last line splices INTO the step's physical
        # line: the step line is a mid-logical-line continuation, so
        # neither its prefix nor the window is faithful text — no
        # polarity is assertable.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int len) {\n"                     # 1
            "    if (len < 0) {\n"                    # 2
            "        return; } \\\n"                  # 3
            "    sink(len);\n"                        # 4  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 4)], target, {}) == []

    def test_comment_spliced_live_flow_survives_real_smt_prune(
        self, tmp_path: Path,
    ):
        # The suppress-direction consequence, end to end: the
        # comment-splice hides that the arm is empty, the false
        # NEGATED harvest pairs with the downstream positive guard,
        # and z3 minted a proof-grade smt_path_infeasible on a path
        # that is LIVE for any len < 0.  The finding must be kept.
        pytest.importorskip("z3")
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {  // reject \\\n"      # 2
            "        return;\n"                       # 3 (comment!)
            "    }\n"                                 # 4
            "    memcpy(d, s, len);\n"                # 5  <- step
            "    if (len < 0) {\n"                    # 6
            "        memcpy(d, s, len);\n"            # 7  <- step
            "    }\n"                                 # 8
            "}\n",
        )
        sarif = _sarif_with_flow([("src/vuln.c", 5), ("src/vuln.c", 7)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (1, 0)
        assert receipts == []

    def test_spliced_negation_still_feeds_true_prunes(
        self, tmp_path: Path,
    ):
        # No over-correction: the negation recovered from the
        # splice-hidden exit arm still combines with a later positive
        # guard into a genuinely infeasible — prunable — path.
        pytest.importorskip("z3")
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) \\\n"                   # 2
            "    {\n"                                 # 3
            "        return;\n"                       # 4
            "    } log(len);\n"                       # 5  <- step
            "    if (len < 0) {\n"                    # 6
            "        memcpy(d, s, len);\n"            # 7  <- step
            "    }\n"                                 # 8
            "}\n",
        )
        sarif = _sarif_with_flow([("src/vuln.c", 5), ("src/vuln.c", 7)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (0, 1)
        assert receipts[0]["verdict"] == "smt_path_infeasible"


def _stub_validate_path(feasible, *, calls=None):
    def stub(conditions, profile="uint64", timeout_ms=None, **kw):
        if calls is not None:
            calls.append(list(conditions))
        return {
            "feasible": feasible,
            "reasoning": (
                "infeasible: path conditions are mutually exclusive"
                if feasible is False else "sat"
            ),
            "unsatisfied": (
                [c["text"] for c in conditions] if feasible is False else []
            ),
            "satisfied": [],
            "unknown": [],
            "smt_available": feasible is not None,
        }
    return stub


class TestSmtPruneSarifMatches:
    def test_unsat_match_pruned_with_receipt(self, tmp_path, monkeypatch):
        import packages.exploit_feasibility.smt_path as smt_path_mod

        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3), ("src/vuln.c", 5)])
        monkeypatch.setattr(
            smt_path_mod, "validate_path", _stub_validate_path(False),
        )
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert kept == 0
        assert pruned == 1
        assert len(receipts) == 1
        rec = receipts[0]
        assert rec["verdict"] == "smt_path_infeasible"
        assert rec["file"] == "src/vuln.c"
        assert rec["paths"][0]["unsatisfied"] == ["len < 0", "len > 0"]

    def test_sat_match_kept(self, tmp_path, monkeypatch):
        import packages.exploit_feasibility.smt_path as smt_path_mod

        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3)])
        monkeypatch.setattr(
            smt_path_mod, "validate_path", _stub_validate_path(True),
        )
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned, receipts) == (1, 0, [])

    def test_unknown_never_prunes(self, tmp_path, monkeypatch):
        """z3 unavailable / solver unknown must fail open."""
        import packages.exploit_feasibility.smt_path as smt_path_mod

        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3)])
        monkeypatch.setattr(
            smt_path_mod, "validate_path", _stub_validate_path(None),
        )
        kept, pruned, _ = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (1, 0)

    def test_condition_free_path_kept(self, tmp_path, monkeypatch):
        """No harvestable guards → nothing to judge → match survives."""
        import packages.exploit_feasibility.smt_path as smt_path_mod

        target = _write_guarded_source(tmp_path)
        # Step on line 1 (function header, no enclosing guard).
        sarif = _sarif_with_flow([("src/vuln.c", 1)])
        calls: list = []
        monkeypatch.setattr(
            smt_path_mod, "validate_path",
            _stub_validate_path(False, calls=calls),
        )
        kept, pruned, _ = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (1, 0)
        assert calls == []

    def test_prune_treats_signedness_as_guessed(
        self, tmp_path, monkeypatch,
    ):
        # The harvested guard text carries no type information, so the
        # prune must not assert a known signedness: profile=None routes
        # validate_path to the both-profiles-agree rule instead of the
        # single-profile check an explicit "uint64" buys.
        import packages.exploit_feasibility.smt_path as smt_path_mod

        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3)])
        profiles: list = []

        def stub(conditions, profile="MISSING", timeout_ms=None, **kw):
            profiles.append(profile)
            return {
                "feasible": True, "reasoning": "sat",
                "unsatisfied": [], "satisfied": [], "unknown": [],
                "smt_available": True,
            }

        monkeypatch.setattr(smt_path_mod, "validate_path", stub)
        _smt_prune_sarif_matches(sarif, target)
        assert profiles == [None]

    @pytest.mark.skipif(
        not __import__(
            "core.smt_solver.availability", fromlist=["z3_available"],
        ).z3_available(),
        reason="z3 not installed",
    )
    def test_signed_error_check_guard_not_pruned(self, tmp_path):
        """``if (ret < 0)`` — the ubiquitous C signed error check —
        must keep the match: under a pinned unsigned profile it
        encodes as ULT(ret, 0), unsat, and refuted a live path."""
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "signed.c").write_text(
            "int f(int ret) {\n"
            "    if (ret < 0)\n"
            "        sink(ret);\n"
            "}\n",
        )
        sarif = _sarif_with_flow([("src/signed.c", 3)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned, receipts) == (1, 0, [])

    @pytest.mark.skipif(
        not __import__(
            "core.smt_solver.availability", fromlist=["z3_available"],
        ).z3_available(),
        reason="z3 not installed",
    )
    def test_real_solver_kills_contradictory_guards(self, tmp_path):
        """Integration: len < 0 AND len > 0 is UNSAT for real."""
        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3), ("src/vuln.c", 5)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (0, 1)
        assert receipts[0]["paths"][0]["reasoning"]


class TestValidateClaimSmtPrune:
    def _mock_analyze(self, sarif_data):
        @dataclass
        class FakeResult:
            sarif_path: Path
            queries: tuple = ()
            extension_pack: object = None
            elapsed_seconds: float = 0.1

        def mock_analyze(db_path, queries, output_path, **kwargs):
            output_path.write_text(json.dumps(sarif_data))
            return FakeResult(sarif_path=output_path)

        return mock_analyze

    def test_vacuous_match_refuted_with_receipts(
        self, tmp_path: Path, monkeypatch,
    ):
        import core.dataflow.codeql_augmented_run as codeql_mod
        import packages.exploit_feasibility.smt_path as smt_path_mod

        db = tmp_path / "db"
        db.mkdir()
        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3), ("src/vuln.c", 5)])

        monkeypatch.setattr(
            codeql_mod, "analyze", self._mock_analyze(sarif),
        )
        monkeypatch.setattr(
            smt_path_mod, "validate_path", _stub_validate_path(False),
        )

        result = validate_dataflow_claim(
            _claim(), db_path=db, target_path=target,
        )
        assert result.confirmed is False
        assert result.sarif_matches == 0
        assert result.smt_pruned == 1
        assert result.smt_receipts
        assert "vacuous" in result.reasoning

    def test_no_target_path_skips_prune(self, tmp_path: Path, monkeypatch):
        import core.dataflow.codeql_augmented_run as codeql_mod
        import packages.exploit_feasibility.smt_path as smt_path_mod

        db = tmp_path / "db"
        db.mkdir()
        sarif = _sarif_with_flow([("src/vuln.c", 3)])
        calls: list = []

        monkeypatch.setattr(
            codeql_mod, "analyze", self._mock_analyze(sarif),
        )
        monkeypatch.setattr(
            smt_path_mod, "validate_path",
            _stub_validate_path(False, calls=calls),
        )

        result = validate_dataflow_claim(_claim(), db_path=db)
        assert result.confirmed is True
        assert result.smt_pruned == 0
        assert calls == []

    def test_surviving_match_still_confirms(
        self, tmp_path: Path, monkeypatch,
    ):
        import core.dataflow.codeql_augmented_run as codeql_mod
        import packages.exploit_feasibility.smt_path as smt_path_mod

        db = tmp_path / "db"
        db.mkdir()
        target = _write_guarded_source(tmp_path)
        sarif = _sarif_with_flow([("src/vuln.c", 3)])

        monkeypatch.setattr(
            codeql_mod, "analyze", self._mock_analyze(sarif),
        )
        monkeypatch.setattr(
            smt_path_mod, "validate_path", _stub_validate_path(True),
        )

        result = validate_dataflow_claim(
            _claim(), db_path=db, target_path=target,
        )
        assert result.confirmed is True
        assert result.sarif_matches == 1
        assert result.smt_pruned == 0


class TestExtractClaimsFromReview:
    def test_no_claims(self):
        result = {"file": "a.c", "function": "f", "status": "clean"}
        claims = extract_claims_from_review(result)
        assert claims == []

    def test_full_claim(self):
        result = {
            "file": "a.c",
            "function": "f",
            "hypothesis": "input flows to system",
            "dataflow_source": {"file": "src/in.c", "function": "read_input"},
            "dataflow_sink": {"file": "src/exec.c", "function": "system"},
        }
        claims = extract_claims_from_review(result)
        assert len(claims) == 1
        assert claims[0].source_function == "read_input"
        assert claims[0].sink_function == "system"
        assert claims[0].description == "input flows to system"

    def test_inherits_file_from_result(self):
        result = {
            "file": "main.c",
            "dataflow_source": {"function": "src_fn"},
            "dataflow_sink": {"function": "sink_fn"},
        }
        claims = extract_claims_from_review(result)
        assert claims[0].source_file == "main.c"
        assert claims[0].sink_file == "main.c"

    def test_empty_function_name_skipped(self):
        result = {
            "file": "a.c",
            "dataflow_source": {"file": "a.c"},
            "dataflow_sink": {"function": "bar"},
        }
        claims = extract_claims_from_review(result)
        assert claims == []


class TestSourceLineContainment:
    """SARIF uris are attacker-influenced: containment must be
    separator-anchored (the old bare startswith accepted sibling
    directories like /repo-evil for target /repo)."""

    def test_in_target_loads(self, tmp_path):
        from core.audit.codeql_validation import _load_source_lines

        target = tmp_path / "repo"
        target.mkdir()
        (target / "a.c").write_text("int x;\nint y;\n", encoding="utf-8")
        cache: dict = {}
        lines = _load_source_lines("a.c", target, cache)
        assert lines == ["int x;", "int y;"]

    def test_sibling_directory_rejected(self, tmp_path):
        from core.audit.codeql_validation import _load_source_lines

        target = tmp_path / "repo"
        target.mkdir()
        evil = tmp_path / "repo-evil"
        evil.mkdir()
        (evil / "leak.c").write_text("secret\n", encoding="utf-8")
        cache: dict = {}
        assert _load_source_lines(
            "../repo-evil/leak.c", target, cache,
        ) is None

    def test_traversal_rejected(self, tmp_path):
        from core.audit.codeql_validation import _load_source_lines

        target = tmp_path / "repo"
        target.mkdir()
        (tmp_path / "outside.c").write_text("secret\n", encoding="utf-8")
        cache: dict = {}
        assert _load_source_lines("../outside.c", target, cache) is None


class TestScopeContainment:
    def test_sibling_scope_dir_rejected(self, tmp_path):
        from core.audit.codeql_backend import _path_in_scope_dirs

        (tmp_path / "src").mkdir()
        (tmp_path / "src2").mkdir()
        (tmp_path / "src" / "a.py").write_text("x = 1\n")
        (tmp_path / "src2" / "b.py").write_text("x = 1\n")
        scope_dirs = (str((tmp_path / "src").resolve()),)
        assert _path_in_scope_dirs(tmp_path / "src" / "a.py", scope_dirs)
        assert not _path_in_scope_dirs(
            tmp_path / "src2" / "b.py", scope_dirs,
        )

    def test_scope_dir_itself_in_scope(self, tmp_path):
        from core.audit.codeql_backend import _path_in_scope_dirs

        (tmp_path / "src").mkdir()
        scope_dirs = (str((tmp_path / "src").resolve()),)
        assert _path_in_scope_dirs(tmp_path / "src", scope_dirs)

    def test_unscoped_everything_in(self, tmp_path):
        from core.audit.codeql_backend import _path_in_scope_dirs

        assert _path_in_scope_dirs(tmp_path / "anything.py", None)


class TestSarifBudget:
    def test_oversize_sarif_is_inconclusive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A SARIF over the bounded loader's cap grades as a tool
        failure (confirmed=None with a size-naming error), never as a
        refuted claim. Sparse truncate: the stat gate fires before
        any read."""
        import os
        from dataclasses import dataclass as dc

        db = tmp_path / "db"
        db.mkdir()

        @dc
        class FakeResult:
            sarif_path: Path
            queries: tuple = ()
            extension_pack: object = None
            elapsed_seconds: float = 0.1

        def mock_analyze(db_path, queries, output_path, **kwargs):
            output_path.write_text(json.dumps({"runs": []}))
            os.truncate(output_path, 100 * 1024 * 1024 + 1)
            return FakeResult(sarif_path=output_path)

        import core.dataflow.codeql_augmented_run as codeql_mod
        monkeypatch.setattr(codeql_mod, "analyze", mock_analyze)

        result = validate_dataflow_claim(_claim(), db_path=db)
        assert result.confirmed is None
        assert "size cap" in result.error


class TestSourceLineLoadBound:
    """_load_source_lines reads files from the scanned tree at
    SARIF-influenced paths — an oversize (planted) file must be
    refused by the size gate, never buffered."""

    def test_oversize_source_file_refused(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ) -> None:
        import logging
        import os

        from core.audit.codeql_validation import (
            _MAX_SOURCE_FILE_BYTES,
            _load_source_lines,
        )

        blob = tmp_path / "planted.c"
        with blob.open("wb") as fh:
            os.truncate(fh.fileno(), _MAX_SOURCE_FILE_BYTES + 1)

        cache: dict = {}
        with caplog.at_level(
            logging.WARNING, logger="core.audit.codeql_validation",
        ):
            lines = _load_source_lines("planted.c", tmp_path, cache)
        assert lines is None
        assert cache["planted.c"] is None
        # The gate's refusal, not a post-read failure, must produce
        # the None — red before the bound existed.
        assert "refusing oversize source file" in caplog.text

    def test_small_source_file_still_loads(self, tmp_path: Path) -> None:
        from core.audit.codeql_validation import _load_source_lines

        src = tmp_path / "ok.c"
        src.write_text("int main(void) {\n  return 0;\n}\n")
        lines = _load_source_lines("ok.c", tmp_path, {})
        assert lines is not None
        assert lines[1] == "  return 0;"


class TestDetectDbLanguage:
    """codeql_backend._detect_db_language — the pre-sweep's language
    detection, verified against the CLI's real JSON output shape (the
    old line scan never matched it and the pre-sweep silently died)."""

    def test_real_cli_json_languages_array(self):
        from core.audit.codeql_backend import _detect_db_language
        stdout = (
            '{\n'
            '  "sourceLocationPrefix" : "/x/src",\n'
            '  "languages" : [\n'
            '    "cpp"\n'
            '  ],\n'
            '  "scratchDir" : "/x/db/working"\n'
            '}\n'
        )
        assert _detect_db_language(stdout) == "cpp"

    def test_primary_language_json_key(self):
        from core.audit.codeql_backend import _detect_db_language
        assert _detect_db_language(
            '{"primaryLanguage": "java", "languages": ["java"]}',
        ) == "java"

    def test_legacy_yaml_line_fallback(self):
        from core.audit.codeql_backend import _detect_db_language
        assert _detect_db_language(
            "sourceLocationPrefix: /x\nprimaryLanguage: python\n",
        ) == "python"

    def test_unrecognised_output_is_none(self):
        from core.audit.codeql_backend import _detect_db_language
        assert _detect_db_language("") is None
        assert _detect_db_language("gibberish") is None
        assert _detect_db_language('{"languages": []}') is None


class TestCppNameNormalisation:
    """CodeQL's getName() is unqualified and template-arg-free — a
    qualified/template spelling interpolated verbatim can never match
    it, so every such claim came back a vacuous confirmed=False."""

    def test_qualified_and_template_names_normalise(self):
        from core.audit.codeql_validation import _codeql_base_name

        assert _codeql_base_name("ns::f") == "f"
        assert _codeql_base_name("f<T>") == "f"
        assert _codeql_base_name("ns::f<T>") == "f"
        assert _codeql_base_name("f<T>::g") == "g"
        assert _codeql_base_name("plain") == "plain"
        assert _codeql_base_name("~Dtor") == "~Dtor"

    def test_query_interpolates_base_names(self):
        from core.audit.codeql_validation import (
            DataflowClaim,
            generate_taint_query,
        )

        claim = DataflowClaim(
            source_file="a.cpp", source_function="ns::get_input",
            sink_file="b.cpp", sink_function="util::copy_bytes<char>",
        )
        q = generate_taint_query(claim)
        assert '"get_input"' in q
        assert '"copy_bytes"' in q
        assert "ns::" not in q.split("@id")[1]


class TestGuardPolarityLabels:
    def test_label_between_guard_and_step_drops_condition(
        self, tmp_path: Path,
    ):
        # `if (err) goto out;` above a LABELLED statement: another
        # path reaches the step via goto without evaluating the
        # guard — neither polarity is assertable.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int len) {\n"                # 1
            "    if (len < 0)\n"                 # 2
            "        return;\n"                  # 3
            "retry:\n"                           # 4
            "    sink(len);\n"                   # 5  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 5)], target, {}) == []

    def test_label_on_the_step_line_drops_condition(
        self, tmp_path: Path,
    ):
        # Reviewer repro shape: the goto target IS the step line —
        # `if (len < 0) goto out; return;` then `out: memcpy(...)`.
        # The path through the goto reaches the step with the guard
        # TRUE; asserting the negation falsely proved a live flow
        # "mutually exclusive" against a later positive guard.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) goto out;\n"            # 2
            "    return;\n"                           # 3
            "out: memcpy(d, s, len);\n"               # 4  <- step
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 4)], target, {}) == []

    def test_label_after_the_step_does_not_drop(self, tmp_path: Path):
        # Third direction: a label AFTER the step is unreachable
        # before it — the guard still binds normally.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(int len) {\n"                     # 1
            "    if (len < 0)\n"                      # 2
            "        return;\n"                       # 3
            "    sink(len);\n"                        # 4  <- step
            "out:\n"                                  # 5
            "    log();\n"                            # 6
            "}\n",
        )
        conds = _path_conditions([("src/vuln.c", 4)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("len < 0", True),
        ]

    def test_live_goto_target_flow_survives_real_smt_prune(
        self, tmp_path: Path,
    ):
        pytest.importorskip("z3")
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) goto out;\n"            # 2
            "    return;\n"                           # 3
            "out: memcpy(d, s, len);\n"               # 4  <- step
            "    if (len < 0) {\n"                    # 5
            "        memcpy(d, s, len);\n"            # 6  <- step
            "    }\n"
            "}\n",
        )
        sarif = _sarif_with_flow([("src/vuln.c", 4), ("src/vuln.c", 6)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (1, 0)
        assert receipts == []


class TestGuardPolarityMultiLineLabels:
    """C allows a label's identifier and colon on separate lines; the
    per-line between-check saw neither half, judged the arm still
    open, and asserted the guard POSITIVELY for a step every goto
    path reaches with the guard false — the false-suppression
    direction.  Labels are re-checked on the joined logical region."""

    def test_two_line_label_in_open_arm_drops_condition(
        self, tmp_path: Path,
    ):
        # Plain two-line label, no splice: `ok` and `:` on separate
        # physical lines are ONE label — a goto target inside the
        # still-open arm, so another path reaches the step with the
        # guard FALSE and neither polarity is assertable.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {\n"                    # 2
            "ok\n"                                    # 3
            ":\n"                                     # 4
            "        sink(d, s, len);\n"              # 5  <- step
            "    }\n"                                 # 6
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 5)], target, {}) == []

    def test_spliced_label_in_open_arm_drops_condition(
        self, tmp_path: Path,
    ):
        # Splice-assembled variant: `ok\` + `:` is the logical line
        # `ok:`.  The splice normalisation joins it, but the label
        # judgement ran on raw physical lines — same wrong positive.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {\n"                    # 2
            "ok\\\n"                                  # 3
            ":\n"                                     # 4
            "        sink(d, s, len);\n"              # 5  <- step
            "    }\n"                                 # 6
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 5)], target, {}) == []

    def test_two_line_case_label_drops_condition(self, tmp_path: Path):
        # Duff's-device shape: a case arm interleaved into the guarded
        # block, its expression and colon on separate lines — the
        # switch dispatch reaches the step without the guard.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(char *d, int len) {\n"            # 1
            "    if (len < 0) {\n"                    # 2
            "    case 1\n"                            # 3
            "        :\n"                             # 4
            "        sink(d, len);\n"                 # 5  <- step
            "    }\n"                                 # 6
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 5)], target, {}) == []

    def test_label_at_window_seam_drops_condition(self, tmp_path: Path):
        # The label head is the LAST between line and its colon leads
        # the step's own line: the label targets the step statement
        # itself — the goto path reaches it with the guard false.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {\n"                    # 2
            "ok\n"                                    # 3
            ": sink(d, s, len);\n"                    # 4  <- step
            "    }\n"                                 # 5
            "}\n",
        )
        assert _path_conditions([("src/vuln.c", 4)], target, {}) == []

    def test_ternary_colon_keeps_positive_arm(self, tmp_path: Path):
        # No over-correction, harvest level: a ternary's `? a : b`
        # colon has no statement boundary before its identifier, so
        # it is NOT a label — the provable positive assertion (a true
        # prune input) survives.
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void f(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {\n"                    # 2
            "        log(s ? d : s);\n"               # 3
            "        sink(d, s, len);\n"              # 4  <- step
            "    }\n"                                 # 5
            "}\n",
        )
        conds = _path_conditions([("src/vuln.c", 4)], target, {})
        assert [(c["text"], c["negated"]) for c in conds] == [
            ("len < 0", False),
        ]

    def test_live_two_line_label_flow_survives_real_smt_prune(
        self, tmp_path: Path,
    ):
        # The suppress-direction consequence, end to end: the missed
        # two-line label minted a positive `len < 0` for a step the
        # goto path reaches with len >= 0; paired with the downstream
        # positive `len >= 0` guard, z3 proved the LIVE path
        # "mutually exclusive" and minted a proof-grade
        # smt_path_infeasible.  The finding must be kept.
        pytest.importorskip("z3")
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {\n"                    # 2
            "ok\n"                                    # 3
            ":\n"                                     # 4
            "        sink(d, s, len);\n"              # 5  <- step
            "    }\n"                                 # 6
            "    if (len >= 0) {\n"                   # 7
            "        sink(d, s, len);\n"              # 8  <- step
            "    }\n"                                 # 9
            "}\n",
        )
        sarif = _sarif_with_flow([("src/vuln.c", 5), ("src/vuln.c", 8)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (1, 0)
        assert receipts == []

    def test_open_arm_positive_still_feeds_true_prunes(
        self, tmp_path: Path,
    ):
        # No over-correction, end to end: a genuine label-free open
        # arm (with a benign ternary colon in it) still asserts the
        # positive, and the genuinely contradictory pair still earns
        # its suppression.
        pytest.importorskip("z3")
        target = tmp_path / "target"
        (target / "src").mkdir(parents=True)
        (target / "src" / "vuln.c").write_text(
            "void g(char *d, char *s, int len) {\n"   # 1
            "    if (len < 0) {\n"                    # 2
            "        log(s ? d : s);\n"               # 3
            "        sink(d, s, len);\n"              # 4  <- step
            "    }\n"                                 # 5
            "    if (len >= 0) {\n"                   # 6
            "        sink(d, s, len);\n"              # 7  <- step
            "    }\n"                                 # 8
            "}\n",
        )
        sarif = _sarif_with_flow([("src/vuln.c", 4), ("src/vuln.c", 7)])
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (0, 1)
        assert receipts[0]["verdict"] == "smt_path_infeasible"


def _write_ff_twin_source(tmp_path: Path, pad: str) -> Path:
    r"""Guarded sink with planted contradictory guards ABOVE it and a
    comment whose content is attacker-chosen (*pad*).  \n-model layout
    (what CodeQL numbers): steps at lines 7 and 10, real guard x > 0."""
    target = tmp_path / "target"
    (target / "src").mkdir(parents=True)
    (target / "src" / "vuln.c").write_bytes((
        f"/* {pad} */\n"              # 1
        "static void f(int x) {\n"    # 2
        "    if (x > 5) {\n"          # 3  planted
        "        mark();\n"           # 4
        "    }\n"                     # 5
        "    if (x < 3) {\n"          # 6  planted
        "        mark2();\n"          # 7  <- step
        "    }\n"                     # 8
        "    if (x > 0) {\n"          # 9  the real guard
        "        sink(x);\n"          # 10 <- step
        "    }\n"                     # 11
        "}\n"                         # 12
    ).encode())
    return target


class TestSourceLineModel:
    """SARIF line numbers count \n; the loaded source view must too.

    A splitlines() view desyncs on one \f (legal inside a C comment):
    the guard-harvest window shifts onto attacker-planted contradictory
    guards, the harvested set goes jointly UNSAT, and the SMT pruner
    suppresses the REAL finding as a false positive pre-LLM."""

    STEPS = [("src/vuln.c", 7), ("src/vuln.c", 10)]

    def test_comment_form_feeds_cannot_shift_guard_harvest(
        self, tmp_path: Path,
    ):
        clean = _path_conditions(
            self.STEPS, _write_ff_twin_source(tmp_path / "a", "padding"), {},
        )
        evil = _path_conditions(
            self.STEPS,
            _write_ff_twin_source(tmp_path / "b", "pad\x0c\x0cding"), {},
        )
        assert [(c["text"], c["negated"]) for c in clean] == [
            ("x < 3", False), ("x > 0", False),
        ]
        assert evil == clean

    def test_ff_twin_survives_real_smt_prune(self, tmp_path: Path):
        pytest.importorskip("z3")
        target = _write_ff_twin_source(tmp_path, "pad\x0c\x0cding")
        sarif = _sarif_with_flow(self.STEPS)
        kept, pruned, receipts = _smt_prune_sarif_matches(sarif, target)
        assert (kept, pruned) == (1, 0)
        assert receipts == []
