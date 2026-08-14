"""Tests for core.audit.mechanical_gates — FP categories A-E."""

from __future__ import annotations

import textwrap

from core.audit.mechanical_gates import (
    build_feeds_security_map,
    build_provenance_map,
    build_security_decision_set,
    dedup_callers,
    detect_constant_dangerous_calls,
    detect_universal_preconditions,
    extract_type_constraints,
    format_callee_defenses,
    format_provenance_for_context,
    format_security_decision_for_context,
    format_type_constraints,
    format_universal_preconditions,
    sort_callers_by_constraint,
)


# ── helpers ──


def _context_map(entries=None, edges=None, sinks=None):
    return {
        "entry_points": entries or [],
        "call_edges": edges or [],
        "sink_details": sinks or [],
    }


def _ep(id_, name, etype="http", trust_level="", file="app.py"):
    return {
        "id": id_,
        "name": name,
        "type": etype,
        "file": file,
        "trust_level": trust_level,
    }


def _edge(caller, callee, caller_file="app.py", callee_file=None):
    return {
        "caller": caller,
        "caller_file": caller_file,
        "callee": callee,
        "callee_file": callee_file or caller_file,
    }


class _FakeSummary:
    def __init__(self, function, preconditions=None, error_paths=None):
        self.function = function
        self.preconditions = preconditions or []
        self.error_paths = error_paths or []


class _FakePrecondition:
    def __init__(self, param, conditions):
        self.param = param
        self.conditions = conditions


# ── A: Provenance ──


class TestBuildProvenanceMap:
    def test_single_ep_reaches_callee(self):
        cm = _context_map(
            entries=[_ep("EP-1", "handle_req", "http")],
            edges=[_edge("handle_req", "do_work")],
        )
        prov = build_provenance_map(cm)
        assert "app.py:do_work" in prov
        tags = prov["app.py:do_work"]
        assert len(tags) == 1
        assert tags[0]["ep_id"] == "EP-1"
        assert tags[0]["trust"] == "untrusted"

    def test_trusted_cli_ep(self):
        cm = _context_map(
            entries=[_ep("EP-2", "cli_main", "cli")],
            edges=[_edge("cli_main", "run_task")],
        )
        prov = build_provenance_map(cm)
        assert prov["app.py:run_task"][0]["trust"] == "trusted"

    def test_trust_level_overrides_type(self):
        cm = _context_map(
            entries=[_ep("EP-3", "handler", "http", trust_level="internal_value")],
            edges=[_edge("handler", "work")],
        )
        prov = build_provenance_map(cm)
        assert prov["app.py:work"][0]["trust"] == "trusted"

    def test_attacker_controlled_trust_level(self):
        cm = _context_map(
            entries=[_ep("EP-4", "ws_handler", "websocket", trust_level="attacker_controlled")],
            edges=[_edge("ws_handler", "parse")],
        )
        prov = build_provenance_map(cm)
        assert prov["app.py:parse"][0]["trust"] == "untrusted"

    def test_multiple_eps_reach_same_function(self):
        cm = _context_map(
            entries=[
                _ep("EP-1", "handle_req", "http"),
                _ep("EP-2", "cli_main", "cli"),
            ],
            edges=[
                _edge("handle_req", "shared_fn"),
                _edge("cli_main", "shared_fn"),
            ],
        )
        prov = build_provenance_map(cm)
        tags = prov["app.py:shared_fn"]
        assert len(tags) == 2
        trusts = {t["trust"] for t in tags}
        assert trusts == {"trusted", "untrusted"}

    def test_transitive_reachability(self):
        cm = _context_map(
            entries=[_ep("EP-1", "entry", "http")],
            edges=[
                _edge("entry", "middle"),
                _edge("middle", "deep"),
            ],
        )
        prov = build_provenance_map(cm)
        assert "app.py:deep" in prov
        assert prov["app.py:deep"][0]["ep_id"] == "EP-1"

    def test_empty_edges_returns_empty(self):
        cm = _context_map(entries=[_ep("EP-1", "foo")], edges=[])
        assert build_provenance_map(cm) == {}

    def test_empty_entries_returns_empty(self):
        cm = _context_map(entries=[], edges=[_edge("a", "b")])
        assert build_provenance_map(cm) == {}

    def test_threat_model_trusted_names(self):
        cm = _context_map(
            entries=[_ep("EP-5", "load_config", "python_api")],
            edges=[_edge("load_config", "parse_yaml")],
        )
        tm = {"trusted_inputs": ["load_config (config loader)"]}
        prov = build_provenance_map(cm, threat_model=tm)
        assert prov["app.py:parse_yaml"][0]["trust"] == "trusted"

    def test_threat_model_untrusted_names(self):
        cm = _context_map(
            entries=[_ep("EP-6", "upload_handler", "python_api")],
            edges=[_edge("upload_handler", "save_file")],
        )
        tm = {"untrusted_inputs": ["upload_handler (user upload)"]}
        prov = build_provenance_map(cm, threat_model=tm)
        assert prov["app.py:save_file"][0]["trust"] == "untrusted"


class TestFormatProvenanceForContext:
    def test_all_trusted_message(self):
        prov = [{"ep_id": "EP-1", "ep_name": "cli_main", "trust": "trusted", "ep_type": "cli"}]
        text = format_provenance_for_context(prov)
        assert "ONLY from trusted" in text
        assert "NOT attacker-controlled" in text

    def test_untrusted_message(self):
        prov = [{"ep_id": "EP-1", "ep_name": "handler", "trust": "untrusted", "ep_type": "http"}]
        text = format_provenance_for_context(prov)
        assert "UNTRUSTED" in text

    def test_mixed_message(self):
        prov = [
            {"ep_id": "EP-1", "ep_name": "handler", "trust": "untrusted", "ep_type": "http"},
            {"ep_id": "EP-2", "ep_name": "cli", "trust": "trusted", "ep_type": "cli"},
        ]
        text = format_provenance_for_context(prov)
        assert "UNTRUSTED" in text
        assert "trusted" in text.lower()

    def test_empty_returns_empty(self):
        assert format_provenance_for_context([]) == ""


# ── B: Callee defenses ──


class TestFormatCalleeDefenses:
    def test_with_preconditions(self):
        summaries = [
            _FakeSummary(
                "validate_input",
                preconditions=[_FakePrecondition("path", ["must not contain '..'"])],
            ),
        ]
        text = format_callee_defenses(summaries)
        assert "CALLEE DEFENSE" in text
        assert "validate_input" in text
        assert "path" in text

    def test_no_preconditions_returns_empty(self):
        summaries = [_FakeSummary("plain_fn")]
        assert format_callee_defenses(summaries) == ""

    def test_empty_summaries_returns_empty(self):
        assert format_callee_defenses([]) == ""

    def test_multiple_defenses(self):
        summaries = [
            _FakeSummary(
                "check_auth",
                preconditions=[_FakePrecondition("token", ["non-empty", "valid JWT"])],
            ),
            _FakeSummary(
                "sanitize_html",
                preconditions=[_FakePrecondition("html", ["escaped"])],
            ),
        ]
        text = format_callee_defenses(summaries)
        assert "check_auth" in text
        assert "sanitize_html" in text

    def test_max_10_defenses(self):
        summaries = [
            _FakeSummary(
                f"fn_{i}",
                preconditions=[_FakePrecondition("x", [f"cond_{i}"])],
            )
            for i in range(15)
        ]
        text = format_callee_defenses(summaries)
        lines = [line for line in text.split("\n") if line.strip()]
        assert len(lines) <= 10


# ── C: Security-decision reachability ──


class TestBuildSecurityDecisionSet:
    def test_auth_function_detected(self):
        cm = _context_map(edges=[_edge("handler", "authenticate_user")])
        keys = build_security_decision_set(cm)
        assert "app.py:authenticate_user" in keys

    def test_crypto_function_detected(self):
        cm = _context_map(edges=[_edge("handler", "encrypt_data")])
        keys = build_security_decision_set(cm)
        assert "app.py:encrypt_data" in keys

    def test_plain_function_not_detected(self):
        cm = _context_map(edges=[_edge("handler", "format_output")])
        keys = build_security_decision_set(cm)
        assert "app.py:format_output" not in keys

    def test_sanitize_detected(self):
        cm = _context_map(edges=[_edge("handler", "sanitize_input")])
        keys = build_security_decision_set(cm)
        assert "app.py:sanitize_input" in keys

    def test_empty_edges(self):
        assert build_security_decision_set(_context_map()) == frozenset()


class TestBuildFeedsSecurityMap:
    def test_caller_of_auth_detected(self):
        cm = _context_map(edges=[_edge("handler", "check_access")])
        sec_keys = build_security_decision_set(cm)
        feeds = build_feeds_security_map(cm, security_keys=sec_keys)
        assert "app.py:handler" in feeds

    def test_non_security_caller_not_detected(self):
        cm = _context_map(edges=[_edge("handler", "format_text")])
        sec_keys = build_security_decision_set(cm)
        feeds = build_feeds_security_map(cm, security_keys=sec_keys)
        assert "app.py:handler" not in feeds

    def test_transitive_not_included(self):
        cm = _context_map(edges=[
            _edge("entry", "middleware"),
            _edge("middleware", "verify_token"),
        ])
        sec_keys = build_security_decision_set(cm)
        feeds = build_feeds_security_map(cm, security_keys=sec_keys)
        assert "app.py:middleware" in feeds
        assert "app.py:entry" not in feeds


class TestFormatSecurityDecisionForContext:
    def test_with_callees(self):
        text = format_security_decision_for_context(True, ["check_access", "verify_token"])
        assert "SECURITY CONSEQUENCE" in text
        assert "check_access" in text

    def test_without_callees(self):
        text = format_security_decision_for_context(True)
        assert "SECURITY CONSEQUENCE" in text

    def test_not_feeds_returns_empty(self):
        assert format_security_decision_for_context(False) == ""


# ── D: Constant argument detection ──


class TestDetectConstantDangerousCalls:
    def test_literal_eval(self):
        src = textwrap.dedent("""\
            x = eval("1 + 2")
        """)
        results = detect_constant_dangerous_calls(src, "test.py")
        assert len(results) == 1
        assert results[0]["call"] == "eval"
        assert results[0]["line"] == 1

    def test_variable_eval_not_detected(self):
        src = textwrap.dedent("""\
            x = eval(user_input)
        """)
        results = detect_constant_dangerous_calls(src, "test.py")
        assert len(results) == 0

    def test_module_constant(self):
        src = textwrap.dedent("""\
            CMD = "ls -la"
            result = eval(CMD)
        """)
        results = detect_constant_dangerous_calls(src, "test.py")
        assert len(results) == 1
        assert "'ls -la'" in results[0]["args"][0]

    def test_subprocess_run_literal(self):
        src = textwrap.dedent("""\
            import subprocess
            subprocess.run(["echo", "hello"])
        """)
        results = detect_constant_dangerous_calls(src, "test.py")
        assert len(results) == 1
        assert "subprocess.run" in results[0]["call"]

    def test_open_literal(self):
        src = textwrap.dedent("""\
            f = open("/etc/hostname", "r")
        """)
        results = detect_constant_dangerous_calls(src, "test.py")
        assert len(results) == 1

    def test_mixed_args_not_detected(self):
        src = textwrap.dedent("""\
            f = open(user_path, "r")
        """)
        results = detect_constant_dangerous_calls(src, "test.py")
        assert len(results) == 0

    def test_non_python_skipped(self):
        results = detect_constant_dangerous_calls("eval('x')", "test.c")
        assert results == []

    def test_syntax_error_handled(self):
        results = detect_constant_dangerous_calls("def (broken", "test.py")
        assert results == []

    def test_no_args_skipped(self):
        src = "exec()\n"
        results = detect_constant_dangerous_calls(src, "test.py")
        assert len(results) == 0


# ── E: Caller constraint sorting ──


class TestSortCallersByConstraint:
    def test_constrained_first(self):
        callers = [
            {"file": "a.py", "name": "no_checks"},
            {"file": "a.py", "name": "validated"},
        ]
        summaries = {
            "a.py:no_checks": _FakeSummary("no_checks"),
            "a.py:validated": _FakeSummary(
                "validated",
                preconditions=[_FakePrecondition("x", ["non-negative"])],
                error_paths=["raise ValueError"],
            ),
        }
        sorted_ = sort_callers_by_constraint(callers, taint_summaries=summaries)
        assert sorted_[0]["name"] == "validated"

    def test_no_summaries_preserves_order(self):
        callers = [{"file": "a.py", "name": "a"}, {"file": "a.py", "name": "b"}]
        result = sort_callers_by_constraint(callers, taint_summaries=None)
        assert result == callers

    def test_empty_callers(self):
        assert sort_callers_by_constraint([], taint_summaries={}) == []

    def test_missing_summary_sorts_last(self):
        callers = [
            {"file": "a.py", "name": "unknown"},
            {"file": "a.py", "name": "known"},
        ]
        summaries = {
            "a.py:known": _FakeSummary(
                "known",
                preconditions=[_FakePrecondition("x", ["valid"])],
            ),
        }
        sorted_ = sort_callers_by_constraint(callers, taint_summaries=summaries)
        assert sorted_[0]["name"] == "known"


# ── E-2: Caller dedup ──


class TestDedupCallers:
    def test_identical_call_sites_collapsed(self):
        callers = [
            {"file": "a.py", "name": "fn1", "call_site": "  10  process(data, 'utf-8')"},
            {"file": "b.py", "name": "fn2", "call_site": "  20  process(data, 'utf-8')"},
        ]
        result = dedup_callers(callers)
        assert len(result) == 1
        assert result[0]["same_pattern_count"] == 2

    def test_different_call_sites_kept(self):
        callers = [
            {"file": "a.py", "name": "fn1", "call_site": "  10  process(data, 'utf-8')"},
            {"file": "b.py", "name": "fn2", "call_site": "  20  process(data, 'binary')"},
        ]
        result = dedup_callers(callers)
        assert len(result) == 2

    def test_no_call_site_treated_as_unique(self):
        callers = [
            {"file": "a.py", "name": "fn1"},
            {"file": "b.py", "name": "fn2"},
        ]
        result = dedup_callers(callers)
        assert len(result) == 2

    def test_empty_callers(self):
        assert dedup_callers([]) == []

    def test_representative_preserves_info(self):
        callers = [
            {"file": "a.py", "name": "fn1", "line_start": 10, "call_site": "  10  run('ls')"},
            {"file": "b.py", "name": "fn2", "line_start": 20, "call_site": "  20  run('ls')"},
            {"file": "c.py", "name": "fn3", "line_start": 30, "call_site": "  30  run('ls')"},
        ]
        result = dedup_callers(callers)
        assert len(result) == 1
        assert result[0]["same_pattern_count"] == 3
        assert len(result[0]["same_pattern_callers"]) == 2

    def test_mixed_with_and_without_site(self):
        callers = [
            {"file": "a.py", "name": "fn1", "call_site": "  10  do(x)"},
            {"file": "b.py", "name": "fn2"},
            {"file": "c.py", "name": "fn3", "call_site": "  30  do(y)"},
        ]
        result = dedup_callers(callers)
        # do(x) and do(y) normalise to same pattern (variables → _)
        assert len(result) == 2

    def test_different_literals_not_collapsed(self):
        callers = [
            {"file": "a.py", "name": "fn1", "call_site": '  10  run("ls")'},
            {"file": "b.py", "name": "fn2", "call_site": '  20  run("rm")'},
        ]
        result = dedup_callers(callers)
        assert len(result) == 2

    def test_line_numbers_stripped_for_comparison(self):
        callers = [
            {"file": "a.py", "name": "fn1", "call_site": "  42  check(val)"},
            {"file": "b.py", "name": "fn2", "call_site": "  99  check(val)"},
        ]
        result = dedup_callers(callers)
        assert len(result) == 1


# ── E-3: Universal preconditions ──


class TestDetectUniversalPreconditions:
    def test_all_callers_guard_same_param(self):
        callers = [
            {"file": "a.py", "name": "fn1"},
            {"file": "a.py", "name": "fn2"},
            {"file": "a.py", "name": "fn3"},
        ]
        summaries = {
            "a.py:fn1": _FakeSummary("fn1", [_FakePrecondition("path", ["not empty"])]),
            "a.py:fn2": _FakeSummary("fn2", [_FakePrecondition("path", ["valid path"])]),
            "a.py:fn3": _FakeSummary("fn3", [_FakePrecondition("path", ["no .."])]),
        }
        result = detect_universal_preconditions(callers, summaries)
        assert len(result) == 1
        assert result[0]["param"] == "path"
        assert result[0]["n_callers"] == "3"

    def test_partial_guard_not_universal(self):
        callers = [
            {"file": "a.py", "name": "fn1"},
            {"file": "a.py", "name": "fn2"},
            {"file": "a.py", "name": "fn3"},
        ]
        summaries = {
            "a.py:fn1": _FakeSummary("fn1", [_FakePrecondition("x", ["check"])]),
            "a.py:fn2": _FakeSummary("fn2"),
            "a.py:fn3": _FakeSummary("fn3", [_FakePrecondition("x", ["check"])]),
        }
        result = detect_universal_preconditions(callers, summaries)
        assert len(result) == 0

    def test_single_caller_not_universal(self):
        callers = [{"file": "a.py", "name": "fn1"}]
        summaries = {
            "a.py:fn1": _FakeSummary("fn1", [_FakePrecondition("x", ["check"])]),
        }
        result = detect_universal_preconditions(callers, summaries)
        assert len(result) == 0

    def test_no_summaries(self):
        callers = [{"file": "a.py", "name": "fn1"}]
        assert detect_universal_preconditions(callers, None) == []

    def test_no_callers(self):
        assert detect_universal_preconditions([], {}) == []


class TestFormatUniversalPreconditions:
    def test_format_output(self):
        preconds = [{"param": "path", "conditions": "not empty, no ..", "n_callers": "4"}]
        text = format_universal_preconditions(preconds)
        assert "ALL 4 callers" in text
        assert "CANNOT reach" in text
        assert "path" in text

    def test_empty(self):
        assert format_universal_preconditions([]) == ""


# ── E-4: Type constraint extraction ──


class TestExtractTypeConstraints:
    def test_python_int_param(self):
        src = textwrap.dedent("""\
            def process(count: int, name: str) -> None:
                pass
        """)
        results = extract_type_constraints(src, "test.py", "process")
        assert len(results) == 1
        assert results[0]["param"] == "count"
        assert results[0]["type"] == "int"
        assert "numeric" in results[0]["constraint_note"]

    def test_python_bool_param(self):
        src = textwrap.dedent("""\
            def toggle(flag: bool) -> None:
                pass
        """)
        results = extract_type_constraints(src, "test.py", "toggle")
        assert len(results) == 1
        assert results[0]["type"] == "bool"

    def test_python_str_param_not_constrained(self):
        src = textwrap.dedent("""\
            def greet(name: str) -> None:
                pass
        """)
        results = extract_type_constraints(src, "test.py", "greet")
        assert len(results) == 0

    def test_python_no_annotation_skipped(self):
        src = textwrap.dedent("""\
            def process(data):
                pass
        """)
        results = extract_type_constraints(src, "test.py", "process")
        assert len(results) == 0

    def test_python_path_type(self):
        src = textwrap.dedent("""\
            from pathlib import Path
            def load(p: Path) -> None:
                pass
        """)
        results = extract_type_constraints(src, "test.py", "load")
        assert len(results) == 1
        assert "path type" in results[0]["constraint_note"]

    def test_python_enum_type(self):
        src = textwrap.dedent("""\
            def set_mode(mode: MyEnum) -> None:
                pass
        """)
        results = extract_type_constraints(src, "test.py", "set_mode")
        assert len(results) == 1
        assert "enum" in results[0]["constraint_note"]

    def test_python_self_skipped(self):
        src = textwrap.dedent("""\
            class Foo:
                def run(self, count: int) -> None:
                    pass
        """)
        results = extract_type_constraints(src, "test.py", "run")
        assert len(results) == 1
        assert results[0]["param"] == "count"

    def test_c_int_param(self):
        src = "int process(int count, char *name) {\n    return 0;\n}\n"
        results = extract_type_constraints(src, "test.c", "process")
        assert len(results) == 1
        assert results[0]["param"] == "count"
        assert results[0]["type"] == "int"

    def test_c_pointer_not_constrained(self):
        src = "void handle(char *buf) {}\n"
        results = extract_type_constraints(src, "test.c", "handle")
        assert len(results) == 0

    def test_rust_numeric_param(self):
        src = "fn process(count: u32, name: &str) -> Result<()> {\n    Ok(())\n}\n"
        results = extract_type_constraints(src, "test.rs", "process")
        assert len(results) == 1
        assert results[0]["param"] == "count"

    def test_go_int_param(self):
        src = "func Process(count int, name string) error {\n    return nil\n}\n"
        results = extract_type_constraints(src, "test.go", "Process")
        assert len(results) == 1
        assert results[0]["param"] == "count"
        assert results[0]["type"] == "int"

    def test_java_int_param(self):
        src = "public void process(int count, String name) {\n}\n"
        results = extract_type_constraints(src, "test.java", "process")
        assert len(results) == 1
        assert results[0]["param"] == "count"

    def test_unknown_extension_returns_empty(self):
        results = extract_type_constraints("fn x", "test.xyz", "x")
        assert results == []

    def test_syntax_error_returns_empty(self):
        results = extract_type_constraints("def (broken", "test.py", "broken")
        assert results == []

    def test_wrong_function_name_returns_empty(self):
        src = textwrap.dedent("""\
            def other(count: int) -> None:
                pass
        """)
        results = extract_type_constraints(src, "test.py", "process")
        assert len(results) == 0


class TestFormatTypeConstraints:
    def test_format_output(self):
        constraints = [{"param": "n", "type": "int", "constraint_note": "numeric"}]
        text = format_type_constraints(constraints)
        assert "TYPE CONSTRAINTS" in text
        assert "`n`" in text
        assert "`int`" in text

    def test_empty(self):
        assert format_type_constraints([]) == ""


class TestRustRefTypeDetection:
    def test_ref_str_skipped(self):
        src = "fn process(name: &str) -> () {}\n"
        results = extract_type_constraints(src, "test.rs", "process")
        assert all(r["param"] != "name" for r in results)

    def test_ref_u8_slice_skipped(self):
        src = "fn process(buf: &[u8]) -> () {}\n"
        results = extract_type_constraints(src, "test.rs", "process")
        assert all(r["param"] != "buf" for r in results)
