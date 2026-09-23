"""Tests for core.audit.mechanical_gates — FP categories A-E."""

from __future__ import annotations

import textwrap
import time

from core.audit.mechanical_gates import (
    _classify_entry_points,
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

    def test_trust_level_cannot_override_untrusted_type(self):
        # The map's trust_level is LLM-authored — it may only mark an
        # entry untrusted. An internal_value stamp on an http entry
        # point must not flip it to trusted (the old inversion fed
        # provenance_all_trusted, a live suppression gate).
        cm = _context_map(
            entries=[_ep("EP-3", "handler", "http", trust_level="internal_value")],
            edges=[_edge("handler", "work")],
        )
        prov = build_provenance_map(cm)
        assert prov["app.py:work"][0]["trust"] == "untrusted"

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
        # Preconditions are callee ASSUMPTIONS (caller obligations),
        # never "defended" claims — see TestCalleeDefenseSemantics.
        assert "CALLEE ASSUMPTION" in text
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
    def test_format_output_arg_verified(self):
        preconds = [{
            "param": "path", "conditions": "not empty, no ..",
            "n_callers": "4", "arg_verified": "true",
        }]
        text = format_universal_preconditions(preconds)
        assert "ALL 4 callers" in text
        assert "CANNOT reach" in text
        assert "path" in text

    def test_format_output_unverified_is_observation_grade(self):
        # No arg_verified field (legacy shape) — must not render the
        # definitive suppression instruction.
        preconds = [{"param": "path", "conditions": "not empty", "n_callers": "4"}]
        text = format_universal_preconditions(preconds)
        assert "CANNOT" not in text
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


class TestTypeConstraintPatternFloodPerformance:
    """Hostile-source floods against the declaration patterns: the
    repeated-modifier prefixes (the Java one's bare ``|\\s`` arm made
    whitespace floods catastrophic), unanchored scans over long word
    runs, and unbounded parameter/generics/receiver classes were each
    quadratic or worse — tens of seconds to unbounded at 64KB. The
    anchored, token-bounded patterns run in milliseconds; the budget
    is generous for slow machines yet an order of magnitude below the
    broken variants at this input size."""

    def test_c_and_java_patterns_on_hostile_floods(self):
        from core.audit.mechanical_gates import _C_FUNC_PAT, _JAVA_METHOD_PAT
        floods = [
            "public " * (128 * 1024 // 7),
            "static\n" * (128 * 1024 // 7),
            "synchronized " * (128 * 1024 // 13),
            "x" * (128 * 1024),
            " " * (128 * 1024),
            "a b(" * (128 * 1024 // 4),
            "a, " * (128 * 1024 // 3),
            "int" + " " * (128 * 1024),
        ]
        for pat in (_C_FUNC_PAT, _JAVA_METHOD_PAT):
            for flood in floods:
                start = time.monotonic()
                assert pat.findall(flood) == []
                assert time.monotonic() - start < 2.0

    def test_rust_and_go_patterns_on_hostile_floods(self):
        from core.audit.mechanical_gates import _GO_FUNC_PAT, _RUST_FUNC_PAT
        # The generics and receiver floods are sized at 256KB: the
        # unbounded variants squeak under the budget at 128KB on a
        # fast machine, and quadratic scaling puts 256KB decisively
        # over it.
        cases = [
            (_RUST_FUNC_PAT, "fn f" + " " * (128 * 1024)),
            (_RUST_FUNC_PAT, "fn f(" * (128 * 1024 // 5)),
            (_RUST_FUNC_PAT, "fn f<a " * (256 * 1024 // 7)),
            (_GO_FUNC_PAT, "func f(" * (128 * 1024 // 7)),
            (_GO_FUNC_PAT, "func (" * (256 * 1024 // 6)),
        ]
        for pat, flood in cases:
            start = time.monotonic()
            assert pat.findall(flood) == []
            assert time.monotonic() - start < 2.0

    def test_real_declarations_still_enriched(self):
        # Direction checks across all four arms, including the
        # kernel-style split C declaration and generic/receiver
        # shapes.
        c_src = "static int\nkern(unsigned int flags, size_t len)\n{\n}\n"
        assert extract_type_constraints(c_src, "k.c", "kern")
        java_src = (
            "protected static Map<String, Integer> gen(long id, "
            "boolean flag) { return null; }"
        )
        assert extract_type_constraints(java_src, "G.java", "gen")
        rust_src = "pub fn generic<T: Send>(n: usize, item: T) -> T { item }"
        assert extract_type_constraints(rust_src, "g.rs", "generic")
        go_src = "func (s *Server) Handle(count int, name string) {}"
        assert extract_type_constraints(go_src, "h.go", "Handle")

    def test_long_c_prototype_still_enriched(self):
        # Direction check for the C arm's raised parameter cap:
        # ~600 chars of column-aligned multi-line parameters — the
        # shape long real C prototypes take — must keep enriching.
        params = ",\n".join(
            f"    const struct display_mode_lib *mode_lib_{i:02d}"
            for i in range(12)
        ) + ",\n    unsigned int flags"
        assert 400 < len(params) <= 1000
        src = f"static void dlg_get_reg(\n{params})\n{{\n}}\n"
        results = extract_type_constraints(src, "d.c", "dlg_get_reg")
        assert any(r["param"] == "flags" for r in results)

    def test_declaration_past_caps_unenriched(self):
        # Direction checks documenting the accepted trade-offs: the
        # Java arm's parameter class is bounded at 400 chars, the C
        # arm's at 1000 (see the cap comment at _C_FUNC_PAT).
        params_520 = ", ".join(f"int p{i}" for i in range(60))
        assert 400 < len(params_520) < 1000
        java_src = f"public void wide({params_520}) {{}}"
        assert extract_type_constraints(java_src, "W.java", "wide") == []
        # The same list stays inside the C arm's higher cap...
        assert extract_type_constraints(
            f"int wide({params_520}) {{}}", "w.c", "wide",
        )
        # ...and past 1000 chars the C arm stops enriching too.
        params_1200 = ", ".join(f"int q{i}" for i in range(140))
        assert len(params_1200) > 1000
        c_src = f"int huge({params_1200}) {{}}"
        assert extract_type_constraints(c_src, "w.c", "huge") == []


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


class TestExtractPythonTypesRobustness:
    def test_indented_method_snippet_parses(self):
        from core.audit.mechanical_gates import _extract_python_types

        src = (
            "    def handle(self, n: int, s: str) -> None:\n"
            "        return None\n"
        )
        results = _extract_python_types(src, "handle")
        # str carries no constraint note; the int param proves the
        # dedent recovered the method (the old path returned []).
        assert {r["param"] for r in results} == {"n"}

    def test_same_named_functions_refuse(self):
        # Two same-named defs: the first one's parameter types were
        # emitted as constraints for the WRONG function — a false
        # steering hint. Ambiguity now yields no constraint.
        from core.audit.mechanical_gates import _extract_python_types

        src = (
            "class A:\n"
            "    def handle(self, n: int):\n"
            "        pass\n"
            "class B:\n"
            "    def handle(self, s: str):\n"
            "        pass\n"
        )
        assert _extract_python_types(src, "handle") == []

    def test_unique_function_still_extracts(self):
        from core.audit.mechanical_gates import _extract_python_types

        src = "def f(n: int):\n    pass\n"
        results = _extract_python_types(src, "f")
        assert results and results[0]["param"] == "n"


class TestNormaliseCallSiteStrings:
    def test_hash_inside_string_does_not_truncate(self):
        from core.audit.mechanical_gates import _normalise_call_site

        a = _normalise_call_site('f("a #b", x)')
        b = _normalise_call_site('f("a #c", y)')
        assert a != b
        assert '"a #b"' in a

    def test_real_comment_still_stripped(self):
        from core.audit.mechanical_gates import _normalise_call_site

        assert _normalise_call_site(
            "f(x)  # trailing comment",
        ) == _normalise_call_site("f(y)")


class TestModuleConstantInvalidation:
    def test_non_literal_rebinding_invalidates(self):
        import ast as _ast

        from core.audit.mechanical_gates import _collect_module_constants

        tree = _ast.parse("CMD = 'ls'\nCMD = input()\n")
        assert "CMD" not in _collect_module_constants(tree)

    def test_stable_literal_still_collected(self):
        import ast as _ast

        from core.audit.mechanical_gates import _collect_module_constants

        tree = _ast.parse("CMD = 'ls'\nOTHER = 3\n")
        constants = _collect_module_constants(tree)
        assert constants == {"CMD": "ls", "OTHER": 3}


# ── E-3: arg-verified universal preconditions ──


class TestUniversalPreconditionArgVerification:
    def _summaries(self):
        return {
            "a.py:fn1": _FakeSummary(
                "fn1", [_FakePrecondition("size", ["size > 0"])],
            ),
            "a.py:fn2": _FakeSummary(
                "fn2", [_FakePrecondition("size", ["size < MAX"])],
            ),
        }

    def test_same_named_locals_do_not_mint_definitive_claim(self):
        # Both callers guard a local named `size`, but neither call
        # site passes it — a name coincidence must not render the
        # "CANNOT reach this function unvalidated" instruction.
        callers = [
            {"file": "a.py", "name": "fn1", "call_site": "process(buf, n)"},
            {"file": "a.py", "name": "fn2", "call_site": "process(data, m)"},
        ]
        result = detect_universal_preconditions(callers, self._summaries())
        assert len(result) == 1
        assert result[0]["arg_verified"] == "false"
        text = format_universal_preconditions(result)
        assert "CANNOT" not in text
        assert "observation" in text.lower()

    def test_genuinely_passed_param_still_definitive(self):
        callers = [
            {"file": "a.py", "name": "fn1", "call_site": "process(size, buf)"},
            {"file": "a.py", "name": "fn2", "call_site": "process(size, data)"},
        ]
        result = detect_universal_preconditions(callers, self._summaries())
        assert len(result) == 1
        assert result[0]["arg_verified"] == "true"
        text = format_universal_preconditions(result)
        assert "CANNOT reach" in text

    def test_missing_call_site_downgrades_to_observation(self):
        callers = [
            {"file": "a.py", "name": "fn1"},
            {"file": "a.py", "name": "fn2"},
        ]
        result = detect_universal_preconditions(callers, self._summaries())
        assert len(result) == 1
        assert result[0]["arg_verified"] == "false"
        assert "CANNOT" not in format_universal_preconditions(result)

    def test_attribute_of_other_object_not_matched(self):
        # `obj.size` is not the caller's guarded local `size`.
        callers = [
            {"file": "a.py", "name": "fn1", "call_site": "process(obj.size)"},
            {"file": "a.py", "name": "fn2", "call_site": "process(obj.size)"},
        ]
        result = detect_universal_preconditions(callers, self._summaries())
        assert result[0]["arg_verified"] == "false"

    def test_one_unverified_caller_downgrades_all(self):
        callers = [
            {"file": "a.py", "name": "fn1", "call_site": "process(size, buf)"},
            {"file": "a.py", "name": "fn2", "call_site": "process(data, m)"},
        ]
        result = detect_universal_preconditions(callers, self._summaries())
        assert result[0]["arg_verified"] == "false"


# ── A: threat-model item tokenisation ──


class TestThreatModelItemTokenisation:
    def test_prose_item_does_not_trust_unrelated_entry_points(self):
        # "local config file parsing" must not turn entry points that
        # happen to be named "file" or "parsing" into trusted ones.
        cm = _context_map(
            entries=[
                _ep("EP-1", "file", "http"),
                _ep("EP-2", "parsing", "http"),
            ],
            edges=[_edge("file", "sink_a"), _edge("parsing", "sink_b")],
        )
        tm = {"trusted_inputs": ["local config file parsing"]}
        prov = build_provenance_map(cm, threat_model=tm)
        assert prov["app.py:sink_a"][0]["trust"] == "untrusted"
        assert prov["app.py:sink_b"][0]["trust"] == "untrusted"

    def test_prose_untrusted_item_does_not_flip_trusted_types(self):
        cm = _context_map(
            entries=[_ep("EP-1", "parsing", "cli")],
            edges=[_edge("parsing", "sink_a")],
        )
        tm = {"untrusted_inputs": ["all network parsing paths"]}
        prov = build_provenance_map(cm, threat_model=tm)
        assert prov["app.py:sink_a"][0]["trust"] == "trusted"

    def test_whole_item_name_still_matches(self):
        cm = _context_map(
            entries=[_ep("EP-1", "argv", "python_api")],
            edges=[_edge("argv", "sink_a")],
        )
        tm = {"trusted_inputs": ["argv"]}
        prov = build_provenance_map(cm, threat_model=tm)
        assert prov["app.py:sink_a"][0]["trust"] == "trusted"

    def test_identifier_token_in_prose_still_matches(self):
        cm = _context_map(
            entries=[_ep("EP-1", "load_config", "python_api")],
            edges=[_edge("load_config", "sink_a")],
        )
        tm = {"trusted_inputs": ["the load_config startup path"]}
        prov = build_provenance_map(cm, threat_model=tm)
        assert prov["app.py:sink_a"][0]["trust"] == "trusted"

    def test_call_signature_token_still_matches(self):
        cm = _context_map(
            entries=[_ep("EP-1", "loadconf", "python_api")],
            edges=[_edge("loadconf", "sink_a")],
        )
        tm = {"trusted_inputs": ["loadconf(path) at startup"]}
        prov = build_provenance_map(cm, threat_model=tm)
        assert prov["app.py:sink_a"][0]["trust"] == "trusted"

    def test_untrusted_identifier_still_classifies(self):
        cm = _context_map(
            entries=[_ep("EP-1", "upload_handler", "cli")],
            edges=[_edge("upload_handler", "sink_a")],
        )
        tm = {"untrusted_inputs": ["upload_handler (user upload)"]}
        prov = build_provenance_map(cm, threat_model=tm)
        assert prov["app.py:sink_a"][0]["trust"] == "untrusted"


class TestConstantScopeHoles:
    """A name is a constant only when NO other binding of it exists
    anywhere in the tree — a function-local shadow, tuple unpacking,
    loop/with/walrus binder, parameter, or import alias all
    invalidate. Keeping the first literal minted "definitively not
    attacker-controllable" over tainted calls."""

    def test_function_local_shadow_invalidates(self):
        src = (
            "CMD = 'ls -l'\n"
            "def handler(user_input):\n"
            "    CMD = user_input\n"
            "    os.system(CMD)\n"
        )
        assert detect_constant_dangerous_calls(src, "a.py") == []

    def test_tuple_rebind_invalidates(self):
        src = (
            "CMD = 'ls -l'\n"
            "CMD, OTHER = get_user_input(), 2\n"
            "os.system(CMD)\n"
        )
        assert detect_constant_dangerous_calls(src, "a.py") == []

    def test_for_binder_invalidates(self):
        src = (
            "CMD = 'ls'\n"
            "for CMD in sys.argv:\n"
            "    pass\n"
            "os.system(CMD)\n"
        )
        assert detect_constant_dangerous_calls(src, "a.py") == []

    def test_walrus_invalidates(self):
        src = (
            "CMD = 'ls'\n"
            "if (CMD := input()):\n"
            "    os.system(CMD)\n"
        )
        assert detect_constant_dangerous_calls(src, "a.py") == []

    def test_parameter_shadow_invalidates(self):
        src = (
            "CMD = 'ls'\n"
            "def f(CMD):\n"
            "    os.system(CMD)\n"
        )
        assert detect_constant_dangerous_calls(src, "a.py") == []

    def test_import_alias_invalidates(self):
        src = (
            "CMD = 'ls'\n"
            "import evil as CMD\n"
            "os.system(CMD)\n"
        )
        assert detect_constant_dangerous_calls(src, "a.py") == []

    def test_plain_rebind_still_invalidates(self):
        # The landed plain-rebind invalidation keeps working.
        src = "CMD = 'ls -l'\nCMD = input()\nos.system(CMD)\n"
        assert detect_constant_dangerous_calls(src, "a.py") == []

    def test_unshadowed_constant_still_detected(self):
        src = "CMD = 'ls -l'\nos.system(CMD)\n"
        hits = detect_constant_dangerous_calls(src, "a.py")
        assert hits and hits[0]["call"] == "os.system"


class TestUniversalPreconditionUniverseGate:
    def test_unsummarized_caller_refuses_the_claim(self):
        # "ALL callers validate" is only claimable when every caller
        # HAS a summary — the third, unsummarized caller passes
        # anything, so the definitive guarantee must not render.
        callers = [
            {"file": "a.c", "name": "c1", "call_site": "f(buf)"},
            {"file": "a.c", "name": "c2", "call_site": "f(buf)"},
            {"file": "a.c", "name": "c3", "call_site": "f(evil)"},
        ]
        summaries = {
            "a.c:c1": _FakeSummary("c1", [_FakePrecondition("buf", ["buf != NULL"])]),
            "a.c:c2": _FakeSummary("c2", [_FakePrecondition("buf", ["buf != NULL"])]),
        }
        assert detect_universal_preconditions(callers, summaries) == []


class TestCalleeDefenseSemantics:
    def test_precondition_renders_as_assumption_not_defense(self):
        # A callee precondition is what the callee ASSUMES (the
        # llm_summaries prompt semantics) — not validation inside the
        # callee. Rendering it as "flow ... is defended" was an
        # inverted, suppression-direction hint.
        summaries = [
            _FakeSummary(
                "use_buf",
                preconditions=[_FakePrecondition("buf", ["buf != NULL"])],
            ),
        ]
        text = format_callee_defenses(summaries)
        assert "is defended" not in text
        assert "ASSUM" in text.upper()
        assert "use_buf" in text and "buf" in text


class TestOperatorThreatModelOutranksMapTrust:
    """The context map's trust_level is LLM-authored /understand
    output (imported unconditionally at prep) — it may only mark an
    entry UNTRUSTED. Trusted classification comes from the operator's
    threat model or the type heuristic; a hostile or hallucinated map
    stamping entry points internal_value must never flip an
    operator-declared untrusted entry (provenance_all_trusted then
    resolves corroborated suspicious outcomes to clean)."""

    def test_operator_untrusted_beats_llm_internal_value(self):
        eps = [{"id": "e1", "name": "parse_upload", "type": "upload",
                "trust_level": "internal_value"}]
        tm = {"untrusted_inputs": ["parse_upload"]}
        out = _classify_entry_points(eps, tm)
        assert out["e1"]["trust"] == "untrusted"

    def test_llm_trusted_stamp_cannot_beat_untrusted_type(self):
        eps = [{"id": "e1", "name": "ws", "type": "websocket",
                "trust_level": "runtime_constant"}]
        out = _classify_entry_points(eps, None)
        assert out["e1"]["trust"] == "untrusted"

    def test_llm_untrusted_stamp_still_downgrades(self):
        eps = [{"id": "e1", "name": "boot", "type": "cli",
                "trust_level": "attacker_controlled"}]
        out = _classify_entry_points(eps, None)
        assert out["e1"]["trust"] == "untrusted"

    def test_operator_trusted_name_still_trusted(self):
        eps = [{"id": "e1", "name": "load_config", "type": ""}]
        tm = {"trusted_inputs": ["load_config"]}
        out = _classify_entry_points(eps, tm)
        assert out["e1"]["trust"] == "trusted"

    def test_unknown_type_with_llm_trusted_stamp_defaults_untrusted(self):
        eps = [{"id": "e1", "name": "mystery", "type": "",
                "trust_level": "internal_value"}]
        out = _classify_entry_points(eps, None)
        assert out["e1"]["trust"] == "untrusted"
