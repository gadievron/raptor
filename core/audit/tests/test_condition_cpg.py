"""Tests for condition_cpg — CPG guard relevance and interprocedural checks."""

import pytest
try:
    import tree_sitter  # noqa: F401
    _HAS_TS = True
except ImportError:
    _HAS_TS = False
pytestmark = pytest.mark.skipif(not _HAS_TS, reason="tree-sitter not installed")


from core.audit.condition_cpg import (  # noqa: E402
    CallerGuard,
    CpgGuardResult,
    ExposureContext,
    InterproceduralGuardResult,
    _build_callers_query,
    _build_caller_guards_query,
    _build_dominance_query,
    _build_guard_identifiers_query,
    _build_sink_arg_identifiers_query,
    _build_taint_reaches_guard_query,
    _parse_scala_list,
    _safe_name,
    assess_exposure_context,
    check_interprocedural_guards,
    verify_guard_relevance_cpg,
)
from core.audit.condition_extraction import GuardCondition, SinkGuard  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _guard(text: str, category: str, line: int = 5) -> GuardCondition:
    return GuardCondition(text=text, category=category, polarity="required", line=line)


def _sg(guards: list, func: str = "process_input") -> SinkGuard:
    return SinkGuard(
        sink_file="src/handler.c",
        sink_line=42,
        sink_function=func,
        sink_api="memcpy",
        guards=guards,
        unconditional=(len(guards) == 0),
    )


# ---------------------------------------------------------------------------
# CPG guard relevance (without Joern — graceful no-op)
# ---------------------------------------------------------------------------


class TestVerifyGuardRelevanceCpg:
    def test_returns_empty_without_joern(self):
        sg = _sg([_guard("len < sizeof(buf)", "bounds")])
        results = verify_guard_relevance_cpg(sg)
        assert results == []

    def test_with_mock_server_taint_flow(self):
        """Mock server returns taint path elements containing guard vars."""
        class MockServer:
            def query(self, q):
                # reachableByFlows query returns code elements on taint path
                if "reachableByFlows" in q:
                    return ["len", "buf", "memcpy(dst, src, len)"]
                # Dominance query
                if "dominates" in q:
                    return ["<node>"]
                return []

        sg = _sg([_guard("len < sizeof(buf)", "bounds")])
        results = verify_guard_relevance_cpg(sg, joern_server=MockServer())
        assert len(results) == 1
        assert results[0].data_dep_bound is True
        assert results[0].dominates_sink is True
        assert "len" in results[0].tainted_vars_in_guard

    def test_decorative_via_cpg(self):
        """Guard variable not on taint path → decorative."""
        class MockServer:
            def query(self, q):
                # Taint path contains dst, src, len — not debug_flag
                if "reachableByFlows" in q:
                    return ["dst", "src", "len"]
                if "dominates" in q:
                    return ["<node>"]
                return []

        sg = _sg([_guard("debug_flag", "config")])
        results = verify_guard_relevance_cpg(sg, joern_server=MockServer())
        assert len(results) == 1
        assert results[0].data_dep_bound is False

    def test_server_error_handled(self):
        """Broken server → graceful degradation, error recorded."""
        class BrokenServer:
            def query(self, q):
                raise RuntimeError("connection lost")

        sg = _sg([_guard("len < 100", "bounds")])
        results = verify_guard_relevance_cpg(sg, joern_server=BrokenServer())
        assert len(results) == 1
        # _run_query catches exceptions → returns None → outer code
        # records "query returned no results"; either way, data_dep_bound
        # stays None (not falsely True/False)
        assert results[0].data_dep_bound is None
        assert results[0].error != ""

    def test_joern_result_protocol(self):
        """Mock server returns JoernResult-like objects."""
        class FakeJoernResult:
            def __init__(self, raw, ok=True):
                self.raw_output = raw
                self.ok = ok

        class MockServer:
            def query(self, q):
                if "reachableByFlows" in q:
                    return FakeJoernResult('List(len, buf, size)')
                if "dominates" in q:
                    return FakeJoernResult('List(node1)')
                return FakeJoernResult('List()')

        sg = _sg([_guard("len < buf_size", "bounds")])
        results = verify_guard_relevance_cpg(sg, joern_server=MockServer())
        assert len(results) == 1
        assert results[0].data_dep_bound is True
        assert "len" in results[0].tainted_vars_in_guard

    def test_to_dict(self):
        result = CpgGuardResult(
            sink_file="test.c", sink_line=10, sink_api="memcpy",
            guard_text="len < 100",
            data_dep_bound=True, dominates_sink=True,
            tainted_vars_in_guard=["len"],
        )
        d = result.to_dict()
        assert d["data_dep_bound"] is True
        assert d["dominates_sink"] is True
        assert "len" in d["tainted_vars_in_guard"]


# ---------------------------------------------------------------------------
# Interprocedural guard check (without Joern — fallback to grep)
# ---------------------------------------------------------------------------


class TestCheckInterproceduralGuards:
    def test_no_server_no_source_map(self):
        result = check_interprocedural_guards("process_input", "src/handler.c")
        assert result.error  # should report no source map

    def test_fallback_with_source_map(self):
        source_map = {
            "src/handler.c": "void process_input(char *data) {\n    memcpy(buf, data, len);\n}",
            "src/main.c": "void handle_request() {\n    if (is_valid(req))\n        process_input(req->data);\n}",
        }
        result = check_interprocedural_guards(
            "process_input", "src/handler.c",
            source_map=source_map,
        )
        assert result.total_callers >= 1

    def test_all_callers_guarded(self):
        source_map = {
            "src/handler.c": "void do_copy(char *d, char *s, int n) {\n    memcpy(d, s, n);\n}",
            "src/caller1.c": "void f() {\n    if (n < 256)\n        do_copy(a, b, n);\n}",
            "src/caller2.c": "void g() {\n    if (len <= MAX)\n        do_copy(x, y, len);\n}",
        }
        result = check_interprocedural_guards(
            "do_copy", "src/handler.c",
            source_map=source_map,
        )
        assert result.total_callers == 2
        assert result.guarded_callers == 2
        assert result.all_callers_guarded

    def test_some_unguarded(self):
        source_map = {
            "src/handler.c": "void do_copy(char *d, char *s, int n) {\n    memcpy(d, s, n);\n}",
            "src/caller1.c": "void f() {\n    if (n < 256)\n        do_copy(a, b, n);\n}",
            "src/caller2.c": "void g() {\n    do_copy(x, y, len);\n}",
        }
        result = check_interprocedural_guards(
            "do_copy", "src/handler.c",
            source_map=source_map,
        )
        assert result.unguarded_callers >= 1
        assert not result.all_callers_guarded

    def test_to_dict(self):
        result = InterproceduralGuardResult(
            callee_function="process",
            callee_file="src/handler.c",
            total_callers=2,
            guarded_callers=1,
            unguarded_callers=1,
            caller_guards=[CallerGuard(
                caller_file="src/main.c",
                caller_function="handle",
                caller_line=10,
                guard_text="is_valid(req)",
                guard_category="type",
            )],
        )
        d = result.to_dict()
        assert d["total_callers"] == 2
        assert len(d["caller_guards"]) == 1


# ---------------------------------------------------------------------------
# Framework exposure context
# ---------------------------------------------------------------------------


class TestAssessExposureContext:
    def test_public_endpoint(self):
        sg = _sg([_guard("len < 100", "bounds")])
        eps = [{"file": "src/handler.c", "name": "handle_upload", "route": "/upload"}]
        ctx = assess_exposure_context(sg, eps)
        assert ctx is not None
        assert ctx.exposure_level == "public"
        assert ctx.priority_adjustment > 0

    def test_authenticated_endpoint(self):
        sg = _sg([_guard("len < 100", "bounds")])
        eps = [{
            "file": "src/handler.c",
            "name": "admin_panel",
            "auth_required": True,
            "auth_decorators": ["@login_required"],
        }]
        ctx = assess_exposure_context(sg, eps)
        assert ctx is not None
        assert ctx.exposure_level == "authenticated"
        assert ctx.requires_auth
        assert ctx.priority_adjustment < 0

    def test_admin_endpoint(self):
        sg = _sg([_guard("len < 100", "bounds")])
        eps = [{
            "file": "src/handler.c",
            "name": "admin_settings",
            "auth_required": True,
            "auth_decorators": ["@admin_required"],
        }]
        ctx = assess_exposure_context(sg, eps)
        assert ctx is not None
        assert ctx.exposure_level == "admin"
        assert ctx.priority_adjustment < -0.1

    def test_no_reaching_entry_point(self):
        sg = _sg([_guard("len < 100", "bounds")])
        eps = [{"file": "src/other.c", "name": "unrelated"}]
        ctx = assess_exposure_context(sg, eps)
        assert ctx is None

    def test_with_reachability_map(self):
        sg = _sg([_guard("len < 100", "bounds")])
        eps = [{"file": "src/api.py", "name": "upload_endpoint"}]
        reachability = {
            "src/handler.c:process_input": ["src/api.py:upload_endpoint"],
        }
        ctx = assess_exposure_context(sg, eps, reachability=reachability)
        assert ctx is not None
        assert ctx.exposure_level == "public"

    def test_worst_exposure_wins(self):
        sg = _sg([_guard("len < 100", "bounds")])
        eps = [
            {"file": "src/handler.c", "name": "public_route"},
            {"file": "src/handler.c", "name": "admin_route",
             "auth_required": True, "auth_decorators": ["@admin_required"]},
        ]
        ctx = assess_exposure_context(sg, eps)
        assert ctx is not None
        # Public is worst (most exposed)
        assert ctx.exposure_level == "public"

    def test_to_dict(self):
        ctx = ExposureContext(
            sink_file="test.c", sink_line=10, sink_api="memcpy",
            entry_point_route="/upload", exposure_level="public",
        )
        d = ctx.to_dict()
        assert d["exposure_level"] == "public"
        assert d["priority_adjustment"] == 0.2


# ---------------------------------------------------------------------------
# Joern query builder correctness
# ---------------------------------------------------------------------------


class TestQueryBuilders:
    def test_safe_name_valid(self):
        result = _safe_name("process_input")
        assert result is not None
        assert result == "process_input"

    def test_safe_name_qualified(self):
        result = _safe_name("pkg.MyClass.method")
        assert result is not None

    def test_safe_name_rejects_injection(self):
        result = _safe_name('foo"); sys.exit(1); //')
        assert result is None

    def test_safe_name_rejects_empty(self):
        assert _safe_name("") is None

    def test_callers_query_uses_caller_not_callIn(self):
        q = _build_callers_query("process_input")
        assert q is not None
        assert ".caller" in q
        assert ".callIn" not in q

    def test_callers_query_maps_filename_name_line(self):
        q = _build_callers_query("handle_request")
        assert q is not None
        assert "m.filename" in q
        assert "m.name" in q
        assert "lineNumber" in q

    def test_guard_identifiers_query(self):
        q = _build_guard_identifiers_query("my_func", 42)
        assert q is not None
        assert "isControlStructure" in q
        assert "lineNumber == Some(42)" in q
        assert ".condition.isIdentifier.name.l" in q
        # Should NOT have .condition.ast.isIdentifier (extra .ast is wrong)
        assert ".condition.ast" not in q

    def test_sink_arg_identifiers_query(self):
        q = _build_sink_arg_identifiers_query("my_func", 100)
        assert q is not None
        assert "isCall" in q
        assert "lineNumber == Some(100)" in q
        assert ".argument.isIdentifier.name.l" in q

    def test_taint_reaches_guard_query(self):
        q = _build_taint_reaches_guard_query("handler", "memcpy")
        assert q is not None
        assert "reachableByFlows" in q
        assert ".parameter" in q
        assert 'name("memcpy")' in q

    def test_taint_reaches_guard_query_has_engine_config(self):
        q = _build_taint_reaches_guard_query("handler", "memcpy")
        assert q is not None
        assert "EngineConfig" in q
        assert "maxCallDepth = 2" in q

    def test_dominance_query(self):
        q = _build_dominance_query("my_func", 10, 42)
        assert q is not None
        assert ".dominates" in q
        assert "lineNumber == Some(10)" in q
        assert "lineNumber == Some(42)" in q

    def test_caller_guards_query(self):
        q = _build_caller_guards_query("main", 25)
        assert q is not None
        assert "isCall" in q
        assert "lineNumber == Some(25)" in q
        assert "isControlStructure" in q
        assert "condition.code.l" in q

    def test_invalid_name_returns_none(self):
        assert _build_callers_query("") is None
        assert _build_guard_identifiers_query("", 10) is None
        assert _build_dominance_query("", 1, 2) is None


# ---------------------------------------------------------------------------
# Scala output parsing
# ---------------------------------------------------------------------------


class TestParseScalaList:
    def test_empty_list(self):
        assert _parse_scala_list("List()") == []

    def test_simple_list(self):
        result = _parse_scala_list('List(foo, bar, baz)')
        assert result == ["foo", "bar", "baz"]

    def test_quoted_strings(self):
        result = _parse_scala_list('List("hello", "world")')
        assert result == ["hello", "world"]

    def test_tuple_list(self):
        result = _parse_scala_list('List((file.c, main, 10), (util.c, helper, 20))')
        assert len(result) == 2
        assert result[0] == ["file.c", "main", "10"]
        assert result[1] == ["util.c", "helper", "20"]

    def test_newline_fallback(self):
        result = _parse_scala_list("foo\nbar\nbaz")
        assert result == ["foo", "bar", "baz"]

    def test_whitespace_stripped(self):
        result = _parse_scala_list("  List( x , y , z )  ")
        assert result == ["x", "y", "z"]


# ── Safety contract compliance ──────────────────────────────────────────


class TestContractCompliance:
    def test_assert_boost_only_succeeds(self):
        from core.audit.safety_contract import assert_boost_only
        assert_boost_only("condition_cpg")

    def test_suppress_evidence_raises(self):
        import pytest
        from core.audit.safety_contract import ContractViolation, SuppressEvidence
        with pytest.raises(ContractViolation):
            SuppressEvidence(
                source="condition_cpg",
                verdict="decorative_guard",
                reason="test",
            )

    def test_boost_evidence_allowed(self):
        from core.audit.safety_contract import BoostEvidence
        ev = BoostEvidence(
            source="condition_cpg",
            action="add_finding",
            description="guard not on data-dep path to sink",
        )
        assert ev.source == "condition_cpg"
        assert ev.action == "add_finding"
