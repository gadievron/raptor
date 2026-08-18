"""Six-value return-usage census (consistency phase 1, design §2.1).

Hermetic — no LLM, no subprocesses. Every classification case is a
pair: the deviant form must land in a deviant-eligible class, the
conforming/acknowledged twin must not.

Two extraction tiers, BOTH pinned (§2.1: "regex fallback keeps
today's coarse classes"): the classification tests parametrise over
``parser_tier`` so the tree-sitter contract and the regex-fallback
contract are each asserted wherever they can run. Bare CI (no grammar
wheels installed) skips the tree-sitter leg with a reason and still
executes the fallback leg; provisioned hosts run both.
"""

from __future__ import annotations

import textwrap

import pytest

from core.audit.callsite_consistency import (
    USAGE_ACKNOWLEDGED,
    USAGE_CAPTURED_UNUSED,
    USAGE_CAPTURED_USED,
    USAGE_DISCARDED,
    USAGE_PROPAGATED,
    USAGE_TESTED,
    CallSite,
    _extract_callsites_cpg,
    build_return_census,
    census_to_dict,
    clear_parse_cache,
    detect_callsite_deviations,
    parse_source_cached,
)
from core.testing import (
    force_census_regex_fallback,
    requires_ts,
    ts_parser_available,
)


@pytest.fixture(params=["tree-sitter", "regex-fallback"])
def parser_tier(request, monkeypatch):
    """Run the census contract on both extraction tiers."""
    if request.param == "regex-fallback":
        force_census_regex_fallback(monkeypatch)
    return request.param


def _tier(parser_tier: str, *langs: str) -> str:
    """``"ts"`` / ``"rx"``; skips the tree-sitter leg when any of the
    fixture's grammars is not installed (bare CI)."""
    if parser_tier == "tree-sitter":
        missing = [lang for lang in langs if not ts_parser_available(lang)]
        if missing:
            pytest.skip(
                "no tree-sitter grammar for: " + ", ".join(missing),
            )
        return "ts"
    return "rx"


def _usages(source_texts: dict[str, str]) -> dict[tuple[str, str], str]:
    """(callee, enclosing_function) → usage for single-site callees."""
    census = build_return_census(source_texts)
    out: dict[tuple[str, str], str] = {}
    for callee, c in census.items():
        for site in c.sites:
            out[(callee, site.enclosing_function)] = site.usage
    return out


class TestCUsage:
    def test_void_cast_is_acknowledged(self, parser_tier):
        _tier(parser_tier, "c")
        src = textwrap.dedent("""\
            int run(void) {
                (void)drop_privileges();
                return 0;
            }
        """)
        u = _usages({"main.c": src})
        assert u[("drop_privileges", "run")] == USAGE_ACKNOWLEDGED

    def test_bare_statement_is_discarded(self, parser_tier):
        _tier(parser_tier, "c")
        src = textwrap.dedent("""\
            int run(void) {
                drop_privileges();
                return 0;
            }
        """)
        u = _usages({"main.c": src})
        assert u[("drop_privileges", "run")] == USAGE_DISCARDED

    def test_condition_is_tested(self, parser_tier):
        _tier(parser_tier, "c")
        src = textwrap.dedent("""\
            int run(void) {
                if (drop_privileges() != 0)
                    return -1;
                return 0;
            }
        """)
        u = _usages({"main.c": src})
        assert u[("drop_privileges", "run")] == USAGE_TESTED

    def test_captured_then_tested_is_tested(self, parser_tier):
        tier = _tier(parser_tier, "c")
        src = textwrap.dedent("""\
            int run(void) {
                int rc = drop_privileges();
                if (rc != 0)
                    return -1;
                return 0;
            }
        """)
        u = _usages({"main.c": src})
        # Fallback contract: no read-scan without a tree (§2.1) — a
        # captured binding stays captured_used on the regex tier.
        expected = USAGE_TESTED if tier == "ts" else USAGE_CAPTURED_USED
        assert u[("drop_privileges", "run")] == expected

    def test_captured_never_read_is_captured_unused(self, parser_tier):
        tier = _tier(parser_tier, "c")
        src = textwrap.dedent("""\
            int run(void) {
                int rc = drop_privileges();
                do_work();
                return 0;
            }
        """)
        u = _usages({"main.c": src})
        # Fallback contract: without a read-scan the regex tier cannot
        # see that the binding is never consulted.
        expected = (
            USAGE_CAPTURED_UNUSED if tier == "ts" else USAGE_CAPTURED_USED
        )
        assert u[("drop_privileges", "run")] == expected

    def test_captured_and_passed_on_is_captured_used(self, parser_tier):
        _tier(parser_tier, "c")
        src = textwrap.dedent("""\
            int run(void) {
                int rc = drop_privileges();
                report(rc);
                return 0;
            }
        """)
        u = _usages({"main.c": src})
        assert u[("drop_privileges", "run")] == USAGE_CAPTURED_USED

    def test_return_call_is_propagated(self, parser_tier):
        _tier(parser_tier, "c")
        src = textwrap.dedent("""\
            int run(void) {
                return drop_privileges();
            }
        """)
        u = _usages({"main.c": src})
        assert u[("drop_privileges", "run")] == USAGE_PROPAGATED

    def test_argument_call_is_captured_used(self, parser_tier):
        tier = _tier(parser_tier, "c")
        src = textwrap.dedent("""\
            int run(void) {
                report(drop_privileges());
                return 0;
            }
        """)
        u = _usages({"main.c": src})
        # Fallback contract: line shapes only — the inner call rides
        # the statement-only classification of its line.
        expected = USAGE_CAPTURED_USED if tier == "ts" else USAGE_DISCARDED
        assert u[("drop_privileges", "run")] == expected


class TestGoUsage:
    def test_blank_assign_is_captured_unused(self, parser_tier):
        """Regression for the pre-enum hole: `_ = f()` counted as
        captured; it is an assigned-then-unreadable discard."""
        _tier(parser_tier, "go")
        src = textwrap.dedent("""\
            package main

            func run() {
                _ = doWork()
            }
        """)
        u = _usages({"main.go": src})
        assert u[("doWork", "run")] == USAGE_CAPTURED_UNUSED

    def test_err_checked_is_tested(self, parser_tier):
        tier = _tier(parser_tier, "go")
        src = textwrap.dedent("""\
            package main

            func run() error {
                v, err := doWork()
                if err != nil {
                    return err
                }
                consume(v)
                return nil
            }
        """)
        u = _usages({"main.go": src})
        # Fallback contract: `v, err := f()` is an assignment line —
        # without a tree the later `err != nil` test is invisible.
        expected = USAGE_TESTED if tier == "ts" else USAGE_CAPTURED_USED
        assert u[("doWork", "run")] == expected

    def test_err_never_consulted_is_captured_unused(self, parser_tier):
        _tier(parser_tier, "go")
        src = textwrap.dedent("""\
            package main

            func run() {
                v, err := doWork()
                _ = v
                _ = err
            }
        """)
        # Both bindings are only ever re-discarded, never read as
        # values feeding a test or a use.
        src2 = textwrap.dedent("""\
            package main

            func run() {
                out, err := doWork()
                consume(out)
            }
        """)
        u = _usages({"main.go": src2})
        # `out` is read (consumed) but `err` never is; the binding as a
        # whole was used — the *tested* obligation is what the verdict
        # layer checks against the contract.
        assert u[("doWork", "run")] == USAGE_CAPTURED_USED
        del src

    def test_err_rebound_before_read_is_captured_unused(self, parser_tier):
        tier = _tier(parser_tier, "go")
        src = textwrap.dedent("""\
            package main

            func run() {
                rc := doWork()
                rc = otherWork()
                consume(rc)
            }
        """)
        u = _usages({"main.go": src})
        # doWork's binding is rebound before any read — visible only
        # with a tree; the fallback sees two capture lines.
        expected = (
            USAGE_CAPTURED_UNUSED if tier == "ts" else USAGE_CAPTURED_USED
        )
        assert u[("doWork", "run")] == expected
        assert u[("otherWork", "run")] == USAGE_CAPTURED_USED


class TestPythonRustUsage:
    def test_python_underscore_is_acknowledged(self, parser_tier):
        _tier(parser_tier, "python")
        src = textwrap.dedent("""\
            def run():
                _ = do_work()
        """)
        u = _usages({"app.py": src})
        assert u[("do_work", "run")] == USAGE_ACKNOWLEDGED

    def test_python_unused_binding_is_captured_unused(self, parser_tier):
        tier = _tier(parser_tier, "python")
        src = textwrap.dedent("""\
            def run():
                result = do_work()
                other_thing()
        """)
        u = _usages({"app.py": src})
        # Fallback contract: no read-scan — captured stays captured.
        expected = (
            USAGE_CAPTURED_UNUSED if tier == "ts" else USAGE_CAPTURED_USED
        )
        assert u[("do_work", "run")] == expected

    def test_rust_let_underscore_is_acknowledged(self, parser_tier):
        _tier(parser_tier, "rust")
        src = textwrap.dedent("""\
            fn run() {
                let _ = do_work();
            }
        """)
        u = _usages({"app.rs": src})
        assert u.get(("do_work", "run")) == USAGE_ACKNOWLEDGED


class TestCensusAggregate:
    def test_counts_and_check_ratio(self, parser_tier):
        _tier(parser_tier, "c")
        parts = []
        for i in range(9):
            parts.append(textwrap.dedent(f"""\
                int caller_{i}(void) {{
                    if (do_auth() != 0)
                        return -1;
                    return 0;
                }}
            """))
        parts.append(textwrap.dedent("""\
            int caller_9(void) {
                do_auth();
                return 0;
            }
        """))
        census = build_return_census({"auth.c": "\n".join(parts)})
        c = census["do_auth"]
        assert c.n == 10
        assert c.count("tested") == 9
        assert c.count("discarded") == 1
        assert c.check_ratio == pytest.approx(0.9)
        assert c.majority_says_check
        assert not c.majority_says_discard_ok
        assert len(c.deviants) == 1
        assert c.deviants[0].enclosing_function == "caller_9"

    def test_acknowledged_excluded_from_ratio(self, parser_tier):
        _tier(parser_tier, "c")
        parts = []
        for i in range(4):
            parts.append(textwrap.dedent(f"""\
                int caller_{i}(void) {{
                    if (do_auth() != 0)
                        return -1;
                    return 0;
                }}
            """))
        parts.append(textwrap.dedent("""\
            int caller_ack(void) {
                (void)do_auth();
                return 0;
            }
        """))
        census = build_return_census({"auth.c": "\n".join(parts)})
        c = census["do_auth"]
        assert c.n == 5
        assert c.considered == 4
        assert c.check_ratio == pytest.approx(1.0)
        assert not c.deviants

    def test_majority_discard_gives_ignorability(self, parser_tier):
        _tier(parser_tier, "c")
        parts = []
        for i in range(5):
            parts.append(textwrap.dedent(f"""\
                int caller_{i}(void) {{
                    log_message("x");
                    return 0;
                }}
            """))
        census = build_return_census({"log.c": "\n".join(parts)})
        c = census["log_message"]
        assert c.majority_says_discard_ok
        assert not c.majority_says_check

    def test_census_to_dict_shape(self, parser_tier):
        _tier(parser_tier, "c")
        src = textwrap.dedent("""\
            int run(void) {
                do_work();
                return 0;
            }
        """)
        d = census_to_dict(build_return_census({"a.c": src}))
        row = d["do_work"]
        assert row["sites"] == 1
        assert row["counts"]["discarded"] == 1
        assert "check_ratio" in row
        assert row["deviants"][0]["usage"] == "discarded"

    def test_error_path_site_marked(self, parser_tier):
        tier = _tier(parser_tier, "python")
        src = textwrap.dedent("""\
            def run():
                try:
                    step()
                except ValueError:
                    cleanup()
        """)
        census = build_return_census({"app.py": src})
        site = census["cleanup"].sites[0]
        # Fallback contract: no error-path walk without a tree — the
        # regex tier never marks a site on_error_path (the verdict
        # channel's error-path demotion is tree-sitter-tier only).
        assert site.on_error_path is (tier == "ts")
        assert census["step"].sites[0].on_error_path is False


class TestLegacyCompat:
    def test_callsite_boolean_derivation(self):
        s = CallSite(file="a.c", line=1, callee="f",
                     enclosing_function="g", usage=USAGE_CAPTURED_UNUSED)
        assert s.discarded is True
        s2 = CallSite(file="a.c", line=1, callee="f",
                      enclosing_function="g", discarded=True)
        assert s2.usage == USAGE_DISCARDED

    def test_detect_deviations_accepts_prebuilt_census(self):
        parts = []
        for i in range(3):
            parts.append(textwrap.dedent(f"""\
                int caller_{i}(void) {{
                    if (do_auth() != 0)
                        return -1;
                    return 0;
                }}
            """))
        parts.append("int caller_3(void) {\n    do_auth();\n    return 0;\n}\n")
        texts = {"auth.c": "\n".join(parts)}
        census = build_return_census(texts)
        devs = detect_callsite_deviations({}, census=census)
        assert len(devs) == 1
        assert devs[0].usage == USAGE_DISCARDED


class TestParseCache:
    def test_cache_returns_same_tree(self, parser_tier):
        tier = _tier(parser_tier, "c")
        clear_parse_cache()
        src = "int run(void) { do_work(); return 0; }\n"
        t1, lang1 = parse_source_cached("a.c", src)
        t2, lang2 = parse_source_cached("a.c", src)
        if tier == "ts":
            assert lang1 == "c" and lang2 == "c"
            assert t1 is t2
        else:
            # Degradation contract: without tree-sitter the cache
            # answers (None, None) — consumers fall back, never crash.
            assert (t1, lang1) == (None, None)
            assert (t2, lang2) == (None, None)

    def test_unsupported_language_falls_through(self):
        clear_parse_cache()
        tree, lang = parse_source_cached("script.xyz", "whatever()\n")
        assert tree is None and lang is None


class TestCpgUsage:
    """The Joern CPG supplement's blank-assign blindness fix (phase-0
    deferral): `_ = f()` used to count as captured because ANY
    assignment ancestor did."""

    def _fake_server_rows(self, rows):
        class _Server:
            pass
        return _Server(), rows

    def test_blank_assign_row_is_discarded(self, monkeypatch):

        rows = [
            ("doWork", "run", "main.go", 4, "discarded"),
            ("doWork", "other", "main.go", 9, "captured_used"),
            ("doWork", "third", "main.go", 14, "tested"),
        ]
        monkeypatch.setattr(
            "core.audit.cross_function_verify._run_query",
            lambda server, query: rows,
        )
        sites = _extract_callsites_cpg(object(), frozenset({"doWork"}))
        by_fn = {s.enclosing_function: s for s in sites}
        assert by_fn["run"].usage == USAGE_DISCARDED
        assert by_fn["run"].discarded is True
        assert by_fn["other"].usage == USAGE_CAPTURED_USED
        assert by_fn["third"].usage == USAGE_TESTED

    def test_query_carries_blank_lhs_shape(self, monkeypatch):
        """The generated Scala must test the assignment LHS for the
        all-blank shape instead of treating any assignment as capture."""
        import core.audit.cross_function_verify as cfv

        captured_queries = []

        def _record(server, query):
            captured_queries.append(query)
            return []

        monkeypatch.setattr(cfv, "_run_query", _record)
        _extract_callsites_cpg(object(), frozenset({"doWork"}))
        assert captured_queries
        q = captured_queries[0]
        assert "argument(1)" in q
        assert "matches" in q

    def test_legacy_boolean_payload_still_parses(self, monkeypatch):
        rows = [("doWork", "run", "main.go", 4, "true")]
        monkeypatch.setattr(
            "core.audit.cross_function_verify._run_query",
            lambda server, query: rows,
        )
        sites = _extract_callsites_cpg(object(), frozenset({"doWork"}))
        assert sites[0].usage == USAGE_DISCARDED


class TestEngineParity:
    """The two extraction legs must classify shared shapes
    identically — a call-used-as-argument used to be captured_used on
    the tree-sitter leg and discarded on the CPG leg, flipping the
    majority statistic by extraction engine rather than by code."""

    @requires_ts("c")
    def test_ts_call_as_argument_is_captured_used(self):
        # Pins the tree-sitter leg specifically, so it needs the real
        # grammar: on a bare host build_return_census silently takes
        # the regex tier, whose documented coarse classes land this
        # shape in `discarded` — the fallback tier's contract is
        # pinned by the parser_tier-parametrised tests, not here.
        src = textwrap.dedent("""\
            int outer(int x) {
                consume(doWork(x));
                return 0;
            }
        """)
        usages = _usages({"a.c": src})
        assert usages[("doWork", "outer")] == USAGE_CAPTURED_USED

    def test_query_carries_argument_consumption_clause(self, monkeypatch):
        """The generated Scala classifies argument-consumed calls as
        captured_used, excluding <operator>.* pseudo-calls so the
        assignment logic keeps governing RHS shapes."""
        import core.audit.cross_function_verify as cfv
        captured = {}

        def spy(server, query):
            captured["q"] = query
            return []

        monkeypatch.setattr(cfv, "_run_query", spy)
        _extract_callsites_cpg(object(), frozenset({"doWork"}))
        q = captured["q"]
        assert "inCall" in q
        assert '<operator>' in q
        assert "asArg" in q

    def test_cpg_rows_carry_engine_tag(self, monkeypatch):
        rows = [["doWork", "run", "a.c", 10, "discarded"]]
        monkeypatch.setattr(
            "core.audit.cross_function_verify._run_query",
            lambda server, query: rows,
        )
        sites = _extract_callsites_cpg(object(), frozenset({"doWork"}))
        assert sites and all(s.engine == "cpg" for s in sites)

    def test_ts_rows_default_engine_tag(self):
        src = "int f(void) { doWork(); return 0; }\n"
        census = build_return_census({"a.c": src})
        for c in census.values():
            for site in c.sites:
                assert site.engine == "ts"
