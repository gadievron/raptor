"""Tests for core.audit.callsite_consistency — Engler-style call-site deviation."""

import textwrap

from core.audit.callsite_consistency import (
    CallSiteDeviation,
    detect_callsite_deviations,
    format_callsite_deviations_for_prompt,
)


class TestCallSiteDeviation:
    def test_to_dict(self):
        d = CallSiteDeviation(
            callee="validate",
            file="a.py",
            line=10,
            enclosing_function="process",
            total_sites=10,
            captured_count=9,
            discarded_count=1,
        )
        out = d.to_dict()
        assert out["callee"] == "validate"
        assert out["confidence"] == 0.9
        assert out["security_relevant"] is True

    def test_security_relevant(self):
        d = CallSiteDeviation(
            callee="frobnicate", file="a.py", line=1,
            enclosing_function="f", total_sites=4,
            captured_count=3, discarded_count=1,
        )
        assert d.security_relevant is False

        d2 = CallSiteDeviation(
            callee="parse_header", file="a.py", line=1,
            enclosing_function="f", total_sites=4,
            captured_count=3, discarded_count=1,
        )
        assert d2.security_relevant is True


class TestDetectDeviations:
    def test_discarded_minority_detected(self):
        """When most callers capture the return, the one that discards is flagged."""
        src = textwrap.dedent("""\
            def caller_a():
                result = validate(x)
                return result

            def caller_b():
                result = validate(y)
                return result

            def caller_c():
                result = validate(z)
                return result

            def caller_d():
                validate(w)
                return True
        """)
        devs = detect_callsite_deviations({"app.py": src}, min_sites=3)
        assert len(devs) == 1
        assert devs[0].callee == "validate"
        assert devs[0].enclosing_function == "caller_d"
        assert devs[0].captured_count == 3
        assert devs[0].discarded_count == 1

    def test_no_deviation_when_all_agree(self):
        src = textwrap.dedent("""\
            def a():
                result = check(x)
            def b():
                result = check(y)
            def c():
                result = check(z)
        """)
        devs = detect_callsite_deviations({"app.py": src}, min_sites=3)
        assert len(devs) == 0

    def test_no_deviation_when_all_discard(self):
        src = textwrap.dedent("""\
            def a():
                log(x)
            def b():
                log(y)
            def c():
                log(z)
        """)
        devs = detect_callsite_deviations({"app.py": src}, min_sites=3)
        assert len(devs) == 0

    def test_below_min_sites_not_reported(self):
        src = textwrap.dedent("""\
            def a():
                result = check(x)
            def b():
                check(y)
        """)
        devs = detect_callsite_deviations({"app.py": src}, min_sites=3)
        assert len(devs) == 0

    def test_cross_file_grouping(self):
        """Call sites across files are grouped by callee name."""
        src_a = textwrap.dedent("""\
            def handler_a():
                result = validate(x)
                return result
        """)
        src_b = textwrap.dedent("""\
            def handler_b():
                result = validate(y)
                return result
        """)
        src_c = textwrap.dedent("""\
            def handler_c():
                validate(z)
                return True
        """)
        src_d = textwrap.dedent("""\
            def handler_d():
                result = validate(w)
                return result
        """)
        devs = detect_callsite_deviations({
            "a.py": src_a, "b.py": src_b, "c.py": src_c, "d.py": src_d,
        }, min_sites=3)
        assert len(devs) == 1
        assert devs[0].file == "c.py"

    def test_method_calls_grouped_by_method_name(self):
        """obj.validate() and other.validate() group under 'validate'."""
        src = textwrap.dedent("""\
            def a():
                result = obj.validate(x)
                use(result)
            def b():
                result = other.validate(y)
                use(result)
            def c():
                result = third.validate(z)
                use(result)
            def d():
                something.validate(w)
        """)
        devs = detect_callsite_deviations({"app.py": src}, min_sites=3)
        assert len(devs) == 1
        assert devs[0].callee == "validate"

    def test_keywords_not_treated_as_calls(self):
        src = textwrap.dedent("""\
            def a():
                if check(x):
                    pass
            def b():
                if check(y):
                    pass
            def c():
                if check(z):
                    pass
        """)
        devs = detect_callsite_deviations({"app.py": src}, min_sites=3)
        assert len(devs) == 0

    def test_security_relevant_sorted_first(self):
        """Security-relevant callees sort before non-security ones."""
        src = textwrap.dedent("""\
            def a():
                result = frobnicate(x)
                use(result)
            def b():
                result = frobnicate(y)
                use(result)
            def c():
                result = frobnicate(z)
                use(result)
            def d():
                frobnicate(w)

            def e():
                result = validate(1)
                use(result)
            def f():
                result = validate(2)
                use(result)
            def g():
                result = validate(3)
                use(result)
            def h():
                validate(4)
        """)
        devs = detect_callsite_deviations({"app.py": src}, min_sites=3)
        assert len(devs) == 2
        assert devs[0].callee == "validate"
        assert devs[1].callee == "frobnicate"


class TestGoCallSites:
    def test_go_discarded_detected(self):
        src = textwrap.dedent("""\
            package main

            func handlerA() {
                result := validate(x)
                use(result)
            }

            func handlerB() {
                result := validate(y)
                use(result)
            }

            func handlerC() {
                result := validate(z)
                use(result)
            }

            func handlerD() {
                validate(w)
            }
        """)
        devs = detect_callsite_deviations({"srv.go": src}, min_sites=3)
        assert len(devs) == 1
        assert devs[0].enclosing_function == "handlerD"

    def test_go_blank_assignment_is_discard(self):
        """`_ = f()` explicitly discards the return — it must count as
        a deviant site among capturing siblings, not as captured."""
        src = textwrap.dedent("""\
            package main

            func handlerA() {
                err := validate(x)
                use(err)
            }

            func handlerB() {
                err := validate(y)
                use(err)
            }

            func handlerC() {
                err := validate(z)
                use(err)
            }

            func handlerD() {
                _ = validate(w)
            }
        """)
        devs = detect_callsite_deviations({"srv.go": src}, min_sites=3)
        assert len(devs) == 1
        assert devs[0].callee == "validate"
        assert devs[0].enclosing_function == "handlerD"
        assert devs[0].discarded_count == 1

    def test_go_all_blank_multi_assignment_is_discard(self):
        """`_, _ = g()` discards every return value."""
        src = textwrap.dedent("""\
            package main

            func handlerA() {
                n, err := parseInput(x)
                use(n, err)
            }

            func handlerB() {
                n, err := parseInput(y)
                use(n, err)
            }

            func handlerC() {
                n, err := parseInput(z)
                use(n, err)
            }

            func handlerD() {
                _, _ = parseInput(w)
            }
        """)
        devs = detect_callsite_deviations({"srv.go": src}, min_sites=3)
        assert len(devs) == 1
        assert devs[0].enclosing_function == "handlerD"

    def test_go_partial_blank_assignment_stays_captured(self):
        """`v, _ := f()` captures at least one value — not a discard."""
        src = textwrap.dedent("""\
            package main

            func handlerA() {
                n, err := parseInput(x)
                use(n, err)
            }

            func handlerB() {
                n, err := parseInput(y)
                use(n, err)
            }

            func handlerC() {
                n, err := parseInput(z)
                use(n, err)
            }

            func handlerD() {
                n, _ := parseInput(w)
                use(n)
            }
        """)
        devs = detect_callsite_deviations({"srv.go": src}, min_sites=3)
        assert devs == []

    def test_go_blank_assignment_regex_fallback(self):
        """The regex fallback must classify `_ = f()` as a discard too."""
        from core.audit.callsite_consistency import _extract_callsites_regex

        src = textwrap.dedent("""\
            package main

            func handlerA() {
                err := validate(x)
            }

            func handlerD() {
                _ = validate(w)
            }
        """)
        sites = _extract_callsites_regex("srv.go", src)
        by_func = {s.enclosing_function: s for s in sites if s.callee == "validate"}
        assert by_func["handlerA"].discarded is False
        assert by_func["handlerD"].discarded is True

    def test_python_underscore_assignment_not_discard(self):
        """Python `_ = f()` is an acknowledged discard idiom — it must
        NOT create a deviation against capturing siblings (the author
        demonstrably saw the return value)."""
        src = textwrap.dedent("""\
            def a():
                r = validate(1)
                return r

            def b():
                r = validate(2)
                return r

            def c():
                r = validate(3)
                return r

            def d():
                _ = validate(4)
        """)
        devs = detect_callsite_deviations({"app.py": src}, min_sites=3)
        assert devs == []


class TestJsCallSites:
    def test_js_const_captured_bare_discarded(self):
        src = textwrap.dedent("""\
            function a() {
                const result = validate(x);
                return result;
            }

            function b() {
                const result = validate(y);
                return result;
            }

            function c() {
                let result = validate(z);
                return result;
            }

            function d() {
                validate(w);
            }
        """)
        devs = detect_callsite_deviations({"app.js": src}, min_sites=3)
        assert len(devs) == 1
        assert devs[0].enclosing_function == "d"


class TestCCallSites:
    def test_c_discarded_detected(self):
        src = textwrap.dedent("""\
            void handler_a() {
                int ret = check_auth(ctx);
                if (ret < 0) return;
            }

            void handler_b() {
                int ret = check_auth(ctx);
                if (ret < 0) return;
            }

            void handler_c() {
                int ret = check_auth(ctx);
                if (ret < 0) return;
            }

            void handler_d() {
                check_auth(ctx);
            }
        """)
        devs = detect_callsite_deviations({"auth.c": src}, min_sites=3)
        assert len(devs) == 1
        assert devs[0].callee == "check_auth"
        assert devs[0].security_relevant is True


class TestIRISExtraSecurityNames:
    """IRIS spec consumption via extra_security_names."""

    def test_extra_names_boost_security_relevant(self):
        """A callee not matching regex becomes security_relevant via IRIS."""
        src = textwrap.dedent("""\
            def a():
                result = frobnicate(x)
                use(result)
            def b():
                result = frobnicate(y)
                use(result)
            def c():
                result = frobnicate(z)
                use(result)
            def d():
                frobnicate(w)
        """)
        devs = detect_callsite_deviations({"app.py": src}, min_sites=3)
        assert len(devs) == 1
        assert devs[0].security_relevant is False

        devs2 = detect_callsite_deviations(
            {"app.py": src}, min_sites=3,
            extra_security_names=frozenset({"frobnicate"}),
        )
        assert len(devs2) == 1
        assert devs2[0].security_relevant is True


class TestRegexFallback:
    """Tests for _extract_callsites_regex — the non-tree-sitter path."""

    def test_multiple_calls_on_one_line(self):
        """Each call on a line should produce its own CallSite."""
        from core.audit.callsite_consistency import _extract_callsites_regex

        src = textwrap.dedent("""\
            def handler():
                foo(bar(x))
        """)
        sites = _extract_callsites_regex("app.py", src)
        callees = [s.callee for s in sites]
        assert "foo" in callees
        assert "bar" in callees

    def test_line_without_call_does_not_duplicate(self):
        """A non-call line must not re-append the previous line's callee."""
        from core.audit.callsite_consistency import _extract_callsites_regex

        src = textwrap.dedent("""\
            def handler():
                foo(x)
                y = 42
                bar(z)
        """)
        sites = _extract_callsites_regex("app.py", src)
        callees = [s.callee for s in sites]
        assert callees.count("foo") == 1, f"foo duplicated: {callees}"
        assert callees.count("bar") == 1, f"bar duplicated: {callees}"


class TestFormatForPrompt:
    def test_empty(self):
        assert format_callsite_deviations_for_prompt([]) == ""

    def test_formatting(self):
        devs = [CallSiteDeviation(
            callee="validate",
            file="a.py",
            line=42,
            enclosing_function="process",
            total_sites=10,
            captured_count=9,
            discarded_count=1,
        )]
        text = format_callsite_deviations_for_prompt(devs)
        assert "validate()" in text
        assert "a.py:42" in text
        assert "9/10" in text
        assert "CHECK" in text

    def test_captured_minority_no_check_directive(self):
        devs = [CallSiteDeviation(
            callee="log_event",
            file="a.py",
            line=10,
            enclosing_function="f",
            total_sites=10,
            captured_count=1,
            discarded_count=9,
        )]
        text = format_callsite_deviations_for_prompt(devs)
        assert "captured" in text
        assert "CHECK" not in text
