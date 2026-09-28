"""Tests for core.audit.callsite_consistency — Engler-style call-site deviation."""

import textwrap

import pytest


def _ts_python_available() -> bool:
    """True when the census's tree-sitter path can parse Python.

    Probes _parse_file itself rather than importing grammar modules:
    the census degrades to the regex extractor whenever the parse
    returns nothing — absent module, broken wheel, or load failure —
    and tests asserting tree-sitter-path semantics must skip in
    exactly those same conditions.
    """
    from core.audit.callsite_consistency import _parse_file
    tree, lang = _parse_file("x = f(1)\n", "probe.py")
    return tree is not None and lang is not None


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


class TestSwiftCallSites:
    """Swift wildcard assignment is the acknowledged-discard idiom.

    The census routes .swift through the regex tier (no swift entry in
    ts_extract._CALL_TYPES), so the idiom arm lives in the regex
    table. `acknowledged` — not `captured_used` — is load-bearing:
    it is what makes a security-role callee's census refutation hand
    off to the fail_open channel's try?-erasure leg.
    """

    SRC = (
        "func caller1() -> Bool {\n"
        "    let ok = validateToken(t1)\n"
        "    return ok\n"
        "}\n"
        "\n"
        "func caller2() -> Bool {\n"
        "    let ok = validateToken(t2)\n"
        "    return ok\n"
        "}\n"
        "\n"
        "func caller3() -> Bool {\n"
        "    let ok = validateToken(t3)\n"
        "    return ok\n"
        "}\n"
        "\n"
        "func handlerD() {\n"
        "    _ = validateToken(w)\n"
        "}\n"
        "\n"
        "func handlerE() {\n"
        "    _ = try? validateToken(v)\n"
        "}\n"
    )

    def test_swift_underscore_assignment_is_acknowledged(self):
        """Both spellings (`_ =`, `_ = try?`) classify acknowledged —
        never captured_used (which would silently inflate the capture
        majority) and never discarded (which would mint a deviation
        against an author who demonstrably saw the return value)."""
        from core.audit.callsite_consistency import build_return_census

        census = build_return_census({"App.swift": self.SRC})
        entry = census["validateToken"]
        ack_lines = sorted(s.line for s in entry.acknowledged_sites)
        assert ack_lines == [17, 21]
        assert entry.deviants == []

    def test_swift_underscore_assignment_regex_fallback(self):
        from core.audit.callsite_consistency import (
            USAGE_ACKNOWLEDGED,
            _extract_callsites_regex,
        )

        sites = _extract_callsites_regex("App.swift", self.SRC)
        by_func = {
            s.enclosing_function: s
            for s in sites if s.callee == "validateToken"
        }
        assert by_func["caller1"].usage != USAGE_ACKNOWLEDGED
        assert by_func["handlerD"].usage == USAGE_ACKNOWLEDGED
        assert by_func["handlerE"].usage == USAGE_ACKNOWLEDGED

    def test_swift_acknowledged_security_role_hands_to_fail_open(self):
        """The point of the idiom arm: an acknowledged discard of a
        security-role callee refutes the consistency claim AND raises
        the fail_open handoff — the premise splits to the erasure
        leg instead of dying as a false discard deviation."""
        from core.audit.callsite_consistency import build_return_census
        from core.audit.consistency_verify import (
            REFUTED_ACKNOWLEDGED,
            census_verdict,
        )
        from core.audit.fail_open_roles import RoleContext

        texts = {"App.swift": self.SRC}
        census = build_return_census(texts)
        entry = census["validateToken"]
        assert entry.acknowledged_sites
        res = census_verdict(
            entry, entry.acknowledged_sites[0],
            context=RoleContext(), source_texts=texts,
        )
        assert res.outcome == "refuted"
        assert res.reason.startswith(REFUTED_ACKNOWLEDGED)
        assert res.fail_open_handoff is True


def test_underscore_assign_acknowledged_only_for_swift():
    """The ``_ =`` acknowledged-discard arm is gated on ``.swift`` on
    purpose: in JavaScript/TypeScript ``_`` is a REAL variable (the
    lodash convention), so ``_ = validateToken(w)`` is a live capture
    that gets used — classifying it ``acknowledged`` would exclude
    the site from deviant comparison and steer a security-role
    census toward refuted_acknowledged on evidence that does not
    exist. Only the exact-language gate keeps that contract.
    """
    from core.audit.callsite_consistency import (
        USAGE_ACKNOWLEDGED,
        USAGE_CAPTURED_USED,
        _extract_callsites_regex,
    )

    js = (
        "function caller1() {\n"
        "    const ok = validateToken(t1);\n"
        "    return ok;\n"
        "}\n"
        "function handler() {\n"
        "    _ = validateToken(w);\n"
        "    audit(_);\n"
        "}\n"
    )
    sites = [s for s in _extract_callsites_regex("app.js", js)
             if s.callee == "validateToken"]
    by_line = {s.line: s for s in sites}
    assert by_line[6].usage != USAGE_ACKNOWLEDGED, (
        "lodash-style `_` capture in a .js file treated as a Swift "
        "wildcard discard"
    )
    assert by_line[6].usage == USAGE_CAPTURED_USED


def test_swift_underscore_comparison_is_not_a_discard():
    """``_ == expr`` is comparison-shaped, not a wildcard assignment;
    the ``[^=]`` guard in ``_SWIFT_UNDERSCORE_ASSIGN_RE`` is what
    separates them (mirroring the python arm's guard). Hostile or
    macro-mangled Swift containing a line-initial ``_ ==`` must not
    mint an acknowledged-discard receipt.
    """
    from core.audit.callsite_consistency import (
        USAGE_ACKNOWLEDGED,
        _extract_callsites_regex,
    )

    sw = (
        "func hostile() {\n"
        "    _ == validateToken(x)\n"
        "}\n"
    )
    sites = [s for s in _extract_callsites_regex("App.swift", sw)
             if s.callee == "validateToken"]
    assert sites and all(
        s.usage != USAGE_ACKNOWLEDGED for s in sites
    ), "comparison-shaped `_ ==` line minted an acknowledged discard"


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


class TestCensusSelfLimits:
    """Regression: build_return_census walked ALL descendants of the
    enclosing scope per captured site (whole file tree for module
    scope) with no cap and no deadline — pre-budget hang. The build
    self-limits and stamps every entry ``truncated``."""

    def test_site_cap_truncates_and_stamps(self):
        from core.audit.callsite_consistency import build_return_census
        src = "\n".join(f"z{i} = hh(a)" for i in range(300))
        census = build_return_census(
            {"b.py": src}, max_sites_per_file=100,
        )
        entry = census["hh"]
        assert entry.n == 100
        assert entry.truncated is True
        assert entry.to_dict()["truncated"] is True

    def test_deadline_truncates_and_stamps(self):
        from core.audit.callsite_consistency import build_return_census
        src = "\n".join(f"z{i} = hh(a)" for i in range(2000))
        census = build_return_census({"b.py": src}, budget_s=0.0)
        for entry in census.values():
            assert entry.truncated is True

    def test_site_cap_holds_on_regex_fallback(self, monkeypatch):
        """The self-limits must hold on hosts where tree-sitter (or a
        grammar) is unavailable and the regex fallback is the only
        extractor — the fallback used to receive no limiter at all,
        so the cap was silently ignored exactly where an unbounded
        walk could bite."""
        import core.audit.callsite_consistency as cc
        monkeypatch.setattr(
            cc, "_extract_callsites_ts", lambda *a, **k: None,
        )
        src = "\n".join(f"z{i} = hh(a)" for i in range(300))
        census = cc.build_return_census(
            {"b.py": src}, max_sites_per_file=100,
        )
        entry = census["hh"]
        assert entry.n == 100
        assert entry.truncated is True
        assert entry.sites[0].engine == "regex"

    def test_complete_census_is_not_stamped(self):
        from core.audit.callsite_consistency import build_return_census
        src = "\n".join(f"y{i} = gg(a)" for i in range(20))
        census = build_return_census({"ok.py": src})
        assert census["gg"].truncated is False
        assert "truncated" not in census["gg"].to_dict()

    def test_large_file_complete_above_old_cap(self):
        """Cap trade-off, admit direction: a file with well over 2000
        sites (the old per-file cap) but under the current cap gets a
        COMPLETE census — no truncation stamp — with correct per-site
        classifications throughout (the index-backed read scan, not a
        per-site scope walk, makes this affordable)."""
        if not _ts_python_available():
            pytest.skip("tree-sitter python grammar unavailable")
        from core.audit.callsite_consistency import build_return_census
        lines = []
        for i in range(2500):
            lines.append(f"z{i} = hh(a)")
            if i % 3 == 0:
                lines.append(f"use(z{i})")
        src = "\n".join(lines)
        census = build_return_census({"big.py": src})
        entry = census["hh"]
        assert entry.n == 2500
        assert entry.truncated is False
        assert "truncated" not in entry.to_dict()
        counts = entry.counts
        assert counts["captured_used"] == 834
        assert counts["captured_unused"] == 1666
        assert census["use"].n == 834

    def test_default_cap_still_truncates_hostile_file(self):
        """Cap trade-off, bound direction: sites past the default cap
        still stop the build and stamp every entry ``truncated`` — the
        raised cap is a real bound, not decoration."""
        from core.audit.callsite_consistency import (
            _CENSUS_MAX_SITES_PER_FILE,
            build_return_census,
        )
        n = _CENSUS_MAX_SITES_PER_FILE + 50
        src = "\n".join(f"z{i} = hh(a)" for i in range(n))
        census = build_return_census({"big.py": src})
        entry = census["hh"]
        assert entry.n == _CENSUS_MAX_SITES_PER_FILE
        assert entry.truncated is True
        assert entry.to_dict()["truncated"] is True


class TestScopeBoundedReadIndex:
    """The captured-binding read scan is index-backed; the index is
    file-wide, so the scan must still honour scope boundaries."""

    def test_read_in_later_function_does_not_count(self):
        """A later function reading the SAME binding name must not
        mark an earlier function's binding as used — occurrences past
        the enclosing scope's end are out of range."""
        if not _ts_python_available():
            pytest.skip("tree-sitter python grammar unavailable")
        import textwrap
        from core.audit.callsite_consistency import build_return_census

        src = textwrap.dedent("""\
            def a():
                r = ff(x)

            def b():
                r = gg(y)
                use(r)
        """)
        census = build_return_census({"app.py": src})
        assert census["ff"].sites[0].usage == "captured_unused"
        assert census["gg"].sites[0].usage == "captured_used"

    def test_module_scope_read_counts(self):
        """Module-level bindings scan to end of file (root scope)."""
        if not _ts_python_available():
            pytest.skip("tree-sitter python grammar unavailable")
        from core.audit.callsite_consistency import build_return_census

        src = "r = ff(x)\n\ndef later():\n    use(r)\n"
        census = build_return_census({"app.py": src})
        assert census["ff"].sites[0].usage == "captured_used"
