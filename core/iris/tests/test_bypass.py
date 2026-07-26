"""Tests for core.iris.bypass — compositional bypass detection."""

from core.inventory.call_graph import CallSite, ClassDef, FileCallGraph
from core.iris.assumptions import AssumptionCategory, SafetyAssumption
from core.iris.bypass import CompositionalAnalyzer


def _graph(calls):
    """Build a FileCallGraph from a list of (caller, callee, line) tuples."""
    return FileCallGraph(
        calls=[
            CallSite(line=line, chain=[callee], caller=caller)
            for caller, callee, line in calls
        ],
    )


def _assumption(target, enforced_by, **kw):
    if isinstance(enforced_by, str):
        enforced_by = [enforced_by]
    return SafetyAssumption(
        target=target,
        file=kw.pop("file", "test.c"),
        assumption=f"{target} requires {enforced_by}",
        category=kw.pop("category", AssumptionCategory.ORDERING),
        enforced_by=enforced_by,
        **kw,
    )


class TestTransitiveCallers:
    def test_direct_callers(self):
        graphs = {"f.c": _graph([("a", "sink", 10), ("b", "sink", 20)])}
        ana = CompositionalAnalyzer(graphs)
        callers = ana.transitive_callers("sink")
        names = {fn for _, fn in callers}
        assert names == {"a", "b"}

    def test_transitive(self):
        graphs = {"f.c": _graph([
            ("a", "b", 10),
            ("b", "sink", 20),
        ])}
        ana = CompositionalAnalyzer(graphs)
        callers = ana.transitive_callers("sink")
        names = {fn for _, fn in callers}
        assert "a" in names
        assert "b" in names

    def test_cycle_safe(self):
        graphs = {"f.c": _graph([
            ("a", "b", 10),
            ("b", "a", 20),
            ("b", "sink", 30),
        ])}
        ana = CompositionalAnalyzer(graphs)
        callers = ana.transitive_callers("sink")
        names = {fn for _, fn in callers}
        assert names == {"a", "b"}


class TestDetectBypasses:
    def test_basic_bypass(self):
        graphs = {"f.c": _graph([
            ("safe", "guard", 10),
            ("safe", "sink", 20),
            ("unsafe", "sink", 30),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "guard")
        findings = ana.detect_bypasses(a)
        assert len(findings) == 1
        assert findings[0].caller_function == "unsafe"

    def test_no_bypass_when_guard_present(self):
        graphs = {"f.c": _graph([
            ("safe", "guard", 10),
            ("safe", "sink", 20),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "guard")
        assert ana.detect_bypasses(a) == []

    def test_transitive_bypass(self):
        graphs = {"f.c": _graph([
            ("safe_outer", "guard", 5),
            ("safe_outer", "helper", 10),
            ("helper", "sink", 20),
            ("unsafe_outer", "helper", 30),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "guard")
        findings = ana.detect_bypasses(a)
        funcs = {f.caller_function for f in findings}
        assert "unsafe_outer" in funcs
        transitive = [f for f in findings if f.caller_function == "unsafe_outer"]
        assert transitive[0].is_transitive is True

    def test_main_excluded(self):
        graphs = {"f.c": _graph([
            ("main", "sink", 10),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "guard")
        findings = ana.detect_bypasses(a)
        assert all(f.caller_function != "main" for f in findings)


class TestTransitiveCallees:
    def test_direct_callees(self):
        graphs = {"f.c": _graph([("entry", "a", 10), ("entry", "b", 20)])}
        ana = CompositionalAnalyzer(graphs)
        callees = ana.transitive_callees("entry")
        names = {fn for _, fn in callees}
        assert names == {"a", "b"}

    def test_transitive(self):
        graphs = {"f.c": _graph([
            ("entry", "mid", 10),
            ("mid", "leaf", 20),
        ])}
        ana = CompositionalAnalyzer(graphs)
        callees = ana.transitive_callees("entry")
        names = {fn for _, fn in callees}
        assert "mid" in names
        assert "leaf" in names

    def test_cross_file(self):
        graphs = {
            "a.c": _graph([("entry", "helper", 10)]),
            "b.c": _graph([("helper", "leaf", 20)]),
        }
        ana = CompositionalAnalyzer(graphs)
        callees = ana.transitive_callees("entry")
        names = {fn for _, fn in callees}
        assert "helper" in names
        assert "leaf" in names


class TestCrossFile:
    def test_cross_file_callers_detected(self):
        graphs = {
            "auth.c": _graph([
                ("check_auth", "validate_token", 10),
            ]),
            "admin.c": _graph([
                ("safe_handler", "check_auth", 10),
                ("safe_handler", "admin_action", 20),
                ("unsafe_handler", "admin_action", 30),
            ]),
        }
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("admin_action", "check_auth")
        findings = ana.detect_bypasses(a)
        funcs = {f.caller_function for f in findings}
        assert "unsafe_handler" in funcs
        assert "safe_handler" not in funcs

    def test_cross_file_intermediate_labeled(self):
        """Third-file caller through cross-file intermediate
        should get via_intermediate correctly populated."""
        graphs = {
            "auth.c": _graph([
                ("check_auth", "validate_token", 10),
            ]),
            "admin.c": _graph([
                ("safe_handler", "check_auth", 10),
                ("safe_handler", "do_admin", 20),
                ("do_admin", "admin_action", 30),
                ("unsafe_handler", "do_admin", 40),
            ]),
            "routes.c": _graph([
                ("route_handler", "do_admin", 10),
            ]),
        }
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("admin_action", "check_auth")
        findings = ana.detect_bypasses(a)

        route_f = [f for f in findings if f.caller_function == "route_handler"]
        assert len(route_f) == 1
        assert route_f[0].via_intermediate == "do_admin"
        assert route_f[0].is_transitive is True


class TestOrderingViolations:
    def test_underminer_before_enforcer(self):
        graphs = {"f.c": _graph([
            ("caller", "underminer", 10),
            ("caller", "enforcer", 20),
            ("caller", "sink", 30),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "enforcer", underminer="underminer")
        findings = ana.detect_ordering_violations(a)
        assert len(findings) == 1
        assert findings[0].ordering_violation is True
        assert findings[0].line_info["underminer_line"] == 10
        assert findings[0].line_info["enforcer_line"] == 20

    def test_no_violation_when_enforcer_first(self):
        graphs = {"f.c": _graph([
            ("caller", "enforcer", 10),
            ("caller", "underminer", 20),
            ("caller", "sink", 30),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "enforcer", underminer="underminer")
        assert ana.detect_ordering_violations(a) == []

    def test_no_violation_without_underminer(self):
        graphs = {"f.c": _graph([
            ("caller", "sink", 10),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "enforcer")
        assert ana.detect_ordering_violations(a) == []

    def test_multi_enforcer_one_after_underminer(self):
        """With multiple enforcers (any sufficient), no violation if
        any enforcer precedes the underminer."""
        graphs = {"f.c": _graph([
            ("caller", "underminer", 10),
            ("caller", "enforcer_a", 20),
            ("caller", "enforcer_b", 5),  # before underminer
            ("caller", "sink", 30),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption(
            "sink",
            ["enforcer_a", "enforcer_b"],
            underminer="underminer",
        )
        assert ana.detect_ordering_violations(a) == []

    def test_multi_enforcer_all_after_underminer(self):
        """Violation when underminer precedes ALL enforcers."""
        graphs = {"f.c": _graph([
            ("caller", "underminer", 5),
            ("caller", "enforcer_a", 10),
            ("caller", "enforcer_b", 20),
            ("caller", "sink", 30),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption(
            "sink",
            ["enforcer_a", "enforcer_b"],
            underminer="underminer",
        )
        findings = ana.detect_ordering_violations(a)
        assert len(findings) == 1


class TestWidening:
    def test_sibling_discovery(self):
        graphs = {"f.c": _graph([
            ("handler_a", "guard", 5),
            ("handler_a", "intermediate", 10),
            ("handler_b", "intermediate", 20),
            ("intermediate", "sink", 30),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "guard")
        bypasses = ana.detect_bypasses(a)

        bypass_b = [f for f in bypasses if f.caller_function == "handler_b"]
        assert len(bypass_b) == 1
        assert bypass_b[0].via_intermediate == "intermediate"

        siblings = ana.widen_from_finding(bypass_b[0])
        # handler_a also calls intermediate, but it has the guard, so not a sibling
        sibling_funcs = {s.caller_function for s in siblings}
        assert "handler_a" not in sibling_funcs

    def test_no_widening_without_intermediate(self):
        graphs = {"f.c": _graph([
            ("direct_caller", "sink", 10),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "guard")
        bypasses = ana.detect_bypasses(a)
        for finding in bypasses:
            assert ana.widen_from_finding(finding) == []


# ── Safety contract blind spots (adversarial) ──────────────────────────


class TestBlindSpotNoBypasses:
    """'No bypasses detected' must not demote or suppress any finding.

    An empty bypass list means no additional findings — it says nothing
    about whether the target function is safe.
    """

    def test_no_bypass_returns_empty_not_suppression(self):
        graphs = {"f.c": _graph([
            ("caller", "sink", 10),
            ("caller", "guard", 5),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "guard")
        bypasses = ana.detect_bypasses(a)
        assert bypasses == []


class TestBlindSpotHallucinatedEnforcer:
    """LLM may hallucinate enforcer names that don't exist in the codebase.

    A non-existent enforcer means transitive_callers(enforcer) is empty,
    so ALL callers of target are flagged as bypasses.  This is noise
    (extra findings), not silence — safe direction.
    """

    def test_nonexistent_enforcer_flags_all_callers(self):
        graphs = {"f.c": _graph([
            ("handler_a", "sink", 10),
            ("handler_b", "sink", 20),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "does_not_exist_in_codebase")
        bypasses = ana.detect_bypasses(a)
        bypass_funcs = {f.caller_function for f in bypasses}
        assert "handler_a" in bypass_funcs
        assert "handler_b" in bypass_funcs


class TestBlindSpotWrongAssumption:
    """Wrong assumptions produce extra findings, not missed findings.

    If the LLM synthesises an assumption about a function that is actually
    safe without the enforcer, the bypass detector will flag callers that
    don't call the enforcer.  These are false positives (noise) but they
    never cause a real bypass to be hidden.
    """

    def test_wrong_assumption_produces_findings_not_silence(self):
        graphs = {"f.c": _graph([
            ("safe_caller", "target_fn", 10),
        ])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("target_fn", "unnecessary_guard")
        bypasses = ana.detect_bypasses(a)
        assert len(bypasses) >= 1
        assert bypasses[0].caller_function == "safe_caller"


# ── Safety contract compliance ──────────────────────────────────────────


class TestContractCompliance:
    def test_assert_boost_only_succeeds(self):
        from core.audit.safety_contract import assert_boost_only
        assert_boost_only("bypass_loop")

    def test_suppress_evidence_raises(self):
        import pytest
        from core.audit.safety_contract import ContractViolation, SuppressEvidence
        with pytest.raises(ContractViolation):
            SuppressEvidence(
                source="bypass_loop",
                verdict="no_bypasses",
                reason="test",
            )

    def test_boost_evidence_allowed(self):
        from core.audit.safety_contract import BoostEvidence
        ev = BoostEvidence(
            source="bypass_loop",
            action="add_finding",
            description="caller handler_a bypasses guard for sink",
        )
        assert ev.source == "bypass_loop"
        assert ev.action == "add_finding"


# ── Type hierarchy bypass detection ──────────────────────────────────────


def _graph_with_classes(calls, classes):
    """Build a FileCallGraph with call sites and ClassDef data."""
    return FileCallGraph(
        calls=[
            CallSite(line=line, chain=[callee], caller=caller)
            for caller, callee, line in calls
        ],
        classes=classes,
    )


class TestTypeHierarchyBypasses:
    def test_subtype_overrides_enforcer(self):
        graphs = {
            "auth.py": _graph_with_classes(
                [("handler", "validate", 10), ("handler", "sink", 20)],
                [
                    ClassDef(name="BaseAuth", line=1, bases=[],
                             methods=[("validate", 5), ("process", 8)]),
                    ClassDef(name="PermissiveAuth", line=30,
                             bases=["BaseAuth"],
                             methods=[("validate", 35)]),
                ],
            ),
        }
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "validate")
        findings = ana.detect_type_hierarchy_bypasses(a)
        assert len(findings) == 1
        assert findings[0].caller_function == "PermissiveAuth.validate"
        assert findings[0].missing_enforcer == "validate"

    def test_no_override_no_finding(self):
        graphs = {
            "auth.py": _graph_with_classes(
                [("handler", "validate", 10)],
                [
                    ClassDef(name="BaseAuth", line=1, bases=[],
                             methods=[("validate", 5)]),
                    ClassDef(name="PermissiveAuth", line=30,
                             bases=["BaseAuth"],
                             methods=[("other_method", 35)]),
                ],
            ),
        }
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "validate")
        assert ana.detect_type_hierarchy_bypasses(a) == []

    def test_multi_level_inheritance(self):
        graphs = {
            "auth.py": _graph_with_classes(
                [("handler", "check", 10), ("handler", "sink", 20)],
                [
                    ClassDef(name="A", line=1, bases=[],
                             methods=[("check", 5)]),
                    ClassDef(name="B", line=20, bases=["A"],
                             methods=[("helper", 25)]),
                    ClassDef(name="C", line=40, bases=["B"],
                             methods=[("check", 45)]),
                ],
            ),
        }
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "check")
        findings = ana.detect_type_hierarchy_bypasses(a)
        funcs = {f.caller_function for f in findings}
        assert "C.check" in funcs

    def test_no_classes_returns_empty(self):
        graphs = {"f.c": _graph([("a", "sink", 10)])}
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "guard")
        assert ana.detect_type_hierarchy_bypasses(a) == []

    def test_unrelated_class_same_method(self):
        """Class in a disconnected file is filtered by context."""
        graphs = {
            "auth.py": _graph_with_classes(
                [("handler", "validate", 10), ("handler", "sink", 20)],
                [
                    ClassDef(name="Auth", line=1, bases=[],
                             methods=[("validate", 5)]),
                    ClassDef(name="SubAuth", line=30, bases=["Auth"],
                             methods=[("validate", 35)]),
                ],
            ),
            "widgets.py": _graph_with_classes(
                [],
                [
                    ClassDef(name="Widget", line=1, bases=[],
                             methods=[("validate", 5)]),
                    ClassDef(name="SubWidget", line=30, bases=["Widget"],
                             methods=[("validate", 35)]),
                ],
            ),
        }
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "validate")
        findings = ana.detect_type_hierarchy_bypasses(a)
        funcs = {f.caller_function for f in findings}
        assert "SubAuth.validate" in funcs
        assert "SubWidget.validate" not in funcs

    def test_multiple_enforcers_all_checked(self):
        graphs = {
            "auth.py": _graph_with_classes(
                [("handler", "sink", 10)],
                [
                    ClassDef(name="Base", line=1, bases=[],
                             methods=[("check_a", 5), ("check_b", 8)]),
                    ClassDef(name="Sub", line=30, bases=["Base"],
                             methods=[("check_b", 35)]),
                ],
            ),
        }
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", ["check_a", "check_b"])
        findings = ana.detect_type_hierarchy_bypasses(a)
        assert len(findings) == 1
        assert findings[0].caller_function == "Sub.check_b"

    def test_hallucinated_enforcer_safe(self):
        graphs = {
            "auth.py": _graph_with_classes(
                [("handler", "sink", 10)],
                [
                    ClassDef(name="Base", line=1, bases=[],
                             methods=[("validate", 5)]),
                    ClassDef(name="Sub", line=30, bases=["Base"],
                             methods=[("validate", 35)]),
                ],
            ),
        }
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "nonexistent_method")
        assert ana.detect_type_hierarchy_bypasses(a) == []

    def test_dotted_base_resolved(self):
        graphs = {
            "auth.py": _graph_with_classes(
                [("handler", "sink", 10)],
                [
                    ClassDef(name="BaseAuth", line=1, bases=[],
                             methods=[("validate", 5)]),
                    ClassDef(name="Sub", line=30,
                             bases=["some_module.BaseAuth"],
                             methods=[("validate", 35)]),
                ],
            ),
        }
        ana = CompositionalAnalyzer(graphs)
        a = _assumption("sink", "validate")
        findings = ana.detect_type_hierarchy_bypasses(a)
        assert len(findings) == 1
        assert findings[0].caller_function == "Sub.validate"
