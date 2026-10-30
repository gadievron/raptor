"""Tests for Phase C gap 6: enforcer → sanitiser promotion."""

from core.evidence import EvidenceTier
from core.iris.assumptions import (
    AssumptionCategory,
    BypassFinding,
    SafetyAssumption,
)
from core.iris.refine import _promote_enforcers
from core.iris.specs import TaintSpec


def _spec(fn="check_input", file="src/auth.py", role="sanitiser", **kw):
    return TaintSpec(function=fn, file=file, role=role, **kw)


def _assumption(target="sink", enforced_by=None, **kw):
    return SafetyAssumption(
        target=target,
        file=kw.pop("file", "src/app.py"),
        assumption=f"{target} needs enforcer",
        category=kw.pop("category", AssumptionCategory.SANITISATION),
        enforced_by=enforced_by or ["validate_input"],
        bug_class=kw.pop("bug_class", "CWE-79"),
        **kw,
    )


def _bypass(assumption=None, caller="unsafe_handler", **kw):
    a = assumption or _assumption()
    return BypassFinding(
        assumption=a,
        caller_file=kw.pop("caller_file", "src/routes.py"),
        caller_function=caller,
        missing_enforcer=kw.pop("missing_enforcer", a.enforced_by[0]),
        **kw,
    )


class TestPromoteEnforcers:
    def test_basic_promotion(self):
        specs = [_spec()]
        findings = [_bypass()]
        result = _promote_enforcers(specs, findings)
        new = [s for s in result if s.source == "bypass_promotion"]
        assert len(new) == 1
        assert new[0].function == "validate_input"
        assert new[0].role == "sanitiser"
        assert new[0].evidence_tier == EvidenceTier.HEURISTIC
        assert new[0].confidence == 0.5

    def test_no_duplicate_when_already_exists(self):
        existing = _spec(fn="validate_input", file="src/app.py")
        specs = [existing]
        findings = [_bypass()]
        result = _promote_enforcers(specs, findings)
        promoted = [s for s in result if s.source == "bypass_promotion"]
        assert len(promoted) == 0

    def test_empty_findings(self):
        specs = [_spec()]
        result = _promote_enforcers(specs, [])
        assert result == specs

    def test_multiple_enforcers_from_same_assumption(self):
        a = _assumption(enforced_by=["sanitise_html", "escape_xss"])
        findings = [_bypass(assumption=a, missing_enforcer="sanitise_html")]
        result = _promote_enforcers([], findings)
        promoted = [s for s in result if s.source == "bypass_promotion"]
        assert len(promoted) == 2
        names = {s.function for s in promoted}
        assert names == {"sanitise_html", "escape_xss"}

    def test_bug_class_propagated(self):
        a = _assumption(bug_class="CWE-89")
        findings = [_bypass(assumption=a)]
        result = _promote_enforcers([], findings)
        promoted = [s for s in result if s.source == "bypass_promotion"]
        assert promoted[0].taint_classes == ["CWE-89"]

    def test_multiple_bug_classes_merged(self):
        a1 = _assumption(bug_class="CWE-79", enforced_by=["guard"])
        a2 = _assumption(
            target="sink2", bug_class="CWE-89",
            enforced_by=["guard"],
        )
        f1 = _bypass(assumption=a1, missing_enforcer="guard")
        f2 = _bypass(assumption=a2, missing_enforcer="guard")
        result = _promote_enforcers([], [f1, f2])
        promoted = [s for s in result if s.source == "bypass_promotion"]
        assert len(promoted) == 1
        assert sorted(promoted[0].taint_classes) == ["CWE-79", "CWE-89"]

    def test_no_file_on_assumption_skips(self):
        a = SafetyAssumption(
            target="sink",
            file="",
            assumption="test",
            category=AssumptionCategory.SANITISATION,
            enforced_by=["guard"],
        )
        findings = [_bypass(assumption=a)]
        result = _promote_enforcers([], findings)
        promoted = [s for s in result if s.source == "bypass_promotion"]
        assert len(promoted) == 0

    def test_preserves_original_specs(self):
        original = [_spec(fn="orig1"), _spec(fn="orig2")]
        findings = [_bypass()]
        result = _promote_enforcers(original, findings)
        assert result[:2] == original
        assert len(result) == 3
