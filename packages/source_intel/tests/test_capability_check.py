"""Tests for axis-4 capability/privilege dominance.

Mirrors test_abort_proximate.py structure: real-spatch E2E for the
cocci rule, Python-side enclosing-function lookup, adapter verdict
policy, and integration with the rest of the verdict chain.
"""

from __future__ import annotations

import shutil
from unittest.mock import patch

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.adapter import (
    SourceIntelValidator,
    _line_uses_privileged_cap,
    _privileged_capability_dominates,
)
from packages.source_intel.analyze import (
    GRADE_SAME_FUNCTION,
    CapabilityEvidence,
    SourceIntelResult,
    analyze,
)


def _finding(file_path: str, rule_id: str,
             sink_line: int = 5) -> Finding:
    return Finding(
        finding_id="test",
        producer="codeql",
        rule_id=rule_id,
        message="test",
        source=Step(file_path=file_path, line=1, column=1,
                    snippet="x", label="source"),
        sink=Step(file_path=file_path, line=sink_line, column=1,
                  snippet="x", label="sink"),
        intermediate_steps=(),
        raw={},
    )


# =====================================================================
# Real-spatch E2E
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_capability_check_fires_on_capable(tmp_path):
    """The capability_check rule fires on `capable(CAP_SYS_ADMIN)`."""
    src = tmp_path / "cap_fixture.c"
    src.write_text(
        "extern int capable(int);\n"
        "extern int ns_capable(struct user_namespace *ns, int);\n"
        "#define CAP_SYS_ADMIN 21\n"
        "\n"
        "int privileged_op(void) {\n"
        "    if (!capable(CAP_SYS_ADMIN))\n"
        "        return -1;\n"
        "    return 0;\n"
        "}\n"
        "\n"
        "int unprivileged_op(void) {\n"
        "    return 0;\n"
        "}\n"
    )

    r = analyze(tmp_path)
    fns = {c.cap_function for c in r.capabilities}
    assert "capable" in fns


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_capability_captures_enclosing_function(tmp_path):
    src = tmp_path / "cap_fns.c"
    src.write_text(
        "extern int capable(int);\n"
        "#define CAP_SYS_ADMIN 21\n"
        "\n"
        "int privileged(void) {\n"
        "    if (!capable(CAP_SYS_ADMIN))\n"
        "        return -1;\n"
        "    return 0;\n"
        "}\n"
        "\n"
        "int free_for_all(void) {\n"
        "    return 0;\n"
        "}\n"
    )

    r = analyze(tmp_path)
    privileged = [
        c for c in r.capabilities if c.enclosing_function == "privileged"
    ]
    assert privileged, (
        f"expected capable() attributed to privileged; got "
        f"{[(c.cap_function, c.enclosing_function) for c in r.capabilities]!r}"
    )


# =====================================================================
# _line_uses_privileged_cap helper
# =====================================================================


def test_line_uses_privileged_cap_positive(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "if (capable(CAP_SYS_ADMIN)) return 0;\n"
        "if (capable(CAP_NET_BIND_SERVICE)) return 0;\n"
    )
    assert _line_uses_privileged_cap(str(f), 1) is True


def test_line_uses_privileged_cap_negative_unprivileged_constant(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "if (capable(CAP_NET_BIND_SERVICE)) return 0;\n"
    )
    # CAP_NET_BIND_SERVICE doesn't grant root-equivalent power → False
    assert _line_uses_privileged_cap(str(f), 1) is False


def test_line_uses_privileged_cap_returns_false_on_missing_file():
    assert _line_uses_privileged_cap("/no/such/file.c", 1) is False


# =====================================================================
# Verdict policy
# =====================================================================


def test_capability_dominates_emits_not_exploitable(tmp_path):
    """Privileged capable() in same function as memory-corruption
    sink → NOT_EXPLOITABLE."""
    src = tmp_path / "test.c"
    src.write_text(
        "int privileged(int *p) {\n"
        "    if (!capable(CAP_SYS_ADMIN)) return -1;\n"
        "    *p = 1;\n"
        "}\n"
        "int main(void){int x; privileged(&x); return 0;}\n"
    )

    finding = _finding(str(src), "cpp/null-dereference",
                       sink_line=3)
    result = SourceIntelResult(capabilities=(CapabilityEvidence(
        cap_function="capable",
        location=(str(src), 2),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="privileged",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.NOT_EXPLOITABLE


def test_unprivileged_capability_does_not_dominate(tmp_path):
    """capable(CAP_NET_BIND_SERVICE) doesn't grant root-equivalent
    power — verdict stays UNCERTAIN."""
    src = tmp_path / "test.c"
    src.write_text(
        "int low_priv(int *p) {\n"
        "    if (!capable(CAP_NET_BIND_SERVICE)) return -1;\n"
        "    *p = 1;\n"
        "}\n"
        "int main(void){int x; low_priv(&x); return 0;}\n"
    )

    finding = _finding(str(src), "cpp/null-dereference",
                       sink_line=3)
    result = SourceIntelResult(capabilities=(CapabilityEvidence(
        cap_function="capable",
        location=(str(src), 2),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="low_priv",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_ns_capable_does_not_dominate(tmp_path):
    """ns_capable scoped to a userns — userns admin can self-grant
    CAP_SYS_ADMIN inside their own ns without root. Phase 8 excludes
    ns_capable from the privileged-function set."""
    src = tmp_path / "test.c"
    src.write_text(
        "int userns_op(int *p) {\n"
        "    if (!ns_capable(ns, CAP_SYS_ADMIN)) return -1;\n"
        "    *p = 1;\n"
        "}\n"
        "int main(void){int x; userns_op(&x); return 0;}\n"
    )

    finding = _finding(str(src), "cpp/null-dereference",
                       sink_line=3)
    result = SourceIntelResult(capabilities=(CapabilityEvidence(
        cap_function="ns_capable",
        location=(str(src), 2),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="userns_op",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_capability_skipped_for_injection_cwe(tmp_path):
    """Injection CWEs don't benefit from capability evidence."""
    src = tmp_path / "test.c"
    src.write_text(
        "int privileged(int *p) {\n"
        "    if (!capable(CAP_SYS_ADMIN)) return -1;\n"
        "    *p = 1;\n"
        "}\n"
        "int main(void){int x; privileged(&x); return 0;}\n"
    )
    finding = _finding(str(src), "cpp/command-line-injection",
                       sink_line=3)
    result = SourceIntelResult(capabilities=(CapabilityEvidence(
        cap_function="capable",
        location=(str(src), 2),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="privileged",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_capability_in_different_function_does_not_dominate(tmp_path):
    """Capability check in a sibling function, not the finding's
    function — verdict stays UNCERTAIN."""
    src = tmp_path / "test.c"
    src.write_text(
        "int sibling(void){if(!capable(CAP_SYS_ADMIN))return -1;return 0;}\n"
        "int target(int *p){*p=1;}\n"
        "int main(void){int x; target(&x); sibling(); return 0;}\n"
    )
    finding = _finding(str(src), "cpp/null-dereference", sink_line=2)
    result = SourceIntelResult(capabilities=(CapabilityEvidence(
        cap_function="capable",
        location=(str(src), 1),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="sibling",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_capability_dominance_pure_helper(tmp_path):
    """Direct test of _privileged_capability_dominates."""
    src = tmp_path / "x.c"
    src.write_text(
        "int privileged(int *p) {\n"
        "    if (!capable(CAP_SYS_ADMIN)) return -1;\n"
        "    *p = 1;\n"
        "}\n"
    )
    finding = _finding(str(src), "cpp/null-dereference", sink_line=3)
    matching = SourceIntelResult(capabilities=(CapabilityEvidence(
        cap_function="capable",
        location=(str(src), 2),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="privileged",
    ),))
    assert _privileged_capability_dominates(finding, matching) is True

    sibling = SourceIntelResult(capabilities=(CapabilityEvidence(
        cap_function="capable",
        location=(str(src), 2),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="other_fn",
    ),))
    assert _privileged_capability_dominates(finding, sibling) is False
