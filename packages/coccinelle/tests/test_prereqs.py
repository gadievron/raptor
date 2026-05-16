"""Tests for ``packages.coccinelle.prereqs``.

Unit coverage for the gather/evaluate split + 1 real-spatch E2E that
runs the shipped ``function_inventory.cocci`` against a tiny C
fixture and verifies the orphan-static-helper detection works
end-to-end.
"""

from __future__ import annotations

import os
import shutil
import sys
from unittest.mock import patch

import pytest

_RAPTOR_DIR = os.environ["RAPTOR_DIR"]
if _RAPTOR_DIR not in sys.path:
    sys.path.insert(0, _RAPTOR_DIR)

from packages.coccinelle.models import SpatchMatch, SpatchResult
from packages.coccinelle.prereqs import (
    PrereqFacts,
    evaluate_finding,
    gather_prereqs,
)


# ---------------------------------------------------------------------
# PrereqFacts data class
# ---------------------------------------------------------------------


def test_prereq_facts_default_is_not_skipped():
    f = PrereqFacts()
    assert f.is_skipped is False
    assert f.function_exists("foo") is False
    assert f.function_has_callers("foo") is False


def test_prereq_facts_skipped_reason_marks_skipped():
    f = PrereqFacts(skipped_reason="spatch_not_available")
    assert f.is_skipped is True


def test_prereq_facts_callers_of_returns_sorted():
    f = PrereqFacts(
        calls={"foo": {("b.c", 10), ("a.c", 1), ("a.c", 5)}},
    )
    assert f.callers_of("foo") == [("a.c", 1), ("a.c", 5), ("b.c", 10)]


# ---------------------------------------------------------------------
# gather_prereqs — skip paths
# ---------------------------------------------------------------------


def test_gather_prereqs_skips_when_spatch_missing(tmp_path):
    (tmp_path / "x.c").write_text("\n")
    with patch("packages.coccinelle.prereqs.spatch_available",
               return_value=False):
        facts = gather_prereqs(tmp_path)
    assert facts.is_skipped is True
    assert facts.skipped_reason == "spatch_not_available"


def test_gather_prereqs_skips_when_no_c_source(tmp_path):
    """Python-only target → skipped silently (cocci is C-only).

    This is the same skip semantic as the /scan cocci leg — ensures
    /validate prereqs don't mis-fire on Python/JS/Go projects."""
    (tmp_path / "main.py").write_text("\n")
    with patch("packages.coccinelle.prereqs.spatch_available",
               return_value=True):
        facts = gather_prereqs(tmp_path)
    assert facts.skipped_reason == "no_c_cpp_source"


def test_gather_prereqs_skips_when_rules_dir_missing(tmp_path):
    """No shipped rules → skipped silently (minimal install /
    packaging strip). Don't error; the consumer treats this as
    "no structural evidence available"."""
    (tmp_path / "x.c").write_text("\n")
    with patch("packages.coccinelle.prereqs.spatch_available",
               return_value=True), patch(
        "packages.coccinelle.prereqs._shipped_prereqs_rules_dir",
        return_value=None,
    ):
        facts = gather_prereqs(tmp_path)
    assert facts.skipped_reason == "rules_dir_missing"


# ---------------------------------------------------------------------
# gather_prereqs — happy path (mocked spatch)
# ---------------------------------------------------------------------


def test_gather_prereqs_parses_def_and_call_messages(tmp_path):
    """Cocci result shape: ``def:<name>`` and ``call:<name>``
    messages → indexed into ``facts.defs`` and ``facts.calls``."""
    (tmp_path / "x.c").write_text("\n")
    rules_dir = tmp_path / "rules"; rules_dir.mkdir()

    fake_results = [SpatchResult(
        rule="function_inventory",
        matches=[
            SpatchMatch(file="src/a.c", line=10, message="def:helper"),
            SpatchMatch(file="src/a.c", line=20, message="def:main"),
            SpatchMatch(file="src/a.c", line=21, message="call:helper"),
            SpatchMatch(file="src/a.c", line=22, message="call:printf"),
        ],
    )]

    with patch("packages.coccinelle.prereqs.spatch_available",
               return_value=True), patch(
        "packages.coccinelle.prereqs.spatch_run_rules",
        return_value=fake_results,
    ):
        facts = gather_prereqs(tmp_path, rules_dir=rules_dir)

    assert facts.is_skipped is False
    assert facts.function_exists("helper") is True
    assert facts.function_exists("main") is True
    assert facts.function_exists("printf") is False  # libc, not defined here
    assert facts.function_has_callers("helper") is True
    assert facts.function_has_callers("main") is False  # main is called by libc
    assert facts.callers_of("helper") == [("src/a.c", 21)]


def test_gather_prereqs_ignores_unknown_message_shapes(tmp_path):
    """Future rule additions may emit other COCCIRESULT shapes;
    the gather pass stays neutral and ignores them."""
    (tmp_path / "x.c").write_text("\n")
    rules_dir = tmp_path / "rules"; rules_dir.mkdir()

    fake_results = [SpatchResult(
        rule="function_inventory",
        matches=[
            SpatchMatch(file="x.c", line=1, message="def:f"),
            SpatchMatch(file="x.c", line=2, message="future_kind:something"),
            SpatchMatch(file="x.c", line=3, message=""),  # empty msg
        ],
    )]
    with patch("packages.coccinelle.prereqs.spatch_available",
               return_value=True), patch(
        "packages.coccinelle.prereqs.spatch_run_rules",
        return_value=fake_results,
    ):
        facts = gather_prereqs(tmp_path, rules_dir=rules_dir)
    assert facts.function_exists("f") is True
    # No spurious entries from the unknown / empty messages:
    assert facts.calls == {}
    assert list(facts.defs.keys()) == ["f"]


# ---------------------------------------------------------------------
# evaluate_finding — per-finding evidence shape
# ---------------------------------------------------------------------


def _facts(defs=None, calls=None):
    f = PrereqFacts()
    for name, locs in (defs or {}).items():
        f.defs[name] = set(locs)
    for name, locs in (calls or {}).items():
        f.calls[name] = set(locs)
    return f


def test_evaluate_finding_returns_skipped_reason_when_facts_skipped():
    facts = PrereqFacts(skipped_reason="spatch_not_available")
    out = evaluate_finding({"function": "foo", "file": "a.c"}, facts)
    assert out["applicable"] is False
    assert out["skipped_reason"] == "spatch_not_available"


def test_evaluate_finding_skips_when_finding_has_no_function():
    """Findings without a ``function`` field can't be checked
    structurally — gracefully skip rather than asserting."""
    out = evaluate_finding({"file": "a.c"}, _facts())
    assert out["applicable"] is False
    assert out["skipped_reason"] == "finding_missing_function"


def test_evaluate_finding_skips_for_non_c_cpp_files():
    """Findings on Python / JS / Go files are skipped (cocci can't
    see them). This is the per-finding mirror of the gather-time
    target-language check."""
    out = evaluate_finding(
        {"function": "foo", "file": "src/auth.py"},
        _facts(defs={"foo": [("a.c", 1)]}),
    )
    assert out["applicable"] is False
    assert out["skipped_reason"] == "non_c_cpp_file"


def test_evaluate_finding_function_exists_with_callers():
    """Function defined and called somewhere → both checks True,
    callers_count surfaces in details for downstream evidence."""
    facts = _facts(
        defs={"helper": [("a.c", 10)]},
        calls={"helper": [("a.c", 20), ("b.c", 5)]},
    )
    out = evaluate_finding(
        {"function": "helper", "file": "a.c"}, facts,
    )
    assert out["applicable"] is True
    assert out["checks"]["function_exists"] is True
    assert out["checks"]["function_has_callers"] is True
    assert out["details"]["function"] == "helper"
    assert out["details"]["callers_count"] == 2


def test_evaluate_finding_orphan_static_helper():
    """Function defined but never called → exists True, has_callers
    False. This is the classic LLM-hallucinated-call-chain case."""
    facts = _facts(
        defs={"orphan": [("a.c", 10)]},
        calls={},
    )
    out = evaluate_finding(
        {"function": "orphan", "file": "a.c"}, facts,
    )
    assert out["checks"]["function_exists"] is True
    assert out["checks"]["function_has_callers"] is False


def test_evaluate_finding_function_not_defined_locally():
    """Function isn't in the local tree (e.g. libc, header-only) →
    function_exists False AND has_callers stays None (we can't
    assert "no callers" for a function we don't see defined)."""
    facts = _facts(
        defs={"main": [("a.c", 1)]},
        calls={"strlen": [("a.c", 5)]},
    )
    out = evaluate_finding(
        {"function": "strlen", "file": "a.c"}, facts,
    )
    assert out["checks"]["function_exists"] is False
    assert out["checks"]["function_has_callers"] is None
    assert out["details"] == {"function": "strlen"}


def test_evaluate_finding_files_with_no_extension_treated_as_c():
    """Header-less or extensionless C source (e.g. driver code that
    omits the .c suffix) — proceed as if C/C++ rather than skip,
    since cocci will have scanned them. The empty extension fall-
    through avoids a false "non_c_cpp_file" skip on these targets."""
    out = evaluate_finding(
        {"function": "foo", "file": "Makefile_target"},
        _facts(defs={"foo": [("a.c", 1)]}),
    )
    assert out["applicable"] is True
    assert out["checks"]["function_exists"] is True


# ---------------------------------------------------------------------
# Real-spatch E2E
# ---------------------------------------------------------------------


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_real_spatch_orphan_static_helper(tmp_path):
    """End-to-end: real spatch runs the shipped ``function_inventory``
    rule against a tiny C fixture; the prereqs module correctly
    classifies an orphan static helper (defined, never called) and
    a called static helper (both checks True). Pin against the
    shipped rule corpus so corpus drift surfaces here."""
    src = tmp_path / "main.c"
    src.write_text(
        "#include <stdio.h>\n"
        "static int helper_called(int x) { return x + 1; }\n"
        "static int helper_orphan(int y) { return y * 2; }\n"
        "int main(void) {\n"
        "    return helper_called(5);\n"
        "}\n"
    )

    facts = gather_prereqs(tmp_path)
    assert not facts.is_skipped, (
        f"expected real spatch to produce facts; got skipped_reason="
        f"{facts.skipped_reason!r}"
    )
    assert facts.function_exists("helper_called") is True
    assert facts.function_exists("helper_orphan") is True
    assert facts.function_has_callers("helper_called") is True
    assert facts.function_has_callers("helper_orphan") is False, (
        "helper_orphan has no caller in fixture — orphan-static-helper "
        "detection broke (rule corpus drift?)"
    )
