"""Tests for ``packages.coccinelle.prereqs``.

Unit coverage for the gather/evaluate split + 1 real-spatch E2E that
runs the shipped ``function_inventory.cocci`` against a tiny C
fixture and verifies the orphan-static-helper detection works
end-to-end.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# parents[3] climbs:
#   [0] packages/coccinelle/tests/  (this file's directory)
#   [1] packages/coccinelle/
#   [2] packages/
#   [3] <repo root>
_REPO_ROOT = str(Path(__file__).resolve().parents[3])
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from packages.coccinelle import prereqs  # noqa: E402
from packages.coccinelle.models import SpatchMatch, SpatchResult  # noqa: E402
from packages.coccinelle.prereqs import (  # noqa: E402
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
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

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
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

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
# gather_prereqs — errored sweeps hold no absence evidence
# ---------------------------------------------------------------------


def _gather_with(tmp_path, results):
    (tmp_path / "x.c").write_text("\n")
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    with patch("packages.coccinelle.prereqs.spatch_available",
               return_value=True), patch(
        "packages.coccinelle.prereqs.spatch_run_rules",
        return_value=results,
    ):
        return gather_prereqs(tmp_path, rules_dir=rules_dir)


def test_gather_prereqs_all_rules_errored_is_skipped(tmp_path):
    """A sweep in which every rule errored produced no absence
    evidence — it must read as skipped (``rules_failed``), never as
    an empty fact base whose every function_exists lookup answers
    False (engine failure read as mechanical refutation)."""
    facts = _gather_with(tmp_path, [SpatchResult(
        rule="prereq-defs", returncode=2,
        errors=["spatch: parse error"], elapsed_ms=10,
    )])
    assert facts.is_skipped is True
    assert facts.skipped_reason == "rules_failed"


def test_gather_prereqs_empty_result_set_is_skipped(tmp_path):
    """Zero results (empty rules dir) is the same no-evidence shape."""
    facts = _gather_with(tmp_path, [])
    assert facts.is_skipped is True
    assert facts.skipped_reason == "rules_failed"


def test_gather_prereqs_partial_sweep_marks_incomplete(tmp_path):
    """One rule ok + one errored: positive evidence is kept, but the
    base is marked incomplete so absence answers abstain downstream."""
    facts = _gather_with(tmp_path, [
        SpatchResult(rule="a", matches=[
            SpatchMatch(file="a.c", line=1, message="def:f"),
        ]),
        SpatchResult(rule="b", returncode=2, errors=["fatal error"]),
    ])
    assert facts.is_skipped is False
    assert facts.complete is False
    assert facts.function_exists("f") is True


def test_gather_prereqs_clean_sweep_is_complete(tmp_path):
    facts = _gather_with(tmp_path, [SpatchResult(rule="a", matches=[
        SpatchMatch(file="a.c", line=1, message="def:f"),
    ])])
    assert facts.complete is True
    assert facts.headers_parsed is False


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
# evaluate_finding — condemn-toward-abstain
# ---------------------------------------------------------------------


def test_evaluate_finding_cpp_file_not_in_fact_base():
    """The sweep parses C translation units only — a .cpp finding's
    function can never appear in defs, so its absence proves nothing.
    Pre-fix this minted function_exists=False for every C++ finding,
    which core/audit/feedback accepted as a mechanical refutation."""
    out = evaluate_finding(
        {"function": "HandleRequest", "file": "src/server.cpp"},
        _facts(),
    )
    assert out["applicable"] is False
    assert out["skipped_reason"] == "ext_not_in_fact_base"
    assert out["checks"]["function_exists"] is None


def test_evaluate_finding_header_absence_abstains():
    """Header-defined static/inline functions are invisible under
    --no-includes: a .h finding's absent name answers null, never
    False. A positive hit (defined in a parsed .c) still answers
    True."""
    out = evaluate_finding(
        {"function": "inline_helper", "file": "include/util.h"},
        _facts(),
    )
    assert out["applicable"] is True
    assert out["checks"]["function_exists"] is None
    assert out["details"]["abstained"] == "headers_not_parsed"

    hit = evaluate_finding(
        {"function": "shared", "file": "include/util.h"},
        _facts(defs={"shared": [("a.c", 3)]}),
    )
    assert hit["checks"]["function_exists"] is True


def test_evaluate_finding_partial_sweep_absence_abstains():
    """Incomplete sweep (some rule errored): a .c finding's absent
    name answers null — the errored rule may have been the one that
    would have seen the definition."""
    facts = _facts(defs={"other": [("a.c", 1)]})
    facts.complete = False
    out = evaluate_finding(
        {"function": "parse_packet", "file": "src/net.c"}, facts,
    )
    assert out["applicable"] is True
    assert out["checks"]["function_exists"] is None
    assert out["details"]["abstained"] == "sweep_partial"


def test_evaluate_finding_partial_sweep_positive_evidence_stands():
    """Positive witnesses survive a partial sweep; only the
    zero-callers claim degrades to null."""
    facts = _facts(defs={"f": [("a.c", 1)]})
    facts.complete = False
    out = evaluate_finding({"function": "f", "file": "src/a.c"}, facts)
    assert out["checks"]["function_exists"] is True
    assert out["checks"]["function_has_callers"] is None
    assert out["details"]["abstained"] == "sweep_partial"


def test_evaluate_finding_complete_sweep_still_answers_false():
    """Two-direction pin: with a complete fact base the absence
    witness still fires — the abstention must not swallow the real
    check."""
    out = evaluate_finding(
        {"function": "ghost_fn", "file": "src/a.c"},
        _facts(defs={"main": [("a.c", 1)]}),
    )
    assert out["applicable"] is True
    assert out["checks"]["function_exists"] is False


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


# ---------------------------------------------------------------------------
# _has_c_cpp_source bounded walk
# ---------------------------------------------------------------------------


def test_has_c_cpp_source_ignores_vcs_internals(tmp_path):
    """.git internals must not consume the file cap: a repo with
    hundreds of loose objects and one real C file was read as
    'no C source' pre-fix, silently skipping all prereq evidence."""
    objects = tmp_path / ".git" / "objects"
    objects.mkdir(parents=True)
    for i in range(300):
        (objects / f"obj{i:03d}").write_text("x")
    native = tmp_path / "src" / "native"
    native.mkdir(parents=True)
    (native / "addon.c").write_text("int f(void) { return 0; }\n")
    assert prereqs._has_c_cpp_source(tmp_path) is True


def test_has_c_cpp_source_false_without_c(tmp_path):
    (tmp_path / "app.js").write_text("x\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "HEAD").write_text("ref\n")
    assert prereqs._has_c_cpp_source(tmp_path) is False


def test_has_c_cpp_source_cap_still_bounds_walk(tmp_path):
    """Two-direction: the cap still applies to non-VCS files — a huge
    source-free tree returns False without unbounded work."""
    # Distractors at the walk root: os.walk processes a directory's
    # files before descending, so these deterministically hit the cap
    # before the subdirectory's C file is reached.
    for i in range(250):
        (tmp_path / f"d{i:03d}.md").write_text("x")
    deep = tmp_path / "zz" / "deep"
    deep.mkdir(parents=True)
    (deep / "late.c").write_text("int f(void);\n")
    assert prereqs._has_c_cpp_source(tmp_path, max_files=200) is False
