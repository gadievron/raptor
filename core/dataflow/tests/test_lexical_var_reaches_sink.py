"""Unit tests for _lexical_var_reaches_sink (a204f309 rebind-KILL).

The non-Python value-reach in the charset prescreen / SMT tier-0 path used
a bare `\\bvar\\b` match at the sink with no rebind-KILL, so a decoy
charset guard on a variable that was later re-tainted still suppressed a
live JS/TS/Java finding. This helper mirrors the Python AST rebind-KILL
lexically.
"""
from __future__ import annotations

from core.dataflow.smt_barrier import _lexical_var_reaches_sink


def _reaches(src, var, validator_line, sink_line):
    lines = src.splitlines()
    sink_text = lines[sink_line - 1]
    return _lexical_var_reaches_sink(var, src, validator_line, sink_line, sink_text)


def test_no_rebind_reaches():
    # validated value flows straight to the sink -> still a valid guard
    src = (
        "function h(req){\n"          # 1
        "  let p = validate(req.q);\n"  # 2 validator
        "  exec(p);\n"                  # 3 sink
        "}\n"
    )
    assert _reaches(src, "p", 2, 3) is True


def test_rebind_from_nonself_rhs_kills():
    # a204f309: p is re-tainted after the guard -> must NOT reach validated
    src = (
        "function h(req){\n"          # 1
        "  let p = validate(req.q);\n"  # 2 validator
        "  p = req.query.evil;\n"       # 3 rebind from attacker data
        "  exec(p);\n"                  # 4 sink
        "}\n"
    )
    assert _reaches(src, "p", 2, 4) is False


def test_self_referencing_rebind_does_not_kill():
    # p = p + '/' keeps p's validated constraint tie -> not a KILL
    src = (
        "function h(req){\n"
        "  let p = validate(req.q);\n"  # 2
        "  p = p + '/x';\n"             # 3 self-referencing
        "  exec(p);\n"                  # 4
        "}\n"
    )
    assert _reaches(src, "p", 2, 4) is True


def test_member_and_index_writes_are_not_rebinds():
    src = (
        "function h(req){\n"
        "  let p = validate(req.q);\n"  # 2
        "  p.field = req.query.evil;\n"  # 3 member write, p still validated
        "  p[0] = 9;\n"                  # 4 index write
        "  exec(p);\n"                   # 5
        "}\n"
    )
    assert _reaches(src, "p", 2, 5) is True


def test_comparison_is_not_a_rebind():
    src = (
        "function h(req){\n"
        "  let p = validate(req.q);\n"  # 2
        "  if (p == 'x') {}\n"          # 3 comparison, not assignment
        "  exec(p);\n"                  # 4
        "}\n"
    )
    assert _reaches(src, "p", 2, 4) is True


def test_absent_at_sink_does_not_reach():
    src = (
        "function h(req){\n"
        "  let p = validate(req.q);\n"  # 2
        "  exec(other);\n"              # 3 sink uses a different var
        "}\n"
    )
    assert _reaches(src, "p", 2, 3) is False


def test_compound_assign_with_taint_kills():
    """``p += req.query.evil`` mixes unvalidated data — the lexical
    analogue of the AST path's AugAssign kill.  Pre-fix the rebind
    regex matched only the plain ``=`` spelling, so the mix slid
    through and the prescreen suppressed a live flow."""
    src = (
        "function h(req){\n"            # 1
        "  let p = validate(req.q);\n"  # 2 validator
        "  p += req.query.evil;\n"      # 3 mixes taint
        "  exec(p);\n"                  # 4 sink
        "}\n"
    )
    assert _reaches(src, "p", 2, 4) is False


def test_other_compound_operators_kill_too():
    for op in ("-=", "*=", "/=", "%=", "&=", "|=", "^=",
               "<<=", ">>=", "**=", "||=", "&&=", "??="):
        src = (
            "function h(req){\n"
            "  let p = validate(req.q);\n"
            f"  p {op} req.query.evil;\n"
            "  exec(p);\n"
            "}\n"
        )
        assert _reaches(src, "p", 2, 4) is False, op


def test_compound_assign_pure_self_survives():
    """``p += p`` references only the validated value itself — no new
    data enters, the reach survives (mirrors the AST rule)."""
    src = (
        "function h(req){\n"
        "  let p = validate(req.q);\n"
        "  p += p;\n"
        "  exec(p);\n"
        "}\n"
    )
    assert _reaches(src, "p", 2, 4) is True


def test_comparison_operators_still_not_rebinds():
    """``<=`` / ``>=`` / ``!=`` must not read as compound assigns."""
    src = (
        "function h(req){\n"
        "  let p = validate(req.q);\n"
        "  if (p <= limit) { log(p); }\n"
        "  exec(p);\n"
        "}\n"
    )
    assert _reaches(src, "p", 2, 4) is True
