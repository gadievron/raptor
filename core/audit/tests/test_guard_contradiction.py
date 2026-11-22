"""Guard-contradiction oracle — unit and lifetime-witness tests.

The oracle may only NARROW lifetime-witness refusals: a release and a
later use whose governing ``if`` conditions are PROVEN jointly
unsatisfiable lie on an infeasible lexical path and are discharged;
every unproven, unmodeled or unadmitted construct keeps today's
conservative refusal. The red-team cases here are shapes where the
claimed bug is REAL (or could be) and a discharge would manufacture a
false negative — each must keep refusing.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_c")

from core.audit.defassign import (
    _node_text,
    _parse_function,
    _walk_nodes,
    function_scope_names,
)
from core.audit.guard_contradiction import GuardContradictionOracle
from core.audit.lifetime_witness import check_lifetime_claim
from core.smt_solver.availability import z3 as _z3

needs_z3 = pytest.mark.skipif(_z3 is None, reason="z3 unavailable")

REL = "src/mod.c"

UAF_CLAIM = "Use-after-free: p freed at line 7 and then used later"
DF_CLAIM = "Double-free of p: p freed at line 7 then again at line 9"


# ---------------------------------------------------------------------------
# Direct oracle harness
# ---------------------------------------------------------------------------


def _oracle(src: str, macro_names: frozenset[str] = frozenset()):
    fn = _parse_function(src)
    locals_, params = function_scope_names(src)
    oracle = GuardContradictionOracle(
        fn, locals_=locals_, params=params,
        params_admissible=True, macro_names=macro_names,
    )
    return oracle, fn


def _stmt_of_call(fn, callee: str):
    body = fn.child_by_field_name("body")
    for n in _walk_nodes(body):
        if n.type == "call_expression":
            f = n.child_by_field_name("function")
            if f is not None and _node_text(f) == callee:
                st = n
                while st is not None and st.type != "expression_statement":
                    st = st.parent
                assert st is not None
                return st
    raise AssertionError(f"no call to {callee}")


def _contra(src: str, macro_names: frozenset[str] = frozenset()) -> bool:
    oracle, fn = _oracle(src, macro_names)
    return oracle.contradicts(
        _stmt_of_call(fn, "rel"), _stmt_of_call(fn, "use"),
    )


# ---------------------------------------------------------------------------
# Direct: contradictions the oracle must prove
# ---------------------------------------------------------------------------


@needs_z3
def test_opposite_truthiness_contradicts():
    assert _contra("""
void h(int a)
{
\tint err = a;
\tif (err)
\t\trel();
\tif (!err)
\t\tuse();
}
""") is True


@needs_z3
def test_else_branch_polarity_contradicts():
    assert _contra("""
void h(int a)
{
\tint err = a;
\tif (err)
\t\trel();
\telse
\t\tuse();
}
""") is True


@needs_z3
def test_relational_split_contradicts():
    assert _contra("""
void h(int n)
{
\tif (n > 8)
\t\trel();
\tif (n <= 8)
\t\tuse();
}
""") is True


@needs_z3
def test_conjunction_against_negated_conjunct_contradicts():
    assert _contra("""
void h(int a, int b)
{
\tif (a && b)
\t\trel();
\tif (!a)
\t\tuse();
}
""") is True


@needs_z3
def test_const_local_is_admitted():
    assert _contra("""
void h(int a)
{
\tconst int err = a;
\tif (err)
\t\trel();
\tif (!err)
\t\tuse();
}
""") is True


@needs_z3
def test_hex_literal_split_contradicts():
    assert _contra("""
void h(int v)
{
\tif (v == 0x10)
\t\trel();
\tif (v != 0x10)
\t\tuse();
}
""") is True


@needs_z3
def test_unsigned_nonnegativity_is_encoded():
    # Signed reading is satisfiable (v = -5 performs both); only the
    # v >= 0 constraint of the unsigned type makes the pair impossible.
    assert _contra("""
void h(unsigned int v)
{
\tif (v <= 0)
\t\trel();
\tif (v != 0)
\t\tuse();
}
""") is True


@needs_z3
def test_signed_negative_literal_contradicts():
    assert _contra("""
void h(int v)
{
\tif (v == -1)
\t\trel();
\tif (v != -1)
\t\tuse();
}
""") is True


# ---------------------------------------------------------------------------
# Direct: red team — a True here would discharge a feasible pair
# ---------------------------------------------------------------------------


def test_same_polarity_is_satisfiable():
    assert _contra("""
void h(int a)
{
\tint err = a;
\tif (err)
\t\trel();
\tif (err)
\t\tuse();
}
""") is False


def test_disjunction_leaves_a_joint_model():
    # a = 0, b = 1 performs both statements.
    assert _contra("""
void h(int a, int b)
{
\tif (a || b)
\t\trel();
\tif (!a)
\t\tuse();
}
""") is False


def test_unguarded_use_never_contradicts():
    assert _contra("""
void h(int a)
{
\tint err = a;
\tif (err)
\t\trel();
\tuse();
}
""") is False


def test_goto_disables_the_oracle():
    # A jump target inside a branch would break "entry implies the
    # condition held" — any goto/label disables the whole function.
    assert _contra("""
void h(int a)
{
\tint err = a;
\tif (err)
\t\trel();
\tif (!err)
\t\tuse();
\tgoto out;
out:
\treturn;
}
""") is False


def test_switch_disables_the_oracle():
    assert _contra("""
void h(int a, int b)
{
\tint err = a;
\tswitch (b) {
\tcase 0:
\t\tbreak;
\t}
\tif (err)
\t\trel();
\tif (!err)
\t\tuse();
}
""") is False


def test_written_guard_is_refused():
    assert _contra("""
void h(int a)
{
\tint err = a;
\tif (err)
\t\trel();
\terr = 0;
\tif (!err)
\t\tuse();
}
""") is False


def test_updated_guard_is_refused():
    assert _contra("""
void h(int a)
{
\tint err = a;
\tif (err)
\t\trel();
\terr++;
\tif (!err)
\t\tuse();
}
""") is False


def test_addressed_guard_is_refused():
    assert _contra("""
void h(int a)
{
\tint err = a;
\tif (err)
\t\trel();
\tprobe(&err);
\tif (!err)
\t\tuse();
}
""") is False


def test_call_in_condition_is_refused():
    # probe() may answer differently per evaluation — no single value.
    assert _contra("""
void h(int a)
{
\tif (probe(a))
\t\trel();
\tif (!probe(a))
\t\tuse();
}
""") is False


def test_variable_to_variable_comparison_is_refused():
    # Mixed-signedness conversion makes var-vs-var width-dependent.
    assert _contra("""
void h(int a, int b)
{
\tif (a < b)
\t\trel();
\tif (a >= b)
\t\tuse();
}
""") is False


def test_declaration_inside_loop_is_refused():
    # err re-initialises per iteration: rel() in one iteration and
    # use() in the next is a REAL cross-iteration pair.
    assert _contra("""
void h(int n)
{
\twhile (n) {
\t\tint err = probe(n);
\t\tif (err)
\t\t\trel();
\t\tif (!err)
\t\t\tuse();
\t}
}
""") is False


def test_shadowed_guard_is_refused():
    assert _contra("""
void h(int a)
{
\tint err = a;
\tif (err)
\t\trel();
\t{
\t\tint err = 0;
\t\tnote(err);
\t}
\tif (!err)
\t\tuse();
}
""") is False


def test_macro_named_guard_is_refused():
    src = """
void h(int a)
{
\tint err = a;
\tif (err)
\t\trel();
\tif (!err)
\t\tuse();
}
"""
    assert _contra(src, macro_names=frozenset({"err"})) is False


def test_uninitialised_local_is_refused():
    # An indeterminate value need not read the same twice.
    assert _contra("""
void h(int a)
{
\tint err;
\tif (err)
\t\trel();
\tif (!err)
\t\tuse();
}
""") is False


def test_volatile_guard_is_refused():
    assert _contra("""
void h(int a)
{
\tvolatile int err = a;
\tif (err)
\t\trel();
\tif (!err)
\t\tuse();
}
""") is False


def test_negative_literal_against_unsigned_is_refused():
    # (unsigned)v == -1 converts width-dependently; the mathematical
    # encoding would prove a contradiction the hardware may not honour.
    assert _contra("""
void h(unsigned int v)
{
\tif (v == -1)
\t\trel();
\tif (v != -1)
\t\tuse();
}
""") is False


def test_suffixed_literal_is_refused():
    assert _contra("""
void h(int v)
{
\tif (v == 5u)
\t\trel();
\tif (v != 5u)
\t\tuse();
}
""") is False


def test_bitwise_operator_is_refused():
    assert _contra("""
void h(int a)
{
\tint err = a;
\tif (err & 4)
\t\trel();
\tif (!(err & 4))
\t\tuse();
}
""") is False


# ---------------------------------------------------------------------------
# Lifetime-witness integration harness
# ---------------------------------------------------------------------------


def _check(
    tmp_path: Path,
    func_source: str,
    mechanism: str,
    cwes: set[str],
    *,
    prelude: str = "",
):
    f = tmp_path / REL
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(prelude + "\n" + func_source + "\n")
    return check_lifetime_claim(
        func_source, mechanism, frozenset(cwes),
        target_path=tmp_path, rel_file=REL, vocab=None,
    )


_NOUSE_CONTRA = """
static int reap(struct ctx *c, int a)
{
\tstruct filt *p = get_obj(c);
\tint err = a;

\tif (err)
\t\tkfree(p);
\tif (!err)
\t\tconsume(c, p);
\treturn 0;
}
"""


@needs_z3
def test_nouse_discharges_guard_contradictory_use(tmp_path):
    r = _check(tmp_path, _NOUSE_CONTRA, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is True
    assert "discharged" in r.reason
    assert "SMT" in r.reason


def test_nouse_same_polarity_keeps_refusing(tmp_path):
    src = _NOUSE_CONTRA.replace("if (!err)\n\t\tconsume",
                                "if (err)\n\t\tconsume")
    r = _check(tmp_path, src, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is False
    assert "occurs after the release" in r.reason


def test_nouse_unguarded_use_keeps_refusing(tmp_path):
    src = _NOUSE_CONTRA.replace("\tif (!err)\n\t\tconsume(c, p);",
                                "\tconsume(c, p);")
    r = _check(tmp_path, src, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is False


def test_nouse_written_guard_keeps_refusing(tmp_path):
    src = _NOUSE_CONTRA.replace("\tif (!err)",
                                "\terr = fix(c);\n\tif (!err)")
    r = _check(tmp_path, src, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is False


def test_nouse_goto_keeps_refusing(tmp_path):
    src = _NOUSE_CONTRA.replace(
        "\treturn 0;",
        "\tif (a)\n\t\tgoto out;\nout:\n\treturn 0;",
    )
    r = _check(tmp_path, src, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is False


def test_nouse_bitwise_guard_keeps_refusing(tmp_path):
    src = _NOUSE_CONTRA.replace("if (err)", "if (err & 4)").replace(
        "if (!err)", "if (!(err & 4))",
    )
    r = _check(tmp_path, src, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is False


def test_nouse_volatile_guard_keeps_refusing(tmp_path):
    src = _NOUSE_CONTRA.replace("int err = a;", "volatile int err = a;")
    r = _check(tmp_path, src, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is False


def test_nouse_shadowed_guard_keeps_refusing(tmp_path):
    src = _NOUSE_CONTRA.replace(
        "\tif (!err)",
        "\t{\n\t\tint err = 0;\n\t\tnote(err);\n\t}\n\tif (!err)",
    )
    r = _check(tmp_path, src, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is False


@needs_z3
def test_nouse_parameter_guard_discharges(tmp_path):
    # Parameters are admissible: construction already certified every
    # invoked macro against the locals-including-parameters set.
    src = """
static int reap(struct ctx *c, int err)
{
\tstruct filt *p = get_obj(c);

\tif (err)
\t\tkfree(p);
\tif (!err)
\t\tconsume(c, p);
\treturn 0;
}
"""
    r = _check(tmp_path, src, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is True


def test_macro_writing_a_parameter_refuses_at_certification(tmp_path):
    # The reason parameters are admissible at all: a macro naming one
    # refuses the whole analysis before any oracle runs.
    src = """
static int reap(struct ctx *c, int err)
{
\tstruct filt *p = get_obj(c);

\tPOKE();
\tif (err)
\t\tkfree(p);
\tif (!err)
\t\tconsume(c, p);
\treturn 0;
}
"""
    r = _check(
        tmp_path, src, UAF_CLAIM, {"CWE-416"},
        prelude="#define POKE() (err = 1)\n",
    )
    assert r.discharged is False


@needs_z3
def test_nouse_discharges_derived_pointer_on_contradictory_branch(tmp_path):
    src = """
static int reap(struct ctx *c, int a)
{
\tstruct filt *p = get_obj(c);
\tstruct filt *q = p + 1;
\tint err = a;

\tif (err)
\t\tkfree(p);
\tif (!err)
\t\tconsume(c, q);
\treturn 0;
}
"""
    r = _check(tmp_path, src, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is True


@needs_z3
def test_nouse_signed_negative_literal_discharges(tmp_path):
    src = _NOUSE_CONTRA.replace("if (err)", "if (err == -1)").replace(
        "if (!err)", "if (err != -1)",
    )
    r = _check(tmp_path, src, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is True


def test_nouse_unsigned_negative_literal_keeps_refusing(tmp_path):
    src = _NOUSE_CONTRA.replace(
        "int err = a;", "unsigned int err = a;",
    ).replace("if (err)", "if (err == -1)").replace(
        "if (!err)", "if (err != -1)",
    )
    r = _check(tmp_path, src, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is False


_FREEPATH_CONTRA = """
static int reap2(struct ctx *c, int a)
{
\tstruct filt *p = get_obj(c);
\tint err = a;

\tif (err)
\t\tkfree(p);
\tif (!err)
\t\tkfree(p);
\treturn 0;
}
"""


@needs_z3
def test_freepath_discharges_guard_contradictory_sites(tmp_path):
    r = _check(tmp_path, _FREEPATH_CONTRA, DF_CLAIM, {"CWE-415"})
    assert r.discharged is True
    assert "jointly unsatisfiable" in r.reason


def test_freepath_same_polarity_keeps_refusing(tmp_path):
    src = _FREEPATH_CONTRA.replace("if (!err)", "if (err)")
    r = _check(tmp_path, src, DF_CLAIM, {"CWE-415"})
    assert r.discharged is False
    assert "two release sites lie on one path" in r.reason


def test_freepath_loop_refusal_keeps_priority(tmp_path):
    # A loop-enclosed site must surface as the loop refusal even when
    # the guards look contradictory.
    src = """
static int reap2(struct ctx *c, int a)
{
\tstruct filt *p = get_obj(c);
\tint err = a;
\tint i;

\tif (err)
\t\tkfree(p);
\tfor (i = 0; i < a; i++) {
\t\tif (!err)
\t\t\tkfree(p);
\t}
\treturn 0;
}
"""
    r = _check(tmp_path, src, DF_CLAIM, {"CWE-415"})
    assert r.discharged is False
    assert "inside a loop" in r.reason


def test_z3_absence_keeps_every_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr("core.smt_solver.availability.z3", None)
    r = _check(tmp_path, _NOUSE_CONTRA, UAF_CLAIM, {"CWE-416"})
    assert r.discharged is False
    assert "occurs after the release" in r.reason
