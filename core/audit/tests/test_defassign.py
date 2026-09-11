"""Definite-assignment prover — unit tests.

The prover certifies "the claimed variable is assigned on every path
to every use" over macro-expanded C.  These tests pin the two sides of
its contract: the shapes it must PROVE (structured assignment on all
paths, iterator-macro expansion from the target tree's own headers,
parameter/static trivia, SMT-discharged contradictory branches) and —
more importantly — the shapes it must REFUSE (every red-team fixture
with a real or undecidable uninitialised path must yield NO PROOF).
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_c")

from core.audit.defassign import (
    check_definite_assignment,
    function_local_names,
    resolve_include_closure,
)


def _check(src: str, var: str = "v", **kw):
    return check_definite_assignment(src, var, **kw)


# ---------------------------------------------------------------------------
# Structural proofs (macro-free)
# ---------------------------------------------------------------------------


class TestStructuralProofs:
    def test_both_branches_assign(self):
        r = _check("int f(int a){int v; if(a>0){v=1;}else{v=2;} return v;}")
        assert r.proven and r.method == "structural"

    def test_straightline_assign(self):
        r = _check("int f(void){int v; v = 3; return v;}")
        assert r.proven

    def test_use_confined_to_assigning_branch(self):
        r = _check("int f(int a){int v; if(a>0){v=1; g(v);} return 0;}")
        assert r.proven

    def test_do_while_body_assigns(self):
        r = _check("int f(int n){int v; do{v=1;}while(n--); return v;}")
        assert r.proven

    def test_for_counter_is_claimed_variable(self):
        r = _check(
            "int f(int n){int i; for(i=0;i<n;i++) g(i); return i;}", "i",
        )
        assert r.proven

    def test_assignment_inside_condition(self):
        r = _check(
            "int f(void){int v; if((v = g()) != 0) return v; return v;}",
        )
        assert r.proven

    def test_infinite_loop_assign_then_break(self):
        r = _check("int f(int n){int v; while(1){ v=1; break;} return v;}")
        assert r.proven

    def test_comma_and_ternary_rhs(self):
        assert _check("int f(int a){int v; v = (a, 3); return v;}").proven
        assert _check(
            "int f(int a){int v; v = a ? 1 : 2; return v;}",
        ).proven

    def test_parameter_is_trivially_assigned(self):
        r = _check("int f(int v){return v;}")
        assert r.proven
        assert "parameter" in r.reason

    def test_static_local_is_zero_initialized(self):
        r = _check("int f(void){static int v; return v;}")
        assert r.proven
        assert "static" in r.reason

    def test_declaration_initializer(self):
        assert _check("int f(void){int v = 4; return v;}").proven


# ---------------------------------------------------------------------------
# Red-team refusals — every fixture with a real or undecidable
# uninitialised path must yield NO PROOF
# ---------------------------------------------------------------------------


class TestRefusals:
    def test_goto_path_skips_assignment(self):
        r = _check(
            "int f(int a){int v; if(a) goto out; v=1; out: return v;}",
        )
        assert not r.proven

    def test_label_alone_refuses(self):
        r = _check("int f(void){int v; v=1; out: return v;}")
        assert not r.proven

    def test_switch_without_default(self):
        r = _check(
            "int f(int a){int v; switch(a){case 1: v=1; break;"
            " case 2: v=2; break;} return v;}",
        )
        assert not r.proven

    def test_switch_with_default_still_refuses(self):
        # Fallthrough semantics are out of scope wholesale.
        r = _check(
            "int f(int a){int v; switch(a){default: v=1;} return v;}",
        )
        assert not r.proven

    def test_partial_struct_initialization(self):
        r = _check(
            "struct s{int a;int b;};"
            " struct s f(void){struct s v; v.a=1; return v;}",
        )
        assert not r.proven

    def test_address_taken_then_written_through_pointer(self):
        r = _check("int f(void){int v; int *p=&v; *p=5; return v;}")
        assert not r.proven
        assert "address" in r.reason

    def test_single_branch_assignment(self):
        r = _check("int f(int a){int v; if(a>0) v=1; return v;}")
        assert not r.proven

    def test_loop_body_assignment_only(self):
        r = _check(
            "int f(int n){int v; int i;"
            " for(i=0;i<n;i++) v=1; return v;}",
        )
        assert not r.proven

    def test_assignment_under_short_circuit(self):
        r = _check(
            "int f(int a){int v; if(a && (v=g())) return v; return 0;}",
        )
        assert not r.proven

    def test_assignment_under_ternary(self):
        r = _check("int f(int a){int v; a ? (v=1) : 2; return v;}")
        assert not r.proven

    def test_self_referential_initializer(self):
        assert not _check("int f(void){int v = v; return v;}").proven

    def test_shadowing_declaration(self):
        r = _check(
            "int f(int a){int v=1; if(a){int v; g(v);} return v;}",
        )
        assert not r.proven

    def test_asm_refuses(self):
        r = _check(
            'int f(void){int v; __asm__("nop"); v=1; return v;}',
        )
        assert not r.proven

    def test_setjmp_refuses(self):
        r = _check(
            "int f(void){int v; jmp_buf b;"
            " if(setjmp(b)) return v; v=1; return v;}",
        )
        assert not r.proven

    def test_statement_expression_refuses(self):
        r = _check("int f(void){int v; v = ({int t=1; t;}); return v;}")
        assert not r.proven

    def test_read_before_assignment(self):
        assert not _check("int f(void){int v; g(v); v=1; return v;}").proven

    def test_sibling_declarator_reads_unassigned(self):
        assert not _check("int f(void){int v, w = v; return w;}").proven

    def test_compound_assign_and_update_on_unassigned(self):
        assert not _check("int f(void){int v; v += 1; return v;}").proven
        assert not _check("int f(void){int v; v++; return v;}").proven

    def test_break_before_assignment(self):
        r = _check(
            "int f(int n){int v; while(1){ if(n) break; v=1; break;}"
            " return v;}",
        )
        assert not r.proven

    def test_extern_declaration_refuses(self):
        assert not _check("int f(void){extern int v; return v;}").proven

    def test_preprocessor_directive_inside_function(self):
        r = _check(
            "int f(void){int v;\n#ifdef X\n v=1;\n#endif\n return v;}",
        )
        assert not r.proven
        assert "preprocessor" in r.reason

    def test_undeclared_variable_refuses(self):
        assert not _check("int f(void){int w = 1; return w;}", "v").proven

    def test_non_identifier_refuses(self):
        assert not _check("int f(void){int v=1; return v;}", "v x").proven


# ---------------------------------------------------------------------------
# Macro expansion from the target tree's headers
# ---------------------------------------------------------------------------


_ITER_H = """\
#ifndef _MINI_ITER_H
#define _MINI_ITER_H
#include <mini/base.h>

#define entry_of(ptr, type, member) ({ \\
\tvoid *__eptr = (void *)(ptr); \\
\t((type *)(__eptr - offset_of(type, member))); })

#define first_node(head, type, member) \\
\tentry_of((head)->next, type, member)

#define node_is_head(pos, head, member) (&pos->member == (head))

#define next_node(pos, member) \\
\tentry_of((pos)->member.next, typeof(*(pos)), member)

#define for_each_node(pos, head, member) \\
\tfor (pos = first_node(head, typeof(*pos), member); \\
\t     !node_is_head(pos, head, member); \\
\t     pos = next_node(pos, member))
#endif
"""

_BASE_H = """\
#ifndef _MINI_BASE_H
#define _MINI_BASE_H
#undef offset_of
#define offset_of(t, m) __builtin_offsetof(t, m)
#define MININULL ((void *)0)
#endif
"""

_FINDER_C = """\
#include <mini/iter.h>

struct node { struct node *next; };
struct item { const char *name; struct node link; };

static struct item *find_item(struct node *all, const char *want)
{
\tstruct item *it;

\tfor_each_node(it, all, link)
\t\tif (!namecmp(want, it->name))
\t\t\treturn it;

\treturn MININULL;
}
"""


def _write_tree(tmp_path: Path) -> Path:
    root = tmp_path / "target"
    (root / "include" / "mini").mkdir(parents=True)
    (root / "src").mkdir()
    (root / "include" / "mini" / "iter.h").write_text(_ITER_H)
    (root / "include" / "mini" / "base.h").write_text(_BASE_H)
    (root / "src" / "finder.c").write_text(_FINDER_C)
    return root


def _finder_source(root: Path) -> str:
    lines = (root / "src" / "finder.c").read_text().splitlines(
        keepends=True,
    )
    return "".join(lines[5:])  # the function definition only


class TestMacroExpansion:
    def test_iterator_macro_proves(self, tmp_path):
        root = _write_tree(tmp_path)
        r = check_definite_assignment(
            _finder_source(root), "it",
            target_path=root, rel_file="src/finder.c",
        )
        assert r.proven, r.reason
        assert "for_each_node" in r.expanded_macros
        assert "first_node" in r.expanded_macros
        assert r.macro_files_scanned == 3

    def test_iterator_macro_without_headers_refuses(self, tmp_path):
        # Same function, no header tree: the iterator macro cannot be
        # located, the spliced control structure never materialises,
        # and the raw text does not parse as C → no proof.
        root = tmp_path / "bare"
        (root / "src").mkdir(parents=True)
        (root / "src" / "finder.c").write_text(_FINDER_C)
        r = check_definite_assignment(
            _finder_source(root), "it",
            target_path=root, rel_file="src/finder.c",
        )
        assert not r.proven

    def test_macro_conditional_assignment_refuses(self, tmp_path):
        root = tmp_path / "target"
        (root / "include").mkdir(parents=True)
        (root / "include" / "setif.h").write_text(
            "#define SET_IF(c, x) do { if (c) x = 1; } while (0)\n",
        )
        (root / "m.c").write_text(
            '#include "include/setif.h"\n'
            "int f(int a){int v; SET_IF(a, v); return v;}\n",
        )
        r = check_definite_assignment(
            "int f(int a){int v; SET_IF(a, v); return v;}", "v",
            target_path=root, rel_file="m.c",
        )
        assert not r.proven

    def test_macro_unconditional_assignment_proves(self, tmp_path):
        root = tmp_path / "target"
        (root / "include").mkdir(parents=True)
        (root / "include" / "setif.h").write_text(
            "#define SET(x) do { x = 1; } while (0)\n",
        )
        (root / "m.c").write_text(
            '#include "include/setif.h"\n'
            "int f(int a){int v; SET(v); return v;}\n",
        )
        r = check_definite_assignment(
            "int f(int a){int v; SET(v); return v;}", "v",
            target_path=root, rel_file="m.c",
        )
        assert r.proven

    def test_conflicting_definitions_refuse(self, tmp_path):
        root = tmp_path / "target"
        (root / "include").mkdir(parents=True)
        (root / "include" / "a.h").write_text("#define GET() (1)\n")
        (root / "include" / "b.h").write_text("#define GET() (2)\n")
        (root / "m.c").write_text(
            '#include "include/a.h"\n#include "include/b.h"\n'
            "int f(void){int v; v = GET(); return v;}\n",
        )
        r = check_definite_assignment(
            "int f(void){int v; v = GET(); return v;}", "v",
            target_path=root, rel_file="m.c",
        )
        assert not r.proven
        assert "conflicting" in r.reason

    def test_claimed_variable_named_by_macro_refuses(self, tmp_path):
        root = tmp_path / "target"
        root.mkdir()
        (root / "m.c").write_text(
            "#define v other\nint f(void){int v; v = 1; return v;}\n",
        )
        r = check_definite_assignment(
            "int f(void){int v; v = 1; return v;}", "v",
            target_path=root, rel_file="m.c",
        )
        assert not r.proven
        assert "macro" in r.reason

    def test_macro_taking_address_refuses(self, tmp_path):
        root = tmp_path / "target"
        root.mkdir()
        (root / "m.c").write_text(
            "#define FILL(x) initbuf(&x)\n"
            "int f(void){int v; FILL(v); return v;}\n",
        )
        r = check_definite_assignment(
            "int f(void){int v; FILL(v); return v;}", "v",
            target_path=root, rel_file="m.c",
        )
        assert not r.proven

    def test_macro_with_function_fallback_declaration_refuses(
        self, tmp_path,
    ):
        # Config-guarded macro + closure-visible function declaration
        # of the same name: the alternate config compiles a by-value
        # CALL (which cannot assign) where the text shows an assigning
        # macro — no conflicting #define, nothing invisible.  The
        # name collision is treated as a conflict.
        root = tmp_path / "target"
        root.mkdir()
        (root / "cfg.h").write_text(
            "#ifdef CONFIG_FASTINIT\n"
            "#define INIT_V(x) do { x = 1; } while (0);\n"
            "#endif\n"
            "void INIT_V(int x);\n",
        )
        (root / "m.c").write_text(
            '#include "cfg.h"\n'
            "int f(int c){int v; INIT_V(v); return v;}\n",
        )
        r = check_definite_assignment(
            "int f(int c){int v; INIT_V(v); return v;}", "v",
            target_path=root, rel_file="m.c",
        )
        assert not r.proven
        assert "declared as a function" in r.reason

    def test_keyword_macro_defeats_constant_folding(self, tmp_path):
        # The walk's constant-condition folding believes literal truth
        # values — the one polarity-sensitive structural step.  A
        # keyword-named macro in the closure (`#define if`) could
        # invert or kill a branch, so it must disable the folding:
        # `if (1) v = 1;` no longer proves.
        root = tmp_path / "target"
        root.mkdir()
        (root / "kw.h").write_text("#define if(c) if (0 && (c))\n")
        (root / "m.c").write_text(
            '#include "kw.h"\n'
            "int f(void){int v; if (1) { v = 1; } return v;}\n",
        )
        r = check_definite_assignment(
            "int f(void){int v; if (1) { v = 1; } return v;}", "v",
            target_path=root, rel_file="m.c",
        )
        assert not r.proven
        # Control: without the keyword macro the same shape proves.
        assert _check(
            "int f(void){int v; if (1) { v = 1; } return v;}",
        ).proven

    def test_macro_hiding_control_escape_refuses(self, tmp_path):
        root = tmp_path / "target"
        root.mkdir()
        (root / "m.c").write_text(
            "#define BAIL_ZERO(x) (x ? x : ({ return 0; 0; }))\n"
            "int f(int a){int v; v = BAIL_ZERO(a); return v;}\n",
        )
        r = check_definite_assignment(
            "int f(int a){int v; v = BAIL_ZERO(a); return v;}", "v",
            target_path=root, rel_file="m.c",
        )
        assert not r.proven

    def test_expression_macro_guard_branch_stays_unknown(self, tmp_path):
        # An expression-shaped macro guard reduces to a placeholder;
        # the placeholder must be OPAQUE, not a constant.  A constant
        # (0) lets the walker const-fold the guarded branch away and
        # erase the uninitialized use inside it — a false proof.
        root = tmp_path / "target"
        root.mkdir()
        (root / "m.c").write_text(
            "#define GUARD(c) (!!(c))\n"
            "int f(int a){int v; if (GUARD(a)) { return v; }"
            " v = 1; return v;}\n",
        )
        r = check_definite_assignment(
            "int f(int a){int v; if (GUARD(a)) { return v; }"
            " v = 1; return v;}", "v",
            target_path=root, rel_file="m.c",
        )
        assert not r.proven

    def test_expression_macro_guard_both_arms_assigning_proves(
        self, tmp_path,
    ):
        # Control: the reduction itself stays usable — when both arms
        # of the macro-guarded branch assign, the proof still lands.
        root = tmp_path / "target"
        root.mkdir()
        (root / "m.c").write_text(
            "#define GUARD(c) (!!(c))\n"
            "int f(int a){int v; if (GUARD(a)) { v = 2; }"
            " else { v = 1; } return v;}\n",
        )
        r = check_definite_assignment(
            "int f(int a){int v; if (GUARD(a)) { v = 2; }"
            " else { v = 1; } return v;}", "v",
            target_path=root, rel_file="m.c",
        )
        assert r.proven, r.reason


# ---------------------------------------------------------------------------
# Z3 arm
# ---------------------------------------------------------------------------


class TestSmtArm:
    def _contradiction_src(self) -> str:
        return (
            "int f(int a){int v; if(a > 5) v=1;"
            " if(a > 5) return v; return 0;}"
        )

    def test_contradictory_branch_conditions_prove(self):
        pytest.importorskip("z3")
        r = _check(self._contradiction_src())
        assert r.proven
        assert r.method == "structural+smt"
        assert r.smt_paths_discharged >= 1

    def test_independent_conditions_refuse(self):
        r = _check(
            "int f(int a, int b){int v; if(a > 5) v=1;"
            " if(b > 5) return v; return 0;}",
        )
        assert not r.proven

    def test_overlapping_satisfiable_conditions_refuse(self):
        r = _check(
            "int f(int a){int v; if(a > 5) v=1;"
            " if(a > 3) return v; return 0;}",
        )
        assert not r.proven

    def test_condition_variable_mutated_refuses(self):
        # The naive condition conjunction is only faithful when every
        # named variable is immutable across the path.
        r = _check(
            "int f(int a){int v; if(a > 5) v=1; a = 0;"
            " if(a > 5) return v; return 0;}",
        )
        assert not r.proven

    def test_extern_condition_variable_refuses(self):
        # A function-scope extern is not a parameter: a call between
        # the two condition reads can change it, so joint
        # unsatisfiability over the reads is not a refutation.
        r = _check(
            "int f(void){ extern int g; extern void se(void); int v;"
            " if(g > 5) v=1; se(); if(g <= 5) return 0; return v;}",
        )
        assert not r.proven

    def test_uninit_local_condition_variable_refuses(self):
        # Reads of an indeterminate local are unstable (and UB) —
        # the SMT fence admits parameters only.
        r = _check(
            "int f(void){int c; int v;"
            " if(c > 5) v=1; if(c <= 5) return 0; return v;}",
        )
        assert not r.proven

    def test_initialized_local_condition_variable_refuses(self):
        # Parameters only — even a well-defined local is out of the
        # fence (margin over precision).
        r = _check(
            "int f(int a){int c = a; int v;"
            " if(c > 5) v=1; if(c <= 5) return 0; return v;}",
        )
        assert not r.proven

    def test_call_in_condition_refuses(self):
        # Two calls can return different values — same text is not the
        # same value.
        r = _check(
            "int f(void){int v; if(g() > 5) v=1;"
            " if(g() > 5) return v; return 0;}",
        )
        assert not r.proven

    def test_z3_absent_degrades_to_no_proof(self, monkeypatch):
        # Structural violations stay violations without the solver;
        # a structurally-proven case is unaffected.
        import core.audit.defassign as da
        monkeypatch.setattr(
            da, "_discharge_with_smt", lambda *_a, **_k: (False, 0),
        )
        assert not _check(self._contradiction_src()).proven
        assert _check("int f(void){int v; v=1; return v;}").proven


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_function_local_names(self):
        names = function_local_names(
            "int f(int a, char *b){int v; unsigned w = 1; return v;}",
        )
        assert {"a", "b", "v", "w"} <= names

    def test_resolve_include_closure(self, tmp_path):
        root = _write_tree(tmp_path)
        files, unresolved = resolve_include_closure(root, "src/finder.c")
        rels = {str(f.relative_to(root.resolve())) for f in files}
        assert rels == {
            "src/finder.c",
            "include/mini/iter.h",
            "include/mini/base.h",
        }
        assert unresolved == []

    def test_resolve_include_closure_reports_unresolved(self, tmp_path):
        root = tmp_path / "t"
        root.mkdir()
        (root / "m.c").write_text('#include <no/such.h>\nint x;\n')
        files, unresolved = resolve_include_closure(root, "m.c")
        assert len(files) == 1
        assert unresolved == ["<no/such.h>"]

    def test_closure_containment_not_prefix_based(self, tmp_path):
        # /x/tree vs /x/tree-evil share a string prefix; a symlink
        # escaping into the sibling must resolve as OUTSIDE the tree
        # (path containment, not str.startswith).
        root = tmp_path / "tree"
        evil = tmp_path / "tree-evil"
        root.mkdir()
        evil.mkdir()
        (evil / "h.h").write_text("#define GONE 1\n")
        (root / "m.c").write_text('#include "esc.h"\nint x;\n')
        (root / "esc.h").symlink_to(evil / "h.h")
        files, unresolved = resolve_include_closure(root, "m.c")
        resolved_names = {f.name for f in files}
        assert "h.h" not in resolved_names
        assert '"esc.h"' in unresolved

    def test_function_parameter_names(self):
        from core.audit.defassign import function_parameter_names
        names = function_parameter_names(
            "int f(int a, char *b){int v; return v;}",
        )
        assert names == frozenset({"a", "b"})


class TestInitDeclaratorSizeReads:
    def test_vla_size_read_in_initialized_declarator_not_proven(self):
        # ``int (*rows)[x] = get_rows();`` evaluates x at the
        # declaration; the init branch only scanned the initializer,
        # so the prover certified "assigned before every use" over an
        # uninitialized size read.
        r = _check(
            "int f(int a){int x; int (*rows)[x] = get_rows();"
            " x = a; return x;}",
            "x",
        )
        assert not r.proven

    def test_assigned_size_read_still_proven(self):
        # Two-direction guard: the same shape with x assigned FIRST
        # stays provable.
        r = _check(
            "int f(int a){int x; x = a;"
            " int (*rows)[x] = get_rows(); return x;}",
            "x",
        )
        assert r.proven
