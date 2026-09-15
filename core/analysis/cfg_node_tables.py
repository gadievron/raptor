"""Grammar-backed node-type tables for the CFG / scope builders.

The Java and C++ builders drive refusal, local-scope collection and
loop modelling off tree-sitter node-type NAMES. A wrong name in one of
these tables fails silently in the dangerous direction: the construct
it was meant to catch simply never matches, so the guard it powers
(refuse-on-unmodellable, member-declarator barriers) is dead while the
build proceeds — the suppression-ward failure. A table entry once
named ``anonymous_class_body``, a node the installed grammar never
produces; methods containing anonymous classes built instead of
refusing and member declarators re-armed the vouch oracle.

This module is the single home for those tables, one instance per
grammar (per-grammar overrides are the per-instance values — node
names differ between grammars: ``block`` vs ``compound_statement``,
``enhanced_for_statement`` vs ``for_range_loop``). The closure test
(``core/analysis/tests/test_cfg_node_tables.py``) asserts, against the
installed grammar wheels, that every listed name is producible — a
dead or renamed entry fails CI instead of silently disarming a guard —
and that the builder modules consume these exact objects.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GrammarNodeTables:
    """Node-type tables one CFG builder keys on, bound to the grammar
    whose node inventory validates them.

    ``refused``: constructs whose control/data flow the builder cannot
    model faithfully — the build must refuse, never emit a wrong
    graph. Empty for builders that demote instead of refusing.

    ``scope_barriers``: nested scopes whose declarations are NOT
    locals of the enclosing function (lambda frames, class-like
    bodies). A missing member here hands field-grade names the
    "locals are unaliasable" premise.

    ``scope_bounds``: constructs that bound a declarator's vouch
    window. Missing a member widens a window toward the function end
    (suppression-ward), so these err inclusive.

    ``loops``: the loop statement node types the builder dispatches —
    each must also bound declarator scope (asserted by the closure
    test).
    """

    builder_module: str
    grammar_module: str
    refused: frozenset[str]
    scope_barriers: frozenset[str]
    scope_bounds: frozenset[str]
    loops: frozenset[str]


JAVA_TABLES = GrammarNodeTables(
    builder_module="core.analysis.cfg_builder_java",
    grammar_module="tree_sitter_java",
    # switch stays refused so a switch nested in VALUE position
    # (inside any expression payload) refuses via the subtree walk;
    # statement-position switch is dispatched before the check. The
    # pinned grammar produces ``switch_expression`` for BOTH statement
    # and value positions (there is no ``switch_statement`` node kind
    # — the closure test rejects it as a dead entry; a grammar upgrade
    # that re-splits the kinds fails the producibility test and forces
    # a table review).
    refused=frozenset({
        "lambda_expression",
        "method_reference",
        "switch_expression",
        "class_declaration",         # local class inside a method body
        # Class-like BODIES, not declaration kinds: refusing the body
        # node covers every spelling that can nest one in a method —
        # anonymous classes (object_creation_expression carrying a
        # class_body, the only class-shaped construct with no
        # declaration node), local records (class_body), local enums /
        # interfaces / annotations. A declarator inside any of these
        # binds a MEMBER of the nested type, not a method local.
        "class_body",
        "enum_body",
        "interface_body",
        "annotation_type_body",
    }),
    scope_barriers=frozenset({
        "class_declaration",
        "class_body",
        "enum_body",
        "interface_body",
        "annotation_type_body",
        "lambda_expression",
        "method_reference",
    }),
    scope_bounds=frozenset({
        "block",
        "for_statement",
        "enhanced_for_statement",
        "while_statement",
        "do_statement",
        "if_statement",
        "switch_expression",
        "switch_block",
        "try_statement",
        "try_with_resources_statement",
        "catch_clause",
        "synchronized_statement",
    }),
    loops=frozenset({
        "while_statement",
        "for_statement",
        "enhanced_for_statement",
        "do_statement",
    }),
)


CPP_TABLES = GrammarNodeTables(
    builder_module="core.analysis.cfg_builder_cpp",
    # The builder serves both the C and C++ grammars; validation runs
    # against tree-sitter-cpp, whose node inventory is the superset
    # (C++-only names like lambda_expression / class_specifier never
    # match in a C parse — degradation, not a wrong match).
    grammar_module="tree_sitter_cpp",
    # The C/C++ builder demotes unmodellable stores (may_escape, no
    # assigned_names) instead of refusing whole builds.
    refused=frozenset(),
    scope_barriers=frozenset({
        "lambda_expression",
        "class_specifier",
        "struct_specifier",
        "union_specifier",
    }),
    scope_bounds=frozenset({
        "compound_statement",
        "for_statement",
        "for_range_loop",
        "while_statement",
        "do_statement",
        "if_statement",
        "switch_statement",
        "case_statement",
        "catch_clause",
    }),
    # ``for_range_loop`` is deliberately absent: the builder does not
    # dispatch it (the whole construct collapses to one straight-line
    # node — contained by the value-gate discipline, since collapsed
    # call sites carry no assigned_names). It still bounds declarator
    # scope above.
    loops=frozenset({
        "while_statement",
        "for_statement",
        "do_statement",
    }),
)


# Registry the closure test enumerates. Every tree-sitter-backed CFG
# builder module must have exactly one entry (the Python builder is
# ast-backed and exempt).
GRAMMAR_NODE_TABLES: dict[str, GrammarNodeTables] = {
    "java": JAVA_TABLES,
    "cpp": CPP_TABLES,
}


__all__ = [
    "CPP_TABLES",
    "GRAMMAR_NODE_TABLES",
    "GrammarNodeTables",
    "JAVA_TABLES",
]
