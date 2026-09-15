"""Closure tests for the grammar-backed CFG node-type tables.

A node-type name the installed grammar cannot produce is a DEAD table
entry: the guard it powers (refusal, scope barrier, vouch-window
bound) silently never matches while the build proceeds — the
suppression-ward failure direction. These tests make that class of
drift fail in CI instead.
"""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest

from core.analysis.cfg_node_tables import (
    GRAMMAR_NODE_TABLES,
    JAVA_TABLES,
)


def _language(grammar_module: str):
    mod = pytest.importorskip(grammar_module)
    from tree_sitter import Language

    return Language(mod.language())


# ---------------------------------------------------------------------------
# Registry closure: every tree-sitter-backed CFG builder module on
# disk has exactly one tables entry. The Python builder is ast-backed
# and exempt.
# ---------------------------------------------------------------------------


def test_every_grammar_backed_builder_registers_tables():
    analysis_dir = Path(__file__).resolve().parents[1]
    on_disk = {p.name for p in analysis_dir.glob("cfg_builder*.py")}
    registered = {
        t.builder_module.rsplit(".", 1)[1] + ".py"
        for t in GRAMMAR_NODE_TABLES.values()
    }
    assert on_disk == registered | {"cfg_builder.py"}, (
        "CFG-builder module set changed — every tree-sitter-backed "
        "builder must register its node-type tables in "
        "core.analysis.cfg_node_tables (grammar-validated here); "
        "only the ast-backed Python builder is exempt"
    )


# ---------------------------------------------------------------------------
# Grammar-node existence: every listed name must be producible by the
# installed grammar (id_for_node_kind != 0 for named kinds).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", sorted(GRAMMAR_NODE_TABLES))
def test_every_table_name_is_producible(key):
    tables = GRAMMAR_NODE_TABLES[key]
    lang = _language(tables.grammar_module)
    for field in ("refused", "scope_barriers", "scope_bounds", "loops"):
        names = getattr(tables, field)
        missing = sorted(
            n for n in names if not lang.id_for_node_kind(n, True)
        )
        assert missing == [], (
            f"{key}.{field}: node names {tables.grammar_module} cannot "
            f"produce (dead entries / grammar rename): {missing}"
        )


def test_dead_entry_negative_control():
    # The historical dead entry: tree-sitter-java has never produced
    # ``anonymous_class_body`` (anonymous classes emit ``class_body``).
    # This is exactly the drift shape the producibility test exists to
    # catch — pin that the oracle can see it.
    lang = _language("tree_sitter_java")
    # (id_for_node_kind returns a falsy value — 0 or None depending on
    # the py-tree-sitter version — for unknown kinds.)
    assert not lang.id_for_node_kind("anonymous_class_body", True)
    assert lang.id_for_node_kind("class_body", True)


# ---------------------------------------------------------------------------
# Consumption lock: the builder modules must consume THESE objects —
# a re-forked local copy would bypass the validation above.
# ---------------------------------------------------------------------------


_CONSUMED_ATTRS = {
    "_REFUSED_NODE_TYPES": "refused",
    "_LOCAL_SCOPE_BARRIERS": "scope_barriers",
    "_LOCAL_SCOPE_BOUNDS": "scope_bounds",
}


@pytest.mark.parametrize("key", sorted(GRAMMAR_NODE_TABLES))
def test_builders_consume_the_shared_tables(key):
    tables = GRAMMAR_NODE_TABLES[key]
    pytest.importorskip(tables.grammar_module)
    builder = importlib.import_module(tables.builder_module)
    for attr, field in _CONSUMED_ATTRS.items():
        if not hasattr(builder, attr):
            # The C/C++ builder demotes instead of refusing and has no
            # refusal set; its tables entry records that as empty.
            assert getattr(tables, field) == frozenset(), (
                f"{tables.builder_module} lacks {attr} but the shared "
                f"table's {field} is non-empty"
            )
            continue
        assert getattr(builder, attr) is getattr(tables, field), (
            f"{tables.builder_module}.{attr} is not the shared "
            f"cfg_node_tables object — local forks bypass the "
            f"grammar-validation closure"
        )


# ---------------------------------------------------------------------------
# Cross-table consistency
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key", sorted(GRAMMAR_NODE_TABLES))
def test_loop_constructs_bound_declarator_scope(key):
    tables = GRAMMAR_NODE_TABLES[key]
    assert tables.loops <= tables.scope_bounds, (
        f"{key}: loop constructs missing from scope_bounds — a "
        f"loop-scoped declarator's vouch window would leak past the "
        f"loop (suppression-ward)"
    )


def test_java_class_shaped_bodies_are_both_refused_and_barriered():
    # The class-shaped body nodes must appear in BOTH sets: refusal
    # keeps the builder honest, the barrier keeps the shared scope
    # collector honest for consumers that run without a build
    # (JavaConstIndex).
    bodies = {"class_body", "enum_body", "interface_body",
              "annotation_type_body"}
    assert bodies <= JAVA_TABLES.refused
    assert bodies <= JAVA_TABLES.scope_barriers
