"""Regression: audit-channel inventory readers accept the builder's schema.

The inventory builder emits per-file ``items`` (older inventories
carried ``functions``). Three channel legs read the per-file function
list; each must work against a REAL builder record — a reader keyed on
the wrong name silently returns nothing and its leg goes dead
(void-callee FP refuter, learned-cleanup verb mining, Go fallibility
signature fallback).
"""

from __future__ import annotations

import textwrap

import pytest

from core.audit.consistency_prepass import _inventory_function_names
from core.audit.consistency_verify import _callee_returns_void
from core.audit.fail_open_verify import _inventory_signature


def _inventory_emits_go_signatures() -> bool:
    """True when the builder's Go leg records signatures/return types.

    Only the tree-sitter extraction path populates them; the regex
    ``GoExtractor`` fallback documents parameters and return types as
    unextractable. Probe the SAME loader the builder uses so this gate
    cannot drift from what the fixture actually produced.
    """
    from core.inventory.extractors import _get_ts_languages
    return "go" in _get_ts_languages()


@pytest.fixture(scope="module")
def real_inventory(tmp_path_factory):
    """A real builder-produced inventory over a tiny C + Go tree."""
    from core.inventory import build_inventory

    repo = tmp_path_factory.mktemp("repo")
    out = tmp_path_factory.mktemp("inv_out")
    (repo / "util.c").write_text(textwrap.dedent("""\
        void reset_counters(int *c) {
            *c = 0;
        }

        int checked_add(int a, int b) {
            return a + b;
        }
    """), encoding="utf-8")
    (repo / "verify.go").write_text(textwrap.dedent("""\
        package main

        func VerifySig(data []byte) error {
            return nil
        }
    """), encoding="utf-8")
    return build_inventory(str(repo), output_dir=str(out), parallel=False)


class TestBuilderEmitsItems:
    def test_files_carry_items_not_functions(self, real_inventory):
        files = real_inventory.get("files", [])
        assert files, "builder produced no file records"
        assert any(f.get("items") for f in files)
        # Pin the schema premise: if the builder ever renames the key,
        # this test — not a silently dead channel leg — fails.
        assert all("functions" not in f for f in files)


class TestConsistencyVerifyReader:
    def test_void_callee_found_in_real_inventory(self, real_inventory):
        assert _callee_returns_void("reset_counters", None, real_inventory)

    def test_non_void_callee_not_flagged(self, real_inventory):
        assert not _callee_returns_void("checked_add", None, real_inventory)

    def test_legacy_functions_key_still_accepted(self):
        legacy = {"files": [{"path": "a.c", "functions": [
            {"name": "reset_counters", "metadata": {"return_type": "void"}},
        ]}]}
        assert _callee_returns_void("reset_counters", None, legacy)


class TestConsistencyPrepassReader:
    def test_function_names_mined_from_real_inventory(self, real_inventory):
        names = _inventory_function_names(real_inventory)
        assert "reset_counters" in names
        assert "checked_add" in names
        assert "VerifySig" in names

    def test_legacy_functions_key_still_accepted(self):
        legacy = {"files": [{"path": "a.c", "functions": [
            {"name": "old_style"},
        ]}]}
        assert _inventory_function_names(legacy) == {"old_style"}


class TestFailOpenVerifyReader:
    @pytest.mark.skipif(
        not _inventory_emits_go_signatures(),
        reason="inventory Go signatures need the tree-sitter Go grammar"
               " (the regex fallback extracts names only)",
    )
    def test_signature_found_in_real_inventory(self, real_inventory):
        sig = _inventory_signature(real_inventory, "VerifySig")
        assert sig, "inventory signature leg returned nothing"
        assert "error" in sig

    def test_legacy_functions_key_still_accepted(self):
        legacy = {"files": [{"path": "a.go", "functions": [
            {"name": "VerifySig", "signature": "func VerifySig() error"},
        ]}]}
        assert "error" in _inventory_signature(legacy, "VerifySig")
