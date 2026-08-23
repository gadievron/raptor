"""Contract tests for ``packages/sca/reachability/_shared``.

These test the FUNCTIONS' contracts (what callers rely on), not the
consolidation itself — the per-ecosystem modules re-export the
helpers under their historical private names.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from packages.sca.reachability._shared import (
    extract_function_names,
    format_evidence,
    extract_qualified_symbols,
)


def _adv(es=None, ds=None):
    return SimpleNamespace(ecosystem_specific=es, database_specific=ds)


class TestExtractQualifiedSymbols:
    def test_imports_symbols_qualified_with_path(self):
        adv = _adv(es={"imports": [{"path": "foo::bar", "symbols": ["baz", "qux"]}]})
        assert extract_qualified_symbols(adv, "dep") == [
            "foo::bar.baz", "foo::bar.qux",
        ]

    def test_import_path_falls_back_to_dep_name(self):
        adv = _adv(es={"imports": [{"symbols": ["run"]}]})
        assert extract_qualified_symbols(adv, "mygem") == ["mygem.run"]

    def test_flat_lists_qualified_with_dep_name(self):
        adv = _adv(
            es={"affected_symbols": ["a"]},
            ds={"affected_functions": ["b"]},
        )
        assert extract_qualified_symbols(adv, "dep") == ["dep.a", "dep.b"]

    def test_both_sources_consulted_in_order(self):
        adv = _adv(
            es={"imports": [{"path": "p", "symbols": ["one"]}]},
            ds={"imports": [{"path": "q", "symbols": ["two"]}]},
        )
        assert extract_qualified_symbols(adv, "dep") == ["p.one", "q.two"]

    def test_non_dict_sources_skipped(self):
        adv = _adv(es=["not-a-dict"], ds="also-not")
        assert extract_qualified_symbols(adv, "dep") == []

    def test_missing_attrs_default_empty(self):
        assert extract_qualified_symbols(object(), "dep") == []

    def test_non_string_symbols_skipped(self):
        adv = _adv(es={
            "imports": [{"path": "p", "symbols": ["ok", 3, None, ""]}],
            "affected_symbols": ["fine", 7],
        })
        assert extract_qualified_symbols(adv, "dep") == ["p.ok", "dep.fine"]

    def test_empty_dep_name_disables_flat_lists_only(self):
        adv = _adv(es={
            "imports": [{"path": "p", "symbols": ["s"]}],
            "affected_symbols": ["t"],
        })
        # imports[] still qualify via explicit path; flat lists need
        # a dep_name to qualify with.
        assert extract_qualified_symbols(adv, "") == ["p.s"]

    def test_non_string_path_skipped(self):
        adv = _adv(es={"imports": [{"path": 42, "symbols": ["s"]}]})
        assert extract_qualified_symbols(adv, "dep") == []


class TestExtractFunctionNames:
    def test_imports_symbols_unqualified(self):
        adv = _adv(es={"imports": [{"path": "ignored", "symbols": ["f", "g"]}]})
        assert extract_function_names(adv) == ["f", "g"]

    def test_flat_lists_from_both_sources(self):
        adv = _adv(
            es={"affected_symbols": ["a"]},
            ds={"affected_functions": ["b"]},
        )
        assert extract_function_names(adv) == ["a", "b"]

    def test_flat_list_key_order_dominates_source_order(self):
        # affected_symbols from BOTH sources come before any
        # affected_functions (key-major iteration).
        adv = _adv(
            es={"affected_functions": ["f2"], "affected_symbols": ["s1"]},
            ds={"affected_symbols": ["s2"]},
        )
        assert extract_function_names(adv) == ["s1", "s2", "f2"]

    def test_non_string_entries_skipped(self):
        adv = _adv(es={
            "imports": [{"symbols": ["ok", 1, None]}],
            "affected_symbols": ["fine", {}],
        })
        assert extract_function_names(adv) == ["ok", "fine"]

    def test_missing_attrs_default_empty(self):
        assert extract_function_names(object()) == []

    def test_non_dict_sources_skipped(self):
        adv = _adv(es="nope", ds=["nah"])
        assert extract_function_names(adv) == []

    def test_duplicates_preserved_for_caller_dedup(self):
        adv = _adv(
            es={"affected_symbols": ["x"]},
            ds={"affected_symbols": ["x"]},
        )
        assert extract_function_names(adv) == ["x", "x"]


class TestFormatEvidence:
    def test_relative_under_target_and_absolute_outside(self):
        target = Path("/repo")
        hits = [
            (Path("/repo/src/a.py"), 3, False),
            (Path("/elsewhere/b.py"), 9, False),
        ]
        assert format_evidence(hits, target=target) == [
            "src/a.py:3", "/elsewhere/b.py:9",
        ]

    def test_none_target_keeps_paths_verbatim(self):
        hits = [(Path("/x/y.go"), 12, True)]
        assert format_evidence(hits, target=None) == ["/x/y.go:12"]

    def test_cap_with_overflow_marker(self):
        hits = [(Path(f"/t/f{i}.rb"), i, False) for i in range(7)]
        out = format_evidence(hits, target=Path("/t"), cap=5)
        assert len(out) == 6
        assert out[-1] == "... (+2 more)"

    def test_exactly_cap_no_marker(self):
        hits = [(Path(f"/t/f{i}.cs"), i, False) for i in range(5)]
        out = format_evidence(hits, target=Path("/t"))
        assert len(out) == 5

    def test_target_itself_not_relativised(self):
        # ``target in f.parents`` is False for the target itself.
        hits = [(Path("/t"), 1, False)]
        assert format_evidence(hits, target=Path("/t")) == ["/t:1"]
