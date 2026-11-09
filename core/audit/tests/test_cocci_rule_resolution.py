"""CWE-table Coccinelle rules must reach dispatch as on-disk paths.

Dual-control: the previously-broken shape (bare table filename,
CWD-relative at spatch time — a deterministic dispatch error) now
resolves to an existing absolute path, while a genuinely missing rule
file still surfaces as a counted channel error when handed to the
sweep directly.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

import core.audit.cwe_dispatch as cwe_dispatch
from core.audit.cwe_dispatch import (
    CWE_TO_TOOL_DISPATCH,
    cocci_rules_for_cwe,
    resolve_cocci_rules_for_cwe,
)
from core.audit.tests.codeql_catalogue import codeql_chain_catalogue as codeql_chain_catalogue

from core.audit.orchestrator import (
    TierCounters,
    _cwe_fallback_chain,
    _run_tool_chain,
)


def _cocci_entries(chain):
    return [e for e in chain if e["type"] == "coccinelle"]


class TestResolution:
    def test_table_names_resolve_to_existing_files(self):
        """Every rule name in the dispatch table exists on disk —
        a table/tree drift would silently re-open the dead channel."""
        missing = []
        for cwe, entry in CWE_TO_TOOL_DISPATCH.items():
            for name in cocci_rules_for_cwe(cwe):
                resolved = resolve_cocci_rules_for_cwe(cwe)
                if not any(Path(p).name == name for p in resolved):
                    missing.append((cwe, name))
        assert missing == []

    def test_resolved_paths_are_absolute_and_exist(self):
        paths = resolve_cocci_rules_for_cwe("CWE-415")
        assert paths, "CWE-415 carries double_free.cocci in the table"
        for p in paths:
            assert Path(p).is_absolute()
            assert Path(p).is_file()

    def test_missing_rule_dropped_with_one_warning(
        self, monkeypatch, caplog,
    ):
        monkeypatch.setitem(
            CWE_TO_TOOL_DISPATCH, "CWE-415",
            {"cocci": "no_such_rule_xyz.cocci"},
        )
        monkeypatch.setattr(
            cwe_dispatch, "_MISSING_COCCI_WARNED", set(),
        )
        with caplog.at_level(logging.WARNING, logger=cwe_dispatch.__name__):
            assert resolve_cocci_rules_for_cwe("CWE-415") == []
            assert resolve_cocci_rules_for_cwe("CWE-415") == []
        warnings = [
            r for r in caplog.records
            if "no_such_rule_xyz.cocci" in r.getMessage()
        ]
        assert len(warnings) == 1

    def test_absolute_table_value_passes_through(self, monkeypatch, tmp_path):
        rule = tmp_path / "custom.cocci"
        rule.write_text("@@\n@@\n")
        monkeypatch.setitem(
            CWE_TO_TOOL_DISPATCH, "CWE-415", {"cocci": str(rule)},
        )
        assert resolve_cocci_rules_for_cwe("CWE-415") == [str(rule)]


class TestChainEmission:
    def test_cwe_chain_carries_resolved_rule_path(self, codeql_chain_catalogue):
        chain = _cwe_fallback_chain("CWE-415")
        assert [e["config"]["query"] for e in chain if e["type"] == "codeql"] == [
            str(codeql_chain_catalogue["cpp/use-after-free"]),
        ]
        entries = _cocci_entries(chain)
        assert entries
        for e in entries:
            assert Path(e["config"]["rule"]).is_file()

    def test_missing_rule_no_longer_shadows_keyword_leg(self, monkeypatch):
        """A dead table entry used to claim the chain's coccinelle
        slot AND error on every dispatch; now the keyword-mapped leg
        gets the slot instead."""
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        monkeypatch.setitem(
            CWE_TO_TOOL_DISPATCH, "CWE-416",
            {"cocci": "no_such_rule_xyz.cocci"},
        )
        chain = _hypothesis_to_tool_chain(
            "use-after-free of `conn` after free", "src/a.c",
            cwe="CWE-416",
        )
        entries = _cocci_entries(chain)
        assert len(entries) == 1
        assert Path(entries[0]["config"]["rule"]).is_file()


class _Cfg:
    def __init__(self, target: Path):
        self.target_path = target
        self.out_dir = None
        self.codeql_db_path = None
        self.project_sinks = None


class TestErrorCounterControl:
    def test_genuinely_missing_rule_still_counts_as_error(self, tmp_path):
        """The honest error accounting stays: a nonexistent rule path
        reaching the sweep is a channel error, never a refutation."""
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.c").write_text("int f(void) { return 0; }\n")
        counters = {"coccinelle": TierCounters()}
        confirmed = _run_tool_chain(
            [{
                "type": "coccinelle",
                "config": {"rule": str(tmp_path / "gone.cocci")},
            }],
            config=_Cfg(tmp_path),
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis="double free of `p`",
            tier_counters=counters,
            joern_server=None,
        )
        assert confirmed == []
        assert counters["coccinelle"].errors == 1
        assert counters["coccinelle"].refuted == 0


@pytest.fixture(autouse=True)
def _fresh_warned_set(monkeypatch):
    # Keep the once-per-process warning dedup from leaking across
    # tests in either direction.
    monkeypatch.setattr(cwe_dispatch, "_MISSING_COCCI_WARNED", set())
