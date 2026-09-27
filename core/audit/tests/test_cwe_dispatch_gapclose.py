"""Dispatch adjudication for tool-verifiable empty-dispatch classes.

An instrumented audit run warned ``review emitted CWE-<n> but no
tool-chain dispatch entry exists`` for sixty concrete classes. The
classes a deterministic tool CAN adjudicate are wired here: a real
stock-tool chain (cocci / curated semgrep / CodeQL @id / SMT verb /
joern+sinks) where a tool states the harm mechanism, or a fallback
channel (fail_open / api_boundary / resource_bounds / compiler)
where a channel's question matches the class. Hermetic — no LLM, no
tool subprocesses.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.api_boundary import api_boundary_applicable
from core.audit.compiler_sweep import COMPILER_CWE_MAP, compiler_applicable
from core.audit.cwe_dispatch import (
    dark_verify_applicable,
    lookup,
    resolve_cocci_rules_for_cwe,
    resolve_semgrep_rule_for_cwe,
    smt_verb_for_cwe,
)
from core.audit.fail_open_verify import fail_open_applicable
from core.audit.orchestrator import _cwe_fallback_chain
from core.audit.resource_bounds import resource_bounds_applicable

class TestToctouFamily:
    """CWE-59/61 (symlink following) — the CWE-367 mechanism: SMT
    TOCTOU verb, stat-then-open cocci rule, cpp TOCTOU query."""

    @pytest.mark.parametrize("cwe", ["CWE-59", "CWE-61"])
    def test_dispatch_entry(self, cwe):
        entry = lookup(cwe)
        assert entry is not None
        assert smt_verb_for_cwe(cwe) == "check-toctou"
        assert entry["cocci"] == "toctou_stat_open.cocci"
        assert entry["codeql"] == "cpp/toctou-race-condition"

    @pytest.mark.parametrize("cwe", ["CWE-59", "CWE-61"])
    def test_fallback_chain(self, cwe):
        types = {e["type"] for e in _cwe_fallback_chain(cwe)}
        assert types >= {"smt", "coccinelle", "codeql"}


class TestTaintEntries:
    """Joern-seeded taint families reusing established sibling
    vocabularies (CWE-73 <- 22/23, CWE-776 <- 611, CWE-915 <- 1321,
    CWE-807 <- 863)."""

    def test_path_control(self):
        entry = lookup("CWE-73")
        assert entry is not None and entry["joern"] is True
        assert entry["codeql"] == "py/path-injection"
        assert entry["sinks"] == lookup("CWE-23")["sinks"]

    def test_entity_expansion(self):
        entry = lookup("CWE-776")
        assert entry is not None and entry["joern"] is True
        assert entry["codeql"] == "py/xml-bomb"
        assert entry["sinks"] == lookup("CWE-611")["sinks"]

    def test_mass_assignment(self):
        entry = lookup("CWE-915")
        assert entry is not None and entry["joern"] is True
        assert entry["sinks"] == lookup("CWE-1321")["sinks"]

    def test_security_decision(self):
        entry = lookup("CWE-807")
        assert entry is not None and entry["joern"] is True
        assert smt_verb_for_cwe("CWE-807") == "check-auth-bypass"
        assert entry["sinks"] == lookup("CWE-863")["sinks"]
        # The dark-code heuristic's calibration evidence covers the
        # authn/authz families only — CWE-807 must not inherit it.
        assert dark_verify_applicable("CWE-807") is False


class TestCuratedRuleEntries:
    """Entries whose verifying channel is a curated semgrep rule:
    language-gated so non-matching targets keep pre-entry behaviour."""

    _CASES = [
        ("CWE-117", "app.py", "injection/log-injection.yaml"),
        ("CWE-117", "app.go", "injection/log-injection.yaml"),
        ("CWE-532", "app.java", "logging/logs-secrets.yaml"),
        ("CWE-923", "app.py", "auth/tls-skip-verify.yaml"),
        ("CWE-943", "app.js", "injection/nosql-taint.yaml"),
        ("CWE-1333", "app.ts", "injection/regex-dos.yaml"),
        ("CWE-1336", "app.py", "injection/ssti-taint.yaml"),
    ]

    @pytest.mark.parametrize("cwe,path,rule", _CASES)
    def test_rule_resolves_on_declared_language(self, cwe, path, rule):
        resolved = resolve_semgrep_rule_for_cwe(cwe, path)
        assert resolved is not None
        assert resolved.endswith(rule)
        assert Path(resolved).is_file()

    @pytest.mark.parametrize(
        "cwe", ["CWE-117", "CWE-532", "CWE-923", "CWE-943", "CWE-1333",
                "CWE-1336"],
    )
    def test_rule_dropped_on_other_language(self, cwe):
        assert resolve_semgrep_rule_for_cwe(cwe, "main.c") is None

    def test_log_injection_keeps_codeql_leg(self):
        assert lookup("CWE-117")["codeql"] == "py/log-injection"

    def test_secret_logging_keeps_codeql_leg(self):
        assert (lookup("CWE-532")["codeql"]
                == "py/clear-text-logging-sensitive-data")

    def test_redos_keeps_codeql_leg(self):
        assert lookup("CWE-1333")["codeql"] == "py/redos"


class TestCocciSmtEntries:
    """Cocci/SMT-anchored fixed-vocabulary families."""

    def test_array_index(self):
        assert smt_verb_for_cwe("CWE-129") == "check-oob"
        assert (lookup("CWE-129")["codeql"]
                == "cpp/unclear-array-index-validation")

    def test_privilege_drop_order(self):
        assert (lookup("CWE-269")["codeql"]
                == "cpp/drop-linux-privileges-outoforder")

    def test_cleartext_storage(self):
        assert (lookup("CWE-312")["codeql"]
                == "py/clear-text-storage-sensitive-data")

    def test_insecure_temp_dir_variant(self):
        entry = lookup("CWE-379")
        assert entry is not None
        assert entry["cocci"] == lookup("CWE-377")["cocci"]
        assert entry["codeql"] == lookup("CWE-377")["codeql"]

    def test_error_path_cleanup(self):
        assert smt_verb_for_cwe("CWE-460") == "check-resource-leak"
        assert lookup("CWE-460")["cocci"] == "resource_leak_err.cocci"

    def test_double_close_family(self):
        rules = resolve_cocci_rules_for_cwe("CWE-675")
        names = {Path(r).name for r in rules}
        assert names == {"double_close.cocci",
                         "fdopendir_double_close.cocci"}

    def test_incorrect_calculation(self):
        assert smt_verb_for_cwe("CWE-682") == "check-overflow"
        rules = resolve_cocci_rules_for_cwe("CWE-682")
        names = {Path(r).name for r in rules}
        assert names == {"shift_overflow.cocci", "division_by_zero.cocci"}


class TestCompilerChannelFamilies:
    """CWE-674 (recursion) and CWE-834 (excessive iteration) join the
    compiler channel confirm-only — silence never refutes."""

    def test_recursion_spec(self):
        assert compiler_applicable("CWE-674")
        spec = COMPILER_CWE_MAP["CWE-674"]
        assert spec.reliable is False
        assert "-Winfinite-recursion" in spec.gcc_ids
        assert "-Winfinite-recursion" in spec.clang_ids
        assert spec.clang_engine == "warning"

    def test_iteration_shares_loop_spec(self):
        assert compiler_applicable("CWE-834")
        assert COMPILER_CWE_MAP["CWE-834"] is COMPILER_CWE_MAP["CWE-835"]
        assert smt_verb_for_cwe("CWE-834") == "check-overflow"

    def test_fallback_chains(self):
        assert {e["type"] for e in _cwe_fallback_chain("CWE-674")} == {
            "compiler",
        }
        assert {e["type"] for e in _cwe_fallback_chain("CWE-834")} >= {
            "compiler", "smt",
        }


class TestChannelOwnedFamilies:
    """All-None keys whose verifier is a fallback channel."""

    @pytest.mark.parametrize(
        "cwe", ["CWE-754", "CWE-755", "CWE-392", "CWE-346"],
    )
    def test_fail_open_members(self, cwe):
        assert lookup(cwe) is not None
        assert fail_open_applicable(cwe)
        assert {e["type"] for e in _cwe_fallback_chain(cwe)} == {
            "fail_open",
        }

    def test_caller_contract(self):
        assert lookup("CWE-573") is not None
        # Unconditional like CWE-345 — no hypothesis phrasing needed.
        assert api_boundary_applicable("CWE-573")
        assert {e["type"] for e in _cwe_fallback_chain("CWE-573")} == {
            "api_boundary",
        }

    def test_excessive_allocation_size(self):
        assert lookup("CWE-789") is not None
        assert resource_bounds_applicable("CWE-789")
        assert {e["type"] for e in _cwe_fallback_chain("CWE-789")} == {
            "resource_bounds",
        }
