"""Tests for core.audit.contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from core.audit.contracts import (
    ContractContext,
    ContractViolation,
    extract_callee_contracts,
    format_contract_violations_for_prompt,
    format_contracts_for_prompt,
)


@dataclass
class FakePrecondition:
    param: str
    param_index: int
    conditions: list


@dataclass
class FakeTaintRule:
    source_param: str
    source_index: int
    sink_call: str
    sink_arg_index: int
    hop_count: int = 0


@dataclass
class FakeSummary:
    function: str
    file: str
    preconditions: List[FakePrecondition] = field(default_factory=list)
    taint_rules: List[FakeTaintRule] = field(default_factory=list)


class TestExtractCalleeContracts:
    def test_with_preconditions(self):
        summaries = {
            "lib.c:ssl_read": FakeSummary(
                function="ssl_read",
                file="lib.c",
                preconditions=[
                    FakePrecondition(
                        param="ctx",
                        param_index=0,
                        conditions=["ctx != NULL", "ctx->state == CONNECTED"],
                    ),
                ],
            ),
        }
        gap = {
            "file": "app.c",
            "name": "handle_request",
            "callees": [{"name": "ssl_read", "file": "lib.c"}],
        }
        contracts = extract_callee_contracts(gap, summaries)
        assert len(contracts) == 1
        assert contracts[0].callee_function == "ssl_read"
        assert "ctx" in contracts[0].preconditions[0]

    def test_with_taint_rules(self):
        summaries = {
            "lib.c:memcpy_wrapper": FakeSummary(
                function="memcpy_wrapper",
                file="lib.c",
                taint_rules=[
                    FakeTaintRule(
                        source_param="buf",
                        source_index=0,
                        sink_call="memcpy",
                        sink_arg_index=1,
                    ),
                ],
            ),
        }
        gap = {
            "file": "app.c",
            "name": "process",
            "callees": [{"name": "memcpy_wrapper", "file": "lib.c"}],
        }
        contracts = extract_callee_contracts(gap, summaries)
        assert len(contracts) == 1
        assert "buf" in contracts[0].preconditions[0]
        assert "memcpy" in contracts[0].preconditions[0]

    def test_no_callees(self):
        gap = {"file": "a.c", "name": "f", "callees": []}
        contracts = extract_callee_contracts(gap, {})
        assert contracts == []

    def test_callee_not_in_summaries(self):
        gap = {
            "file": "a.c",
            "name": "f",
            "callees": [{"name": "unknown_fn", "file": "x.c"}],
        }
        contracts = extract_callee_contracts(gap, {})
        assert contracts == []

    def test_callee_with_empty_summary(self):
        summaries = {
            "lib.c:helper": FakeSummary(
                function="helper", file="lib.c",
            ),
        }
        gap = {
            "file": "a.c",
            "name": "f",
            "callees": [{"name": "helper", "file": "lib.c"}],
        }
        contracts = extract_callee_contracts(gap, summaries)
        assert contracts == []

    def test_string_callee_names(self):
        summaries = {
            "process_data": FakeSummary(
                function="process_data",
                file="",
                preconditions=[
                    FakePrecondition(
                        param="len",
                        param_index=1,
                        conditions=["len > 0"],
                    ),
                ],
            ),
        }
        gap = {
            "file": "a.c",
            "name": "f",
            "callees": ["process_data"],
        }
        contracts = extract_callee_contracts(gap, summaries)
        assert len(contracts) == 1

    def test_lookup_by_function_suffix(self):
        summaries = {
            "other.c:parse": FakeSummary(
                function="parse",
                file="other.c",
                preconditions=[
                    FakePrecondition(
                        param="input",
                        param_index=0,
                        conditions=["input != NULL"],
                    ),
                ],
            ),
        }
        gap = {
            "file": "a.c",
            "name": "f",
            "callees": [{"name": "parse", "file": ""}],
        }
        contracts = extract_callee_contracts(gap, summaries)
        assert len(contracts) == 1

    def test_multiple_callees(self):
        summaries = {
            "lib.c:fn_a": FakeSummary(
                function="fn_a",
                file="lib.c",
                preconditions=[
                    FakePrecondition(param="x", param_index=0, conditions=["x > 0"]),
                ],
            ),
            "lib.c:fn_b": FakeSummary(
                function="fn_b",
                file="lib.c",
                taint_rules=[
                    FakeTaintRule(
                        source_param="data",
                        source_index=0,
                        sink_call="system",
                        sink_arg_index=0,
                    ),
                ],
            ),
        }
        gap = {
            "file": "a.c",
            "name": "f",
            "callees": [
                {"name": "fn_a", "file": "lib.c"},
                {"name": "fn_b", "file": "lib.c"},
                {"name": "fn_c", "file": "lib.c"},
            ],
        }
        contracts = extract_callee_contracts(gap, summaries)
        assert len(contracts) == 2


class TestFormatContractsForPrompt:
    def test_renders_preconditions(self):
        contracts = [
            ContractContext(
                callee_function="ssl_read",
                callee_file="lib.c",
                preconditions=[
                    "parameter `ctx` must satisfy: ctx != NULL",
                ],
            ),
        ]
        text = format_contracts_for_prompt(contracts)
        assert "ssl_read" in text
        assert "ctx != NULL" in text
        assert "Callee contracts" in text
        assert "ALL code paths" in text

    def test_empty_contracts(self):
        assert format_contracts_for_prompt([]) == ""

    def test_multiple_contracts(self):
        contracts = [
            ContractContext(
                callee_function="fn_a",
                callee_file="a.c",
                preconditions=["parameter `x` must satisfy: x > 0"],
            ),
            ContractContext(
                callee_function="fn_b",
                callee_file="",
                preconditions=["parameter `buf` flows to `memcpy()`"],
            ),
        ]
        text = format_contracts_for_prompt(contracts)
        assert "fn_a" in text
        assert "fn_b" in text
        assert "(a.c)" in text

    def test_no_file_in_contract(self):
        contracts = [
            ContractContext(
                callee_function="helper",
                callee_file="",
                preconditions=["parameter `n` must satisfy: n >= 0"],
            ),
        ]
        text = format_contracts_for_prompt(contracts)
        assert "helper" in text
        assert "()" in text  # no file parens


class TestFormatContractViolationsForPrompt:
    def test_renders_violated_precondition(self):
        violations = [
            ContractViolation(
                caller_file="a.c",
                caller_function="caller",
                callee_function="ssl_read",
                violated_precondition="ctx != NULL",
                evidence="no null check on `ctx` before the call",
                cwe="CWE-476",
            ),
        ]
        text = format_contract_violations_for_prompt(violations)
        assert "Contract violations" in text
        assert "ssl_read" in text
        assert "ctx != NULL" in text
        assert "no null check on `ctx`" in text
        assert "CWE-476" in text
        assert "caller" in text

    def test_no_cwe_omits_brackets(self):
        violations = [
            ContractViolation(
                caller_file="a.c",
                caller_function="caller",
                callee_function="helper",
                violated_precondition="n >= 0",
                evidence="no positivity check",
            ),
        ]
        text = format_contract_violations_for_prompt(violations)
        assert "[" not in text.split("\n")[2]

    def test_empty_violations(self):
        assert format_contract_violations_for_prompt([]) == ""
