"""Native reallocation candidates, API coverage and ownership controls."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from engine.coccinelle.tests._rule_runner import run_rule

_RULE = Path(__file__).resolve().parents[1] / "rules" / "realloc_losing_ptr.cocci"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(shutil.which("spatch") is None, reason="coccinelle not installed"),
]

_APIS = [
    ("realloc", "{pointer}, n"),
    ("krealloc", "{pointer}, n, flags"),
    ("reallocarray", "{pointer}, n, sizeof(char)"),
    ("krealloc_array", "{pointer}, n, sizeof(char), flags"),
]
_PARAMS = "char *p, char **slot, struct owner *ctx, struct owner item, char **array, unsigned long i, unsigned long n, int flags"
_HEADER = "struct owner { char *p; };"


def _source(statements: list[str]) -> tuple[str, list[int]]:
    lines = [_HEADER]
    sites = []
    for index, statement in enumerate(statements):
        lines.append(f"void case_{index}({_PARAMS}) {{")
        lines.append(statement)
        sites.append(len(lines))
        lines.append("}")
    return "\n".join(lines) + "\n", sites


@pytest.mark.parametrize("api,arguments", _APIS, ids=[row[0] for row in _APIS])
@pytest.mark.parametrize("cast", ["", "(char *)"], ids=["plain", "cast"])
def test_self_assignment_covers_pointer_storage(tmp_path, api, arguments, cast):
    statements = [
        f"{pointer} = {cast}{api}({arguments.format(pointer=pointer)});"
        for pointer in ["p", "ctx->p", "item.p", "*slot", "array[0]", "array[i]", "(p)"]
    ]
    source, sites = _source(statements)
    rows = run_rule(tmp_path, source, _RULE)
    assert sorted(row["line"] for row in rows) == sites
    assert all(row["rule"] == "realloc_losing_ptr" for row in rows)
    assert all(row["message"].startswith("Candidate:") for row in rows)
    assert all(row["line_end"] == row["line"] and row["col_end"] > row["col"] for row in rows)


@pytest.mark.parametrize("api,arguments", _APIS, ids=[row[0] for row in _APIS])
@pytest.mark.parametrize("cast", ["", "(char *)"], ids=["plain", "cast"])
def test_checked_temporary_preserves_original(tmp_path, api, arguments, cast):
    source, _ = _source([
        f"char *temporary = {cast}{api}({arguments.format(pointer='p')});\n"
        "if (!temporary) { release_original(p); return; }\n"
        "p = temporary; consume(p);",
    ])
    assert run_rule(tmp_path, source, _RULE) == []


def test_saved_alias_remains_a_candidate_without_claiming_unique_ownership(tmp_path):
    source, sites = _source([
        "char *saved = p;\np = realloc(p, n);\nif (!p) free(saved);",
    ])
    rows = run_rule(tmp_path, source, _RULE)
    assert len(rows) == 1 and rows[0]["line"] == sites[0] + 1
    assert "review aliases" in rows[0]["message"]
    assert "only copy" not in rows[0]["message"]


def test_computed_storage_requires_identity_review(tmp_path):
    source = (
        _HEADER + "\nstruct owner *next_owner(void);\n"
        "void f(unsigned long n) { next_owner()->p = realloc(next_owner()->p, n); }\n"
    )
    rows = run_rule(tmp_path, source, _RULE)
    assert len(rows) == 1
    assert "storage identity" in rows[0]["message"]
    assert rows[0]["message"].startswith("Candidate:")


def test_kernel_literal_zero_requests_do_not_claim_lost_allocations(tmp_path):
    statements = []
    for zero in ["0", "00", "0U", "0UL", "0LL", "0x0", "0X00ULL", "(0U)"]:
        statements.extend([
            f"p = krealloc(p, {zero}, flags);",
            f"p = krealloc_array(p, {zero}, n, flags);",
            f"p = krealloc_array(p, n, {zero}, flags);",
        ])
    source, _ = _source(statements)
    assert run_rule(tmp_path, source, _RULE) == []


def test_libc_zero_and_unresolved_sizes_still_require_review(tmp_path):
    source, sites = _source([
        "p = realloc(p, 0);",
        "p = reallocarray(p, 0, sizeof(char));",
        "p = reallocarray(p, n, 0);",
        "p = krealloc(p, n, flags);",
        "p = krealloc(p, n + 0, flags);",
        "p = krealloc_array(p, n, i, flags);",
    ])
    rows = run_rule(tmp_path, source, _RULE)
    assert sorted(row["line"] for row in rows) == sites
    assert all("zero-size semantics" in row["message"] for row in rows)


def test_other_pointer_destinations_are_not_self_assignment(tmp_path):
    source, _ = _source([
        "ctx->p = realloc(p, n);",
        "array[0] = realloc(array[1], n);",
        "*slot = krealloc(p, n, flags);",
        "p = other_realloc(p, n);",
    ])
    assert run_rule(tmp_path, source, _RULE) == []


def test_ordinary_sizeof_does_not_execute_reallocation(tmp_path):
    statements = [
        f"consume(sizeof(p = {cast}{api}({arguments.format(pointer='p')})));"
        for api, arguments in _APIS for cast in ["", "(char *)"]
    ]
    source, _ = _source(statements)
    assert run_rule(tmp_path, source, _RULE) == []


def test_evaluated_vla_bound_is_not_hidden_by_sizeof(tmp_path):
    source, sites = _source([
        "consume(sizeof(char[(p = realloc(p, n)) != 0 ? 1 : 2]));",
    ])
    rows = run_rule(tmp_path, source, _RULE)
    assert len(rows) == 1 and rows[0]["line"] == sites[0]


def test_multiple_same_line_assignments_keep_distinct_positions(tmp_path):
    source, _ = _source(["p = realloc(p, n); p = realloc(p, n + 1);"])
    rows = run_rule(tmp_path, source, _RULE)
    assert len(rows) == 2
    assert len({(row["line"], row["col"]) for row in rows}) == 2
