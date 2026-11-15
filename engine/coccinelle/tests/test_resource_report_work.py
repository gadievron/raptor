"""Owned resource-report statements avoid joins without cleanup proofs."""
import ast
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

_RULE = Path(__file__).resolve().parents[1] / "rules/resource_leak_err.cocci"


def _position(line, filename="owned.c"):
    return SimpleNamespace(file=filename, line=line, column=2, line_end=line, column_end=8)


def _report(allocations, returned, *, proof=False, veto=None):
    source = _RULE.read_text()
    init = source.split("@initialize:python@\n@@\n", 1)[1].split("\n@leak exists@", 1)[0]
    body = source.split("p_alloc << leak.p_alloc;\np_ret << leak.p_ret;\nptr << leak.ptr;\n@@\n", 1)[1]
    namespace = {}
    exec(compile(ast.parse(init), str(_RULE), "exec"), namespace)
    original_pairs = namespace["_rl_pairs"]
    visits = []

    def observed_pairs(a, b):
        for key in original_pairs(a, b):
            visits.append(key)
            yield key

    if proof:
        assert len(allocations) == 1
        allocation, result = allocations[0], returned[0]
        key = (allocation.file, allocation.line, allocation.column, result.line, result.column)
        function = (allocation.file, 1, 2)
        namespace["_rl_safe"][key] = (function, "backing", (2, 2))
        if veto == "bypass":
            namespace["_rl_bypass"].add(key)
        elif veto == "changed":
            namespace["_rl_changed"].add(key)
        elif veto == "addressed":
            namespace["_rl_addressed"].add((*function, "owned"))
        elif veto == "shadowed":
            namespace["_rl_bindings"][(*function, "backing")] = {(99, 2)}
        elif veto == "unrelated":
            namespace["_rl_safe"] = {(*key[:-2], result.line + 100, result.column): namespace["_rl_safe"][key]}
    output = io.StringIO()
    namespace.update({"_rl_pairs": observed_pairs, "p_alloc": allocations, "p_ret": returned,
                      "ptr": "owned", "json": json, "sys": SimpleNamespace(stderr=output)})
    tree = ast.parse(body)
    tree.body = [node for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom))]
    exec(compile(tree, str(_RULE), "exec"), namespace)
    rows = [json.loads(line.removeprefix("COCCIRESULT:")) for line in output.getvalue().splitlines()]
    return rows, visits


def test_empty_cleanup_proofs_skip_pair_work_without_losing_candidates():
    rows, visits = _report([_position(i + 1) for i in range(100)],
                          [_position(i + 200) for i in range(100)])
    assert visits == []
    assert len(rows) == 100
    assert [(row["line"], row["col"], row["line_end"], row["col_end"]) for row in rows] == [
        (i + 200, 2, i + 200, 8) for i in range(100)
    ]
    assert all(row["rule"] == "resource_leak_err" and "from line 1" in row["message"] for row in rows)


def test_cleanup_proof_still_suppresses_covered_return():
    rows, visits = _report([_position(10)], [_position(20)], proof=True)
    assert rows == [] and len(visits) == 1


@pytest.mark.parametrize("veto", ["bypass", "changed", "addressed", "shadowed", "unrelated"])
def test_cleanup_proof_veto_keeps_candidate(veto):
    rows, visits = _report([_position(10)], [_position(20)], proof=True, veto=veto)
    assert len(rows) == len(visits) == 1
    assert rows[0]["line"] == 20 and "from line 10" in rows[0]["message"]


def test_cpp_cleanup_shape_remains_reportable():
    rows, visits = _report([_position(10, "owned.cpp")], [_position(20, "owned.cpp")], proof=True)
    assert len(rows) == len(visits) == 1
    assert rows[0]["file"] == "owned.cpp"


def test_repeated_return_site_still_reports_once():
    returned = _position(20)
    rows, visits = _report([_position(10)], [returned, returned])
    assert visits == [] and len(rows) == 1
