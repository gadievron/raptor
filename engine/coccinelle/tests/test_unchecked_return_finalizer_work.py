"""Run only the owned unchecked-return Python finalizer, without spatch."""

import ast
import io
import json
from pathlib import Path
from types import SimpleNamespace


RULE = Path(__file__).resolve().parents[1] / "rules" / "unchecked_return.cocci"


def finalise(ignored, checked):
    text = RULE.read_text().split("@finalize:python@\n@@\n", 1)[1]
    tree = ast.parse(text)
    # Imports are supplied as owned values so stderr stays local to the test.
    tree.body = [node for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom))]
    output = io.StringIO()
    sort_sizes = []

    def sorting(values, **kwargs):
        values = list(values)
        sort_sizes.append(len(values))
        return sorted(values, **kwargs)

    exec(compile(tree, str(RULE), "exec"), {
        "json": json, "sys": SimpleNamespace(stderr=output), "sorted": sorting,
        "ignored_returns": ignored, "checked_returns": checked,
    })
    rows = [json.loads(line.removeprefix("COCCIRESULT:")) for line in output.getvalue().splitlines()]
    return rows, sort_sizes


def result(file, line, col):
    return {"file": file, "line": line, "col": col, "line_end": line + 1,
            "col_end": col + 2, "rule": "unchecked_return", "message": "owned"}


def test_no_checked_return_skips_all_sorting():
    ignored = {("owned.c", f"function{i}"): [result("owned.c", i + 1, 1)] for i in range(2048)}
    rows, sort_sizes = finalise(ignored, set())
    assert rows == [] and sort_sizes == []
    assert len(ignored) == 2048


def test_nonempty_checked_set_preserves_file_identity_order_and_spans():
    first, second = result("a.c", 1, 9), result("a.c", 2, 3)
    other = result("b.c", 1, 1)
    ignored = {("b.c", "same"): [other], ("a.c", "same"): [second, first]}
    rows, sort_sizes = finalise(ignored, {("a.c", "same")})
    assert rows == [first, second]
    assert sort_sizes == [2, 2]
    assert ignored[("a.c", "same")] == [second, first]


def test_all_checked_returns_keep_all_records():
    ignored = {("owned.c", f"function{i:03d}"): [result("owned.c", i + 1, 1)] for i in range(128)}
    rows, sort_sizes = finalise(ignored, set(ignored))
    assert rows == [record for records in ignored.values() for record in records]
    assert sort_sizes == [128] + [1] * 128


def test_no_ignored_return_stays_empty():
    rows, sort_sizes = finalise({}, {("owned.c", "checked")})
    assert rows == [] and sort_sizes == [0]
