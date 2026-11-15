"""Owned teardown finalizer records retain distinct source extents."""

import ast
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace

from packages.coccinelle.runner import _dedup_matches, _parse_results

_RULE = Path(__file__).resolve().parents[1] / "rules/teardown_lifetime.cocci"


def test_teardown_finalizer_preserves_distinct_spans_and_line_suppression():
    body = re.search(r"@finalize:python@\n@@\n(.*)", _RULE.read_text(), re.S).group(1)
    tree = ast.parse(body)
    tree.body = [node for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom))]
    records = [
        ("owned.c", 4, 2, 4, 9, "first"),
        ("owned.c", 4, 20, 4, 28, "second"),
        ("owned.c", 4, 2, 4, 12, "different end column"),
        ("owned.c", 4, 2, 5, 9, "different end line"),
        ("owned.c", 4, 2, 4, 9, "duplicate keeps first"),
        ("owned.c", 6, 2, 6, 9, "other line"),
        ("other.c", 4, 2, 4, 9, "other file"),
    ]

    def report(suppressed):
        output = io.StringIO()
        namespace = {
            "json": json, "sys": SimpleNamespace(stderr=output),
            "_td_candidates": records, "_td_suppress": suppressed,
        }
        # Trusted shipped report code with owned records, no native matching.
        exec(compile(tree, str(_RULE), "exec"), namespace)
        return output.getvalue()

    # Plain-prefix transport control, not native or nonce-authentication evidence.
    raw = report(set())
    parsed = _parse_results(raw, "teardown_lifetime")
    assert len(parsed) == 6
    rows = _dedup_matches(parsed + parsed)
    assert len(rows) == 6
    assert [(row.file, row.line, row.column, row.line_end, row.column_end) for row in rows] == [
        ("owned.c", 4, 2, 4, 9), ("owned.c", 4, 20, 4, 28),
        ("owned.c", 4, 2, 4, 12), ("owned.c", 4, 2, 5, 9),
        ("owned.c", 6, 2, 6, 9), ("other.c", 4, 2, 4, 9),
    ]
    assert [row.message for row in rows] == [
        "first", "second", "different end column", "different end line",
        "other line", "other file",
    ]
    assert all(row.rule == "teardown_lifetime" for row in rows)
    suppressed = _parse_results(report({("owned.c", 4)}), "teardown_lifetime")
    assert [(row.file, row.line, row.message) for row in suppressed] == [
        ("owned.c", 6, "other line"), ("other.c", 4, "other file"),
    ]
