"""Owned scatterlist count positions survive collection and finalisation."""

import ast
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace

import pytest

from packages.coccinelle.runner import _dedup_matches, _parse_results

_RULE = Path(__file__).resolve().parents[1] / "rules/scatterlist_frag_undersize.cocci"


@pytest.mark.parametrize("collector", ["sfu_count", "sfu_counti"])
def test_count_collector_preserves_distinct_full_spans(collector):
    text = _RULE.read_text()
    output = io.StringIO()
    namespace = {
        "json": json, "sys": SimpleNamespace(stderr=output),
        "_sfu_counts": [], "_sfu_links": [("owned.c", "owned", "table", "n")],
        "_sfu_maps": [("owned.c", "owned", 20, "skb", "table")],
        "_sfu_crypts": [("owned.c", "owned", "table")], "_sfu_guarded": set(),
        "skb": "skb", "nsg": "n", "sg": "table",
    }

    def run(body):
        lines = body.splitlines()
        while lines and (not lines[-1].strip() or lines[-1].lstrip().startswith("//")):
            lines.pop()
        tree = ast.parse("\n".join(lines))
        tree.body = [node for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom))]
        # Trusted shipped collector/report code with owned records only.
        exec(compile(tree, str(_RULE), "exec"), namespace)

    extents = [(5, 2, 5, 12), (5, 20, 5, 28), (5, 2, 5, 18), (5, 2, 6, 12)]
    namespace["p"] = [
        SimpleNamespace(file="owned.c", current_element="owned", line=str(line),
                        column=str(col), line_end=str(end_line), column_end=str(end_col))
        for line, col, end_line, end_col in extents + [extents[0]]
    ]
    body = re.search(
        r"@script:python@\np << " + collector + r"\.p;.*?@@\n(.*?)(?=\n@)",
        text, re.S,
    ).group(1)
    run(body)
    run(text.split("@finalize:python@\n@@\n", 1)[1])
    # Plain-prefix transport control, not native matching or nonce authentication.
    parsed = _parse_results(output.getvalue(), "scatterlist_frag_undersize")
    assert len(parsed) == 4
    rows = _dedup_matches(parsed + parsed)
    assert len(rows) == 4
    assert [(row.line, row.column, row.line_end, row.column_end) for row in rows] == extents
    assert all(row.file == "owned.c" and row.rule == "scatterlist_frag_undersize" for row in rows)
    assert len({row.message for row in rows}) == 1
    assert "at line 5" in rows[0].message and "at line 20" in rows[0].message
