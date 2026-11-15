"""Owned packet collector/finalizer spans survive result intake."""

import ast
import io
import json
from pathlib import Path
import re
from types import SimpleNamespace

from packages.coccinelle.runner import _dedup_matches, _parse_results

_RULE = Path(__file__).resolve().parents[1] / "rules/packet_length_inverted_guard.cocci"


def test_packet_finalizer_keeps_guard_extents_through_result_intake():
    text = _RULE.read_text()

    def report(end_column, *, reachable=True, error_label="bad"):
        output = io.StringIO()
        namespace = {"json": json, "sys": SimpleNamespace(stderr=output)}

        def run_phase(phase):
            body = re.search(
                "@" + phase + r":python[^\n]*\n@@\n(.*?)(?=\n@|\Z)", text, re.S,
            ).group(1)
            tree = ast.parse(body)
            tree.body = [node for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom))]
            # Trusted shipped Python with owned data; no native rule or target execution.
            exec(compile(tree, str(_RULE), "exec"), namespace)

        def position(line):
            return SimpleNamespace(
                file="owned.c", current_element="owned", current_element_line="1",
                line=str(line), column="1", line_end=str(line),
                column_end=str(end_column if line == 4 else 2),
            )

        run_phase("initialize")
        record = namespace["packet_record"]
        record("budget", [position(1)], skb="skb", remaining="remaining")
        record("read", [position(2)], skb="skb", wire="wire")
        record("decode", [position(3)], length="length", wire="wire")
        record("reject", [position(4)], length="length", remaining="remaining", bad="bad")
        record("consume", [position(6)], skb="skb", length="length")
        if reachable:
            record("reachable", [position(4)], sink_line="6", sink_col="1")
        record("error", [position(7)], bad=error_label)
        run_phase("finalize")
        return output.getvalue()

    first, second = report(18), report(23)
    # Plain-prefix owned transport control, not native matching or nonce authentication.
    matches = _parse_results(first + second + first, "packet_length_inverted_guard")
    assert len(matches) == 3
    rows = _dedup_matches(matches)
    assert len(rows) == 2
    assert [(row.file, row.line, row.column, row.line_end, row.column_end) for row in rows] == [
        ("owned.c", 4, 1, 4, 18), ("owned.c", 4, 1, 4, 23),
    ]
    assert all(row.rule == "packet_length_inverted_guard" and row.message for row in rows)
    assert rows[0].message == rows[1].message
    assert report(18, reachable=False) == ""
    assert report(18, error_label="other") == ""
