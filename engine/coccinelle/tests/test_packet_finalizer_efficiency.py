"""Exercise packet-report correlation with inert producer-shaped events."""

import ast
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


class _Consumers(list):
    def __init__(self, items):
        super().__init__(items)
        self.visits = 0

    def __iter__(self):
        for item in super().__iter__():
            self.visits += 1
            yield item


def _events(first_valid, offset=0):
    def event(line, **values):
        return dict(line=line + offset, col=1, **values)

    return {
        "reject": [event(4, length="n", remaining="r", bad="bad")],
        "error": [event(200, bad="bad")],
        "consume": _Consumers([event(5 + i, length="other" if i < first_valid else "n", skb="skb")
                               for i in range(128)]),
        "reachable": [event(4, sink_line=str(5 + i + offset), sink_col="1") for i in range(128)],
        "decode": [event(3, length="n", wire="wire")],
        "read": [event(2, skb="skb", wire="wire")],
        "budget": [event(1, skb="skb", remaining="r")],
    }


def _reports(evidence):
    rule = Path(__file__).resolve().parents[1] / "rules/packet_length_inverted_guard.cocci"
    script = rule.read_text().split("@finalize:python@", 1)[1].split("@@", 1)[1]
    tree = ast.parse(script)
    # Supply an owned stderr without changing process-global streams.
    tree.body = [node for node in tree.body if not isinstance(node, ast.Import)]
    output = io.StringIO()
    exec(compile(tree, str(rule), "exec"), {
        "json": json, "sys": SimpleNamespace(stderr=output), "_packet_evidence": evidence,
    })
    return [json.loads(line.removeprefix("COCCIRESULT:")) for line in output.getvalue().splitlines()]


@pytest.mark.parametrize("first_valid,visits,reports", [(0, 1, 1), (1, 2, 1), (128, 128, 0)],
                         ids=["first-valid", "later-valid", "no-valid"])
def test_report_stops_only_after_success(first_valid, visits, reports):
    events = _events(first_valid)
    rows = _reports({("owned.c", "owned", 1): events})
    assert len(rows) == reports
    assert events["consume"].visits == visits
    if rows:
        assert (rows[0]["file"], rows[0]["line"], rows[0]["col"], rows[0]["rule"]) == (
            "owned.c", 4, 1, "packet_length_inverted_guard",
        )


def test_duplicate_guard_still_emits_once():
    events = _events(0)
    events["reject"].append(dict(events["reject"][0]))
    assert len(_reports({("owned.c", "owned", 1): events})) == 1


def test_distinct_functions_keep_their_reports():
    rows = _reports({("owned.c", "first", 1): _events(0),
                     ("owned.c", "second", 101): _events(0, 100)})
    assert [(row["file"], row["line"]) for row in rows] == [("owned.c", 4), ("owned.c", 104)]


def test_distinct_guards_keep_their_reports():
    events = _events(0)
    events["reject"].append(dict(line=6, col=1, length="n", remaining="r", bad="bad"))
    events["reachable"].extend(dict(line=6, col=1, sink_line=str(line), sink_col="1")
                               for line in range(7, 133))
    rows = _reports({("owned.c", "owned", 1): events})
    assert [row["line"] for row in rows] == [4, 6]
