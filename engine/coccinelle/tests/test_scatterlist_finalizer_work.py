"""Execute owned scatterlist finalizer statements without native matching."""

import ast
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest


RULE = Path(__file__).resolve().parents[1] / "rules" / "scatterlist_frag_undersize.cocci"


class ObservedLinks(list):
    def __init__(self, values):
        super().__init__(values)
        self.visits = 0

    def __iter__(self):
        for value in super().__iter__():
            self.visits += 1
            yield value


def finalise(counts, links, maps, crypts, guarded=()):
    tree = ast.parse(RULE.read_text().split("@finalize:python@\n@@\n", 1)[1])
    tree.body = [node for node in tree.body if not isinstance(node, (ast.Import, ast.ImportFrom))]
    output = io.StringIO()
    exec(compile(tree, str(RULE), "exec"), {
        "json": json, "sys": SimpleNamespace(stderr=output),
        "_sfu_counts": counts, "_sfu_links": links, "_sfu_maps": maps,
        "_sfu_crypts": crypts, "_sfu_guarded": set(guarded),
    })
    return [json.loads(line.removeprefix("COCCIRESULT:")) for line in output.getvalue().splitlines()]


@pytest.mark.parametrize("missing", ["maps", "crypts"], ids=["no-maps", "no-crypts"])
def test_missing_required_category_skips_relationship_work(missing):
    counts = [("owned.c", "owned", i + 1, "skb", f"n{i}") for i in range(128)]
    links = ObservedLinks([("owned.c", "owned", f"table{i}", f"n{i}") for i in range(128)])
    maps = [] if missing == "maps" else [("owned.c", "owned", 200, "skb", "table0")]
    crypts = [] if missing == "crypts" else [("owned.c", "owned", "table0")]
    assert finalise(counts, links, maps, crypts) == []
    assert links.visits == 0
    assert len(counts) == len(links) == 128


def test_complete_relation_keeps_report_span_and_message():
    rows = finalise([("owned.c", "owned", 5, "skb", "n")],
                    [("owned.c", "owned", "table", "n")],
                    [("owned.c", "owned", 20, "skb", "table")],
                    [("owned.c", "owned", "table")])
    assert len(rows) == 1
    row = rows[0]
    assert (row["file"], row["line"], row["col"], row["line_end"], row["col_end"]) == ("owned.c", 5, 0, 5, 0)
    assert row["rule"] == "scatterlist_frag_undersize"
    assert "at line 5" in row["message"] and "at line 20" in row["message"]


def test_inline_count_does_not_require_links():
    rows = finalise([("owned.c", "owned", 5, "skb", "<inline:table>")], [],
                    [("owned.c", "owned", 20, "skb", "table")],
                    [("owned.c", "owned", "table")])
    assert len(rows) == 1 and rows[0]["line"] == 5


def test_other_function_crypto_does_not_qualify():
    assert finalise([("owned.c", "owned", 5, "skb", "n")],
                    [("owned.c", "owned", "table", "n")],
                    [("owned.c", "owned", 20, "skb", "table")],
                    [("owned.c", "other", "table")]) == []


def test_guarded_function_stays_quiet():
    links = ObservedLinks([("owned.c", "owned", "table", "n")])
    assert finalise([("owned.c", "owned", 5, "skb", "n")], links,
                    [("owned.c", "owned", 20, "skb", "table")],
                    [("owned.c", "owned", "table")], guarded=[("owned.c", "owned")]) == []
    assert links.visits == 0


def test_duplicate_maps_keep_first_report_once():
    rows = finalise([("owned.c", "owned", 5, "skb", "n")],
                    [("owned.c", "owned", "a", "n"), ("owned.c", "owned", "b", "n")],
                    [("owned.c", "owned", 20, "skb", "a"), ("owned.c", "owned", 30, "skb", "b")],
                    [("owned.c", "owned", "a"), ("owned.c", "owned", "b")])
    assert len(rows) == 1 and "at line 20" in rows[0]["message"]
