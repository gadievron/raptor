"""Unmarked source avoids uncached descriptor scans without changing scope."""

import pytest

from packages.semgrep import nosemgrep


class ObservedRules(list):
    def __init__(self):
        super().__init__([{"id": f"other-{i}", "guid": f"guid-{i}"} for i in range(127)]
                         + [{"id": "selected", "guid": "wanted"}])
        self.visits = self.index_reads = 0

    def __iter__(self):
        for value in super().__iter__():
            self.visits += 1
            yield value

    def __getitem__(self, index):
        self.index_reads += 1
        return super().__getitem__(index)


def document(files, reference):
    rules = ObservedRules()
    rows = [{"rule": dict(reference), "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": name}, "region": {"startLine": line},
    }}]} for name, line in files]
    return {"runs": [{"tool": {"driver": {"name": "semgrep", "rules": []},
                                "extensions": [{"name": "owned-extension", "rules": rules}]},
                      "results": rows}]}, rules, rows


@pytest.fixture
def lookups(monkeypatch):
    original = nosemgrep.get_result_rule
    calls = []

    def observe(run, result):
        calls.append(result)
        return original(run, result)

    monkeypatch.setattr(nosemgrep, "get_result_rule", observe)
    return calls


@pytest.mark.parametrize("case", ["unmarked", "matching", "mismatched", "previous"])
def test_uncached_reference_preserves_directive_scope(tmp_path, lookups, case):
    sources = {"unmarked": "void owned(void) {}\n",
               "matching": "owned(); // nosemgrep: selected\n",
               "mismatched": "owned(); // nosemgrep: other\n",
               "previous": "// nosemgrep: selected\nowned(); // nosemgrep: other\n"}
    (tmp_path / "owned.c").write_text(sources[case])
    line = 2 if case == "previous" else 1
    doc, rules, rows = document([("owned.c", line)] * 16,
                                {"guid": "wanted", "toolComponent": {"name": "owned-extension"}})
    count = nosemgrep.annotate_sarif(doc, str(tmp_path))
    assert len(lookups) == (0 if case == "unmarked" else 1)
    assert rules.visits == (0 if case == "unmarked" else 128)
    expected = 16 if case in ("matching", "previous") else 0
    assert count == expected
    if expected:
        for row in rows:
            info = row["properties"]["nosemgrep"]
            assert info["rule_ids"] == ["selected"]
            assert info["comment_line"] == 1
    else:
        assert all("nosemgrep" not in row.get("properties", {}) for row in rows)


@pytest.mark.parametrize("index", [0, True], ids=["indexed", "malformed-bool"])
def test_direct_selector_validation_is_not_prefiltered(tmp_path, lookups, index):
    (tmp_path / "owned.c").write_text("void owned(void) {}\n")
    doc, rules, _ = document([("owned.c", 1)] * 4,
                             {"index": index, "toolComponent": {"index": 0}})
    assert nosemgrep.annotate_sarif(doc, str(tmp_path)) == 0
    assert len(lookups) == 4
    assert rules.visits == 0
    assert bool(rules.index_reads) is (type(index) is int)


@pytest.mark.parametrize("marked_first", [False, True])
def test_unmarked_file_does_not_poison_reference_reuse(tmp_path, lookups, marked_first):
    (tmp_path / "marked.c").write_text("owned(); // nosemgrep: selected\n")
    (tmp_path / "quiet.c").write_text("void owned(void) {}\n")
    files = ["marked.c", "quiet.c"] if marked_first else ["quiet.c", "marked.c"]
    doc, rules, rows = document([(name, 1) for name in files],
                                {"guid": "wanted", "toolComponent": {"name": "owned-extension"}})
    assert nosemgrep.annotate_sarif(doc, str(tmp_path)) == 1
    assert len(lookups) == 1 and rules.visits == 128
    by_file = dict(zip(files, rows))
    assert by_file["marked.c"]["properties"]["nosemgrep"]["suppressed"] is True
    assert "nosemgrep" not in by_file["quiet.c"].get("properties", {})
