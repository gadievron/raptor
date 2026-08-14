"""Tests for core.orchestration.joern_hunt."""

from __future__ import annotations

from core.orchestration.joern_hunt import (
    classify_taint_batch,
    find_sink_callsites,
    merge_matches,
)


class FakeResult:
    def __init__(self, raw_output="", errors=None):
        self.raw_output = raw_output
        self.errors = errors or []


class FakeServer:
    def __init__(self, raw_output="", verdicts=None, error=False):
        self.raw_output = raw_output
        self.verdicts = verdicts or {}
        self.error = error
        self.queries = []
        self.exists_queries = []

    def query(self, cpgql, **kwargs):
        self.queries.append(cpgql)
        if self.error:
            raise RuntimeError("joern down")
        return FakeResult(raw_output=self.raw_output)

    def run_taint_exists_query(self, source_method, sink_call, **kwargs):
        self.exists_queries.append((source_method, sink_call))
        if self.error:
            raise RuntimeError("joern down")
        return self.verdicts.get((source_method, sink_call), False)


# Line 2 is an ANSI-wrapped REPL echo of the same site — must dedupe.
# Line 3 is an escaped-quote value echo — must not parse or error.
_CALLSITE_OUTPUT = (
    'JOERN_CALLER:{"caller":"parse_alpha","file":"entry.c","line":25,'
    '"code":"memcpy(out, buf + 1, claimed)"}\n'
    '\x1b[32mJOERN_CALLER:{"caller":"parse_alpha","file":"entry.c",'
    '"line":25,"code":"memcpy(out, buf + 1, claimed)"}\x1b[0m\n'
    'val res0: String = """JOERN_CALLER:{\\"caller\\":\\"x\\"}"""\n'
    'JOERN_CALLER:{"caller":"dispatch_cb","file":"table.c","line":90,'
    '"code":"memcpy(dst, src, n)"}\n'
    "JOERN_CALLERS_DONE"
)


class TestFindSinkCallsites:
    def test_parses_and_dedupes_callsites(self):
        srv = FakeServer(raw_output=_CALLSITE_OUTPUT)
        matches = find_sink_callsites("memcpy", srv)
        assert [(m["file"], m["line"]) for m in matches] == [
            ("entry.c", 25), ("table.c", 90),
        ]
        assert matches[0]["caller"] == "parse_alpha"
        assert matches[0]["sink"] == "memcpy"
        assert all(m["source"] == "joern" for m in matches)

    def test_sink_name_substituted_into_query(self):
        srv = FakeServer()
        find_sink_callsites("memcpy", srv)
        assert 'cpg.call.name("memcpy")' in srv.queries[0]

    def test_rejects_non_identifier_sink(self):
        srv = FakeServer()
        assert find_sink_callsites('x"); system("id', srv) == []
        assert srv.queries == []

    def test_query_error_returns_empty(self):
        assert find_sink_callsites("memcpy", FakeServer(error=True)) == []


class TestMergeMatches:
    def test_union_dedupes_by_file_line(self):
        grep = [{"file": "entry.c", "line": 25, "code": "memcpy(...)"}]
        joern = [
            {"file": "entry.c", "line": 25, "code": "memcpy(...)",
             "caller": "parse_alpha"},
            {"file": "table.c", "line": 90, "code": "memcpy(...)",
             "caller": "dispatch_cb"},
        ]
        merged = merge_matches(grep, joern)
        assert len(merged) == 2
        # Grep hit wins on collision but gains the Joern annotation.
        assert merged[0] is grep[0]
        assert merged[0]["joern_callers_found"] is True
        assert merged[1]["joern_callers_found"] is True

    def test_grep_only_match_not_annotated(self):
        merged = merge_matches(
            [{"file": "a.c", "line": 1, "code": "memcpy(x, y, z)"}], [])
        assert "joern_callers_found" not in merged[0]


class TestClassifyTaintBatch:
    def test_annotates_verdicts(self):
        matches = [
            {"file": "entry.c", "line": 25, "caller": "parse_alpha",
             "sink": "memcpy"},
            {"file": "table.c", "line": 90, "caller": "dispatch_cb",
             "sink": "memcpy"},
        ]
        srv = FakeServer(verdicts={("parse_alpha", "memcpy"): True})
        classify_taint_batch(matches, srv)
        assert matches[0]["joern_tainted"] is True
        assert matches[1]["joern_tainted"] is False

    def test_explicit_sink_arg_beats_code_parse(self):
        matches = [
            {"file": "a.c", "line": 1, "caller": "f"},
            {"file": "b.c", "line": 2, "function": "g",
             "code": "strcpy(dst, src)"},
        ]
        srv = FakeServer()
        classify_taint_batch(matches, srv, sink_call="memcpy")
        assert srv.exists_queries == [("f", "memcpy"), ("g", "memcpy")]

    def test_sink_parsed_from_code_when_no_arg(self):
        matches = [
            {"file": "b.c", "line": 2, "function": "g",
             "code": "strcpy(dst, src)"},
        ]
        srv = FakeServer()
        classify_taint_batch(matches, srv)
        assert srv.exists_queries == [("g", "strcpy")]

    def test_unique_pairs_queried_once(self):
        matches = [
            {"file": "a.c", "line": 1, "caller": "f", "sink": "memcpy"},
            {"file": "a.c", "line": 9, "caller": "f", "sink": "memcpy"},
        ]
        srv = FakeServer()
        classify_taint_batch(matches, srv)
        assert srv.exists_queries == [("f", "memcpy")]

    def test_unresolvable_match_left_untouched(self):
        matches = [{"file": "a.c", "line": 1, "code": "no call here"}]
        srv = FakeServer()
        classify_taint_batch(matches, srv)
        assert "joern_tainted" not in matches[0]
        assert srv.exists_queries == []

    def test_query_error_leaves_match_unclassified(self):
        matches = [
            {"file": "a.c", "line": 1, "caller": "f", "sink": "memcpy"},
        ]
        classify_taint_batch(matches, FakeServer(error=True))
        assert "joern_tainted" not in matches[0]
