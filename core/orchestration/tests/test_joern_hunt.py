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


class FakeFlow:
    steps = []


class FakeServer:
    def __init__(self, raw_output="", verdicts=None, error=False,
                 degraded=False):
        self.raw_output = raw_output
        self.verdicts = verdicts or {}
        self.error = error
        self.degraded = degraded
        self.queries = []
        self.taint_queries = []

    def query(self, cpgql, **kwargs):
        self.queries.append(cpgql)
        if self.error:
            raise RuntimeError("joern down")
        return FakeResult(raw_output=self.raw_output)

    def run_taint_query(self, source_method, sink_call, *,
                        errors_out=None, **kwargs):
        self.taint_queries.append((source_method, sink_call))
        if self.error:
            raise RuntimeError("joern down")
        if self.degraded:
            if errors_out is not None:
                errors_out.append("server restarting")
            return []
        if self.verdicts.get((source_method, sink_call), False):
            return [FakeFlow()]
        return []


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
        assert srv.taint_queries == [("f", "memcpy"), ("g", "memcpy")]

    def test_sink_parsed_from_code_when_no_arg(self):
        matches = [
            {"file": "b.c", "line": 2, "function": "g",
             "code": "strcpy(dst, src)"},
        ]
        srv = FakeServer()
        classify_taint_batch(matches, srv)
        assert srv.taint_queries == [("g", "strcpy")]

    def test_unique_pairs_queried_once(self):
        matches = [
            {"file": "a.c", "line": 1, "caller": "f", "sink": "memcpy"},
            {"file": "a.c", "line": 9, "caller": "f", "sink": "memcpy"},
        ]
        srv = FakeServer()
        classify_taint_batch(matches, srv)
        assert srv.taint_queries == [("f", "memcpy")]

    def test_unresolvable_match_left_untouched(self):
        matches = [{"file": "a.c", "line": 1, "code": "no call here"}]
        srv = FakeServer()
        classify_taint_batch(matches, srv)
        assert "joern_tainted" not in matches[0]
        assert srv.taint_queries == []

    def test_query_error_leaves_match_unclassified(self):
        matches = [
            {"file": "a.c", "line": 1, "caller": "f", "sink": "memcpy"},
        ]
        classify_taint_batch(matches, FakeServer(error=True))
        assert "joern_tainted" not in matches[0]

    def test_degraded_query_not_booked_as_negative(self):
        # Server-degraded query (errors_out populated, no flows):
        # "no taint path" and "the query never ran" are
        # indistinguishable — the match must stay unclassified, never
        # gain joern_tainted: false.
        matches = [
            {"file": "a.c", "line": 1, "caller": "f", "sink": "memcpy"},
        ]
        classify_taint_batch(matches, FakeServer(degraded=True))
        assert "joern_tainted" not in matches[0]

    def test_clean_no_flow_still_books_negative(self):
        # Two-direction guard: a clean (error-free) empty result IS a
        # negative — the degraded-skip must not swallow real verdicts.
        matches = [
            {"file": "a.c", "line": 1, "caller": "f", "sink": "memcpy"},
        ]
        classify_taint_batch(matches, FakeServer())
        assert matches[0]["joern_tainted"] is False


class TestCallsiteProtocolIntegrity:
    """JOERN_CALLER lines survive hostile caller/file values."""

    def test_template_escapes_all_interpolated_fields(self):
        from core.orchestration.joern_hunt import _CALLSITE_QUERY_TEMPLATE
        # caller, file, and code all pass through the same escape
        # helper — a quote or newline in any of them cannot break the
        # JSON line or forge extra records.
        assert "jsonEsc(c.method.name)" in _CALLSITE_QUERY_TEMPLATE
        assert "jsonEsc(c.method.filename)" in _CALLSITE_QUERY_TEMPLATE
        assert "jsonEsc(c.code.take(200))" in _CALLSITE_QUERY_TEMPLATE

    def test_template_embeds_canonical_json_esc(self):
        # Single authority for the Scala-side escape: a local copy can
        # silently lose the tab/C0/U+2028 flattening the canonical
        # definition carries.
        from packages.joern.runner import SCALA_JSON_ESC_DEF

        from core.orchestration.joern_hunt import _CALLSITE_QUERY_TEMPLATE
        assert SCALA_JSON_ESC_DEF in _CALLSITE_QUERY_TEMPLATE

    def test_template_dual_transport(self):
        from core.orchestration.joern_hunt import _CALLSITE_QUERY_TEMPLATE
        # Subprocess transport: println per record. Server transport:
        # /query-sync drops println output, so the records must ALSO
        # ride the final expression's string echo.
        assert "callerLines.foreach(println)" in _CALLSITE_QUERY_TEMPLATE
        assert _CALLSITE_QUERY_TEMPLATE.rstrip().endswith(
            'callerLines.mkString("\\n")'
        )

    def test_quoted_filename_round_trips(self):
        # What Joern prints after the Scala-side escaping for a file
        # literally named `weird"name .c` (quote and newline in the
        # original; the newline is flattened to a space).
        raw = (
            'JOERN_CALLER:{"caller":"handler","file":"weird\\"name .c",'
            '"line":7,"code":"memcpy(dst, src, n)"}\n'
            "JOERN_CALLERS_DONE"
        )
        matches = find_sink_callsites("memcpy", FakeServer(raw_output=raw))
        assert len(matches) == 1
        assert matches[0]["file"] == 'weird"name .c'
        assert matches[0]["caller"] == "handler"

    def test_corrupt_marker_line_warns_instead_of_silent_drop(self, caplog):
        import logging

        raw = (
            'JOERN_CALLER:{"caller":"good","file":"a.c","line":1,'
            '"code":"memcpy(a, b, c)"}\n'
            'JOERN_CALLER:{"caller":"broken", \n'
            "JOERN_CALLERS_DONE"
        )
        with caplog.at_level(logging.WARNING,
                             logger="core.orchestration.joern_hunt"):
            matches = find_sink_callsites(
                "memcpy", FakeServer(raw_output=raw))
        assert [m["caller"] for m in matches] == ["good"]
        assert any("undecodable" in r.message for r in caplog.records)
        assert any("failed to decode" in r.message for r in caplog.records)

    def test_unrecoverable_repl_value_echo_warns(self, caplog):
        # An echo that carries the marker but stays undecodable is a
        # DROPPED call site on the server transport (the value echo is
        # the only record carrier there) — parse_marker_line now
        # surfaces it as a decode error, and this consumer's existing
        # dropped-record warnings fire instead of a silent zero.
        import logging

        raw = (
            'val res0: String = """JOERN_CALLER:{\\"caller\\":\\"x\\"}"""\n'
            "JOERN_CALLERS_DONE"
        )
        with caplog.at_level(logging.WARNING,
                             logger="core.orchestration.joern_hunt"):
            matches = find_sink_callsites(
                "memcpy", FakeServer(raw_output=raw))
        assert matches == []
        assert any("undecodable" in r.message for r in caplog.records)

    def test_quote_bearing_genuine_failure_still_warns(self, caplog):
        # jsonEsc deliberately injects \" into printed records, so
        # escaped quotes in the payload must NOT read as REPL-echo
        # noise: a directly printed record that fails to parse is a
        # dropped call site and must surface.
        import logging

        raw = (
            'JOERN_CALLER:{"caller":"log_it","code":"puts(\\"hi\\")", \n'
            "JOERN_CALLERS_DONE"
        )
        with caplog.at_level(logging.WARNING,
                             logger="core.orchestration.joern_hunt"):
            matches = find_sink_callsites(
                "memcpy", FakeServer(raw_output=raw))
        assert matches == []
        assert any("undecodable" in r.message for r in caplog.records)

    def test_server_echo_first_and_last_records_parse(self):
        # Server transport: /query-sync drops println output — records
        # ride the final expression echo whose first line carries the
        # binder prefix and whose last line carries the closing quotes.
        raw = (
            'val res0: String = """JOERN_CALLER:{"caller":"first",'
            '"file":"a.c","line":1,"code":"memcpy(a, b, c)"}\n'
            'JOERN_CALLER:{"caller":"last","file":"z.c","line":9,'
            '"code":"memcpy(x, y, z)"}"""'
        )
        matches = find_sink_callsites("memcpy", FakeServer(raw_output=raw))
        assert [(m["caller"], m["file"]) for m in matches] == [
            ("first", "a.c"), ("last", "z.c"),
        ]

    def test_server_list_binder_echo_recovered_without_warnings(self, caplog):
        # Server transport transcript of the callsite query: the REPL
        # also echoes the intermediate `val callerLines = ...` binder
        # as a List with one Java-escaped element per line, framed by
        # `List(` / `)` lines, BEFORE the final-expression echo. The
        # binder echo must recover (or dedupe) silently — reading it as
        # dropped records produced phantom warnings on every
        # multi-callsite target.
        import logging

        raw = (
            "val callerLines: List[String] = List(\n"
            '  "JOERN_CALLER:{\\"caller\\":\\"parse_alpha\\",'
            '\\"file\\":\\"entry.c\\",\\"line\\":25,'
            '\\"code\\":\\"memcpy(out, buf + 1, claimed)\\"}",\n'
            '  "JOERN_CALLER:{\\"caller\\":\\"dispatch_cb\\",'
            '\\"file\\":\\"table.c\\",\\"line\\":90,'
            '\\"code\\":\\"memcpy(dst, src, n)\\"}"\n'
            ")\n"
            'val res1: String = """JOERN_CALLER:{"caller":"parse_alpha",'
            '"file":"entry.c","line":25,'
            '"code":"memcpy(out, buf + 1, claimed)"}\n'
            'JOERN_CALLER:{"caller":"dispatch_cb","file":"table.c",'
            '"line":90,"code":"memcpy(dst, src, n)"}"""'
        )
        with caplog.at_level(logging.WARNING,
                             logger="core.orchestration.joern_hunt"):
            matches = find_sink_callsites(
                "memcpy", FakeServer(raw_output=raw))
        assert [(m["caller"], m["line"]) for m in matches] == [
            ("parse_alpha", 25), ("dispatch_cb", 90),
        ]
        assert not caplog.records

    def test_single_line_escaped_echo_recovered(self, caplog):
        # A one-record result echoes single-quoted with Java-escaped
        # content; one unescape round recovers the record silently.
        import logging

        raw = (
            'val res0: String = "JOERN_CALLER:{\\"caller\\":\\"cb\\",'
            '\\"file\\":\\"t.c\\",\\"line\\":7,\\"code\\":\\"memcpy(p, q, r)\\"}"'
        )
        with caplog.at_level(logging.WARNING,
                             logger="core.orchestration.joern_hunt"):
            matches = find_sink_callsites(
                "memcpy", FakeServer(raw_output=raw))
        assert [(m["caller"], m["line"]) for m in matches] == [("cb", 7)]
        assert not caplog.records

    def test_trailing_newline_sink_rejected(self):
        # fullmatch: a $-anchored match() admits "memcpy\n".
        srv = FakeServer()
        assert find_sink_callsites("memcpy\n", srv) == []
        assert srv.queries == []

    def test_classify_rejects_trailing_newline_names(self):
        srv = FakeServer(verdicts={("caller", "memcpy"): True})
        matches = [{"caller": "caller\n", "sink": "memcpy",
                    "file": "a.c", "line": 1}]
        classify_taint_batch(matches, srv)
        assert "joern_tainted" not in matches[0]
        assert srv.taint_queries == []


class TestRestartRetrySeam:
    """find_sink_callsites routes through the server's restart-window
    retry when the server offers it; thinner doubles keep plain query."""

    def test_retry_seam_used_when_available(self):
        from core.orchestration.joern_hunt import find_sink_callsites
        calls = {"retry": 0, "query": 0}

        class _Server:
            def retry_once_after_restart(self, call, *, max_wait_s=None):
                calls["retry"] += 1
                return call()

            def query(self, q, **kw):
                calls["query"] += 1
                class R:
                    errors: list = []
                    stdout = ""
                    raw_output = ""
                return R()

        find_sink_callsites("system", _Server())
        assert calls["retry"] == 1
        assert calls["query"] == 1

    def test_plain_query_without_seam(self):
        from core.orchestration.joern_hunt import find_sink_callsites
        calls = {"query": 0}

        class _Thin:
            def query(self, q, **kw):
                calls["query"] += 1
                class R:
                    errors: list = []
                    stdout = ""
                    raw_output = ""
                return R()

        find_sink_callsites("system", _Thin())
        assert calls["query"] == 1
