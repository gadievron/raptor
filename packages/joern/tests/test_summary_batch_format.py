"""METHOD_SUMMARY batch record format — emitter and parser pair.

The old format was ``METHOD:n|TAINTS:a,b|PRE:...|RET:...`` with zero
escaping: a ``|`` or ``,`` inside a CPG code snippet forged extra
fields/entries, silently corrupting summaries. Records are now one
``METHOD_SUMMARY:{json}`` line each with every string field jsonEsc'd
on the Scala side; the parser is strict per-line JSON.
"""

from __future__ import annotations

from packages.joern.models import JoernMethodSummary
from packages.joern.runner import (
    SCALA_JSON_ESC_DEF,
    _build_summary_batch_query,
    _validate_query,
    parse_summary_output,
)


def _scala_json_esc(v: str) -> str:
    """Python reference of the Scala jsonEsc (semantics under test)."""
    v = (
        v.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\r", "")
        .replace("\n", " ")
    )
    return "".join(
        " " if (ord(c) < 0x20 or ord(c) in (0x85, 0x2028, 0x2029)) else c
        for c in v
    )


def _record(method: str, taints=(), pre=(), ret=(), found: bool = True) -> str:
    """A record line exactly as the Scala emitter builds it."""
    if not found:
        return (
            f'METHOD_SUMMARY:{{"method":"{_scala_json_esc(method)}",'
            '"found":false}'
        )
    def arr(xs) -> str:
        return "[" + ",".join(f'"{_scala_json_esc(x[:200])}"' for x in xs) + "]"
    return (
        f'METHOD_SUMMARY:{{"method":"{_scala_json_esc(method)}","found":true,'
        f'"taints":{arr(taints)},"pre":{arr(pre)},"ret":{arr(ret)}}}'
    )


class TestRoundTrip:
    def test_plain_fields(self):
        raw = _record("parse_hdr", taints=["buf"], pre=["check(len)"],
                      ret=["int"])
        out = parse_summary_output(raw)
        assert set(out) == {"parse_hdr"}
        s = out["parse_hdr"]
        assert isinstance(s, JoernMethodSummary)
        assert s.taint_rules == ["buf"]
        assert s.preconditions == ["check(len)"]
        assert s.returns == ["int"]

    def test_pipes_and_commas_survive_intact(self):
        # The exact class the old format destroyed: '|' forged a new
        # field, ',' forged extra list entries.
        hostile = 'x | y, z|TAINTS:forged,RET:void'
        raw = _record("f", taints=[hostile], ret=["int"])
        out = parse_summary_output(raw)
        assert out["f"].taint_rules == [hostile]
        assert out["f"].returns == ["int"]

    def test_quotes_backslashes_newlines_tabs_flattened_not_fatal(self):
        hostile = 'say "hi" \\ twice\nline2\ttabbed\rcr'
        raw = _record("g", pre=[hostile])
        out = parse_summary_output(raw)
        # jsonEsc strips \r (no space), flattens \n and \t to single
        # spaces; quotes and backslashes round-trip through the JSON
        # escapes.
        assert out["g"].preconditions == ['say "hi" \\ twice line2 tabbedcr']

    def test_unicode_line_separators_flattened(self):
        hostile = "a\u2028b\u2029c\u0085d"
        raw = _record("h", ret=[hostile])
        # str.splitlines on the transport would split BEFORE parsing —
        # the emitter must have flattened these already.
        assert len(raw.splitlines()) == 1
        out = parse_summary_output(raw)
        assert out["h"].returns == ["a b c d"]

    def test_not_found_records_skipped(self):
        raw = "\n".join([
            _record("gone", found=False),
            _record("here", ret=["void"]),
        ])
        out = parse_summary_output(raw)
        assert set(out) == {"here"}


class TestParserTransportTolerance:
    def test_repl_echo_prefix_accepted(self):
        # Server transport: the record rides the final expression's
        # value echo, whose first line carries the val prefix.
        raw = 'val res0: String = """' + _record("f", ret=["int"])
        out = parse_summary_output(raw)
        assert set(out) == {"f"}

    def test_trailing_echo_quotes_stripped(self):
        raw = _record("f", ret=["int"]) + '"""'
        out = parse_summary_output(raw)
        assert out["f"].returns == ["int"]

    def test_single_record_escaped_echo_recovered(self):
        # A ONE-method batch's final expression echoes single-quoted on
        # one line with Java-escaped content — the server transport's
        # ONLY copy of the record, so it must recover, not skip.
        record = _record("helper", taints=["buf"], ret=["int"])
        escaped = record.replace("\\", "\\\\").replace('"', '\\"')
        raw = f'val res3: String = "{escaped}"'
        out = parse_summary_output(raw)
        assert set(out) == {"helper"}
        assert out["helper"].taint_rules == ["buf"]
        assert out["helper"].returns == ["int"]

    def test_two_record_triple_quote_echo_still_parses(self):
        body = _record("f", ret=["int"]) + "\n" + _record("g", ret=["void"])
        raw = f'val res0: String = """{body}"""'
        out = parse_summary_output(raw)
        assert set(out) == {"f", "g"}

    def test_bare_escaped_record_without_echo_framing_warns(self, caplog):
        # No binder shape, no echo prefix: an escaped record printed
        # directly is a genuinely undecodable record — a dropped
        # summary that must be logged, never silently absorbed.
        import logging

        raw = 'METHOD_SUMMARY:{\\"method\\":\\"f\\",\\"found\\":true}'
        with caplog.at_level(logging.WARNING, logger="packages.joern.runner"):
            assert parse_summary_output(raw) == {}
        assert any("dropped" in r.message for r in caplog.records)

    def test_println_plus_echo_duplicates_collapse_silently(self, caplog):
        import logging

        line = _record("f", ret=["int"])
        escaped = line.replace("\\", "\\\\").replace('"', '\\"')
        raw = f'{line}\nval res0: String = "{escaped}"'
        with caplog.at_level(logging.WARNING, logger="packages.joern.runner"):
            out = parse_summary_output(raw)
        assert list(out) == ["f"]
        assert not caplog.records

    def test_noise_lines_ignored(self):
        raw = "warming up\n" + _record("f") + "\nJOERN misc\n"
        assert set(parse_summary_output(raw)) == {"f"}


class TestEmitter:
    def test_dual_transport(self):
        q = _build_summary_batch_query(["alpha", "beta"])
        assert q is not None
        # Subprocess transport: println per record.
        assert "summaryLines.foreach(println)" in q
        # Server transport: records ride the final expression string.
        assert q.rstrip().endswith('summaryLines.mkString("\\n")')

    def test_embeds_canonical_json_esc(self):
        q = _build_summary_batch_query(["alpha"])
        assert SCALA_JSON_ESC_DEF in q
        # Every element is raw-truncated BEFORE escaping inside jsonArr.
        assert 'jsonEsc(x.take(200))' in q

    def test_engine_context_applied_explicitly(self):
        # The server REPL session is persistent: an earlier query's
        # top-level `implicit val engineContext` (standard_sinks.sc
        # declares one) makes bare implicit resolution ambiguous with
        # JoernConsole's own context — a compile error that silently
        # loses the whole batch. Explicit application is immune.
        q = _build_summary_batch_query(["alpha"])
        assert (
            "val summaryCtx = "
            "io.joern.dataflowengineoss.queryengine.EngineContext()"
        ) in q
        assert (
            ".reachableBy(cpg.method.nameExact(n).parameter)(summaryCtx)"
        ) in q

    def test_passes_query_validation(self):
        q = _build_summary_batch_query(["alpha", "beta"])
        assert _validate_query(q, check_length=False) is None

    def test_invalid_names_filtered(self):
        assert _build_summary_batch_query([]) is None
        assert _build_summary_batch_query(["bad name", "a;b"]) is None
        q = _build_summary_batch_query(["bad name", "good_name"])
        assert '"good_name"' in q
        assert "bad name" not in q
