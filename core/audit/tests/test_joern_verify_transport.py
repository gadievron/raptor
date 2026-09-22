"""Sentinel transport discipline for the joern_verify channels.

println output does not come back through the Joern server's
query-sync transport — only the final expression's string echo lands
in ``raw_output``. A println-emitting verification query therefore
answers with an EMPTY protocol stream on a real server: the parsers
find no sentinels, every check degrades to error/inconclusive, and
the channel reads structurally dead while its unit tests (driven by
doubles that echoed println) stay green. These tests pin the
transport contract at build time and prove the parsers read the
final-expression echo shape the real REPL produces.
"""

from __future__ import annotations

from core.audit.joern_verify import (
    _FLOW_COUNT,
    _FLOW_DEEP,
    _FLOW_FUNC,
    _FLOW_SNK,
    _FLOW_SRC,
    _GD_FUNC,
    _GD_GUARDED,
    _GD_SINKS,
    _GD_UNGUARDED,
    _anchored,
    _parse_flow_facts,
    _parse_guard_output,
    build_flow_query,
    build_guard_dominance_query,
)


def _guard_query() -> str:
    return build_guard_dominance_query(
        "process", "memcpy", "len", nonce="abcdef123456",
    )


def _flow_query() -> str:
    return build_flow_query(
        "process", "buf", "memcpy", max_call_depth=2,
        nonce="abcdef123456",
    )


class TestNoPrintln:
    def test_guard_query_never_rides_println(self):
        assert "println" not in _guard_query()

    def test_flow_query_never_rides_println(self):
        assert "println" not in _flow_query()

    def test_the_locally_block_is_the_framed_final_expression(self):
        # The framed string must be the last expression INSIDE the
        # locally block: the block's value is what echoes.
        for q in (_guard_query(), _flow_query()):
            lines = q.strip().splitlines()
            assert lines[-1] == "}"
            assert lines[-2].strip().startswith('"RAPTOR_VERIFY_START')
            assert lines[-2].endswith('"\\nRAPTOR_VERIFY_END"')

    def test_buffer_lives_inside_the_locally_block(self):
        # A TOP-LEVEL binder echoes its POPULATED final state, and
        # quote-bearing elements echo with raw inner quotes that the
        # marker parser tokenises into broken fragments — erroring
        # the channel on any function whose facts quote a string
        # literal. The buffer must be block-local.
        for q in (_guard_query(), _flow_query()):
            assert q.index("locally {") < q.index("val raptorOut")
            assert not any(
                line.startswith("val raptorOut")
                for line in q.splitlines()
            )

    def test_payloads_flatten_every_line_break_class(self):
        # Payload text is hostile; every code point splitlines()
        # honours must flatten, and JOERN_ marker text must be
        # neutralised so it cannot mint record-marker lines.
        q = _guard_query()
        assert "replaceAll(" in q
        for cls in ("\\r", "\\n", "\\u000B", "\\f",
                    "\\u0085", "\\u2028", "\\u2029"):
            assert cls in q
        assert 'replace("JOERN_", "JOERN-")' in q

    def test_verdict_is_full_set_and_emission_is_capped(self):
        # The refutation quantifies over EVERY sink: iteration must be
        # uncapped, only evidence EMISSION is capped, and the uncapped
        # unguarded count rides its own sentinel — a take() on the
        # iteration truncated the quantifier and a genuinely unguarded
        # 51st sink booked a false refutation.
        q = _guard_query()
        assert "raptorSinks.foreach" in q
        assert ".take(50).foreach" not in q
        assert "raptorUngN <= 50" in q
        assert "raptorGrdN <= 50" in q
        assert "RAPTOR_GD_UNG_TOTAL:" in q


class TestParsersReadTheEchoShape:
    """The Scala 3 REPL echoes the final string as
    ``val resN: String = \"\"\"<content>\"\"\"`` with REAL embedded
    newlines — the parsers must extract line-anchored sentinels from
    that shape."""

    def _echo(self, *content_lines: str) -> str:
        body = "\n".join(content_lines)
        return (
            'val res0: String = """RAPTOR_VERIFY_START\n'
            + body
            + '\nRAPTOR_VERIFY_END"""\n'
        )

    def test_guard_facts_parse_from_final_expression_echo(self):
        nonce = "abcdef123456"
        raw = self._echo(
            _anchored(_GD_FUNC, nonce) + "found",
            _anchored(_GD_SINKS, nonce) + "2",
            _anchored(_GD_UNGUARDED, nonce) + "14|memcpy(dst, buf, len)",
            _anchored(_GD_GUARDED, nonce)
            + "22|20|len < 16|memcpy(d, b, len)",
        )
        facts = _parse_guard_output(raw, nonce)
        assert facts["function_found"] is True
        assert facts["sink_count"] == 2
        assert facts["unguarded"] == [
            {"line": 14, "code": "memcpy(dst, buf, len)"},
        ]
        assert facts["guarded"][0]["guard_code"] == "len < 16"

    def test_flow_facts_parse_from_final_expression_echo(self):
        nonce = "abcdef123456"
        raw = self._echo(
            _anchored(_FLOW_FUNC, nonce) + "found",
            _anchored(_FLOW_SRC, nonce) + "3",
            _anchored(_FLOW_SNK, nonce) + "1",
            'JOERN_FLOW:[{"line":4,"code":"memcpy(dst, buf, n)",'
            '"function":"process","file":"a.c"}]',
            _anchored(_FLOW_COUNT, nonce) + "1",
            _anchored(_FLOW_DEEP, nonce) + "0",
        )
        facts = _parse_flow_facts(raw, nonce)
        assert facts["function_found"] is True
        assert facts["source_count"] == 3
        assert facts["sink_count"] == 1
        assert facts["flow_count"] == 1
        assert facts["deep_callee_count"] == 0

    def test_missing_function_parses_from_echo(self):
        nonce = "abcdef123456"
        raw = self._echo(_anchored(_GD_FUNC, nonce) + "missing")
        facts = _parse_guard_output(raw, nonce)
        assert facts["function_found"] is False

    def test_println_shaped_empty_stream_yields_no_facts(self):
        # The pre-fix failure mode: a real server returns '' for a
        # println-riding query — parsers must answer "no protocol
        # output" (function_found None), never fabricate.
        facts = _parse_guard_output("", "abcdef123456")
        assert facts["function_found"] is None
        flow = _parse_flow_facts("", "abcdef123456")
        assert flow["function_found"] is None


class TestErrorScanExemption:
    def test_sentinel_lines_never_read_as_compiler_diagnostics(self):
        # Sentinel payloads quote scanned-repo source; a payload
        # containing a path:N: error: shaped literal must not veto
        # the query's own evidence.
        from packages.joern.server import _has_scala_error

        hostile = (
            'val res0: String = """RAPTOR_VERIFY_START\n'
            'RAPTOR_GD_UNGUARDED:abcdef123456:5|'
            'memcpy(dst,buf,strlen("x:12: error: boom")+len)\n'
            'RAPTOR_FLOW_SNK:abcdef123456:1\n'
            'RAPTOR_VERIFY_END"""\n'
        )
        assert _has_scala_error(hostile) is False
        # A GENUINE diagnostic line still trips the scan.
        assert _has_scala_error("foo.sc:3: error: not found: cpg") is True
