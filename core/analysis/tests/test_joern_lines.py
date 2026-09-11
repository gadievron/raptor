"""Tests for core.analysis._joern_lines transport-tolerant parsing."""

from __future__ import annotations

import json

from core.analysis._joern_lines import (
    parse_marker_line,
    parse_marker_records,
    strip_ansi,
)

_M = "JOERN_CALLER:"


class TestParseMarkerLine:
    def test_plain_record(self):
        records, err = parse_marker_line(f'{_M}{{"caller":"a"}}', _M)
        assert records == [{"caller": "a"}]
        assert err is None

    def test_no_marker(self):
        assert parse_marker_line("some jvm output", _M) == ([], None)

    def test_ansi_wrapped_record(self):
        line = f'\x1b[32m{_M}{{"caller":"a"}}\x1b[0m'
        records, err = parse_marker_line(line, _M)
        assert records == [{"caller": "a"}]
        assert err is None

    def test_echo_prefix_before_marker(self):
        # Server transport: first echoed line carries the binder.
        line = f'val res0: String = """{_M}{{"caller":"a"}}'
        records, err = parse_marker_line(line, _M)
        assert records == [{"caller": "a"}]
        assert err is None

    def test_trailing_triple_quote_framing(self):
        # Last echoed line carries the echo's closing quotes.
        line = f'{_M}{{"caller":"z"}}"""'
        records, err = parse_marker_line(line, _M)
        assert records == [{"caller": "z"}]
        assert err is None

    def test_single_line_escaped_echo_recovered(self):
        line = (
            'val res2: String = "'
            f'{_M}{{\\"caller\\":\\"cb\\",\\"line\\":7}}"'
        )
        records, err = parse_marker_line(line, _M)
        assert records == [{"caller": "cb", "line": 7}]
        assert err is None

    def test_escaped_echo_with_embedded_newline_yields_all_records(self):
        line = (
            'val res0: String = "'
            f'{_M}{{\\"caller\\":\\"a\\"}}\\n{_M}{{\\"caller\\":\\"b\\"}}"'
        )
        records, err = parse_marker_line(line, _M)
        assert records == [{"caller": "a"}, {"caller": "b"}]
        assert err is None

    def test_unrecoverable_echo_reports_error(self):
        # On the server transport the value echo is the ONLY record
        # carrier — an undecodable (width-truncated) echo is a dropped
        # record and must surface as degraded, not read as a healthy
        # zero.
        line = f'val res0: String = "{_M}{{\\"caller\\":\\"a\\", trunc...'
        records, err = parse_marker_line(line, _M)
        assert records == []
        assert err is not None
        assert "unrecoverable" in err

    def test_genuine_failure_reports_error(self):
        records, err = parse_marker_line(f"{_M}{{broken", _M)
        assert records == []
        assert err is not None
        assert "unparseable" in err

    def test_quote_bearing_genuine_failure_reports_error(self):
        # \" in the payload is normal jsonEsc output, not an echo tell.
        line = f'{_M}{{"code":"puts(\\"x\\")", broken'
        records, err = parse_marker_line(line, _M)
        assert records == []
        assert err is not None


class TestListBinderEcho:
    """Intermediate-binder echoes (``val xs: List[String] = List(``)."""

    def test_element_line_with_trailing_comma_recovered(self):
        line = f'  "{_M}[{{\\"line\\":3,\\"code\\":\\"memcpy(a, b, n)\\"}}]",'
        records, err = parse_marker_line(line, _M)
        assert records == [[{"line": 3, "code": "memcpy(a, b, n)"}]]
        assert err is None

    def test_last_element_line_without_comma_recovered(self):
        line = f'  "{_M}[{{\\"line\\":9}}]"'
        records, err = parse_marker_line(line, _M)
        assert records == [[{"line": 9}]]
        assert err is None

    def test_inline_single_element_recovered(self):
        line = (
            'val flowLines: List[String] = '
            f'List("{_M}[{{\\"line\\":3}}]")'
        )
        records, err = parse_marker_line(line, _M)
        assert records == [[{"line": 3}]]
        assert err is None

    def test_inline_multiple_elements_all_recovered(self):
        line = (
            'val callerLines: List[String] = '
            f'List("{_M}{{\\"caller\\":\\"a\\"}}", "{_M}{{\\"caller\\":\\"b\\"}}")'
        )
        records, err = parse_marker_line(line, _M)
        assert records == [{"caller": "a"}, {"caller": "b"}]
        assert err is None

    def test_element_with_escaped_quotes_in_payload(self):
        # jsonEsc output ``\"`` doubles to ``\\\"`` under the echo's
        # Java escaping; one unescape round must undo exactly one
        # layer.
        line = f'  "{_M}[{{\\"code\\":\\"puts(\\\\\\"x\\\\\\")\\"}}]",'
        records, err = parse_marker_line(line, _M)
        assert records == [[{"code": 'puts("x")'}]]
        assert err is None

    def test_framing_lines_carry_no_records_and_no_error(self):
        for framing in (
            "val flowLines: List[String] = List(",
            ")",
            "),",
        ):
            assert parse_marker_line(framing, _M) == ([], None)

    def test_truncated_element_reports_error(self):
        # A width-truncated binder-echo element is a dropped record on
        # the server transport (the binder echo can be the only
        # carrier) — it must surface as degraded, not as a healthy
        # zero. A subprocess transcript that also carries the println
        # copy still yields the record from that line; consumers that
        # hold records prefer them over the error.
        line = f'  "{_M}[{{\\"line\\":3,\\"co'
        records, err = parse_marker_line(line, _M)
        assert records == []
        assert err is not None
        assert "unrecoverable" in err

    def test_genuine_broken_record_still_errors(self):
        # No binder framing, raw quote delimiters: a printed record
        # that fails to decode is a dropped record and must surface.
        records, err = parse_marker_line(f'{_M}{{"caller":"x", broken', _M)
        assert records == []
        assert err is not None

    def test_binder_echo_dedupes_against_println_copies(self):
        record = {"caller": "a", "line": 1}
        println_line = f"{_M}{json.dumps(record, separators=(',', ':'))}"
        echoed = (
            println_line.replace("\\", "\\\\").replace('"', '\\"')
        )
        raw = (
            f"{println_line}\n"
            'val callerLines: List[String] = List(\n'
            f'  "{echoed}"\n'
            ")\n"
        )
        records, errors = parse_marker_records(raw, _M)
        assert records == [record]
        assert errors == []

    def test_healthy_multi_flow_server_transcript_no_errors(self):
        # Server transport transcript for a >=1-flow target: the
        # intermediate binder echo (one Java-escaped element per line)
        # plus the final expression's triple-quoted echo. Flows must
        # come back with EMPTY errors — a phantom error here blocks
        # result caching and pollutes tool-error feedback.
        flows = [
            [{"line": 3, "code": 'memcpy(dst, src, n)', "function": "f"}],
            [{"line": 9, "code": 'strcpy(a, b)', "function": "g"}],
        ]
        marker_lines = [
            f"{_M}{json.dumps(fl, separators=(',', ':'))}" for fl in flows
        ]
        escaped = [
            ln.replace("\\", "\\\\").replace('"', '\\"')
            for ln in marker_lines
        ]
        raw = (
            "val flowLines: List[String] = List(\n"
            f'  "{escaped[0]}",\n'
            f'  "{escaped[1]}"\n'
            ")\n"
            f'val res1: String = """{marker_lines[0]}\n'
            f'{marker_lines[1]}"""\n'
        )
        records, errors = parse_marker_records(raw, _M)
        assert records == flows
        assert errors == []


class TestParseMarkerRecords:
    def test_dedupes_println_and_echo_copies(self):
        record = f'{_M}{{"caller":"a","line":1}}'
        echoed = record.replace("\\", "\\\\").replace('"', '\\"')
        raw = f'{record}\nval res0: String = "{echoed}"\n'
        records, errors = parse_marker_records(raw, _M)
        assert records == [{"caller": "a", "line": 1}]
        assert errors == []

    def test_collects_errors_and_records(self):
        raw = f'{_M}{{"caller":"good"}}\n{_M}{{broken\n'
        records, errors = parse_marker_records(raw, _M)
        assert records == [{"caller": "good"}]
        assert len(errors) == 1

    def test_empty_and_none_output(self):
        assert parse_marker_records("", _M) == ([], [])

    def test_multiline_echo_round_trip(self):
        payloads = [{"caller": "a"}, {"caller": "b"}]
        body = "\n".join(f"{_M}{json.dumps(p)}" for p in payloads)
        raw = f'val res1: String = """{body}"""'
        records, errors = parse_marker_records(raw, _M)
        assert records == payloads
        assert errors == []


class TestStripAnsi:
    def test_removes_colour_codes(self):
        assert strip_ansi("\x1b[31mred\x1b[0m") == "red"


class TestExtractScalarMarker:
    """Transport-tolerant scalar extraction (guard summary shape)."""

    def test_bare_println_line(self):
        from core.analysis._joern_lines import extract_scalar_marker
        raw = "some jvm noise\nJOERN_GUARD_SUMMARY:3/5\n"
        assert extract_scalar_marker(raw, "JOERN_GUARD_SUMMARY:") == "3/5"

    def test_single_line_value_echo(self):
        from core.analysis._joern_lines import extract_scalar_marker
        raw = 'val res0: String = "JOERN_GUARD_SUMMARY:3/5"'
        assert extract_scalar_marker(raw, "JOERN_GUARD_SUMMARY:") == "3/5"

    def test_triple_quoted_echo_first_line(self):
        from core.analysis._joern_lines import extract_scalar_marker
        raw = 'val res1: String = """JOERN_GUARD_SUMMARY:0/2'
        assert extract_scalar_marker(raw, "JOERN_GUARD_SUMMARY:") == "0/2"

    def test_ansi_wrapped(self):
        from core.analysis._joern_lines import extract_scalar_marker
        raw = "\x1b[32mJOERN_GUARD_SUMMARY:1/4\x1b[0m"
        assert extract_scalar_marker(raw, "JOERN_GUARD_SUMMARY:") == "1/4"

    def test_dual_emit_dedupes_to_last(self):
        from core.analysis._joern_lines import extract_scalar_marker
        raw = (
            "JOERN_GUARD_SUMMARY:2/5\n"
            'val res0: String = "JOERN_GUARD_SUMMARY:2/5"\n'
        )
        assert extract_scalar_marker(raw, "JOERN_GUARD_SUMMARY:") == "2/5"

    def test_escaped_echo_cut_at_escape_sequence(self):
        # A single-line Java-escaped echo carrying more content after
        # the scalar: the payload stops at the first backslash.
        from core.analysis._joern_lines import extract_scalar_marker
        raw = 'val res0: String = "JOERN_GUARD_SUMMARY:3/5\\nOTHER:x"'
        assert extract_scalar_marker(raw, "JOERN_GUARD_SUMMARY:") == "3/5"

    def test_no_marker_is_none(self):
        from core.analysis._joern_lines import extract_scalar_marker
        assert extract_scalar_marker("random output", "JOERN_GUARD_SUMMARY:") is None
        assert extract_scalar_marker("", "JOERN_GUARD_SUMMARY:") is None
        assert extract_scalar_marker(None, "JOERN_GUARD_SUMMARY:") is None
