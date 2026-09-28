"""Chunked marker-record reassembly (``MARKER_PART:<i>/<n>/<len>:``).

Oversized ``MARKER:{json}`` records are emitted as ordered chunk lines
so REPL rendering caps can no longer wrap/truncate one overlong line
and drop the record.  These tests pin the assembler's contract:
byte-exact reassembly across every echo shape, ONE error per damaged
sequence (never silent corruption, never unbounded repeats), and
earliest-marker anchoring so hostile payload text cannot reroute
parsing.
"""

from __future__ import annotations

import json

from core.analysis._joern_lines import (
    MarkerChunkAssembler,
    chunk_marker,
    parse_marker_records,
)

_M = "JOERN_FLOW:"
_CM = chunk_marker(_M)


def _record(code: str = "memcpy(dst, src, n)") -> str:
    """A record's full ``[...]`` JSON text."""
    return json.dumps(
        [{"line": 4, "code": code, "function": "handler", "file": "a.c"}],
        separators=(",", ":"),
    )


def _chunks(rec: str, size: int = 24, marker: str = _M) -> list[str]:
    """Chunk lines for *rec* exactly as the Scala emitter builds them."""
    parts = [rec[i:i + size] for i in range(0, len(rec), size)]
    cm = chunk_marker(marker)
    return [
        f"{cm}{i + 1}/{len(parts)}/{len(p)}:{p}"
        for i, p in enumerate(parts)
    ]


def _feed(lines: list[str], marker: str = _M) -> tuple[list, list[str]]:
    asm = MarkerChunkAssembler(marker)
    records: list = []
    errors: list[str] = []
    for line in lines:
        recs, err = asm.feed_line(line)
        records.extend(recs)
        if err is not None:
            errors.append(err)
    tail = asm.finish()
    if tail is not None:
        errors.append(tail)
    return records, errors


def _java_escape(text: str) -> str:
    return (
        text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    )


class TestChunkMarker:
    def test_derivation(self):
        assert chunk_marker("JOERN_FLOW:") == "JOERN_FLOW_PART:"
        assert chunk_marker("JOERN_CALLER:") == "JOERN_CALLER_PART:"


class TestReassembly:
    def test_raw_chunk_lines_reassemble_byte_exact(self):
        rec = _record("a" * 100)
        records, errors = _feed(_chunks(rec))
        assert errors == []
        assert records == [json.loads(rec)]

    def test_unchunked_record_line_delegates_verbatim(self):
        rec = _record()
        records, errors = _feed([f"{_M}{rec}"])
        assert errors == []
        assert records == [json.loads(rec)]

    def test_markerless_line_is_silent(self):
        records, errors = _feed(["some jvm output"])
        assert records == []
        assert errors == []

    def test_noise_lines_between_chunks_do_not_reset(self):
        rec = _record("b" * 90)
        lines = _chunks(rec)
        interleaved = [lines[0], "warning: something", *lines[1:]]
        records, errors = _feed(interleaved)
        assert errors == []
        assert records == [json.loads(rec)]

    def test_fragment_edge_whitespace_survives(self):
        # A chunk boundary landing on a space inside JSON string
        # content must reassemble byte-exact — this is why lines are
        # fed UNSTRIPPED and why the header carries a length field.
        rec = _record("x" * 10 + " " + "y" * 10)
        cut = rec.index(" ") + 1  # first fragment ends WITH the space
        parts = [rec[:cut], rec[cut:]]
        lines = [
            f"{_CM}{i + 1}/2/{len(p)}:{p}" for i, p in enumerate(parts)
        ]
        records, errors = _feed(lines)
        assert errors == []
        assert records == [json.loads(rec)]

    def test_generic_marker_supported_via_parse_marker_records(self):
        marker = "JOERN_CALLER:"
        rec = json.dumps(
            {"caller": "main", "file": "m.c", "line": 3},
            separators=(",", ":"),
        )
        transcript = "\n".join(_chunks(rec, size=10, marker=marker))
        records, errors = parse_marker_records(transcript, marker)
        assert errors == []
        assert records == [json.loads(rec)]


class TestEchoShapes:
    def test_single_line_escaped_echo_of_chunked_value_recovers(self):
        rec = _record("c" * 80)
        value = "\n".join(_chunks(rec))
        line = f'val res0: String = "{_java_escape(value)}"'
        records, errors = _feed([line])
        assert errors == []
        assert records == [json.loads(rec)]

    def test_list_binder_echo_elements_recover(self):
        rec = _record("d" * 80)
        lines = ["val flowLines: List[String] = List("]
        chunk_lines = _chunks(rec)
        for i, chunk in enumerate(chunk_lines):
            comma = "," if i < len(chunk_lines) - 1 else ""
            lines.append(f'  "{_java_escape(chunk)}"{comma}')
        lines.append(")")
        records, errors = _feed(lines)
        assert errors == []
        assert records == [json.loads(rec)]

    def test_dual_emit_copies_dedupe_to_one_record(self):
        # println copy + final-expression echo copy of the same chunk
        # sequence: parse_marker_records' canonical-JSON dedupe holds.
        rec = _record("e" * 80)
        chunk_lines = _chunks(rec)
        transcript = "\n".join(
            [
                *chunk_lines,
                'val res0: String = """' + chunk_lines[0],
                *chunk_lines[1:],
                '"""',
            ]
        )
        records, errors = parse_marker_records(transcript, _M)
        assert errors == []
        assert records == [json.loads(rec)]


class TestAnchoring:
    def test_record_marker_before_chunk_marker_stays_a_record(self):
        rec = _record(f"see {_CM}1/2/3:abc for details")
        records, errors = _feed([f"{_M}{rec}"])
        assert errors == []
        assert records == [json.loads(rec)]

    def test_fragment_containing_record_marker_text_stays_content(self):
        rec = _record(f"payload mentions {_M} inline " + "f" * 60)
        records, errors = _feed(_chunks(rec, size=30))
        assert errors == []
        assert records == [json.loads(rec)]


class TestDamageDiscipline:
    def test_missing_middle_chunk_is_one_error_no_record(self):
        lines = _chunks(_record("g" * 100))
        assert len(lines) >= 3
        records, errors = _feed([lines[0], *lines[2:]])
        assert records == []
        assert len(errors) == 1
        assert f"unrecoverable {_M} chunk sequence" in errors[0]

    def test_orphan_continuation_reports_once(self):
        lines = _chunks(_record("h" * 100))
        assert len(lines) >= 4
        records, errors = _feed(lines[1:])
        assert records == []
        assert len(errors) == 1
        assert "without part 1" in errors[0]

    def test_length_mismatch_is_error_never_silent_corruption(self):
        # Transport edge damage: a fragment ending in a space arrives
        # stripped while its header still declares the original
        # length. Silent absorption would corrupt the record's JSON
        # string content invisibly.
        rec = _record("i" * 10 + " " + "j" * 10)
        cut = rec.index(" ") + 1
        parts = [rec[:cut], rec[cut:]]
        damaged = [
            f"{_CM}1/2/{len(parts[0])}:{parts[0].rstrip()}",
            f"{_CM}2/2/{len(parts[1])}:{parts[1]}",
        ]
        records, errors = _feed(damaged)
        assert records == []
        assert any("length" in e for e in errors)

    def test_dangling_partial_reported_at_finish(self):
        lines = _chunks(_record("k" * 100))
        records, errors = _feed(lines[:-1])
        assert records == []
        assert len(errors) == 1
        assert "transcript ended" in errors[0]

    def test_restart_at_part_one_flushes_previous_sequence(self):
        rec_a = _record("l" * 100)
        rec_b = _record("m" * 100)
        lines = [_chunks(rec_a)[0], *_chunks(rec_b)]
        records, errors = _feed(lines)
        assert records == [json.loads(rec_b)]
        assert len(errors) == 1
        assert "dropped" in errors[0]

    def test_reassembled_garbage_is_error(self):
        cm = _CM
        lines = [f"{cm}1/2/5:[{{not", f"{cm}2/2/6: json]"]
        records, errors = _feed(lines)
        assert records == []
        assert len(errors) == 1
        assert "chunked record" in errors[0]

    def test_malformed_header_is_error(self):
        records, errors = _feed([f"{_CM}banana"])
        assert records == []
        assert len(errors) == 1
        assert "chunk header" in errors[0]

    def test_total_mismatch_mid_sequence_is_error(self):
        rec = _record("n" * 60)
        lines = _chunks(rec, size=24)
        assert len(lines) >= 3
        tampered = lines[1].replace(f"/{len(lines)}/", f"/{len(lines) + 1}/", 1)
        records, errors = _feed([lines[0], tampered, *lines[2:]])
        assert records == []
        assert errors
