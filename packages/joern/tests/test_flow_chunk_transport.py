"""Oversized JOERN_FLOW records must survive the REPL transport.

Field failure this battery regresses: a long flow record echoed as one
overlong line was wrapped/truncated by a REPL rendering cap; every
fragment then failed per-line parsing and the flow was lost, while the
per-fragment errors repeated unbounded in the logs
(``failed to parse flow: unrecoverable JOERN_FLOW: echo record
'JOERN_FLOW:[{'`` — 57KB of repeats in one resume log).

The fix is two-sided and both sides are pinned here:

* emit side: the shared ``flowRecordLines`` Scala helper
  (``SCALA_FLOW_EMIT_DEF``) splits an oversized record into ordered
  ``JOERN_FLOW_PART:<i>/<n>/<len>:`` chunk lines that the parser
  reassembles before JSON parsing — chunk lines stay far below any
  observed line cap, so a wrapping boundary no longer bisects records;
* parse side: repeated decode failures aggregate into ONE bounded
  ``result.errors`` entry that keeps the exact
  ``failed to parse flow: `` prefix — the refute-safety contract
  (``core.analysis.reachability_gates`` classifies that prefix as
  benign noise; ``core.audit.joern_verify`` refuses to refute on ANY
  non-empty ``result.errors``) is preserved bit-for-bit.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from packages.joern.runner import _parse_output

_QUERIES_DIR = Path(__file__).resolve().parents[1] / "queries"
_SERVER = Path(__file__).resolve().parents[1] / "server.py"

# Faked REPL boundary for the regression: physical content lines longer
# than the cap arrive split, modelling the field wrap. The value sits
# between the chunk-line size (~1030 chars survive intact) and the
# oversized single-record line (multiple KB, bisected) so the test
# discriminates the two emission shapes.
_FAKE_LINE_CAP = 2048


def _utf16_units(s: str) -> int:
    """UTF-16 code units — what Scala's ``String.length`` counts."""
    return len(s) + sum(1 for c in s if ord(c) > 0xFFFF)


def _emission_lines(steps: str) -> list[str]:
    """Physical lines the flow emitters produce for one record.

    Derived from the canonical emitter definition
    (``SCALA_FLOW_EMIT_DEF``) so the test exercises the emission
    contract of the revision under test; a pre-chunking emitter (no
    ``SCALA_FLOW_EMIT_DEF``) produces the classic single line.

    The emulation is UTF-16 FAITHFUL: Scala strings are UTF-16, so
    the threshold and the cut positions count code units (an astral
    char is 2), the cut steps back off a bisected surrogate pair
    (modelled here by never letting a 2-unit char straddle a cut —
    Python cannot split a code point), and the declared ``len`` is
    code points, exactly what the Scala def's ``codePointCount``
    yields. A naive Python-slicing emulation silently asserts Python
    length semantics the JVM does not have and cannot catch a
    unit/code-point mismatch in the protocol.
    """
    rec = "[" + steps + "]"
    try:
        from packages.joern.runner import SCALA_FLOW_EMIT_DEF
    except ImportError:
        return ["JOERN_FLOW:" + rec]
    m = re.search(r"s \+ (\d+)", SCALA_FLOW_EMIT_DEF)
    assert m, "chunk size not found in SCALA_FLOW_EMIT_DEF"
    size = int(m.group(1))
    thr = re.search(r"rec\.length <= (\d+)", SCALA_FLOW_EMIT_DEF)
    assert thr, "threshold not found in SCALA_FLOW_EMIT_DEF"
    assert int(thr.group(1)) == size, "threshold != chunk size"
    if _utf16_units(rec) <= size:
        return ["JOERN_FLOW:" + rec]
    parts: list[str] = []
    cur: list[str] = []
    units = 0
    for ch in rec:
        w = 2 if ord(ch) > 0xFFFF else 1
        if units + w > size:
            # An astral char would straddle the cut: Scala sees the
            # high surrogate at charAt(cut-1) and steps the cut back
            # one unit, so the whole char opens the next fragment.
            parts.append("".join(cur))
            cur, units = [ch], w
        else:
            cur.append(ch)
            units += w
            if units == size:
                parts.append("".join(cur))
                cur, units = [], 0
    if cur:
        parts.append("".join(cur))
    total = len(parts)
    return [
        f"JOERN_FLOW_PART:{i + 1}/{total}/{len(p)}:{p}"
        for i, p in enumerate(parts)
    ]


def _wrap_at_cap(text: str, cap: int = _FAKE_LINE_CAP) -> str:
    """The faked REPL boundary: hard-wrap overlong physical lines."""
    out: list[str] = []
    for line in text.split("\n"):
        while len(line) > cap:
            out.append(line[:cap])
            line = line[cap:]
        out.append(line)
    return "\n".join(out)


def _oversized_steps(n_steps: int = 40) -> str:
    """Steps text of a legitimately oversized record (many capped
    steps, the real-world shape — per-step ``code`` is 200-capped at
    emit time, but a deep flow multiplies steps)."""
    steps = [
        {
            "line": i + 1,
            "code": f"step_{i}(" + "a" * 150 + ")",
            "function": f"fn_{i}",
            "file": "src/deep.c",
        }
        for i in range(n_steps)
    ]
    return json.dumps(steps, separators=(",", ":"))[1:-1]


class TestOversizedRecordSurvivesTheBoundary:
    """Red-first regression: at the pre-fix revision the record emits
    as ONE overlong line, the boundary bisects it, and the flow is
    lost with parse errors; with chunked emission the same record
    crosses the same boundary intact."""

    def _transcript(self, steps: str) -> str:
        value_lines = [
            "JOERN_FLOWS_START",
            *_emission_lines(steps),
            "JOERN_FLOWS_END",
        ]
        echoed = (
            'val res0: String = """' + "\n".join(value_lines) + '"""'
        )
        return _wrap_at_cap(echoed)

    def test_oversized_flow_record_recovered_in_full(self):
        steps = _oversized_steps()
        assert len(steps) > 2 * _FAKE_LINE_CAP  # genuinely oversized
        flows, errors = _parse_output(self._transcript(steps))
        assert errors == []
        assert len(flows) == 1
        # Byte-exact recovery: every step, every field.
        assert len(flows[0].steps) == 40
        assert flows[0].steps[0].code == "step_0(" + "a" * 150 + ")"
        assert flows[0].steps[-1].function == "fn_39"

    def test_short_record_emission_shape_is_unchanged(self):
        steps = json.dumps(
            [{"line": 3, "code": "memcpy(dst, src, n)",
              "function": "handler", "file": "a.c"}],
            separators=(",", ":"),
        )[1:-1]
        lines = _emission_lines(steps)
        assert lines == ["JOERN_FLOW:[" + steps + "]"]
        flows, errors = _parse_output(self._transcript(steps))
        assert errors == []
        assert len(flows) == 1

    def test_mixed_batch_short_and_oversized_records(self):
        short = json.dumps(
            [{"line": 7, "code": "strcpy(a, b)",
              "function": "copy_in", "file": "b.c"}],
            separators=(",", ":"),
        )[1:-1]
        long_steps = _oversized_steps()
        value_lines = [
            "JOERN_FLOWS_START",
            *_emission_lines(short),
            *_emission_lines(long_steps),
            "JOERN_FLOWS_END",
        ]
        echoed = (
            'val res0: String = """' + "\n".join(value_lines) + '"""'
        )
        flows, errors = _parse_output(_wrap_at_cap(echoed))
        assert errors == []
        assert len(flows) == 2


class TestFieldFailureSignature:
    def test_width_truncated_single_line_echo_reproduces_field_signature(self):
        # The resume-log failure shape: a single-line Java-escaped echo
        # of the framed value, cut by a width cap right after the first
        # record's opening 'JOERN_FLOW:[{'. Pinned at BOTH revisions:
        # this transcript is already damaged in transit — the parser's
        # duty is the exact loud error, and the aggregation must keep
        # its message intact for the single-failure case.
        record = (
            'JOERN_FLOW:[{"line":4,"code":"' + "A" * 3000
            + '","function":"handler","file":"x.c"}]'
        )
        framed = "JOERN_FLOWS_START\n" + record + "\nJOERN_FLOWS_END"
        esc = (
            framed.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
        )
        echoed = 'val res0: String = "' + esc
        cut = echoed.index("JOERN_FLOW:[{") + len("JOERN_FLOW:[{")
        flows, errors = _parse_output(echoed[:cut])
        assert flows == []
        assert len(errors) == 1
        assert errors[0].startswith("failed to parse flow: ")
        assert (
            "unrecoverable JOERN_FLOW: echo record 'JOERN_FLOW:[{'"
            in errors[0]
        )


class TestAggregatedParseFailureWarning:
    """Red-first: pre-fix, N damaged fragments appended N error lines
    (unbounded — 57KB of repeats in one resume log); now they
    aggregate to ONE bounded entry carrying the count."""

    def test_repeated_failures_aggregate_to_one_bounded_entry(self):
        transcript = "\n".join(
            f"JOERN_FLOW:{{broken-{i}" for i in range(40)
        )
        flows, errors = _parse_output(transcript)
        assert flows == []
        assert len(errors) == 1
        assert errors[0].startswith("failed to parse flow: ")
        assert "(+39 more parse failure(s) suppressed)" in errors[0]
        # Bounded: 500-char head + fixed-size suffix.
        assert len(errors[0]) <= 600

    def test_single_failure_keeps_the_historical_message_shape(self):
        flows, errors = _parse_output("JOERN_FLOW:{broken\n")
        assert flows == []
        assert len(errors) == 1
        assert errors[0].startswith(
            "failed to parse flow: unparseable JOERN_FLOW: payload"
        )
        assert "suppressed" not in errors[0]


class TestRefuteSafetyContract:
    """result.errors is the refute-safety carrier: joern_verify books
    outcome="error" on ANY entry, and reachability_gates classifies
    the 'failed to parse flow:' prefix as benign parse noise. Both
    sides of that contract must survive the aggregation."""

    def test_corrupt_record_still_lands_in_result_errors(self):
        flows, errors = _parse_output(
            "JOERN_FLOWS_START\nJOERN_FLOW:{broken\nJOERN_FLOWS_END\n"
        )
        assert flows == []
        assert len(errors) == 1
        assert "failed to parse flow" in errors[0]

    def test_aggregate_still_classifies_as_benign_parse_noise(self):
        # Mirror of the reachability_gates filter: an error entry
        # WITHOUT the prefix is treated as a real tool failure.
        transcript = "\n".join(
            f"JOERN_FLOW:{{broken-{i}" for i in range(3)
        )
        _, errors = _parse_output(transcript)
        assert errors
        assert not [
            e for e in errors if "failed to parse flow:" not in str(e)
        ]

    def test_corrupt_chunk_sequence_is_error_never_silent(self):
        lines = _emission_lines(_oversized_steps())
        assert len(lines) > 2, "oversized record must emit chunked"
        damaged = "\n".join([lines[0], *lines[2:]])  # part 2 lost
        flows, errors = _parse_output(damaged)
        assert flows == []
        assert len(errors) == 1
        assert "failed to parse flow" in errors[0]


class TestFlowEmitDefCensus:
    """Single-authority census, mirroring the jsonEsc pattern: the
    ``.sc`` files cannot import the Python constant, so byte-identical
    copies are pinned here instead."""

    def _emitters(self) -> dict[str, str]:
        from packages.joern.runner import _TAINT_QUERY_TEMPLATE
        return {
            "standard_sinks.sc": (
                _QUERIES_DIR / "standard_sinks.sc"
            ).read_text(encoding="utf-8"),
            "tiered_taint.sc": (
                _QUERIES_DIR / "tiered_taint.sc"
            ).read_text(encoding="utf-8"),
            "runner._TAINT_QUERY_TEMPLATE": _TAINT_QUERY_TEMPLATE,
        }

    def test_canonical_def_present_verbatim_in_every_flow_emitter(self):
        from packages.joern.runner import SCALA_FLOW_EMIT_DEF
        missing = [
            name for name, text in self._emitters().items()
            if SCALA_FLOW_EMIT_DEF not in text
        ]
        assert not missing, missing

    def test_no_unchunked_record_concatenation_outside_the_def(self):
        offenders = [
            name for name, text in self._emitters().items()
            if '"JOERN_FLOW:[" + steps' in text
        ]
        assert not offenders, offenders

    def test_server_batch_rides_flow_record_lines(self):
        src = _SERVER.read_text(encoding="utf-8")
        assert "SCALA_FLOW_EMIT_DEF," in src
        assert "raptorBatchLines ++= flowRecordLines(steps)" in src
        assert '"JOERN_FLOW:[" + steps' not in src

    def test_verify_flow_query_rides_flow_record_lines(self):
        from core.audit.joern_verify import build_flow_query
        from packages.joern.runner import SCALA_FLOW_EMIT_DEF
        q = build_flow_query(
            "process", "buf", "memcpy", nonce="abcdef123456",
        )
        assert SCALA_FLOW_EMIT_DEF in q
        assert "raptorOut ++= flowRecordLines(steps)" in q
        assert '"JOERN_FLOW:[" + steps' not in q

    def test_def_chunk_size_matches_the_protocol_constant(self):
        from core.analysis._joern_lines import FLOW_RECORD_CHUNK_CHARS
        from packages.joern.runner import SCALA_FLOW_EMIT_DEF
        cut = re.search(r"s \+ (\d+)", SCALA_FLOW_EMIT_DEF)
        threshold = re.search(r"rec\.length <= (\d+)", SCALA_FLOW_EMIT_DEF)
        assert cut and threshold
        assert int(cut.group(1)) == FLOW_RECORD_CHUNK_CHARS
        assert int(threshold.group(1)) == FLOW_RECORD_CHUNK_CHARS

    def test_def_declares_code_points_and_never_splits_a_pair(self):
        # Protocol length unit: the parse side is Python (len() =
        # code points), so the def MUST declare codePointCount — a
        # def declaring UTF-16 units (p.length) spuriously drops
        # every chunked record carrying a non-BMP char. And the cut
        # must snap off a bisected surrogate pair: split pairs become
        # two independently-replaced lone surrogates that PASS a
        # naive length check and silently corrupt the record.
        from packages.joern.runner import SCALA_FLOW_EMIT_DEF
        assert "p.codePointCount(0, p.length)" in SCALA_FLOW_EMIT_DEF
        assert "Character.isHighSurrogate" in SCALA_FLOW_EMIT_DEF
        assert '"/" + p.length' not in SCALA_FLOW_EMIT_DEF

    def test_chunk_size_band_two_direction(self):
        from core.analysis._joern_lines import FLOW_RECORD_CHUNK_CHARS
        # LOWER bound: below this the ~30-char marker+header framing
        # per fragment exceeds ~12% overhead and record line counts
        # multiply into line-count display caps.
        assert FLOW_RECORD_CHUNK_CHARS >= 256
        # UPPER bound: a single-line Java-escaped echo roughly doubles
        # a chunk line worst-case; the escaped line must stay far
        # below kilobyte-scale rendering caps — the field failure cut
        # multi-KB record lines, and chunk lines must never approach
        # the sizes that broke.
        assert FLOW_RECORD_CHUNK_CHARS <= 4096


class TestAstralCharactersSurviveChunking:
    """The chunk-length contract is UNIT-SENSITIVE: Scala counts
    UTF-16 code units, Python counts code points. Red-first: a def
    declaring ``p.length`` (units) made the assembler drop every
    chunked record carrying an astral char (declared > counted), and
    ``grouped()`` could bisect a surrogate pair — two lone surrogates
    the JVM encoder replaces independently, passing the length check
    and silently corrupting the record. The def now declares
    ``codePointCount`` and snaps the cut off a bisected pair."""

    def test_astral_chars_round_trip_through_chunking(self):
        steps = json.dumps(
            [
                {
                    "line": i + 1,
                    "code": 'printf("\U0001F600' + "a" * 120 + '\U0001F680")',
                    "function": f"fn_{i}",
                    "file": "src/uni.c",
                }
                for i in range(30)
            ],
            separators=(",", ":"),
            ensure_ascii=False,
        )[1:-1]
        lines = _emission_lines(steps)
        assert len(lines) > 2, "record must be genuinely oversized"
        # The unit distinction is actually exercised: some fragment's
        # declared code-point len differs from its UTF-16 unit count.
        frags = [line.split(":", 2) for line in lines]
        assert any(
            int(h.split("/")[2]) != _utf16_units(frag)
            for _, h, frag in frags
        )
        flows, errors = _parse_output("\n".join(lines))
        assert errors == []
        assert len(flows) == 1
        assert len(flows[0].steps) == 30
        assert flows[0].steps[0].code == (
            'printf("\U0001F600' + "a" * 120 + '\U0001F680")'
        )

    def test_cut_snaps_off_a_straddling_astral_char(self):
        from core.analysis._joern_lines import FLOW_RECORD_CHUNK_CHARS
        size = FLOW_RECORD_CHUNK_CHARS
        saw_snap = False
        # An emoji run long enough to span every cut: exactly one of
        # the two paddings puts a pair astride a cut (unit parity),
        # forcing the snap; both must round-trip byte-exact.
        for pad in (0, 1):
            code = "p" * pad + "\U0001F600" * size
            steps = json.dumps(
                [{"line": 1, "code": code,
                  "function": "fn", "file": "u.c"}],
                separators=(",", ":"),
                ensure_ascii=False,
            )[1:-1]
            lines = _emission_lines(steps)
            assert len(lines) > 2
            frags = [line.split(":", 2)[2] for line in lines]
            saw_snap = saw_snap or any(
                _utf16_units(f) == size - 1 for f in frags[:-1]
            )
            flows, errors = _parse_output("\n".join(lines))
            assert errors == []
            assert len(flows) == 1
            assert flows[0].steps[0].code == code
        assert saw_snap, "no cut ever landed on a surrogate pair"


class TestChunkLinesKeepTheRecordLineExclusion:
    """JOERN_FLOW_PART lines are query OUTPUT whose fragments embed
    scanned-repo text, exactly like the classic JOERN_FLOW line they
    replace — the full-stdout scanners must exclude them. Red-first:
    the record-line marker tuple lacked the chunk prefix, so a
    diagnostic-shaped string inside a fragment vetoed the whole
    query's evidence (_has_scala_error) and a lease-mismatch string
    inside a fragment read as a graph swap (_lease_swapped, paying
    re-imports up to the cap)."""

    def test_chunk_prefix_is_a_record_line_marker(self):
        from packages.joern.server import _RECORD_LINE_MARKERS
        assert "JOERN_FLOW_PART:" in _RECORD_LINE_MARKERS

    def test_diagnostic_shaped_fragment_does_not_veto_the_query(self):
        from packages.joern.server import _has_scala_error
        frag = '{"code":"expect_out(\\"gen.c:12: error: overflow\\")"'
        stdout = f"JOERN_FLOW_PART:1/2/{len(frag)}:{frag}\n"
        assert _has_scala_error(stdout) is False
        # The scan itself still bites on a REAL diagnostic line.
        assert _has_scala_error("gen.c:12: error: overflow\n") is True

    def test_lease_strings_in_fragment_do_not_read_as_swap(self):
        from packages.joern.server import JoernServer
        frag = (
            '{"code":"require(ok, \\"requirement failed: '
            'raptor-graph-lease-mismatch\\")"'
        )
        stdout = f"JOERN_FLOW_PART:1/2/{len(frag)}:{frag}\n"
        assert JoernServer._lease_swapped(stdout, "") is False
        assert JoernServer._lease_swapped(
            "requirement failed: raptor-graph-lease-mismatch\n", "",
        ) is True
