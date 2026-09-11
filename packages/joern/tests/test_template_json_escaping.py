"""Every interpolated field in a JSON-string context routes through jsonEsc.

The Scala emitters build ``MARKER:{json}`` record lines by string
interpolation. A field interpolated without the shared ``jsonEsc``
helper lets hostile repo content (function names, filenames, code
snippets) forge or destroy records — record loss on the caller query
feeds entry-unreachability demotion of real findings. These tests lint
the query templates themselves:

* the canonical ``jsonEsc`` definition (single authority:
  ``runner.SCALA_JSON_ESC_DEF``) is present verbatim in every emitter
  — the ``.sc`` files carry a byte-identical copy;
* every ``"$var"`` / ``"${expr}"`` interpolation in a quoted JSON
  position is jsonEsc-routed;
* no hand-inlined escape chain survives outside the definition;
* the materialisation caps sit on the traversal BEFORE ``.l``.
"""

from __future__ import annotations

import re
from pathlib import Path

from packages.joern.runner import (
    SCALA_JSON_ESC_DEF,
    _TAINT_QUERY_TEMPLATE,
    _build_summary_batch_query,
)

_QUERIES_DIR = Path(__file__).resolve().parents[1] / "queries"
_SERVER = Path(__file__).resolve().parents[1] / "server.py"

# Quoted interpolations: `"$var"` or `"${expr}"` — a value that IS the
# whole JSON string. Unquoted interpolations (line numbers, indexes,
# pre-built JSON arrays) are not string context.
_QUOTED_VAR = re.compile(r'"\$(\w+)"')
_QUOTED_EXPR = re.compile(r'"\$\{([^}"]+)\}"')

# The hand-inlined chain shape jsonEsc replaced. Exactly one occurrence
# (inside the definition itself) is allowed per emitter. Built from a
# single-backslash char so the target Scala-source bytes are explicit.
_BS = "\\"
_CHAIN = f'.replace("{_BS * 2}", "{_BS * 4}")'


def _emitters() -> dict[str, str]:
    """Every Scala emitter text that JSON-embeds CPG values."""
    from core.orchestration.joern_hunt import _CALLSITE_QUERY_TEMPLATE

    texts = {
        sc.name: sc.read_text(encoding="utf-8")
        for sc in sorted(_QUERIES_DIR.glob("*.sc"))
    }
    texts["runner._TAINT_QUERY_TEMPLATE"] = _TAINT_QUERY_TEMPLATE
    texts["runner._build_summary_batch_query"] = _build_summary_batch_query(
        ["probe_fn"],
    )
    texts["joern_hunt._CALLSITE_QUERY_TEMPLATE"] = _CALLSITE_QUERY_TEMPLATE
    return texts


def _unrouted_interpolations(text: str) -> list[str]:
    bad = []
    for name in _QUOTED_VAR.findall(text):
        if not re.search(rf"val {name} = jsonEsc\(", text):
            bad.append(f"${name}")
    for expr in _QUOTED_EXPR.findall(text):
        if expr.startswith("jsonEsc("):
            continue
        if re.fullmatch(r"\w+", expr) and re.search(
            rf"val {expr} = jsonEsc\(", text,
        ):
            continue
        bad.append(f"${{{expr}}}")
    return bad


class TestJsonEscRouting:
    def test_scan_covers_the_known_emitters(self):
        names = set(_emitters())
        assert {
            "callers.sc", "standard_sinks.sc", "unguarded_sinks.sc",
            "sink_arg_index.sc", "tiered_taint.sc", "summary_returns.sc",
            "summary_error_paths.sc", "summary_preconditions.sc",
            "summary_taint_rules.sc", "runner._TAINT_QUERY_TEMPLATE",
            "runner._build_summary_batch_query",
            "joern_hunt._CALLSITE_QUERY_TEMPLATE",
        } <= names

    def test_canonical_def_present_verbatim(self):
        # Byte-identical copies: the .sc files cannot import the Python
        # constant, so drift is caught here instead.
        missing = [
            name for name, text in _emitters().items()
            if SCALA_JSON_ESC_DEF not in text
        ]
        assert not missing, missing

    def test_every_quoted_interpolation_is_json_escaped(self):
        offenders = {
            name: bad
            for name, text in _emitters().items()
            if (bad := _unrouted_interpolations(text))
        }
        assert not offenders, offenders

    def test_no_hand_inlined_chain_outside_the_definition(self):
        offenders = {
            name: text.count(_CHAIN)
            for name, text in _emitters().items()
            if text.count(_CHAIN) != 1
        }
        assert not offenders, offenders

    def test_no_escape_then_truncate(self):
        # .take(N) must run on the RAW string BEFORE jsonEsc —
        # escape-then-truncate can bisect an injected \" and leave a
        # dangling backslash that breaks the record.
        rx = re.compile(r"jsonEsc\([^)]*\)\.take\(")
        offenders = [
            name for name, text in _emitters().items() if rx.search(text)
        ]
        assert not offenders, offenders

    def test_server_batch_template_routes_through_json_esc(self):
        # The per-pair batch body lives in an f-string; lint the source.
        src = _SERVER.read_text(encoding="utf-8")
        assert "SCALA_JSON_ESC_DEF," in src
        assert "val cd = jsonEsc(e.code.take(200))" in src
        assert "val fnEsc = jsonEsc(fn)" in src
        assert "val flEsc = jsonEsc(fl)" in src
        # The old inline chain (python-escaped form in the f-string
        # source: every Scala backslash doubled) is gone.
        assert f'.replace("{_BS * 4}", "{_BS * 8}")' not in src


class TestMaterialisationCaps:
    """Two-direction pins for the reachableByFlows caps.

    Higher/removed = more flows materialised per sink and unbounded
    transport bytes (the whole reason the cap exists); lower = real
    flows silently dropped past the cap — the JOERN_FLOW protocol has
    no truncation marker, so a starved cap loses evidence invisibly.
    """

    _CAP = re.compile(r"reachableByFlows\((\w+)\)\.take\((\d+)\)\.l")
    _UNCAPPED = re.compile(r"reachableByFlows\(\w+\)\.l")

    def _cap_of(self, text: str) -> int:
        m = self._CAP.search(text)
        assert m, "capped reachableByFlows(...).take(N).l not found"
        return int(m.group(2))

    def test_standard_sinks_cap_present(self):
        text = (_QUERIES_DIR / "standard_sinks.sc").read_text(encoding="utf-8")
        self._cap_of(text)
        assert not self._UNCAPPED.search(text)

    def test_standard_sinks_cap_band(self):
        text = (_QUERIES_DIR / "standard_sinks.sc").read_text(encoding="utf-8")
        assert 100 <= self._cap_of(text) <= 1000

    def test_taint_template_cap_present(self):
        self._cap_of(_TAINT_QUERY_TEMPLATE)
        assert not self._UNCAPPED.search(_TAINT_QUERY_TEMPLATE)

    def test_taint_template_cap_band(self):
        assert 100 <= self._cap_of(_TAINT_QUERY_TEMPLATE) <= 1000


class TestStandardSinksTransport:
    def test_records_ride_the_final_expression(self):
        # /query-sync (server transport) drops println output — the
        # pre-sweep's flows must ride the final expression's string
        # echo, sentinel-wrapped exactly as _parse_output expects.
        text = (_QUERIES_DIR / "standard_sinks.sc").read_text(encoding="utf-8")
        assert text.rstrip().endswith(
            '"JOERN_FLOWS_START\\n" + flowLines.mkString("\\n") '
            '+ "\\nJOERN_FLOWS_END"'
        )

    def test_records_are_also_printed_for_subprocess(self):
        text = (_QUERIES_DIR / "standard_sinks.sc").read_text(encoding="utf-8")
        assert "flowLines.foreach(println)" in text

    def test_server_shaped_output_parses_to_flows(self):
        # Simulated server-mode stdout: final-expression echo only.
        from packages.joern.runner import _parse_output
        record = (
            'JOERN_FLOW:[{"line":3,"code":"memcpy(dst, src, n)",'
            '"function":"handler","file":"a.c"},'
            '{"line":9,"code":"n","function":"handler","file":"a.c"}]'
        )
        stdout = f"JOERN_FLOWS_START\n{record}\nJOERN_FLOWS_END"
        flows, errors = _parse_output(stdout)
        assert errors == []
        assert len(flows) == 1

    def test_full_server_transcript_with_binder_echo_yields_no_errors(self):
        # The REPL also echoes the intermediate `val flowLines = ...`
        # binder: `val flowLines: List[String] = List(` with one
        # Java-escaped element per line. Those lines must dedupe as
        # echo, never read as dropped records — a phantom error on ANY
        # >=1-flow target blocked the pre-sweep flow cache and polluted
        # tool-error feedback.
        from packages.joern.runner import _parse_output
        records = [
            'JOERN_FLOW:[{"line":3,"code":"memcpy(dst, src, n)",'
            '"function":"handler","file":"a.c"}]',
            'JOERN_FLOW:[{"line":7,"code":"strcpy(a, b)",'
            '"function":"copy_in","file":"b.c"}]',
        ]
        escaped = [
            r.replace("\\", "\\\\").replace('"', '\\"') for r in records
        ]
        stdout = (
            "val flowLines: List[String] = List(\n"
            f'  "{escaped[0]}",\n'
            f'  "{escaped[1]}"\n'
            ")\n"
            'val res1: String = """JOERN_FLOWS_START\n'
            f"{records[0]}\n{records[1]}\n"
            'JOERN_FLOWS_END"""'
        )
        flows, errors = _parse_output(stdout)
        assert errors == []
        assert len(flows) == 2

    def test_inline_single_flow_binder_echo_recovers(self):
        # A single short flow can echo the whole List inline on the
        # binder line.
        from packages.joern.runner import _parse_output
        stdout = (
            "val flowLines: List[String] = "
            'List("JOERN_FLOW:[{\\"line\\":3,\\"code\\":\\"gets(buf)\\",'
            '\\"function\\":\\"f\\",\\"file\\":\\"a.c\\"}]")\n'
            'val res1: String = "JOERN_FLOWS_START\\nJOERN_FLOW:'
            '[{\\"line\\":3,\\"code\\":\\"gets(buf)\\",\\"function\\":'
            '\\"f\\",\\"file\\":\\"a.c\\"}]\\nJOERN_FLOWS_END"'
        )
        flows, errors = _parse_output(stdout)
        assert errors == []
        assert len(flows) == 1
