"""Tests for core.audit.joern_verify — hermetic, stubbed Joern server.

No JVM boots here: every check goes through a FakeServer whose
``query`` method returns canned :class:`JoernResult` objects, so the
sweep logic (outcome taxonomy, vacuity guard, identifier-consistency
negative controls) is tested without joern installed.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

import core.audit.joern_verify as joern_verify
from core.audit.joern_verify import (
    FLOW_CWES,
    FLOW_STAMP,
    GUARD_DOMINANCE_CWES,
    GUARD_DOMINANCE_STAMP,
    _parse_flow_facts,
    _parse_guard_output,
    build_flow_query,
    build_guard_dominance_query,
    extract_flow_endpoints,
    extract_guard_target,
    flow_chain_entry,
    guard_chain_entry,
    normalize_cwe,
    run_flow_reachability_check,
    guard_check_kind,
    run_guard_dominance_check,
)
from packages.joern.models import JoernResult
from packages.joern.runner import _parse_output, _validate_query

# Fixed per-invocation sentinel nonce for these tests (the autouse
# fixture below pins _mint_nonce to it).
NONCE = "0123456789abcdef"


def _n(raw: str) -> str:
    """Stamp the fixed test nonce into bare sentinel markers."""
    return re.sub(r"(RAPTOR_(?:GD|FLOW)_[A-Z_]+:)", rf"\g<1>{NONCE}:", raw)


@pytest.fixture(autouse=True)
def _fixed_nonce(monkeypatch):
    monkeypatch.setattr(joern_verify, "_mint_nonce", lambda: NONCE)


class FakeServer:
    """Minimal stand-in for packages.joern.server.JoernServer.

    Stamps the fixed test nonce into canned sentinel lines by default;
    pass ``stamp=False`` to deliver the raw bytes verbatim (forgery
    tests).
    """

    def __init__(self, raw_output: str = "", errors=None, raise_exc=None,
                 *, stamp: bool = True):
        self.raw_output = _n(raw_output) if stamp else raw_output
        self.errors = errors or []
        self.raise_exc = raise_exc
        self.queries = []

    def query(self, cpgql, *, timeout=None, check_length=True, **kw):
        self.queries.append(cpgql)
        if self.raise_exc:
            raise self.raise_exc
        flows, parse_errors = _parse_output(self.raw_output)
        return JoernResult(
            query=cpgql,
            flows=flows,
            raw_output=self.raw_output,
            errors=list(self.errors) + parse_errors,
        )


def _flow_line(source="argv", sink_arg="cmd"):
    return (
        'JOERN_FLOW:[{"line":3,"code":"char *' + source
        + '","function":"main","file":"main.c"},'
        '{"line":9,"code":"system(' + sink_arg + ')",'
        '"function":"main","file":"main.c"}]'
    )


# ── chain entries / CWE routing ──────────────────────────────────────


class TestChainEntries:
    def test_normalize(self):
        assert normalize_cwe("120") == "CWE-120"
        assert normalize_cwe("cwe-79") == "CWE-79"
        assert normalize_cwe("") == ""

    @pytest.mark.parametrize("cwe", sorted(GUARD_DOMINANCE_CWES))
    def test_guard_entry_for_every_dominance_cwe(self, cwe):
        entry = guard_chain_entry(cwe)
        assert entry is not None
        assert entry["type"] == "joern_guard"
        assert entry["config"]["sinks"]

    @pytest.mark.parametrize("cwe", sorted(FLOW_CWES))
    def test_flow_entry_for_every_flow_cwe(self, cwe):
        # CWE-116's legs are language-gated to c/cpp (joern_langs,
        # fail-closed without file context) — a C target exercises
        # every family; ungated families ignore the argument.
        entry = flow_chain_entry(cwe, "src/main.c")
        assert entry is not None
        assert entry["type"] == "joern_flow"
        assert entry["config"]["sinks"]

    def test_no_entry_for_unrelated_cwe(self):
        assert guard_chain_entry("CWE-89") is None
        assert flow_chain_entry("CWE-120") is None
        assert guard_chain_entry("CWE-9999") is None

    def test_cwe_476_uses_fallback_sinks(self):
        entry = guard_chain_entry("CWE-476")
        assert entry is not None
        assert "free" in entry["config"]["sinks"]


# ── hypothesis extraction ────────────────────────────────────────────


class TestExtractGuardTarget:
    def test_bounds_check_before_sink(self):
        ident, sink = extract_guard_target(
            "missing bounds check on `len` before memcpy in parse_hdr",
            ["memcpy", "strcpy"],
        )
        assert (ident, sink) == ("len", "memcpy")

    def test_never_validated_phrasing(self):
        ident, sink = extract_guard_target(
            "size is never validated before it reaches strcpy",
            ["memcpy", "strcpy"],
        )
        assert (ident, sink) == ("size", "strcpy")

    def test_unchecked_phrasing(self):
        ident, sink = extract_guard_target(
            "unchecked `count` used in memcpy length argument",
            ["memcpy"],
        )
        assert (ident, sink) == ("count", "memcpy")

    def test_before_call_names_sink_without_candidates(self):
        ident, sink = extract_guard_target(
            "missing null check on `ptr` before the call to use_ptr",
            [],
        )
        assert (ident, sink) == ("ptr", "use_ptr")

    def test_no_sink_binds_nothing(self):
        assert extract_guard_target(
            "missing bounds check on `len`", [],
        ) == (None, None)

    def test_no_identifier_binds_nothing(self):
        assert extract_guard_target(
            "something is wrong near memcpy", ["memcpy"],
        ) == (None, None)

    def test_prose_words_rejected(self):
        # "check on the" must not bind "the" as identifier.
        ident, sink = extract_guard_target(
            "missing check on the memcpy call", ["memcpy"],
        )
        assert ident is None and sink is None

    def test_identifier_equal_to_sink_rejected(self):
        assert extract_guard_target(
            "missing check on `memcpy` before memcpy", ["memcpy"],
        ) == (None, None)


class TestExtractFlowEndpoints:
    def test_from_reaches(self):
        src, sink = extract_flow_endpoints(
            "attacker data from `argv` reaches system()", ["system"],
        )
        assert (src, sink) == ("argv", "system")

    def test_flows_into(self):
        src, sink = extract_flow_endpoints(
            "`query` flows into cursor.execute without sanitisation",
            ["cursor.execute"],
        )
        assert (src, sink) == ("query", "execute")

    def test_fallback_backtick_plus_candidate_sink(self):
        src, sink = extract_flow_endpoints(
            "user-controlled `path` ends up in popen", ["popen"],
        )
        assert (src, sink) == ("path", "popen")

    def test_nothing_binds(self):
        assert extract_flow_endpoints(
            "there might be an injection somewhere", ["system"],
        ) == (None, None)

    def test_source_equal_sink_rejected(self):
        src, sink = extract_flow_endpoints(
            "data from `system` reaches system", ["system"],
        )
        assert (src, sink) == (None, None)


# ── query builders ───────────────────────────────────────────────────


class TestQueryBuilders:
    def test_guard_query_contains_names_and_sentinels(self):
        q = build_guard_dominance_query("parse_hdr", "memcpy", "len",
                                        nonce=NONCE)
        assert 'nameExact("parse_hdr")' in q
        assert 'nameExact("memcpy")' in q
        assert "\\\\blen\\\\b" in q
        assert f"RAPTOR_GD_FUNC:{NONCE}:" in q
        # CDG, never dominators: a condition dominates the join
        # after the guard too, so dominatedBy falsely refuted the
        # guard-then-unguarded-sink shape (live-reproduced).
        assert "controlledBy" in q
        assert "dominatedBy" not in q

    def test_guard_query_passes_validation(self):
        q = build_guard_dominance_query("f", "memcpy", "n", nonce=NONCE)
        assert _validate_query(q, check_length=False) is None

    def test_flow_query_contains_names_and_sentinels(self):
        q = build_flow_query("handler", "argv", "system", max_call_depth=3,
                             nonce=NONCE)
        assert 'nameExact("handler")' in q
        assert 'nameExact("argv")' in q
        assert 'nameExact("system")' in q
        assert "maxCallDepth = 3" in q
        assert "reachableByFlows" in q
        assert f"RAPTOR_FLOW_FUNC:{NONCE}:" in q

    def test_flow_query_passes_validation(self):
        q = build_flow_query("f", "src", "system", nonce=NONCE)
        assert _validate_query(q, check_length=False) is None

    def test_names_are_escaped(self):
        # Builders escape; callers validate. A hostile value must not
        # break out of the Scala string literal.
        q = build_guard_dominance_query('f"', "memcpy", "n", nonce=NONCE)
        assert 'nameExact("f\\"")' in q


# ── output parsers ───────────────────────────────────────────────────


class TestParsers:
    def test_guard_parse_full(self):
        raw = (
            "RAPTOR_GD_FUNC:found\n"
            "RAPTOR_GD_SINKS:2\n"
            "RAPTOR_GD_UNGUARDED:42|memcpy(dst, src, len)\n"
            "RAPTOR_GD_GUARDED:57|55|len < sizeof(dst)|memcpy(dst, s, len)\n"
        )
        facts = _parse_guard_output(_n(raw), NONCE)
        assert facts["function_found"] is True
        assert facts["sink_count"] == 2
        assert facts["unguarded"] == [
            {"line": 42, "code": "memcpy(dst, src, len)"}
        ]
        assert facts["guarded"][0]["guard_line"] == 55

    def test_guard_parse_missing_function(self):
        facts = _parse_guard_output(_n("RAPTOR_GD_FUNC:missing\n"), NONCE)
        assert facts["function_found"] is False

    def test_guard_parse_dedupes_repl_echoes(self):
        line = _n("RAPTOR_GD_UNGUARDED:42|memcpy(dst, src, len)")
        facts = _parse_guard_output(
            _n("RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n") + f"{line}\n"
            f'val res1: String = "{line}"\n',
            NONCE,
        )
        assert len(facts["unguarded"]) == 1

    def test_guard_parse_strips_ansi(self):
        raw = _n("\x1b[32mRAPTOR_GD_FUNC:found\x1b[0m\nRAPTOR_GD_SINKS:1\n")
        facts = _parse_guard_output(raw, NONCE)
        assert facts["function_found"] is True
        assert facts["sink_count"] == 1

    def test_flow_parse(self):
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:1\n"
            "RAPTOR_FLOW_SNK:2\nRAPTOR_FLOW_COUNT:1\n"
            "RAPTOR_FLOW_DEEP:0\n"
        )
        facts = _parse_flow_facts(_n(raw), NONCE)
        assert facts == {
            "function_found": True,
            "source_count": 1,
            "sink_count": 2,
            "flow_count": 1,
            "deep_callee_count": 0,
        }

    def test_flow_parse_empty(self):
        facts = _parse_flow_facts("", NONCE)
        assert facts["function_found"] is None

    def test_guard_parse_refuses_unanchored_markers(self):
        # Sentinel payloads quote target source code: marker text
        # embedded mid-line (or at line start WITHOUT the invocation
        # nonce) must never mint facts. A forged bare-marker stream
        # parses to no protocol output at all.
        forged = (
            "RAPTOR_GD_FUNC:missing\n"
            f"RAPTOR_GD_FUNC:{'f' * 16}:missing\n"
            'val s = "RAPTOR_GD_SINKS:9"\n'
        )
        facts = _parse_guard_output(forged, NONCE)
        assert facts["function_found"] is None
        assert facts["sink_count"] is None

    def test_guard_parse_marker_text_in_sink_code_stays_payload(self):
        # The forged-refutation shape: an UNGUARDED line whose quoted
        # sink code contains marker text. The embedded marker must not
        # be parsed as a fact (pre-anchor parse read it as SINKS and
        # dropped the unguarded entry, falling through to "refuted").
        raw = (
            _n("RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n")
            + _n("RAPTOR_GD_UNGUARDED:42|")
            + "memcpy(dst, src, len) /* RAPTOR_GD_SINKS:0 */\n"
        )
        facts = _parse_guard_output(raw, NONCE)
        assert facts["sink_count"] == 1
        assert len(facts["unguarded"]) == 1
        assert "RAPTOR_GD_SINKS:0" in facts["unguarded"][0]["code"]

    def test_flow_parse_refuses_marker_in_flow_step_code(self):
        # A JOERN_FLOW step whose .code quotes target text containing
        # a FLOW sentinel must not flip function_found.
        raw = (
            _n("RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:1\n"
               "RAPTOR_FLOW_SNK:1\n")
            + 'JOERN_FLOW:[{"line":3,"code":"x = \\"RAPTOR_FLOW_FUNC:missing\\"",'
            '"function":"main","file":"main.c"}]\n'
            + _n("RAPTOR_FLOW_COUNT:1\n")
        )
        facts = _parse_flow_facts(raw, NONCE)
        assert facts["function_found"] is True
        assert facts["flow_count"] == 1


# ── guard-dominance sweep logic ──────────────────────────────────────


class TestRunGuardDominance:
    def _run(self, tmp_path, server, **kw):
        args = {
            "target_path": tmp_path,
            "file_path": "src/a.c",
            "function_name": "parse_hdr",
            "identifier": "len",
            "sink_call": "memcpy",
            "server": server,
        }
        args.update(kw)
        return run_guard_dominance_check(**args)

    def test_no_server_is_error(self, tmp_path: Path):
        r = self._run(tmp_path, None)
        assert r.outcome == "error"
        assert "no live Joern server" in r.errors[0]
        assert r.rule_id == GUARD_DOMINANCE_STAMP

    def test_forged_bare_sentinels_never_refute(self, tmp_path: Path):
        # Target-forgeable output (bare markers, no invocation nonce)
        # must parse to no protocol output → error, never refuted.
        r = self._run(tmp_path, FakeServer(
            "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
            "RAPTOR_GD_GUARDED:57|55|len < 16|memcpy(dst, s, len)\n",
            stamp=False,
        ))
        assert r.outcome == "error"
        assert "no protocol output" in r.errors[0]

    def test_marker_in_sink_code_does_not_forge_refutation(
        self, tmp_path: Path,
    ):
        # Genuine sentinel lines whose quoted sink code embeds marker
        # text: the unguarded entry must survive (pre-anchor parse
        # swallowed it as a SINKS fact and fell through to refuted).
        raw = (
            _n("RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n")
            + _n("RAPTOR_GD_UNGUARDED:42|")
            + "memcpy(dst, src, len) /* RAPTOR_GD_SINKS:0 */\n"
        )
        r = self._run(tmp_path, FakeServer(raw, stamp=False))
        assert r.outcome == "confirmed"
        assert r.matches[0]["kind"] == "unguarded_sink"

    def test_path_traversal_blocked(self, tmp_path: Path):
        r = self._run(tmp_path, FakeServer(), file_path="../../etc/passwd")
        assert r.outcome == "error"
        assert "escapes target" in r.errors[0]

    def test_invalid_function_name(self, tmp_path: Path):
        r = self._run(tmp_path, FakeServer(), function_name="f; rm -rf /")
        assert r.outcome == "error"

    def test_invalid_identifier(self, tmp_path: Path):
        r = self._run(tmp_path, FakeServer(), identifier='x" ) bad')
        assert r.outcome == "error"

    def test_invalid_sink(self, tmp_path: Path):
        r = self._run(tmp_path, FakeServer(), sink_call="mem cpy()")
        assert r.outcome == "error"

    def test_query_errors_are_error_never_refuted(self, tmp_path: Path):
        r = self._run(
            tmp_path,
            FakeServer(errors=["query failed: value dominatedBy is not"]),
        )
        assert r.outcome == "error"

    def test_server_exception_is_error(self, tmp_path: Path):
        r = self._run(tmp_path, FakeServer(raise_exc=RuntimeError("boom")))
        assert r.outcome == "error"
        assert "boom" in r.errors[0]

    def test_function_missing_is_inconclusive(self, tmp_path: Path):
        r = self._run(tmp_path, FakeServer("RAPTOR_GD_FUNC:missing\n"))
        assert r.outcome == "inconclusive"
        assert "not in CPG" in r.details["reason"]

    def test_no_protocol_output_is_error(self, tmp_path: Path):
        r = self._run(tmp_path, FakeServer("warmup-ok\n"))
        assert r.outcome == "error"

    def test_no_matching_sink_is_inconclusive(self, tmp_path: Path):
        r = self._run(
            tmp_path,
            FakeServer("RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:0\n"),
        )
        assert r.outcome == "inconclusive"
        assert "identifier-consistency" in r.details["reason"]

    def test_dominating_guard_refutes(self, tmp_path: Path):
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_GUARDED:57|55|len < sizeof(dst)|"
                "memcpy(dst, s, len)\n"
                "RAPTOR_GD_UNG_TOTAL:0\n"
            ),
        )
        assert r.outcome == "refuted"
        assert r.details["dominators"][0]["guard_code"] == "len < sizeof(dst)"

    def test_refutation_requires_the_uncapped_zero_count(
            self, tmp_path: Path):
        # Evidence lines are emission-capped; a refutation is a
        # universal quantifier and may only book when the uncapped
        # count says zero. A stream without the count (partial
        # protocol) must refuse to refute.
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_GUARDED:57|55|len < sizeof(dst)|"
                "memcpy(dst, s, len)\n"
            ),
        )
        assert r.outcome == "inconclusive"

    def test_capped_evidence_with_nonzero_count_never_refutes(
            self, tmp_path: Path):
        # 51st-sink shape: every EMITTED sink is guarded (the one
        # unguarded site fell past the emission cap) but the uncapped
        # count says one exists — refutation must not book. Without
        # emitted unguarded evidence the confirm path cannot run its
        # identifier-consistency control either, so inconclusive is
        # the honest answer.
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:51\n"
                "RAPTOR_GD_GUARDED:57|55|len < sizeof(dst)|"
                "memcpy(dst, s, len)\n"
                "RAPTOR_GD_UNG_TOTAL:1\n"
            ),
        )
        assert r.outcome == "inconclusive"

    def test_unguarded_sink_confirms_with_evidence(self, tmp_path: Path):
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_UNGUARDED:42|memcpy(dst, src, len)\n"
            ),
        )
        assert r.outcome == "confirmed"
        assert r.matches[0]["line"] == 42
        assert r.matches[0]["identifier"] == "len"
        assert r.rule_id == GUARD_DOMINANCE_STAMP

    def test_negative_control_sink_without_identifier(self, tmp_path: Path):
        # The CPG returned an unguarded sink whose code does not
        # mention the hypothesis identifier — must NOT confirm.
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_UNGUARDED:42|memcpy(dst, src, other_var)\n"
            ),
        )
        assert r.outcome == "inconclusive"

    def test_mixed_guarded_unguarded_confirms(self, tmp_path: Path):
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:2\n"
                "RAPTOR_GD_GUARDED:30|28|len < 16|memcpy(a, b, len)\n"
                "RAPTOR_GD_UNGUARDED:42|memcpy(dst, src, len)\n"
            ),
        )
        assert r.outcome == "confirmed"
        assert len(r.matches) == 1


# ── flow-reachability sweep logic ────────────────────────────────────


class TestRunFlowReachability:
    def _run(self, tmp_path, server, **kw):
        args = {
            "target_path": tmp_path,
            "file_path": "src/a.c",
            "function_name": "main",
            "source_id": "argv",
            "sink_call": "system",
            "server": server,
        }
        args.update(kw)
        return run_flow_reachability_check(**args)

    def test_no_server_is_error(self, tmp_path: Path):
        r = self._run(tmp_path, None)
        assert r.outcome == "error"
        assert r.rule_id == FLOW_STAMP

    def test_invalid_source_is_error(self, tmp_path: Path):
        r = self._run(tmp_path, FakeServer(), source_id="a b")
        assert r.outcome == "error"

    def test_query_error_never_refutes(self, tmp_path: Path):
        r = self._run(tmp_path, FakeServer(errors=["query failed: E007"]))
        assert r.outcome == "error"

    def test_function_missing_is_inconclusive_not_refuted(
        self, tmp_path: Path,
    ):
        r = self._run(tmp_path, FakeServer("RAPTOR_FLOW_FUNC:missing\n"))
        assert r.outcome == "inconclusive"
        assert "vacuity" in r.details["reason"]

    def test_flow_found_confirms_with_path(self, tmp_path: Path):
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:1\n"
            "RAPTOR_FLOW_SNK:1\n" + _flow_line() + "\n"
            "RAPTOR_FLOW_COUNT:1\n"
        )
        r = self._run(tmp_path, FakeServer(raw))
        assert r.outcome == "confirmed"
        assert r.matches
        assert r.matches[0]["steps"][0]["code"] == "char *argv"

    def test_flow_without_source_identifier_is_inconclusive(
        self, tmp_path: Path,
    ):
        # Negative control: returned flow never mentions the named
        # source — refuse to confirm.
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:1\n"
            "RAPTOR_FLOW_SNK:1\n"
            + _flow_line(source="other", sink_arg="other")
            + "\nRAPTOR_FLOW_COUNT:1\n"
        )
        r = self._run(tmp_path, FakeServer(raw))
        assert r.outcome == "inconclusive"

    def test_no_flow_with_endpoints_present_refutes(self, tmp_path: Path):
        # Refutation requires the depth-bound witness too: the call
        # tree fully covered within the engine's maxCallDepth.
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:2\n"
            "RAPTOR_FLOW_SNK:1\nRAPTOR_FLOW_COUNT:0\n"
            "RAPTOR_FLOW_DEEP:0\n"
        )
        r = self._run(tmp_path, FakeServer(raw))
        assert r.outcome == "refuted"
        assert r.details["source_count"] == 2
        assert r.details["max_call_depth"] == 2
        assert r.details["deep_callee_count"] == 0

    def test_no_flow_with_deep_call_tree_is_inconclusive(
        self, tmp_path: Path,
    ):
        # A genuine flow threaded through helpers nested past the
        # engine's maxCallDepth produces the same zero-flow silence —
        # depth-bounded silence must not read as a mechanical
        # refutation.
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:2\n"
            "RAPTOR_FLOW_SNK:1\nRAPTOR_FLOW_COUNT:0\n"
            "RAPTOR_FLOW_DEEP:3\n"
        )
        r = self._run(tmp_path, FakeServer(raw))
        assert r.outcome == "inconclusive"
        assert "depth" in r.details["reason"]
        assert r.details["deep_callee_count"] == 3
        assert r.details["max_call_depth"] == 2

    def test_no_flow_with_failed_depth_probe_is_inconclusive(
        self, tmp_path: Path,
    ):
        # Probe failed (-1) or sentinel absent: an unverified silence
        # never refutes.
        for deep_line in ("RAPTOR_FLOW_DEEP:-1\n", ""):
            raw = (
                "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:2\n"
                "RAPTOR_FLOW_SNK:1\nRAPTOR_FLOW_COUNT:0\n"
                + deep_line
            )
            r = self._run(tmp_path, FakeServer(raw))
            assert r.outcome == "inconclusive", deep_line
            assert "depth" in r.details["reason"]

    def test_flow_confirm_unaffected_by_deep_call_tree(
        self, tmp_path: Path,
    ):
        # Confirm-direction is depth-safe: a found flow is a found
        # flow.
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:1\n"
            "RAPTOR_FLOW_SNK:1\n" + _flow_line()
            + "\nRAPTOR_FLOW_COUNT:1\nRAPTOR_FLOW_DEEP:9\n"
        )
        r = self._run(tmp_path, FakeServer(raw))
        assert r.outcome == "confirmed"

    def test_no_flow_missing_source_is_inconclusive(self, tmp_path: Path):
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:0\n"
            "RAPTOR_FLOW_SNK:1\nRAPTOR_FLOW_COUNT:0\n"
        )
        r = self._run(tmp_path, FakeServer(raw))
        assert r.outcome == "inconclusive"
        assert "vacuous" in r.details["reason"]

    def test_no_flow_missing_sink_is_inconclusive(self, tmp_path: Path):
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:1\n"
            "RAPTOR_FLOW_SNK:0\nRAPTOR_FLOW_COUNT:0\n"
        )
        r = self._run(tmp_path, FakeServer(raw))
        assert r.outcome == "inconclusive"

    def test_flow_count_without_records_is_protocol_damage(
        self, tmp_path: Path,
    ):
        # The count record says the engine found a flow; no JOERN_FLOW
        # record decoded (a whole line lost without a marker fragment
        # leaves no parse error) — the empty flow list must not ride
        # the refutation lane. Same partial-protocol rule as the
        # guard channel's unguarded count.
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:1\n"
            "RAPTOR_FLOW_SNK:1\nRAPTOR_FLOW_COUNT:1\n"
            "RAPTOR_FLOW_DEEP:0\n"
        )
        r = self._run(tmp_path, FakeServer(raw))
        assert r.outcome == "error"
        assert "protocol damage" in r.errors[0]

    def test_qualified_sink_uses_bare_name(self, tmp_path: Path):
        server = FakeServer("RAPTOR_FLOW_FUNC:missing\n")
        self._run(tmp_path, server, sink_call="subprocess.Popen")
        assert 'nameExact("Popen")' in server.queries[0]

    def test_log_entry_shape(self, tmp_path: Path):
        r = self._run(tmp_path, FakeServer("RAPTOR_FLOW_FUNC:missing\n"))
        entry = r.to_log_entry()
        assert entry["tool"] == "joern"
        assert entry["rule_id"] == FLOW_STAMP
        assert entry["outcome"] == "inconclusive"


# ── evidence-grade integration ───────────────────────────────────────


class TestEvidenceStamps:
    def test_stamps_are_tool_evidence(self):
        from core.audit.evidence_grade import is_tool_evidence

        assert is_tool_evidence(GUARD_DOMINANCE_STAMP)
        assert is_tool_evidence(FLOW_STAMP)

    def test_stamps_not_detection_only(self):
        from core.audit.orchestrator import _is_detection_only

        assert not _is_detection_only(GUARD_DOMINANCE_STAMP)
        assert not _is_detection_only(FLOW_STAMP)


class TestGuardDominanceKindBinding:
    """The refutation binds to the check KIND the hypothesis asserts.

    The dominance query collects EVERY condition mentioning the
    identifier, so without kind-binding a mere USE dominating the
    sink refuted "missing <kind> check" hypotheses. Live-verified
    against joern: `while (ptr->next)` — a dereference, not a null
    check — is collected by the condition query and dominates a
    later `free(ptr)`.
    """

    def _run(self, tmp_path, server, **kw):
        args = {
            "target_path": tmp_path,
            "file_path": "src/a.c",
            "function_name": "free_list",
            "identifier": "ptr",
            "sink_call": "free",
            "server": server,
        }
        args.update(kw)
        return run_guard_dominance_check(**args)

    def test_kind_mismatched_dominator_abstains(self, tmp_path):
        # The live-verified shape: a dereference dominates the sink.
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_GUARDED:9|8|ptr->next|free(ptr)\n"
                "RAPTOR_GD_UNG_TOTAL:0\n"
            ),
            check_kind="null",
        )
        assert r.outcome == "inconclusive"
        assert r.details["kind_mismatched"][0]["guard_code"] == "ptr->next"
        assert "missing-null-check" in r.details["reason"]

    def test_kind_matched_dominator_still_refutes(self, tmp_path):
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_GUARDED:9|8|!ptr|free(ptr)\n"
                "RAPTOR_GD_UNG_TOTAL:0\n"
            ),
            check_kind="null",
        )
        assert r.outcome == "refuted"

    def test_truth_test_conjunct_is_a_null_check(self, tmp_path):
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_GUARDED:9|8|ptr && ready|free(ptr)\n"
                "RAPTOR_GD_UNG_TOTAL:0\n"
            ),
            check_kind="null",
        )
        assert r.outcome == "refuted"

    def test_zero_equality_is_not_a_bounds_check(self, tmp_path):
        # `if (len != 0)` must not refute "missing bounds check on
        # len".
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_GUARDED:9|8|len != 0|memcpy(dst, s, len)\n"
                "RAPTOR_GD_UNG_TOTAL:0\n"
            ),
            identifier="len", sink_call="memcpy", check_kind="bounds",
        )
        assert r.outcome == "inconclusive"
        assert "kind_mismatched" in r.details

    def test_member_access_arrow_is_not_a_bounds_check(self, tmp_path):
        # `if (s->len)` mentions len after a `>`, but the > of the
        # arrow is member access, not a comparison.
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_GUARDED:9|8|s->len|memcpy(dst, s, len)\n"
                "RAPTOR_GD_UNG_TOTAL:0\n"
            ),
            identifier="len", sink_call="memcpy", check_kind="bounds",
        )
        assert r.outcome == "inconclusive"
        assert r.details["kind_mismatched"][0]["guard_code"] == "s->len"

    def test_relational_dominator_refutes_bounds(self, tmp_path):
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_GUARDED:9|8|len < sizeof(dst)|"
                "memcpy(dst, s, len)\n"
                "RAPTOR_GD_UNG_TOTAL:0\n"
            ),
            identifier="len", sink_call="memcpy", check_kind="bounds",
        )
        assert r.outcome == "refuted"

    def test_no_kind_keeps_mention_semantics(self, tmp_path):
        # The release-order / propagation callers ask exactly the
        # mention-dominance question — no kind, no demotion.
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_GUARDED:9|8|ptr->next|free(ptr)\n"
                "RAPTOR_GD_UNG_TOTAL:0\n"
            ),
        )
        assert r.outcome == "refuted"

    def test_mixed_dominators_one_mismatch_abstains(self, tmp_path):
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:2\n"
                "RAPTOR_GD_GUARDED:9|8|!ptr|free(ptr)\n"
                "RAPTOR_GD_GUARDED:19|18|ptr->next|free(ptr->data)\n"
                "RAPTOR_GD_UNG_TOTAL:0\n"
            ),
            check_kind="null",
        )
        assert r.outcome == "inconclusive"
        assert len(r.details["kind_mismatched"]) == 1

    def test_confirmed_direction_untouched_by_kind(self, tmp_path):
        r = self._run(
            tmp_path,
            FakeServer(
                "RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n"
                "RAPTOR_GD_UNGUARDED:42|free(ptr)\n"
                "RAPTOR_GD_UNG_TOTAL:1\n"
            ),
            check_kind="null",
        )
        assert r.outcome == "confirmed"

    def test_kind_mapping_from_cwe(self):
        assert guard_check_kind("CWE-476") == "null"
        assert guard_check_kind("476") == "null"
        for cwe in ("CWE-120", "CWE-121", "CWE-122", "CWE-125",
                    "CWE-787"):
            assert guard_check_kind(cwe) == "bounds"
        # Web validation families keep mention semantics.
        for cwe in ("CWE-22", "CWE-502", "CWE-918", "CWE-77"):
            assert guard_check_kind(cwe) is None

    def test_guard_chain_entry_carries_cwe(self):
        entry = guard_chain_entry("CWE-476")
        assert entry is not None
        assert entry["config"]["cwe"] == "CWE-476"
