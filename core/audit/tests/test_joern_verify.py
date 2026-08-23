"""Tests for core.audit.joern_verify — hermetic, stubbed Joern server.

No JVM boots here: every check goes through a FakeServer whose
``query`` method returns canned :class:`JoernResult` objects, so the
sweep logic (outcome taxonomy, vacuity guard, identifier-consistency
negative controls) is tested without joern installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

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
    run_guard_dominance_check,
)
from packages.joern.models import JoernResult
from packages.joern.runner import _parse_output, _validate_query


class FakeServer:
    """Minimal stand-in for packages.joern.server.JoernServer."""

    def __init__(self, raw_output: str = "", errors=None, raise_exc=None):
        self.raw_output = raw_output
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
        entry = flow_chain_entry(cwe)
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
        q = build_guard_dominance_query("parse_hdr", "memcpy", "len")
        assert 'nameExact("parse_hdr")' in q
        assert 'nameExact("memcpy")' in q
        assert "\\\\blen\\\\b" in q
        assert "RAPTOR_GD_FUNC:" in q
        assert "dominatedBy" in q

    def test_guard_query_passes_validation(self):
        q = build_guard_dominance_query("f", "memcpy", "n")
        assert _validate_query(q, check_length=False) is None

    def test_flow_query_contains_names_and_sentinels(self):
        q = build_flow_query("handler", "argv", "system", max_call_depth=3)
        assert 'nameExact("handler")' in q
        assert 'nameExact("argv")' in q
        assert 'nameExact("system")' in q
        assert "maxCallDepth = 3" in q
        assert "reachableByFlows" in q
        assert "RAPTOR_FLOW_FUNC:" in q

    def test_flow_query_passes_validation(self):
        q = build_flow_query("f", "src", "system")
        assert _validate_query(q, check_length=False) is None

    def test_names_are_escaped(self):
        # Builders escape; callers validate. A hostile value must not
        # break out of the Scala string literal.
        q = build_guard_dominance_query('f"', "memcpy", "n")
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
        facts = _parse_guard_output(raw)
        assert facts["function_found"] is True
        assert facts["sink_count"] == 2
        assert facts["unguarded"] == [
            {"line": 42, "code": "memcpy(dst, src, len)"}
        ]
        assert facts["guarded"][0]["guard_line"] == 55

    def test_guard_parse_missing_function(self):
        facts = _parse_guard_output("RAPTOR_GD_FUNC:missing\n")
        assert facts["function_found"] is False

    def test_guard_parse_dedupes_repl_echoes(self):
        line = "RAPTOR_GD_UNGUARDED:42|memcpy(dst, src, len)"
        facts = _parse_guard_output(
            f"RAPTOR_GD_FUNC:found\nRAPTOR_GD_SINKS:1\n{line}\n"
            f'val res1: String = "{line}"\n'
        )
        assert len(facts["unguarded"]) == 1

    def test_guard_parse_strips_ansi(self):
        raw = "\x1b[32mRAPTOR_GD_FUNC:found\x1b[0m\nRAPTOR_GD_SINKS:1\n"
        facts = _parse_guard_output(raw)
        assert facts["function_found"] is True
        assert facts["sink_count"] == 1

    def test_flow_parse(self):
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:1\n"
            "RAPTOR_FLOW_SNK:2\nRAPTOR_FLOW_COUNT:1\n"
        )
        facts = _parse_flow_facts(raw)
        assert facts == {
            "function_found": True,
            "source_count": 1,
            "sink_count": 2,
            "flow_count": 1,
        }

    def test_flow_parse_empty(self):
        facts = _parse_flow_facts("")
        assert facts["function_found"] is None


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
            ),
        )
        assert r.outcome == "refuted"
        assert r.details["dominators"][0]["guard_code"] == "len < sizeof(dst)"

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
        raw = (
            "RAPTOR_FLOW_FUNC:found\nRAPTOR_FLOW_SRC:2\n"
            "RAPTOR_FLOW_SNK:1\nRAPTOR_FLOW_COUNT:0\n"
        )
        r = self._run(tmp_path, FakeServer(raw))
        assert r.outcome == "refuted"
        assert r.details["source_count"] == 2

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
