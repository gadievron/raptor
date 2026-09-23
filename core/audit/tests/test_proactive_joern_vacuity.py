"""_proactive_validate joern lanes: silence only refutes with CPG coverage.

The sibling of the _run_tool_chain vacuity gate (same rule, other
dispatch site): the CWE-dispatch joern lane added ``"joern"`` to the
per-function dispatch record BEFORE its live query and booked bare
silence as refuted with no coverage probe — for a function the CPG
never modelled (no frontend for the file's language, extraction
miss), gate resolution then counts joern as a covering channel that
"ran and stayed silent" and demotes evidence-free suspicious
outcomes to clean. The cross_function lane (which tool_coverage maps
to "joern") had the same shape: dispatched before the query, kept in
the record on an inconclusive ``None`` verdict.

Confirmed against a live Joern server (tiny C CPG; a .py function the
CPG cannot model): both "joern" and "cross_function" landed in
``tools_dispatched`` with no errors and no skip accounting.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.orchestrator import (
    OrchestratorConfig,
    ReviewOutcome,
    TierCounters,
    _proactive_validate,
)


class _QueryResult:
    def __init__(self, raw_output: str):
        self.raw_output = raw_output


class _Server:
    """Duck-typed Joern server: silent taint batches, scripted
    coverage answers (same transport-faithful double as
    test_joern_vacuity_gate)."""

    def __init__(self, covers: bool | None):
        self._covers = covers
        self.queries: list[str] = []

    def run_taint_queries_batch(self, pairs, timeout=0, errors_out=None,
                                **kwargs):
        return []

    def query(self, query: str, timeout: int = 0,
              check_length: bool = False) -> _QueryResult:
        self.queries.append(query)
        if self._covers is None:
            raise RuntimeError("transport lost")
        if "println" in query:
            return _QueryResult("")
        last = query.strip().rsplit("\n", 1)[-1]
        nonce = last.split('"')[1]
        return _QueryResult(
            f'res0: String = "{nonce}{"true" if self._covers else "false"}"'
        )


def _outcome() -> ReviewOutcome:
    oc = ReviewOutcome(
        file="ghost.py", function="ghost_fn",
        status="suspicious", body="b",
        hypothesis="attacker-controlled data reaches a command sink",
    )
    oc.review_result = {"cwe": "CWE-78", "mechanism": "command injection"}
    return oc


def _run(tmp_path: Path, server: _Server, monkeypatch=None, xf=None):
    cfg = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
    tiers = {"joern": TierCounters(), "joern_xf": TierCounters()}
    if monkeypatch is not None:
        import core.audit.cross_function_verify as xfv
        monkeypatch.setattr(
            xfv, "cross_function_verify",
            lambda **kwargs: xf,
        )
    oc = _proactive_validate(
        _outcome(), cfg, evidence_index={}, dispatched_tools=set(),
        tier_counters=tiers, joern_server=server,
    )
    return oc, tiers


class TestCweDispatchVacuityGate:
    def test_uncovered_function_stays_out_of_dispatch_record(
        self, tmp_path, monkeypatch,
    ):
        oc, tiers = _run(tmp_path, _Server(covers=False), monkeypatch, None)
        assert "joern" not in (oc.tools_dispatched or set())
        assert "joern" in (oc.tools_skipped or set())
        assert tiers["joern"].refuted == 0
        assert tiers["joern"].skipped >= 1

    def test_unanswerable_probe_stays_out_of_dispatch_record(
        self, tmp_path, monkeypatch,
    ):
        oc, tiers = _run(tmp_path, _Server(covers=None), monkeypatch, None)
        assert "joern" not in (oc.tools_dispatched or set())
        assert "joern" in (oc.tools_skipped or set())
        assert tiers["joern"].refuted == 0

    def test_covered_function_silence_still_refutes(
        self, tmp_path, monkeypatch,
    ):
        oc, tiers = _run(tmp_path, _Server(covers=True), monkeypatch, None)
        assert "joern" in (oc.tools_dispatched or set())
        assert tiers["joern"].refuted == 1
        assert tiers["joern"].skipped == 0


class _NamesakeServer(_Server):
    """A same-named non-external definition exists in the CPG — in a
    DIFFERENT file.  Faithful to the real probe's three-way echo
    (joern_backend.joern_function_in_cpg): a file-bound query answers
    ``otherfile``; a name-only query answers ``true`` off the
    cross-file namesake."""

    def __init__(self):
        super().__init__(covers=True)

    def query(self, query: str, timeout: int = 0,
              check_length: bool = False) -> _QueryResult:
        self.queries.append(query)
        if "println" in query:
            return _QueryResult("")
        last = query.strip().rsplit("\n", 1)[-1]
        nonce = last.split('"')[1]
        answer = "otherfile" if "endsWith(" in query else "true"
        return _QueryResult(f'res0: String = "{nonce}{answer}"')


class TestCweDispatchProbeFileBinding:
    """The CWE-dispatch coverage probe must bind to the item's OWN
    file, exactly like its tool-chain twin: a cross-file namesake
    (common-name C static helpers across TUs) is not coverage of this
    item and must never license refutation-grade silence."""

    def test_cross_file_namesake_does_not_license_refutation(
        self, tmp_path, monkeypatch,
    ):
        server = _NamesakeServer()
        oc, tiers = _run(tmp_path, server, monkeypatch, None)
        assert "joern" not in (oc.tools_dispatched or set())
        assert "joern" in (oc.tools_skipped or set())
        assert tiers["joern"].refuted == 0

    def test_coverage_probe_query_names_the_items_file(
        self, tmp_path, monkeypatch,
    ):
        server = _NamesakeServer()
        _run(tmp_path, server, monkeypatch, None)
        cov_queries = [q for q in server.queries if "raptorCov" in q]
        assert cov_queries, "coverage probe never dispatched"
        assert all("ghost.py" in q for q in cov_queries)

    def test_probe_call_sites_are_single_homed(self):
        # Drift-proof pin: every orchestrator coverage probe routes
        # through _joern_coverage_probe (whose file_path parameter is
        # required) — the twin legs asserted the file binding
        # per-site once, and one site lost it.
        import inspect

        import core.audit.orchestrator as orch

        src = inspect.getsource(orch)
        direct = src.count("_joern_function_in_cpg(")
        assert direct == 1, (
            "call _joern_coverage_probe (file-bound builder), never "
            "_joern_function_in_cpg directly"
        )


class TestCrossFunctionDispatchRecord:
    def test_inconclusive_none_stays_out_of_dispatch_record(
        self, tmp_path, monkeypatch,
    ):
        # tool_coverage maps cross_function → joern, so an
        # inconclusive verdict left in the record is phantom class
        # coverage.
        oc, tiers = _run(tmp_path, _Server(covers=True), monkeypatch, None)
        assert "cross_function" not in (oc.tools_dispatched or set())
        assert "cross_function" in (oc.tools_skipped or set())

    def test_refuted_verdict_stays_in_dispatch_record(
        self, tmp_path, monkeypatch,
    ):
        class _XF:
            verified = False
            verifier_name = "lock_pairing"
            evidence = ""

        oc, tiers = _run(tmp_path, _Server(covers=True), monkeypatch, _XF())
        assert "cross_function" in (oc.tools_dispatched or set())
        assert tiers["joern_xf"].refuted == 1
