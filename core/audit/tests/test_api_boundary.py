"""Public-API-boundary guard channel.

Observed field failure: caller-contract hypotheses (NULL host from an
external API consumer; negative outl bypassing bio_read_intern's
guard; kernel notification semantics) were unmappable to any tool —
flow tools reported "no in-tree triggering path" and the verdicts
died speculative. The channel checks the asserted obligation at every
in-repo call site instead: all-guarded → refuted-with-receipts, a
concrete unguarded site → confirmed-with-receipt, external-only
callers / external contracts → inconclusive-with-reason. Hermetic —
no LLM, no subprocesses.
"""

from __future__ import annotations

from core.audit.api_boundary import (
    extract_contract,
    is_caller_contract_hypothesis,
    parse_param_names,
    run_api_boundary_check,
)

DEFINITION = """
int bio_lookup_ex(const char *host, int port, int family)
{
    if (family == AF_UNIX && host == NULL)
        return 0;
    return do_lookup(host, port, family);
}
"""


def _write_target(tmp_path, callers_c: str):
    (tmp_path / "lookup.c").write_text(DEFINITION)
    (tmp_path / "callers.c").write_text(callers_c)
    return tmp_path


class TestHypothesisShape:
    def test_caller_contract_shapes_detected(self):
        assert is_caller_contract_hypothesis(
            "NULL host is only reachable from external API consumers",
        )
        assert is_caller_contract_hypothesis(
            "requires a caller to pass negative outl, bypassing "
            "bio_read_intern's guard",
        )
        assert not is_caller_contract_hypothesis(
            "unchecked memcpy of the notification buffer overflows snp",
        )


class TestContractExtraction:
    PARAMS = ("host", "port", "family")

    def test_null_parameter_contract(self):
        c = extract_contract(
            "a NULL host with AF_UNIX reaches the unchecked branch; "
            "callers must never pass NULL host",
            self.PARAMS,
        )
        assert c is not None and c.kind == "null"
        assert c.param == "host" and c.param_index == 0

    def test_negative_parameter_contract(self):
        c = extract_contract(
            "negative port bypasses the size check in callers",
            self.PARAMS,
        )
        assert c is not None and c.kind == "negative"
        assert c.param == "port" and c.param_index == 1

    def test_external_environment_contract(self):
        c = extract_contract(
            "the kernel may truncate the notification; callers must "
            "handle short reads",
            self.PARAMS,
        )
        assert c is not None and c.kind == "external"

    def test_unbindable_contract_is_none(self):
        assert extract_contract("callers must be careful", self.PARAMS) is None


class TestParamParsing:
    def test_parses_definition_params(self):
        assert parse_param_names(DEFINITION, "bio_lookup_ex") == [
            "host", "port", "family",
        ]

    def test_ignores_prototypes(self):
        src = (
            "int f(const char *host, int port);\n"
            "int f(const char *h2, int p2)\n{\n    return 0;\n}\n"
        )
        assert parse_param_names(src, "f") == ["h2", "p2"]


HYP_NULL = (
    "callers must never pass NULL host; the AF_UNIX branch "
    "dereferences it"
)


class TestVerdicts:
    def test_all_sites_guarded_refutes_with_receipts(self, tmp_path):
        target = _write_target(tmp_path, """
int a(const char *name) {
    if (name == NULL)
        return -1;
    return bio_lookup_ex(name, 80, 0);
}
int b(void) {
    return bio_lookup_ex("localhost", 80, 0);
}
""")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert res.outcome == "refuted", res.to_dict()
        assert len(res.sites) == 2
        assert all(s.verdict == "guarded" for s in res.sites)
        assert all(s.evidence for s in res.sites), (
            "refutation must carry per-site guard receipts"
        )

    def test_concrete_unguarded_site_confirms(self, tmp_path):
        target = _write_target(tmp_path, """
int careless(void) {
    return bio_lookup_ex(NULL, 80, 2);
}
""")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert res.outcome == "confirmed", res.to_dict()
        assert "callers.c" in res.reason
        unguarded = [s for s in res.sites if s.verdict == "unguarded"]
        assert unguarded and "NULL" in unguarded[0].evidence

    def test_external_only_callers_inconclusive(self, tmp_path):
        (tmp_path / "lookup.c").write_text(DEFINITION)
        res = run_api_boundary_check(
            tmp_path, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert res.outcome == "inconclusive"
        assert "external-only callers" in res.reason

    def test_undecided_site_gates_to_inconclusive(self, tmp_path):
        # `name` flows in with no visible guard: never guess.
        target = _write_target(tmp_path, """
int passthrough(const char *name) {
    return bio_lookup_ex(name, 80, 0);
}
""")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex", HYP_NULL,
        )
        assert res.outcome == "inconclusive", res.to_dict()
        assert any(s.verdict == "undecided" for s in res.sites)

    def test_kernel_contract_gets_external_receipt(self, tmp_path):
        target = _write_target(tmp_path, "\n")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex",
            "the kernel may deliver a truncated notification; callers "
            "must tolerate short reads",
        )
        assert res.outcome == "inconclusive"
        assert "external contract" in res.reason

    def test_negative_contract_checks_sign_guards(self, tmp_path):
        target = _write_target(tmp_path, """
int checked(int n) {
    if (n < 0)
        return -1;
    return bio_lookup_ex("x", n, 0);
}
int unsigned_source(void) {
    return bio_lookup_ex("x", sizeof(int), 0);
}
""")
        res = run_api_boundary_check(
            target, "lookup.c", "bio_lookup_ex",
            "callers must never pass negative port",
        )
        assert res.outcome == "refuted", res.to_dict()

    def test_definition_span_not_counted_as_call_site(self, tmp_path):
        (tmp_path / "lookup.c").write_text(DEFINITION)
        (tmp_path / "user.c").write_text(
            "int u(void) { return bio_lookup_ex(NULL, 1, 2); }\n",
        )
        res = run_api_boundary_check(
            tmp_path, "lookup.c", "bio_lookup_ex", HYP_NULL,
            def_span=(1, 8),
        )
        files = {s.file for s in res.sites}
        assert files == {"user.c"}


class TestDispatchWiring:
    def test_chain_builder_emits_api_boundary_step(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(
            "NULL host is only reachable from external API consumers "
            "of this exported function",
            "crypto/bio/bio_addr.c",
        )
        assert any(e["type"] == "api_boundary" for e in chain), (
            "caller-contract hypotheses must dispatch the boundary "
            "channel"
        )

    def test_non_contract_hypotheses_do_not_dispatch(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(
            "unchecked memcpy overflows the destination buffer",
            "a.c",
        )
        assert not any(e["type"] == "api_boundary" for e in chain)

    def test_tool_chain_runs_channel(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            TierCounters,
            _run_tool_chain,
        )

        _write_target(tmp_path, """
int careless(void) {
    return bio_lookup_ex(NULL, 80, 2);
}
""")
        counters = {"api_boundary": TierCounters()}
        confirmed = _run_tool_chain(
            [{"type": "api_boundary", "config": {}}],
            config=OrchestratorConfig(target_path=tmp_path, out_dir=None),
            file_path="lookup.c",
            function_name="bio_lookup_ex",
            source=DEFINITION,
            hypothesis=HYP_NULL,
            tier_counters=counters,
        )
        assert confirmed == ["api_boundary:caller-contract"]
        assert counters["api_boundary"].confirmed == 1
