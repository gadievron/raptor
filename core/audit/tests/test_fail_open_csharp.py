"""Fail-open channel, phase-4 C# leg.

Catch-block outcome classification on the C# grammar — the Java
handler-outcome family with C#'s shapes: typed ``catch_clause`` with
optional ``when (...)`` exception filters (a filtered broad type is
*not* broad — the filter narrows it), the typeless bare ``catch { }``
(broad — it catches everything), the bare ``throw;`` rethrow
statement, ``return default`` as a fail-closed restrictive value, and
same-file ``throw`` statements as the fallibility witness (C# has no
checked exceptions, so the Java declared-``throws`` witness
deliberately has no counterpart). Plus dispatch through
``run_fail_open_check``, census membership, and the parser-absent
degradation contract. Hermetic — fixtures in-test.

Fixtures deliberately hardcode target-like names (``authz.Check``,
``CheckValidity``) — they *simulate targets*, so the vocabulary
policy does not apply to them.
"""

from __future__ import annotations

import pytest

from core.audit.fail_open_census import (
    CENSUS_LANGUAGES,
    run_fail_open_census,
)
from core.audit.fail_open_lang import (
    SUPPORTED_LANGUAGES,
    csharp_function_throws,
    csharp_handlers,
    csharp_method_segment,
)
from core.audit.fail_open_verify import (
    REASON_FALLIBILITY_UNRESOLVED,
    REASON_HYPOTHESIS_UNBINDABLE,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_MECHANISM_UNSUPPORTED,
    RULE_HANDLER_OUTCOME,
    run_fail_open_check,
)
from core.testing import requires_ts


def _write(tmp_path, rel, text):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


@requires_ts("csharp")
class TestCSharpHandlerAnalyzer:
    def test_empty_catch_classified(self):
        src = (
            "class C {\n"
            "    void F(Request req) {\n"
            "        try { authz.Check(req); } "
            "catch (Exception e) { }\n"
            "    }\n"
            "}\n"
        )
        handlers = csharp_handlers(src, "C.cs")
        assert handlers is not None and len(handlers) == 1
        h = handlers[0]
        assert h.outcome_kind == "pass"
        assert h.broad is True
        assert h.enclosing_function == "F"
        assert "authz.Check" in h.try_calls
        assert h.parser == "tree-sitter"

    def test_bare_catch_is_broad(self):
        # A typeless `catch { }` catches everything — broad, with the
        # sentinel caught list.
        src = (
            "class C {\n"
            "    void F(Request req) {\n"
            "        try { authz.Check(req); } catch { }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "pass"
        assert h.broad is True
        assert h.caught == ["<all>"]

    def test_exception_filter_unbroadens(self):
        # `catch (Exception e) when (...)` only catches what the
        # filter admits — it must not count as a broad catch.
        src = (
            "class C {\n"
            "    void F() {\n"
            "        try { Check(); } catch (Exception e) "
            "when (e.HResult == 3) { }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.broad is False
        assert h.caught == ["Exception"]

    def test_bare_rethrow_is_fail_closed(self):
        # `throw;` re-raises the original exception.
        src = (
            "class C {\n"
            "    void F() {\n"
            "        try { Check(); } catch (Exception e) { throw; }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "fail_closed"
        assert h.permissive_value == "re-throws"

    def test_wrapped_rethrow_is_fail_closed(self):
        src = (
            "class C {\n"
            "    void F() {\n"
            "        try { Check(); } "
            "catch (AccessDeniedException e) "
            "{ throw new SecurityException(\"denied\", e); }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "fail_closed"
        assert h.permissive_value == "re-throws"

    def test_return_true_is_permissive(self):
        src = (
            "class C {\n"
            "    bool F() {\n"
            "        try { return acl.Check(); } "
            "catch (LookupException e) { return true; }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "return_permissive"
        assert h.permissive_value == "true"

    def test_return_false_is_fail_closed(self):
        src = (
            "class C {\n"
            "    bool F() {\n"
            "        try { return acl.Check(); } "
            "catch (LookupException e) { return false; }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "fail_closed"

    def test_return_default_is_fail_closed(self):
        # `default` (default_expression) is a restrictive value —
        # the caller receives the zero value, not a permissive one.
        src = (
            "class C {\n"
            "    Session F() {\n"
            "        try { return acl.Check(); } "
            "catch (LookupException e) { return default; }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "fail_closed"

    def test_quiet_log_only_classified(self):
        src = (
            "class C {\n"
            "    void F() {\n"
            "        try { verifier.Verify(chain); } "
            "catch (CertificateException e) "
            "{ _log.LogDebug(\"failed\", e); }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "quiet_log_only"

    def test_loud_log_is_undecided(self):
        src = (
            "class C {\n"
            "    void F() {\n"
            "        try { verifier.Verify(chain); } "
            "catch (CertificateException e) "
            "{ _log.LogError(\"failed\", e); }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "fallback_action"
        assert not h.is_permissive
        assert not h.is_fail_closed

    def test_abort_is_fail_closed(self):
        src = (
            "class C {\n"
            "    void F() {\n"
            "        try { Check(); } catch (Exception e) "
            "{ Environment.Exit(1); }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "fail_closed"
        assert h.permissive_value == "aborts"

    def test_console_print_is_undecided(self):
        src = (
            "class C {\n"
            "    void F() {\n"
            "        try { Check(); } catch (Exception e) "
            "{ Console.Error.WriteLine(e); DoMore(); }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "fallback_action"
        assert not h.is_permissive

    def test_abort_in_comment_does_not_classify(self):
        # Classification regexes run over the sanitized view.
        src = (
            "class C {\n"
            "    bool F() {\n"
            "        try { return acl.Check(); } "
            "catch (Exception e) "
            "{ /* Environment.Exit(1) would be too harsh */ "
            "return true; }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "return_permissive"

    def test_continue_is_permissive(self):
        src = (
            "class C {\n"
            "    void F(List<Item> items) {\n"
            "        foreach (var item in items) {\n"
            "            try { Validate(item); } "
            "catch (Exception e) { continue; }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "continue"
        assert h.is_permissive

    def test_assign_default_classified(self):
        src = (
            "class C {\n"
            "    void F() {\n"
            "        int level;\n"
            "        try { level = LookupLevel(); } "
            "catch (Exception e) { level = 0; }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "assign_default"
        assert h.permissive_value == "0"

    def test_declaration_initializer_classified(self):
        # `var level = 0;` — the RHS lives in a variable_declarator,
        # not an assignment_expression.
        src = (
            "class C {\n"
            "    void F() {\n"
            "        try { Check(); } "
            "catch (Exception e) { var level = 0; }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind == "assign_default"
        assert h.permissive_value == "0"

    def test_throw_inside_lambda_is_not_fail_closed(self):
        # The throw never executes at handler level — it must not
        # mint a fail-closed refutation receipt.
        src = (
            "class C {\n"
            "    void F() {\n"
            "        try { Check(); } catch (Exception e) {\n"
            "            Action h = () => "
            "throw new InvalidOperationException(\"x\");\n"
            "            Register(h);\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind != "fail_closed"

    def test_throw_inside_local_function_is_not_fail_closed(self):
        src = (
            "class C {\n"
            "    void F() {\n"
            "        try { Check(); } catch (Exception e) {\n"
            "            void Local() { throw new Exception(\"x\"); }\n"
            "            Register(Local);\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.outcome_kind != "fail_closed"

    def test_throw_swallowed_by_nested_try_is_not_fail_closed(self):
        src = (
            "class C {\n"
            "    void F() {\n"
            "        try { Check(); } catch (Exception e) {\n"
            "            try { throw new RetryException(); } "
            "catch (RetryException e2) { Note(e2); }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        outer = csharp_handlers(src, "C.cs")[0]
        assert outer.caught == ["Exception"]
        assert outer.outcome_kind != "fail_closed"

    def test_local_function_reports_its_own_name(self):
        src = (
            "class C {\n"
            "    void Outer() {\n"
            "        void Handle(Request req) {\n"
            "            try { authz.Check(req); } "
            "catch (Exception e) { }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        h = csharp_handlers(src, "C.cs")[0]
        assert h.enclosing_function == "Handle"

    def test_parser_absent_returns_none(self, monkeypatch):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        assert csharp_handlers("class C {}", "C.cs") is None


@requires_ts("csharp")
class TestCSharpFunctionThrows:
    THROWS_SRC = (
        "class V {\n"
        "    public void CheckValidity(Chain c) "
        "{ throw new CertificateException(); }\n"
        "    int Quiet() { return 1; }\n"
        "}\n"
    )

    def test_throw_statement_resolved(self):
        assert csharp_function_throws(
            self.THROWS_SRC, "CheckValidity",
        ) == ["CertificateException"]

    def test_no_throws_is_empty(self):
        assert csharp_function_throws(self.THROWS_SRC, "Quiet") == []

    def test_segment_includes_class_header(self):
        seg = csharp_method_segment(self.THROWS_SRC, "CheckValidity")
        assert "CheckValidity" in seg
        assert seg.startswith("class V")


@requires_ts("csharp")
class TestVerdictsCSharp:
    TRUST_VULN = (
        "class ChainValidator {\n"
        "    public bool Validate(Chain chain) {\n"
        "        try { CheckValidity(chain); } "
        "catch (CertificateException e) "
        "{ _log.LogDebug(\"cert check failed\", e); }\n"
        "        return true;\n"
        "    }\n"
        "    void CheckValidity(Chain c) "
        "{ throw new CertificateException(); }\n"
        "}\n"
    )
    HYP_TRUST = (
        "certificate validation fails open: the CertificateException "
        "is swallowed with a debug log and the method returns true"
    )

    def test_trust_manager_quiet_log_confirms(self, tmp_path):
        _write(tmp_path, "src/ChainValidator.cs", self.TRUST_VULN)
        res = run_fail_open_check(
            tmp_path, "src/ChainValidator.cs", "Validate",
            self.HYP_TRUST,
        )
        assert res.outcome == "confirmed"
        assert res.language == "csharp"
        assert res.rule_id.startswith(RULE_HANDLER_OUTCOME)
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "quiet_log_only"
        # Swallowed thrown exception: the callee's same-file throw
        # names the very type the handler catches.
        assert res.fallible is not None
        assert res.fallible["evidence"] == "throws-caught-type"
        assert "CertificateException" in res.fallible["types"]

    def test_rethrow_twin_refutes(self, tmp_path):
        safe = self.TRUST_VULN.replace(
            "{ _log.LogDebug(\"cert check failed\", e); }",
            "{ throw; }",
        )
        assert safe != self.TRUST_VULN
        _write(tmp_path, "src/ChainValidator.cs", safe)
        res = run_fail_open_check(
            tmp_path, "src/ChainValidator.cs", "Validate",
            self.HYP_TRUST,
        )
        assert res.outcome == "refuted"
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "fail_closed"

    def test_broad_catch_any_call_fallibility(self, tmp_path):
        src = (
            "class Gate {\n"
            "    public void Handle(Request req) {\n"
            "        try { VerifyToken(req); } "
            "catch (Exception e) { }\n"
            "        Proceed(req);\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/Gate.cs", src)
        res = run_fail_open_check(
            tmp_path, "src/Gate.cs", "Handle",
            "token verification failure is swallowed by the broad "
            "catch and the request proceeds",
        )
        assert res.outcome == "confirmed"
        assert res.fallible is not None
        assert res.fallible["evidence"].startswith("catchable:")

    def test_bare_catch_any_call_fallibility(self, tmp_path):
        # The typeless catch is broad, so any call under it carries
        # the catchable witness.
        src = (
            "class Gate {\n"
            "    public void Handle(Request req) {\n"
            "        try { VerifyToken(req); } catch { }\n"
            "        Proceed(req);\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/Gate.cs", src)
        res = run_fail_open_check(
            tmp_path, "src/Gate.cs", "Handle",
            "token verification failure is swallowed by the bare "
            "catch and the request proceeds",
        )
        assert res.outcome == "confirmed"
        assert res.fallible is not None
        assert res.fallible["evidence"].startswith("catchable:")

    def test_specific_catch_without_evidence_is_fallibility_unresolved(
        self, tmp_path,
    ):
        # C# has no checked exceptions — a specific catch of a type
        # with no same-file throw evidence is not a witness, so the
        # verdict is fallibility-unresolved (never a guess).
        src = (
            "class Gate {\n"
            "    public void Handle(Request req) {\n"
            "        try { VerifyToken(req); } "
            "catch (AccessDeniedException e) { }\n"
            "        Proceed(req);\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/Gate.cs", src)
        res = run_fail_open_check(
            tmp_path, "src/Gate.cs", "Handle",
            "token verification failure is swallowed and the request "
            "proceeds",
        )
        assert res.outcome == "inconclusive"
        assert REASON_FALLIBILITY_UNRESOLVED in res.reason

    def test_filtered_catch_is_not_the_broad_witness(self, tmp_path):
        # The filter narrows `Exception` — without other fallibility
        # evidence the broad-catch witness must not fire.
        src = (
            "class Gate {\n"
            "    public void Handle(Request req) {\n"
            "        try { VerifyToken(req); } "
            "catch (Exception e) when (e.HResult == 3) { }\n"
            "        Proceed(req);\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/Gate.cs", src)
        res = run_fail_open_check(
            tmp_path, "src/Gate.cs", "Handle",
            "token verification failure is swallowed and the request "
            "proceeds",
        )
        assert res.outcome == "inconclusive"
        assert REASON_FALLIBILITY_UNRESOLVED in res.reason

    def test_mechanism_gate_abstains_on_ignored_return(self, tmp_path):
        src = (
            "class Gate {\n"
            "    public void Handle(Request req) {\n"
            "        VerifyToken(req);\n"
            "        try { Audit(req); } catch (Exception e) "
            "{ throw new AuditException(\"audit\", e); }\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/Gate.cs", src)
        res = run_fail_open_check(
            tmp_path, "src/Gate.cs", "Handle",
            "the return value of `VerifyToken` is ignored — "
            "verification errors are silently discarded and control "
            "proceeds",
        )
        assert res.outcome == "inconclusive"
        assert REASON_MECHANISM_UNSUPPORTED in res.reason

    def test_no_catch_in_function_is_unbindable(self, tmp_path):
        src = (
            "class C {\n"
            "    int F(int x) { return x + 1; }\n"
            "}\n"
        )
        _write(tmp_path, "src/C.cs", src)
        res = run_fail_open_check(
            tmp_path, "src/C.cs", "F",
            "auth check failure swallowed silently",
        )
        assert res.outcome == "inconclusive"
        assert REASON_HYPOTHESIS_UNBINDABLE in res.reason


@requires_ts("csharp")
class TestCSharpCensus:
    def test_census_seeds_csharp_lead(self):
        src = (
            "class Gate {\n"
            "    public void Handle(Request req) {\n"
            "        try { VerifyToken(req); } "
            "catch (Exception e) { }\n"
            "        Proceed(req);\n"
            "    }\n"
            "}\n"
        )
        out = run_fail_open_census({"src/Gate.cs": src})
        leads = out["leads"]
        assert leads, out["telemetry"]
        lead = leads[0]
        assert lead["function"] == "Handle"
        assert lead["outcome_kind"] == "pass"
        assert lead["broad"] is True
        assert out["telemetry"]["by_language"].get("csharp") == 1


class TestCSharpDegradation:
    """Parser-absent honesty (hermetic — no grammar needed)."""

    def test_language_unsupported_when_parser_absent(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        _write(tmp_path, "src/C.cs", "class C {}")
        res = run_fail_open_check(
            tmp_path, "src/C.cs", "F",
            "auth check failure swallowed silently",
        )
        assert res.outcome == "inconclusive"
        assert REASON_LANGUAGE_UNSUPPORTED in res.reason

    def test_csharp_in_supported_and_census_languages(self):
        # C# catch blocks are the Java handler-outcome shape, so
        # csharp joins the census sweep (unlike Rust's premise split).
        assert "csharp" in SUPPORTED_LANGUAGES
        assert "csharp" in CENSUS_LANGUAGES


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
