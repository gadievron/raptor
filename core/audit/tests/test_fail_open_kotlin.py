"""Fail-open channel, phase-4 Kotlin leg.

Catch-block outcome classification on the Kotlin grammar — the Java
handler-outcome family with Kotlin's shapes: ``try_expression`` /
``catch_block``, statements as direct block children, keyword-as-
identifier nodes (``continue``/``true``/``null``), kotlin-logging
lambda arguments, and ``@Throws(X::class)`` as the declared-
fallibility witness (Kotlin has no checked exceptions, so the Java
compilability witness deliberately has no counterpart). Plus dispatch
through ``run_fail_open_check``, census membership, and the
parser-absent degradation contract. Hermetic — fixtures in-test.

Fixtures deliberately hardcode target-like names (``authz.check``,
``checkValidity``) — they *simulate targets*, so the vocabulary
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
    kotlin_function_throws,
    kotlin_handlers,
    kotlin_method_segment,
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


@requires_ts("kotlin")
class TestKotlinHandlerAnalyzer:
    def test_empty_catch_classified(self):
        src = (
            "class C {\n"
            "    fun f(req: Request) {\n"
            "        try { authz.check(req) } catch (e: Exception) { }\n"
            "    }\n"
            "}\n"
        )
        handlers = kotlin_handlers(src, "C.kt")
        assert handlers is not None and len(handlers) == 1
        h = handlers[0]
        assert h.outcome_kind == "pass"
        assert h.broad is True
        assert h.enclosing_function == "f"
        assert "authz.check" in h.try_calls
        assert h.parser == "tree-sitter"

    def test_rethrow_is_fail_closed(self):
        src = (
            "class C {\n"
            "    fun f() {\n"
            "        try { check() } catch (e: AccessDeniedException) "
            "{ throw SecurityException(e) }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        assert h.outcome_kind == "fail_closed"
        assert h.permissive_value == "re-throws"

    def test_return_true_is_permissive(self):
        src = (
            "class C {\n"
            "    fun f(): Boolean {\n"
            "        try { return acl.check() } "
            "catch (e: LookupException) { return true }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        # `true` parses as a bare identifier node in this grammar —
        # the classifier must match it by text.
        assert h.outcome_kind == "return_permissive"
        assert h.permissive_value == "true"

    def test_return_false_is_fail_closed(self):
        src = (
            "class C {\n"
            "    fun f(): Boolean {\n"
            "        try { return acl.check() } "
            "catch (e: LookupException) { return false }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        assert h.outcome_kind == "fail_closed"

    def test_return_null_is_fail_closed(self):
        src = (
            "class C {\n"
            "    fun f(): Session? {\n"
            "        try { return acl.check() } "
            "catch (e: LookupException) { return null }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        assert h.outcome_kind == "fail_closed"

    def test_quiet_log_only_classified(self):
        src = (
            "class C {\n"
            "    fun f() {\n"
            "        try { verifier.verify(chain) } "
            "catch (e: CertificateException) "
            "{ log.debug(\"failed\", e) }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        assert h.outcome_kind == "quiet_log_only"

    def test_quiet_log_lambda_syntax_classified(self):
        # kotlin-logging passes the message as a lambda — no parens.
        src = (
            "class C {\n"
            "    fun f() {\n"
            "        try { verifier.verify(chain) } "
            "catch (e: CertificateException) "
            "{ log.debug { \"failed\" } }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        assert h.outcome_kind == "quiet_log_only"

    def test_loud_log_is_undecided(self):
        src = (
            "class C {\n"
            "    fun f() {\n"
            "        try { verifier.verify(chain) } "
            "catch (e: CertificateException) "
            "{ log.error { \"failed\" } }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        assert h.outcome_kind == "fallback_action"
        assert not h.is_permissive
        assert not h.is_fail_closed

    def test_abort_is_fail_closed(self):
        src = (
            "class C {\n"
            "    fun f() {\n"
            "        try { check() } catch (e: Exception) "
            "{ exitProcess(1) }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        assert h.outcome_kind == "fail_closed"
        assert h.permissive_value == "aborts"

    def test_abort_in_comment_does_not_classify(self):
        # Classification regexes run over the sanitized view.
        src = (
            "class C {\n"
            "    fun f(): Boolean {\n"
            "        try { return acl.check() } catch (e: Exception) "
            "{ /* System.exit(1) would be too harsh */ return true }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        assert h.outcome_kind == "return_permissive"

    def test_continue_is_permissive(self):
        # `continue` parses as a bare identifier — matched by text.
        src = (
            "class C {\n"
            "    fun f(items: List<Item>) {\n"
            "        for (item in items) {\n"
            "            try { validate(item) } "
            "catch (e: Exception) { continue }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        assert h.outcome_kind == "continue"
        assert h.is_permissive

    def test_assign_default_classified(self):
        src = (
            "class C {\n"
            "    fun f() {\n"
            "        var level: Int\n"
            "        try { level = lookupLevel() } "
            "catch (e: Exception) { level = 0 }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        assert h.outcome_kind == "assign_default"
        assert h.permissive_value == "0"

    def test_throw_inside_lambda_is_not_fail_closed(self):
        # The throw never executes at handler level — it must not
        # mint a fail-closed refutation receipt.
        src = (
            "class C {\n"
            "    fun f() {\n"
            "        try { check() } catch (e: Exception) {\n"
            "            val h = { x: Int -> "
            "throw RuntimeException(\"x\") }\n"
            "            register(h)\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "C.kt")[0]
        assert h.outcome_kind != "fail_closed"

    def test_throw_swallowed_by_nested_try_is_not_fail_closed(self):
        src = (
            "class C {\n"
            "    fun f() {\n"
            "        try { check() } catch (e: Exception) {\n"
            "            try { throw RetryException() } "
            "catch (e2: RetryException) { note(e2) }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        outer = kotlin_handlers(src, "C.kt")[0]
        assert outer.caught == ["Exception"]
        assert outer.outcome_kind != "fail_closed"

    def test_secondary_constructor_reports_class_name(self):
        src = (
            "class Gate {\n"
            "    constructor(req: Request) {\n"
            "        try { authz.check(req) } "
            "catch (e: Exception) { }\n"
            "    }\n"
            "}\n"
        )
        h = kotlin_handlers(src, "Gate.kt")[0]
        assert h.enclosing_function == "Gate"

    def test_parser_absent_returns_none(self, monkeypatch):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        assert kotlin_handlers("class C {}", "C.kt") is None


@requires_ts("kotlin")
class TestKotlinFunctionThrows:
    THROWS_SRC = (
        "class V {\n"
        "    @Throws(CertificateException::class)\n"
        "    fun checkValidity(c: List<Cert>) { }\n"
        "    fun boom() { throw ValidationException(\"bad\") }\n"
        "}\n"
    )

    def test_throws_annotation_resolved(self):
        assert kotlin_function_throws(
            self.THROWS_SRC, "checkValidity",
        ) == ["CertificateException"]

    def test_throw_expression_resolved(self):
        assert kotlin_function_throws(
            self.THROWS_SRC, "boom",
        ) == ["ValidationException"]

    def test_segment_includes_annotation_and_class_header(self):
        seg = kotlin_method_segment(self.THROWS_SRC, "checkValidity")
        assert "@Throws(CertificateException::class)" in seg
        assert seg.startswith("class V")


@requires_ts("kotlin")
class TestVerdictsKotlin:
    TRUST_VULN = (
        "class ChainValidator {\n"
        "    fun validate(chain: List<Cert>): Boolean {\n"
        "        try { checkValidity(chain) } "
        "catch (e: CertificateException) "
        "{ log.debug(\"cert check failed\", e) }\n"
        "        return true\n"
        "    }\n"
        "    @Throws(CertificateException::class)\n"
        "    fun checkValidity(c: List<Cert>) { }\n"
        "}\n"
    )
    HYP_TRUST = (
        "certificate validation fails open: the CertificateException "
        "is swallowed with a debug log and the method returns true"
    )

    def test_trust_manager_quiet_log_confirms(self, tmp_path):
        _write(tmp_path, "src/ChainValidator.kt", self.TRUST_VULN)
        res = run_fail_open_check(
            tmp_path, "src/ChainValidator.kt", "validate",
            self.HYP_TRUST,
        )
        assert res.outcome == "confirmed"
        assert res.language == "kotlin"
        assert res.rule_id.startswith(RULE_HANDLER_OUTCOME)
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "quiet_log_only"
        # Swallowed declared exception: the callee's @Throws names the
        # very type the handler catches.
        assert res.fallible is not None
        assert res.fallible["evidence"] == "declared-throws"
        assert "CertificateException" in res.fallible["types"]

    def test_rethrow_twin_refutes(self, tmp_path):
        safe = self.TRUST_VULN.replace(
            "{ log.debug(\"cert check failed\", e) }",
            "{ throw SecurityException(e) }",
        )
        _write(tmp_path, "src/ChainValidator.kt", safe)
        res = run_fail_open_check(
            tmp_path, "src/ChainValidator.kt", "validate",
            self.HYP_TRUST,
        )
        assert res.outcome == "refuted"
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "fail_closed"

    def test_broad_catch_any_call_fallibility(self, tmp_path):
        src = (
            "class Gate {\n"
            "    fun handle(req: Request) {\n"
            "        try { verifyToken(req) } "
            "catch (e: Exception) { }\n"
            "        proceed(req)\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/Gate.kt", src)
        res = run_fail_open_check(
            tmp_path, "src/Gate.kt", "handle",
            "token verification failure is swallowed by the broad "
            "catch and the request proceeds",
        )
        assert res.outcome == "confirmed"
        assert res.fallible is not None
        assert res.fallible["evidence"].startswith("catchable:")

    def test_specific_catch_without_evidence_is_fallibility_unresolved(
        self, tmp_path,
    ):
        # Kotlin has no checked exceptions — a specific catch of an
        # unresolvable type is NOT the Java compilability witness, so
        # the verdict is fallibility-unresolved (never types-
        # unresolved, never a guess).
        src = (
            "class Gate {\n"
            "    fun handle(req: Request) {\n"
            "        try { verifyToken(req) } "
            "catch (e: AccessDeniedException) { }\n"
            "        proceed(req)\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/Gate.kt", src)
        res = run_fail_open_check(
            tmp_path, "src/Gate.kt", "handle",
            "token verification failure is swallowed and the request "
            "proceeds",
        )
        assert res.outcome == "inconclusive"
        assert REASON_FALLIBILITY_UNRESOLVED in res.reason

    def test_specific_catch_must_intersect_declared_throws(
        self, tmp_path,
    ):
        # A specific (non-broad) catch earns fallibility credit only
        # when a caught type INTERSECTS the callee's declared throws.
        # A catch of an unrelated type over a callee declaring only
        # IOException proves nothing about the failure path — the leg
        # abstains with fallibility-unresolved.
        _write(tmp_path, "src/Gate.kt",
               "import java.io.IOException\n"
               "class Gate {\n"
               "    @Throws(IOException::class)\n"
               "    fun validateToken(t: Token) { }\n"
               "    fun admit(t: Token): Boolean {\n"
               "        try {\n"
               "            validateToken(t)\n"
               "        } catch (e: NumberFormatException) {\n"
               "            return true\n"
               "        }\n"
               "        return true\n"
               "    }\n"
               "}\n")
        res = run_fail_open_check(
            tmp_path, "src/Gate.kt", "admit",
            "on failure the handler returns true — authentication "
            "proceeds as if validateToken succeeded",
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_FALLIBILITY_UNRESOLVED)

    def test_mechanism_gate_abstains_on_ignored_return(self, tmp_path):
        src = (
            "class Gate {\n"
            "    fun handle(req: Request) {\n"
            "        verifyToken(req)\n"
            "        try { audit(req) } catch (e: Exception) "
            "{ throw AuditException(e) }\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/Gate.kt", src)
        res = run_fail_open_check(
            tmp_path, "src/Gate.kt", "handle",
            "the return value of `verifyToken` is ignored — "
            "verification errors are silently discarded and control "
            "proceeds",
        )
        assert res.outcome == "inconclusive"
        assert REASON_MECHANISM_UNSUPPORTED in res.reason

    def test_no_catch_in_function_is_unbindable(self, tmp_path):
        src = (
            "class C {\n"
            "    fun f(x: Int): Int { return x + 1 }\n"
            "}\n"
        )
        _write(tmp_path, "src/C.kt", src)
        res = run_fail_open_check(
            tmp_path, "src/C.kt", "f",
            "auth check failure swallowed silently",
        )
        assert res.outcome == "inconclusive"
        assert REASON_HYPOTHESIS_UNBINDABLE in res.reason

    def test_kts_script_extension_routes_to_kotlin(self, tmp_path):
        src = (
            "fun handle(req: Request) {\n"
            "    try { verifyToken(req) } catch (e: Exception) { }\n"
            "    proceed(req)\n"
            "}\n"
        )
        _write(tmp_path, "build/gate.kts", src)
        res = run_fail_open_check(
            tmp_path, "build/gate.kts", "handle",
            "token verification failure is swallowed by the broad "
            "catch and the request proceeds",
        )
        assert res.outcome == "confirmed"
        assert res.language == "kotlin"


@requires_ts("kotlin")
class TestKotlinCensus:
    def test_census_seeds_kotlin_lead(self):
        src = (
            "class Gate {\n"
            "    fun handle(req: Request) {\n"
            "        try { verifyToken(req) } "
            "catch (e: Exception) { }\n"
            "        proceed(req)\n"
            "    }\n"
            "}\n"
        )
        out = run_fail_open_census({"src/Gate.kt": src})
        leads = out["leads"]
        assert leads, out["telemetry"]
        lead = leads[0]
        assert lead["function"] == "handle"
        assert lead["outcome_kind"] == "pass"
        assert lead["broad"] is True
        assert out["telemetry"]["by_language"].get("kotlin") == 1


class TestKotlinDegradation:
    """Parser-absent honesty (hermetic — no grammar needed)."""

    def test_language_unsupported_when_parser_absent(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        _write(tmp_path, "src/C.kt", "class C {}")
        res = run_fail_open_check(
            tmp_path, "src/C.kt", "f",
            "auth check failure swallowed silently",
        )
        assert res.outcome == "inconclusive"
        assert REASON_LANGUAGE_UNSUPPORTED in res.reason

    def test_kotlin_in_supported_and_census_languages(self):
        # Kotlin catch blocks are the Java handler-outcome shape, so
        # kotlin joins the census sweep (unlike Rust's premise split).
        assert "kotlin" in SUPPORTED_LANGUAGES
        assert "kotlin" in CENSUS_LANGUAGES


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
