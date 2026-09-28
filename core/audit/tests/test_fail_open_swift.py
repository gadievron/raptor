"""Fail-open channel, phase-4 Swift leg.

Swift is dual-legged like Rust: a ``do``/``catch`` handler-outcome
leg (the Java family on Swift's shapes — direct ``catch_block``
children, pattern-less broad catches, ``control_transfer_statement``
transfers, ``property_declaration`` bindings) plus a ``try?``-erasure
leg (``try?`` converts the error branch to ``nil`` — a discarded
optional is the ignored-``Result`` shape). The language supplies a
fallibility witness of its own: ``try`` is required at exactly the
call sites that can throw, so a plain-``try``-marked call under a
broad catch is compiler-verified fallibility. Plus dispatch through
``run_fail_open_check``, dual-leg routing, census membership (handler
leg only — the erasure census is the consistency programme's), and
the parser-absent degradation contract. Hermetic — fixtures in-test.

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
    swift_do_has_plain_try,
    swift_erasure_sites,
    swift_function_declares_throws,
    swift_function_throws,
    swift_handlers,
    swift_method_segment,
)
from core.audit.fail_open_verify import (
    REASON_FALLIBILITY_UNRESOLVED,
    REASON_HANDLER_UNDECIDED,
    REASON_HYPOTHESIS_UNBINDABLE,
    REASON_LANGUAGE_UNSUPPORTED,
    RULE_HANDLER_OUTCOME,
    RULE_IGNORED_RETURN,
    run_fail_open_check,
)
from core.testing import requires_ts


def _write(tmp_path, rel, text):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


@requires_ts("swift")
class TestSwiftHandlerAnalyzer:
    def test_empty_bare_catch_classified_broad(self):
        # A pattern-less catch binds the implicit `error` and catches
        # everything — broad, with the `<all>` sentinel.
        src = (
            "class C {\n"
            "    func f(req: Request) {\n"
            "        do { try authz.check(req) } catch { }\n"
            "    }\n"
            "}\n"
        )
        handlers = swift_handlers(src, "C.swift")
        assert handlers is not None and len(handlers) == 1
        h = handlers[0]
        assert h.outcome_kind == "pass"
        assert h.broad is True
        assert h.caught == ["<all>"]
        assert h.enclosing_function == "f"
        assert "authz.check" in h.try_calls
        assert h.parser == "tree-sitter"

    def test_is_pattern_catch_not_broad(self):
        src = (
            "class C {\n"
            "    func f() {\n"
            "        do { try check() } catch is IOError { }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.caught == ["IOError"]
        assert h.broad is False

    def test_let_as_error_pattern_is_broad(self):
        src = (
            "class C {\n"
            "    func f() {\n"
            "        do { try check() } catch let e as Error { }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.caught == ["Error"]
        assert h.broad is True

    def test_rethrow_is_fail_closed(self):
        src = (
            "class C {\n"
            "    func f() throws {\n"
            "        do { try check() } catch "
            "{ throw AuthError.denied }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind == "fail_closed"
        assert h.permissive_value == "re-throws"

    def test_return_true_is_permissive(self):
        src = (
            "class C {\n"
            "    func f() -> Bool {\n"
            "        do { return try acl.check() } "
            "catch let e as LookupError { return true }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind == "return_permissive"
        assert h.permissive_value == "true"

    def test_return_false_is_fail_closed(self):
        src = (
            "class C {\n"
            "    func f() -> Bool {\n"
            "        do { return try acl.check() } "
            "catch let e as LookupError { return false }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind == "fail_closed"

    def test_return_nil_is_fail_closed(self):
        src = (
            "class C {\n"
            "    func f() -> Session? {\n"
            "        do { return try acl.check() } "
            "catch { return nil }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind == "fail_closed"

    def test_quiet_log_only_classified(self):
        src = (
            "class C {\n"
            "    func f() {\n"
            "        do { try verifier.verify(chain) } "
            "catch let e as CertificateError "
            "{ log.debug(\"failed \\(e)\") }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind == "quiet_log_only"

    def test_loud_log_is_undecided(self):
        src = (
            "class C {\n"
            "    func f() {\n"
            "        do { try verifier.verify(chain) } "
            "catch let e as CertificateError "
            "{ log.error(\"failed \\(e)\") }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind == "fallback_action"
        assert not h.is_permissive
        assert not h.is_fail_closed

    def test_abort_is_fail_closed(self):
        src = (
            "class C {\n"
            "    func f() {\n"
            "        do { try check() } catch "
            "{ fatalError(\"boom\") }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind == "fail_closed"
        assert h.permissive_value == "aborts"

    def test_abort_in_comment_does_not_classify(self):
        # Classification regexes run over the sanitized view; the
        # comment is a DIRECT catch_block child in this grammar, not
        # nested under statements.
        src = (
            "class C {\n"
            "    func f() -> Bool {\n"
            "        do { return try acl.check() } catch "
            "{ /* fatalError() would be too harsh */ return true }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind == "return_permissive"

    def test_continue_is_permissive(self):
        src = (
            "class C {\n"
            "    func f(items: [Item]) {\n"
            "        for item in items {\n"
            "            do { try validate(item) } "
            "catch { continue }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind == "continue"
        assert h.is_permissive

    def test_assign_default_classified(self):
        src = (
            "class C {\n"
            "    func f() {\n"
            "        var level = 5\n"
            "        do { level = try lookupLevel() } "
            "catch { level = 0 }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind == "assign_default"
        assert h.permissive_value == "0"

    def test_let_declaration_default_classified(self):
        # property_declaration carries its RHS in the `value` field —
        # a different node shape from assignment.
        src = (
            "class C {\n"
            "    func f() {\n"
            "        do { try check() } catch { let level = 0 }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind == "assign_default"
        assert h.permissive_value == "0"

    def test_throw_inside_closure_is_not_fail_closed(self):
        # The throw never executes at handler level — it must not
        # mint a fail-closed refutation receipt.
        src = (
            "class C {\n"
            "    func f() {\n"
            "        do { try check() } catch {\n"
            "            let h = { throw RetryError.again }\n"
            "            register(h)\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "C.swift")[0]
        assert h.outcome_kind != "fail_closed"

    def test_throw_swallowed_by_nested_do_is_not_fail_closed(self):
        src = (
            "class C {\n"
            "    func f() {\n"
            "        do { try check() } catch {\n"
            "            do { throw RetryError.again } "
            "catch { note(error) }\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        outer = [
            h for h in swift_handlers(src, "C.swift")
            if "check" in h.try_calls
        ][0]
        assert outer.outcome_kind != "fail_closed"

    def test_init_reports_class_name(self):
        src = (
            "class Loader {\n"
            "    init(x: Int) {\n"
            "        do { try check(x) } catch { }\n"
            "    }\n"
            "}\n"
        )
        h = swift_handlers(src, "Loader.swift")[0]
        assert h.enclosing_function == "Loader"

    def test_parser_absent_returns_none(self, monkeypatch):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        assert swift_handlers("class C {}", "C.swift") is None


@requires_ts("swift")
class TestSwiftFunctionThrows:
    THROWS_SRC = (
        "class V {\n"
        "    func checkValidity(_ c: Chain) throws "
        "{ throw CertificateError.expired }\n"
        "    func typedThrows() throws(ParseError) { }\n"
        "    func quiet() -> Int { return 1 }\n"
        "}\n"
    )

    def test_body_throw_resolved(self):
        assert swift_function_throws(
            self.THROWS_SRC, "checkValidity",
        ) == ["CertificateError"]

    def test_typed_throws_clause_resolved(self):
        # Swift 6 typed throws: the clause names the thrown type.
        assert swift_function_throws(
            self.THROWS_SRC, "typedThrows",
        ) == ["ParseError"]

    def test_declares_throws(self):
        assert swift_function_declares_throws(
            self.THROWS_SRC, "checkValidity")
        assert swift_function_declares_throws(
            self.THROWS_SRC, "typedThrows")
        assert not swift_function_declares_throws(
            self.THROWS_SRC, "quiet")

    def test_segment_includes_class_header(self):
        seg = swift_method_segment(self.THROWS_SRC, "checkValidity")
        assert seg.startswith("class V")
        assert "func checkValidity" in seg

    def test_plain_try_witness_distinguishes_try_variants(self):
        # `try` is required at exactly the call sites that can throw
        # — compiler-verified fallibility. `try?`/`try!` never reach
        # a catch block, so only bare `try` counts as the witness.
        src = (
            "class C {\n"
            "    func f() {\n"
            "        do { try check() } catch { }\n"
            "        do { try? probe() } catch { }\n"
            "    }\n"
            "}\n"
        )
        by_line = {
            h.line: h for h in swift_handlers(src, "C.swift")
        }
        assert swift_do_has_plain_try(src, by_line[3].try_span)
        assert not swift_do_has_plain_try(src, by_line[4].try_span)

    def test_plain_try_inside_nested_closure_is_not_a_witness(self):
        # A `try` inside a closure DEFINED within the do block never
        # reaches the enclosing catch — it propagates to the
        # closure's own caller — so it must not serve as the do
        # block's fallibility witness. The direct spelling in the
        # second do block still does.
        src = (
            "class C {\n"
            "    func f() {\n"
            "        do {\n"
            "            let job = { try check() }\n"
            "            run(job)\n"
            "        } catch { }\n"
            "        do {\n"
            "            try check()\n"
            "        } catch { }\n"
            "    }\n"
            "}\n"
        )
        by_line = {
            h.line: h for h in swift_handlers(src, "C.swift")
        }
        assert not swift_do_has_plain_try(src, by_line[6].try_span)
        assert swift_do_has_plain_try(src, by_line[9].try_span)


@requires_ts("swift")
class TestSwiftErasureSites:
    ERASURE_SRC = (
        "class C {\n"
        "    func erasures() {\n"
        "        _ = try? validate(tok)\n"
        "        try? validate(tok)\n"
        "        let unread = try? validate(tok)\n"
        "        let read = try? validate(tok)\n"
        "        let merged = (try? validate(tok)) ?? fallback\n"
        "        guard let g = try? validate(tok) else { return }\n"
        "        if let z = try? validate(tok) { use(z) }\n"
        "        let forced = try! validate(tok)\n"
        "        consume(try? validate(tok))\n"
        "        use(read)\n"
        "    }\n"
        "    func propagates() throws {\n"
        "        try validate(tok)\n"
        "    }\n"
        "}\n"
    )

    def _by_line(self):
        sites = swift_erasure_sites(
            self.ERASURE_SRC, "C.swift", "validate",
        )
        assert sites is not None
        return {s.line: s for s in sites}

    def test_underscore_discard_unguarded(self):
        s = self._by_line()[3]
        assert s.verdict == "unguarded"
        assert s.shape == "underscore-discard"

    def test_bare_statement_unguarded(self):
        s = self._by_line()[4]
        assert s.verdict == "unguarded"
        assert s.shape == "bare-statement"

    def test_never_read_binding_unguarded(self):
        s = self._by_line()[5]
        assert s.verdict == "unguarded"
        assert s.shape == "result-never-checked"

    def test_read_binding_guarded(self):
        s = self._by_line()[6]
        assert s.verdict == "guarded"
        assert s.shape == "captured"

    def test_nil_coalescing_erases_error(self):
        s = self._by_line()[7]
        assert s.verdict == "unguarded"
        assert s.shape == "??-erases-error"

    def test_guard_let_and_if_let_guarded(self):
        by_line = self._by_line()
        assert by_line[8].verdict == "guarded"
        assert by_line[8].shape == "tested"
        assert by_line[9].verdict == "guarded"
        assert by_line[9].shape == "tested"

    def test_try_bang_traps_fail_closed(self):
        s = self._by_line()[10]
        assert s.verdict == "guarded"
        assert s.shape == "try!-traps-on-error"

    def test_consumed_as_argument_guarded(self):
        s = self._by_line()[11]
        assert s.verdict == "guarded"
        assert s.shape == "consumed-as-argument"

    def test_plain_try_propagates_guarded(self):
        s = self._by_line()[15]
        assert s.verdict == "guarded"
        assert s.shape == "propagated"

    def test_parser_absent_returns_none(self, monkeypatch):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        assert swift_erasure_sites("class C {}", "C.swift",
                                   "validate") is None

    def test_underscore_prefixed_binding_is_not_a_discard(self):
        # Swift has no underscore-PREFIX convention: only the exact
        # wildcard `_` is a discard. `_verified` is an ordinary
        # binding — consumed on the next line, it is a guarded site;
        # never read, it is result-never-checked (not
        # underscore-discard).
        src = (
            "class C {\n"
            "    func checked() -> Bool {\n"
            "        let _verified = try? validate(tok)\n"
            "        return _verified != nil\n"
            "    }\n"
            "    func unchecked() {\n"
            "        let _ignored = try? validate(tok)\n"
            "    }\n"
            "}\n"
        )
        sites = swift_erasure_sites(src, "C.swift", "validate")
        assert sites is not None
        by_line = {s.line: s for s in sites}
        assert by_line[3].verdict == "guarded"
        assert by_line[3].shape == "captured"
        assert by_line[7].verdict == "unguarded"
        assert by_line[7].shape == "result-never-checked"

    def test_switch_scrutinee_is_guarded(self):
        # `switch try? f()` scrutinises the optional and Swift
        # switches are exhaustive — the nil branch must be covered by
        # a case, the same claim a binding condition earns. A bare
        # `try?` inside a case BODY is still its own unguarded site.
        src = (
            "class C {\n"
            "    func route(_ tok: Token) -> Bool {\n"
            "        switch try? validate(tok) {\n"
            "        case .some(let ok):\n"
            "            return ok\n"
            "        case .none:\n"
            "            _ = try? validate(tok)\n"
            "            return false\n"
            "        }\n"
            "    }\n"
            "}\n"
        )
        sites = swift_erasure_sites(src, "C.swift", "validate")
        assert sites is not None
        by_line = {s.line: s for s in sites}
        assert by_line[3].verdict == "guarded"
        assert by_line[3].shape == "tested"
        assert by_line[7].verdict == "unguarded"
        assert by_line[7].shape == "underscore-discard"


@requires_ts("swift")
class TestVerdictsSwift:
    TRUST_VULN = (
        "class ChainValidator {\n"
        "    func validate(_ chain: Chain) -> Bool {\n"
        "        do { try checkValidity(chain) } "
        "catch let e as CertificateError "
        "{ log.debug(\"cert check failed \\(e)\") }\n"
        "        return true\n"
        "    }\n"
        "    func checkValidity(_ c: Chain) throws "
        "{ throw CertificateError.expired }\n"
        "}\n"
    )
    HYP_TRUST = (
        "certificate validation fails open: the CertificateError "
        "is swallowed with a debug log and the method returns true"
    )

    def test_trust_manager_quiet_log_confirms(self, tmp_path):
        _write(tmp_path, "src/ChainValidator.swift", self.TRUST_VULN)
        res = run_fail_open_check(
            tmp_path, "src/ChainValidator.swift", "validate",
            self.HYP_TRUST,
        )
        assert res.outcome == "confirmed"
        assert res.language == "swift"
        assert res.rule_id.startswith(RULE_HANDLER_OUTCOME)
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "quiet_log_only"
        # Swallowed declared error: the callee's body throws the very
        # type the handler catches.
        assert res.fallible is not None
        assert res.fallible["evidence"] == "throws-caught-type"
        assert "CertificateError" in res.fallible["types"]

    def test_rethrow_twin_refutes(self, tmp_path):
        safe = self.TRUST_VULN.replace(
            "{ log.debug(\"cert check failed \\(e)\") }",
            "{ throw e }",
        )
        assert safe != self.TRUST_VULN
        _write(tmp_path, "src/ChainValidator.swift", safe)
        res = run_fail_open_check(
            tmp_path, "src/ChainValidator.swift", "validate",
            self.HYP_TRUST,
        )
        assert res.outcome == "refuted"
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "fail_closed"

    def test_plain_try_is_compiler_verified_fallibility(self, tmp_path):
        # The callee resolves nowhere in the file, but the `try`
        # marker under a broad catch is the compiler's own witness
        # that the call can throw.
        src = (
            "class Gate {\n"
            "    func handle(_ req: Request) {\n"
            "        do { try verifyToken(req) } catch { }\n"
            "        proceed(req)\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/Gate.swift", src)
        res = run_fail_open_check(
            tmp_path, "src/Gate.swift", "handle",
            "token verification failure is swallowed by the broad "
            "catch and the request proceeds",
        )
        assert res.outcome == "confirmed"
        assert res.fallible is not None
        assert res.fallible["evidence"] == "try-marked-call"

    def test_broad_catch_without_try_falls_to_catchable(self, tmp_path):
        src = (
            "class Gate {\n"
            "    func handle(_ req: Request) {\n"
            "        do { verifyToken(req) } catch { }\n"
            "        proceed(req)\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/Gate.swift", src)
        res = run_fail_open_check(
            tmp_path, "src/Gate.swift", "handle",
            "token verification failure is swallowed by the broad "
            "catch and the request proceeds",
        )
        assert res.outcome == "confirmed"
        assert res.fallible is not None
        assert res.fallible["evidence"].startswith("catchable:")

    def test_specific_catch_without_evidence_is_fallibility_unresolved(
        self, tmp_path,
    ):
        # A specific catch of a type nothing in the file throws, and
        # no plain-`try` witness applicability (the witness proves
        # throwability, not the caught type) — unresolved, never a
        # guess.
        src = (
            "class Gate {\n"
            "    func handle(_ req: Request) {\n"
            "        do { verifyToken(req) } "
            "catch is AccessDeniedError { }\n"
            "        proceed(req)\n"
            "    }\n"
            "}\n"
        )
        _write(tmp_path, "src/Gate.swift", src)
        res = run_fail_open_check(
            tmp_path, "src/Gate.swift", "handle",
            "token verification failure is swallowed and the request "
            "proceeds",
        )
        assert res.outcome == "inconclusive"
        assert REASON_FALLIBILITY_UNRESOLVED in res.reason

    def test_erasure_leg_confirms_discarded_try_optional(self, tmp_path):
        src = (
            "class TokenGate {\n"
            "    func admit(_ tok: Token) -> Bool {\n"
            "        _ = try? validateToken(tok)\n"
            "        return true\n"
            "    }\n"
            "    func validateToken(_ t: Token) throws { }\n"
            "}\n"
        )
        _write(tmp_path, "src/TokenGate.swift", src)
        res = run_fail_open_check(
            tmp_path, "src/TokenGate.swift", "admit",
            "the result of `validateToken` is ignored — the error "
            "branch is discarded and control proceeds as if the "
            "token were valid",
        )
        assert res.outcome == "confirmed"
        assert res.rule_id.startswith(RULE_IGNORED_RETURN)
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "try_erasure"
        assert res.fallible is not None
        assert res.fallible["evidence"].startswith("declared-throws")
        assert res.sites

    def test_erasure_plain_try_twin_refutes(self, tmp_path):
        src = (
            "class TokenGate {\n"
            "    func admit(_ tok: Token) throws -> Bool {\n"
            "        try validateToken(tok)\n"
            "        return true\n"
            "    }\n"
            "    func validateToken(_ t: Token) throws { }\n"
            "}\n"
        )
        _write(tmp_path, "src/TokenGate.swift", src)
        res = run_fail_open_check(
            tmp_path, "src/TokenGate.swift", "admit",
            "the result of `validateToken` is ignored — the error "
            "branch is discarded and control proceeds as if the "
            "token were valid",
        )
        assert res.outcome == "refuted"
        assert res.rule_id == RULE_IGNORED_RETURN

    def test_mechanism_gate_routes_to_erasure_leg(self, tmp_path):
        # Where the java/kotlin/csharp legs abstain (fail-closed
        # handlers cannot refute an ignored-return hypothesis), Swift
        # HAS an adjudicator for that mechanism — the dual-leg
        # routing hands the hypothesis to the erasure leg instead.
        src = (
            "class TokenGate {\n"
            "    func admit(_ tok: Token) -> Bool {\n"
            "        do { try audit(tok) } catch { return false }\n"
            "        _ = try? validateToken(tok)\n"
            "        return true\n"
            "    }\n"
            "    func validateToken(_ t: Token) throws { }\n"
            "    func audit(_ t: Token) throws { }\n"
            "}\n"
        )
        _write(tmp_path, "src/TokenGate.swift", src)
        res = run_fail_open_check(
            tmp_path, "src/TokenGate.swift", "admit",
            "the result of `validateToken` is ignored — the error "
            "branch is discarded and control proceeds as if the "
            "token were valid",
        )
        assert res.outcome == "confirmed"
        assert res.rule_id.startswith(RULE_IGNORED_RETURN)
        assert res.handler is not None
        assert res.handler["outcome_kind"] == "try_erasure"

    def test_underscore_prefixed_consumed_binding_refutes(
        self, tmp_path,
    ):
        # `let _verified = try? …` followed by a nil test is a guarded
        # site — a `_`-prefixed name is a consumed binding, not a
        # discard, so the leg must refute rather than confirm.
        src = (
            "class TokenGate {\n"
            "    func admit(_ tok: Token) -> Bool {\n"
            "        let _verified = try? validateToken(tok)\n"
            "        if _verified != nil {\n"
            "            return true\n"
            "        }\n"
            "        return false\n"
            "    }\n"
            "    func validateToken(_ t: Token) throws { }\n"
            "}\n"
        )
        _write(tmp_path, "src/TokenGate.swift", src)
        res = run_fail_open_check(
            tmp_path, "src/TokenGate.swift", "admit",
            "the result of `validateToken` is ignored — the error "
            "branch is discarded and control proceeds as if the "
            "token were valid",
        )
        assert res.outcome == "refuted"

    def test_erasure_fallibility_needs_a_receipt(self, tmp_path):
        # The `try?` marker alone must NOT double as its own
        # fallibility witness: with no same-file `throws`
        # declaration, no inventory signature and no learned
        # contract, the erasure leg abstains with
        # fallibility-unresolved instead of minting a confirmation
        # from the marker.
        _write(tmp_path, "src/Gate.swift",
               "class Gate {\n"
               "    func admit(_ tok: Token) -> Bool {\n"
               "        _ = try? validateToken(tok)\n"
               "        return true\n"
               "    }\n"
               "}\n")
        res = run_fail_open_check(
            tmp_path, "src/Gate.swift", "admit",
            "the result of `validateToken` is ignored — the error "
            "branch is discarded and control proceeds as if the "
            "token were valid",
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_FALLIBILITY_UNRESOLVED)

    def test_erasure_undecided_site_blocks_refutation(self, tmp_path):
        # An undecided site (a call of the callee carrying no try
        # marker — not this leg's to adjudicate) must block the
        # all-sites-fail-closed refutation: the honest outcome is
        # handler-undecided inconclusive, not a refutation receipt.
        _write(tmp_path, "src/Gate.swift",
               "class Gate {\n"
               "    func admit(_ tok: Token) -> Bool {\n"
               "        if let ok = try? validateToken(tok) "
               "{ return ok }\n"
               "        validateToken(tok)\n"
               "        return false\n"
               "    }\n"
               "    func validateToken(_ t: Token) throws -> Bool "
               "{ return true }\n"
               "}\n")
        res = run_fail_open_check(
            tmp_path, "src/Gate.swift", "admit",
            "the result of `validateToken` is ignored — the error "
            "branch is discarded and control proceeds as if the "
            "token were valid",
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_HANDLER_UNDECIDED)

    def test_erasure_scan_stays_inside_the_function_span(
        self, tmp_path,
    ):
        # The erasure leg adjudicates the NAMED function only: an
        # unguarded `try?` site of the same callee in a DIFFERENT
        # function must not confirm (or pollute the receipts of) a
        # function whose own sites are all guarded.
        _write(tmp_path, "src/Gate.swift",
               "class Gate {\n"
               "    func admit(_ tok: Token) -> Bool {\n"
               "        if let ok = try? validateToken(tok) "
               "{ return ok }\n"
               "        return false\n"
               "    }\n"
               "    func telemetry(_ tok: Token) {\n"
               "        _ = try? validateToken(tok)\n"
               "    }\n"
               "    func validateToken(_ t: Token) throws -> Bool "
               "{ return true }\n"
               "}\n")
        res = run_fail_open_check(
            tmp_path, "src/Gate.swift", "admit",
            "the result of `validateToken` is ignored — the error "
            "branch is discarded and control proceeds as if the "
            "token were valid",
        )
        # admit's only site is guarded; telemetry's unguarded site is
        # not admit's evidence.
        assert res.outcome == "refuted"
        assert res.sites and all(2 <= s.line <= 5 for s in res.sites), (
            "receipt cites a line outside admit's span"
        )

    def test_switch_scrutinee_twin_refutes(self, tmp_path):
        # The idiomatic switch-over-optional consumption: exhaustive
        # cases cover the nil branch, so the only site is guarded and
        # the leg refutes.
        src = (
            "class TokenGate {\n"
            "    func admit(_ tok: Token) -> Bool {\n"
            "        switch try? validateToken(tok) {\n"
            "        case .some(let ok):\n"
            "            return ok\n"
            "        case .none:\n"
            "            return false\n"
            "        }\n"
            "    }\n"
            "    func validateToken(_ t: Token) throws -> Bool "
            "{ return true }\n"
            "}\n"
        )
        _write(tmp_path, "src/TokenGate.swift", src)
        res = run_fail_open_check(
            tmp_path, "src/TokenGate.swift", "admit",
            "the result of `validateToken` is ignored — the error "
            "branch is discarded and control proceeds as if the "
            "token were valid",
        )
        assert res.outcome == "refuted"

    def test_no_catch_and_no_named_call_is_unbindable(self, tmp_path):
        src = (
            "class C {\n"
            "    func f(_ x: Int) -> Int { return x + 1 }\n"
            "}\n"
        )
        _write(tmp_path, "src/C.swift", src)
        res = run_fail_open_check(
            tmp_path, "src/C.swift", "f",
            "auth check failure swallowed silently",
        )
        assert res.outcome == "inconclusive"
        assert REASON_HYPOTHESIS_UNBINDABLE in res.reason


@requires_ts("swift")
class TestSwiftCensus:
    def test_census_seeds_swift_lead(self):
        src = (
            "class Gate {\n"
            "    func handle(_ req: Request) {\n"
            "        do { try verifyToken(req) } catch { }\n"
            "        proceed(req)\n"
            "    }\n"
            "}\n"
        )
        out = run_fail_open_census({"src/Gate.swift": src})
        leads = out["leads"]
        assert leads, out["telemetry"]
        lead = leads[0]
        assert lead["function"] == "handle"
        assert lead["outcome_kind"] == "pass"
        assert lead["broad"] is True
        assert out["telemetry"]["by_language"].get("swift") == 1


class TestSwiftDegradation:
    """Parser-absent honesty (hermetic — no grammar needed)."""

    def test_language_unsupported_when_parser_absent(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        _write(tmp_path, "src/C.swift", "class C {}")
        res = run_fail_open_check(
            tmp_path, "src/C.swift", "f",
            "auth check failure swallowed silently",
        )
        assert res.outcome == "inconclusive"
        assert REASON_LANGUAGE_UNSUPPORTED in res.reason

    def test_swift_in_supported_and_census_languages(self):
        # The handler leg joins the census sweep (the Java shape);
        # the try?-erasure census stays with the consistency
        # programme, like Rust's ignored-Result census.
        assert "swift" in SUPPORTED_LANGUAGES
        assert "swift" in CENSUS_LANGUAGES


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
