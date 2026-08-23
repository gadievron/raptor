"""Fail-open channel, phase-3 Rust leg.

Ignored-``Result`` site classification on the rust grammar — Rust's
idiom table differs from Go's: ``unwrap``/``expect``/``?`` consume the
Result *fail-closed* (panic or propagate), while ``let _ =``, bare
statements, dropped ``.ok()`` and ``unwrap_or_default()`` erase the
error branch. Plus dispatch through ``run_fail_open_check`` and the
parser-absent degradation contract. Hermetic — fixtures in-test.

Fixtures deliberately hardcode target-like names
(``verify_signature``) — they *simulate targets*, so the vocabulary
policy does not apply to them.
"""

from __future__ import annotations

import json

import pytest

from core.audit.fail_open_census import CENSUS_LANGUAGES
from core.audit.fail_open_lang import (
    SUPPORTED_LANGUAGES,
    rust_discard_sites,
    rust_function_returns_result,
    rust_function_span,
)
from core.audit.fail_open_verify import (
    REASON_FALLIBILITY_UNRESOLVED,
    REASON_HYPOTHESIS_UNBINDABLE,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_ROLE_UNBOUND,
    REASON_SPAN_UNRESOLVED,
    RULE_IGNORED_RETURN,
    run_fail_open_check,
)
from core.testing import requires_ts


def _write(tmp_path, rel, text):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


SIG_RS = """
fn verify_signature(b: &[u8]) -> Result<(), SigError> {
    check(b)
}

fn handle(req: Request) {
    let _ = verify_signature(&req.body);
    process(req);
}
"""



@requires_ts("rust")
class TestRustDiscardSites:
    def test_let_underscore_is_unguarded(self):
        sites = rust_discard_sites(SIG_RS, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "unguarded"
        assert sites[0].shape == "let-underscore-discard"
        assert "let _ =" in sites[0].evidence

    def test_underscore_prefixed_binding_is_unguarded(self):
        src = SIG_RS.replace("let _ =", "let _unused =")
        sites = rust_discard_sites(src, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "unguarded"
        assert sites[0].shape == "let-underscore-discard"

    def test_bare_statement_is_unguarded(self):
        src = SIG_RS.replace("let _ = verify_signature(&req.body);",
                             "verify_signature(&req.body);")
        sites = rust_discard_sites(src, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "unguarded"
        assert sites[0].shape == "bare-statement"

    def test_ok_dropped_is_unguarded(self):
        src = SIG_RS.replace("let _ = verify_signature(&req.body);",
                             "verify_signature(&req.body).ok();")
        sites = rust_discard_sites(src, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "unguarded"
        assert sites[0].shape == "ok-discarded"

    def test_unwrap_or_default_is_unguarded(self):
        src = SIG_RS.replace(
            "let _ = verify_signature(&req.body);",
            "let v = verify_signature(&req.body).unwrap_or_default();",
        )
        sites = rust_discard_sites(src, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "unguarded"
        assert sites[0].shape == ".unwrap_or_default()-erases-error"

    def test_unwrap_is_guarded_fail_closed(self):
        # Rust idiom split from Go: unwrap PANICS on the error branch
        # — the error cannot silently pass, so the site refutes.
        src = SIG_RS.replace(
            "let _ = verify_signature(&req.body);",
            "verify_signature(&req.body).unwrap();",
        )
        sites = rust_discard_sites(src, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "guarded"
        assert "panics" in sites[0].shape

    def test_question_mark_is_guarded(self):
        src = SIG_RS.replace(
            "fn handle(req: Request) {\n"
            "    let _ = verify_signature(&req.body);",
            "fn handle(req: Request) -> Result<(), SigError> {\n"
            "    verify_signature(&req.body)?;",
        )
        sites = rust_discard_sites(src, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "guarded"
        assert sites[0].shape == "propagated"

    def test_match_is_guarded(self):
        src = SIG_RS.replace(
            "let _ = verify_signature(&req.body);",
            "match verify_signature(&req.body) "
            "{ Ok(_) => {}, Err(_) => return }",
        )
        sites = rust_discard_sites(src, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "guarded"
        assert sites[0].shape == "tested"

    def test_is_ok_condition_is_guarded(self):
        src = SIG_RS.replace(
            "let _ = verify_signature(&req.body);",
            "if verify_signature(&req.body).is_ok() { process2(); }",
        )
        sites = rust_discard_sites(src, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "guarded"

    def test_bound_and_read_is_guarded(self):
        src = SIG_RS.replace(
            "let _ = verify_signature(&req.body);\n    process(req);",
            "let r = verify_signature(&req.body);\n"
            "    if r.is_err() { return; }\n    process(req);",
        )
        sites = rust_discard_sites(src, "m.rs", "verify_signature")
        assert sites and sites[0].verdict == "guarded"
        assert sites[0].shape == "captured"

    def test_bound_never_read_is_unguarded(self):
        src = SIG_RS.replace("let _ =", "let outcome =")
        sites = rust_discard_sites(src, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "unguarded"
        assert sites[0].shape == "result-never-checked"

    def test_ok_then_consumed_is_guarded(self):
        src = SIG_RS.replace(
            "let _ = verify_signature(&req.body);",
            "if let Some(v) = verify_signature(&req.body).ok() "
            "{ use_it(v); }",
        )
        sites = rust_discard_sites(src, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "guarded"

    def test_trailing_expression_is_guarded(self):
        sites = rust_discard_sites(SIG_RS, "m.rs", "check",
                                   function_span=(2, 4))
        assert sites and sites[0].verdict == "guarded"
        assert sites[0].shape == "propagated"

    def test_scoped_path_callee_matches(self):
        src = SIG_RS.replace("verify_signature(&req.body)",
                             "sig::verify_signature(&req.body)")
        sites = rust_discard_sites(src, "m.rs", "verify_signature",
                                   function_span=(6, 9))
        assert sites and sites[0].verdict == "unguarded"

    def test_parser_absent_returns_none(self, monkeypatch):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        assert rust_discard_sites(SIG_RS, "m.rs",
                                  "verify_signature") is None


@requires_ts("rust")
class TestRustSignatures:
    def test_returns_result_same_file(self):
        assert rust_function_returns_result(SIG_RS, "verify_signature")

    def test_non_result_function(self):
        assert not rust_function_returns_result(SIG_RS, "handle")

    def test_span(self):
        span = rust_function_span(SIG_RS, "handle")
        assert span == (6, 9)

    def test_regex_fallback_signature_only(self, monkeypatch):
        # Signature shapes have an honest line-regex tier (mirrors the
        # Go leg); handler/site classification does not.
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        assert rust_function_returns_result(SIG_RS, "verify_signature")
        assert rust_function_span(SIG_RS, "handle") is None


@requires_ts("rust")
class TestRustChannelDispatch:
    HYPOTHESIS = (
        "the `verify_signature` Result is discarded with let _ = — "
        "the error is ignored and processing fails open"
    )

    def test_let_underscore_confirmed(self, tmp_path):
        _write(tmp_path, "sig.rs", SIG_RS)
        res = run_fail_open_check(
            tmp_path, "sig.rs", "handle", self.HYPOTHESIS,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id.startswith(RULE_IGNORED_RETURN)
        assert res.language == "rust"
        assert res.fallible["evidence"].startswith("returns-result")
        assert res.handler["permissive_value"] == "let-underscore-discard"

    def test_all_guarded_refutes(self, tmp_path):
        src = SIG_RS.replace(
            "fn handle(req: Request) {\n"
            "    let _ = verify_signature(&req.body);",
            "fn handle(req: Request) -> Result<(), SigError> {\n"
            "    verify_signature(&req.body)?;",
        )
        _write(tmp_path, "sig.rs", src)
        res = run_fail_open_check(
            tmp_path, "sig.rs", "handle", self.HYPOTHESIS,
        )
        assert res.outcome == "refuted"
        assert res.sites and all(
            s.verdict == "guarded" for s in res.sites)

    def test_fallibility_unresolved_without_signature(self, tmp_path):
        src = SIG_RS.replace(
            "fn verify_signature(b: &[u8]) -> Result<(), SigError> {\n"
            "    check(b)\n}",
            "",
        )
        _write(tmp_path, "sig.rs", src)
        res = run_fail_open_check(
            tmp_path, "sig.rs", "handle", self.HYPOTHESIS,
        )
        assert res.outcome == "inconclusive"
        assert REASON_FALLIBILITY_UNRESOLVED in res.reason

    def test_inventory_signature_fallibility(self, tmp_path):
        src = SIG_RS.replace(
            "fn verify_signature(b: &[u8]) -> Result<(), SigError> {\n"
            "    check(b)\n}",
            "",
        )
        _write(tmp_path, "sig.rs", src)
        inventory = {"files": [{"path": "other.rs", "items": [{
            "name": "verify_signature",
            "signature": "fn verify_signature(b: &[u8]) "
                         "-> Result<(), SigError>",
        }]}]}
        res = run_fail_open_check(
            tmp_path, "sig.rs", "handle", self.HYPOTHESIS,
            inventory=inventory,
        )
        assert res.outcome == "confirmed"
        assert "inventory signature" in res.fallible["evidence"]

    def test_span_unresolved_refuses_whole_file(self, tmp_path):
        _write(tmp_path, "sig.rs", SIG_RS)
        res = run_fail_open_check(
            tmp_path, "sig.rs", "nonexistent_fn", self.HYPOTHESIS,
        )
        assert res.outcome == "inconclusive"
        assert REASON_SPAN_UNRESOLVED in res.reason

    def test_hypothesis_unbindable_without_named_call(self, tmp_path):
        _write(tmp_path, "sig.rs", SIG_RS)
        res = run_fail_open_check(
            tmp_path, "sig.rs", "handle",
            "the Result of `frobnicate` is ignored and errors are "
            "discarded — fails open",
        )
        assert res.outcome == "inconclusive"
        assert REASON_HYPOTHESIS_UNBINDABLE in res.reason

    def test_role_unbound_without_vocabulary(self, tmp_path):
        src = SIG_RS.replace("verify_signature", "shuffle_bytes")
        _write(tmp_path, "sig.rs", src)
        res = run_fail_open_check(
            tmp_path, "sig.rs", "handle",
            "the `shuffle_bytes` Result is discarded with let _ = — "
            "the error is ignored, fails open",
        )
        assert res.outcome == "inconclusive"
        assert REASON_ROLE_UNBOUND in res.reason

    def test_learned_spec_binds_registry_grade(self, tmp_path):
        src = SIG_RS.replace("verify_signature", "shuffle_bytes")
        _write(tmp_path, "sig.rs", src)
        out = tmp_path / "out"
        out.mkdir()
        (out / "iris-taint-specs.json").write_text(json.dumps([{
            "function": "shuffle_bytes",
            "file": "",
            "role": "sanitiser",
            "evidence_tier": "xref_backed",
        }]))
        from core.audit.fail_open_roles import RoleContext
        res = run_fail_open_check(
            tmp_path, "sig.rs", "handle",
            "the `shuffle_bytes` Result is discarded with let _ = — "
            "the error is ignored, fails open",
            role_context=RoleContext(out_dir=out),
        )
        assert res.outcome == "confirmed"
        # Registry-grade learned role: plain rule id, promote-capable.
        assert res.rule_id == RULE_IGNORED_RETURN


class TestRustDegradation:
    """Parser-absent honesty (hermetic — no grammar needed)."""

    def test_language_unsupported_when_parser_absent(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        _write(tmp_path, "sig.rs", SIG_RS)
        res = run_fail_open_check(
            tmp_path, "sig.rs", "handle",
            "the `verify_signature` Result is discarded — fails open",
        )
        assert res.outcome == "inconclusive"
        assert REASON_LANGUAGE_UNSUPPORTED in res.reason

    def test_rust_in_supported_but_not_census_languages(self):
        # The handler-outcome census has no Rust shape; the ignored-
        # Result census is the consistency programme's (premise split).
        assert "rust" in SUPPORTED_LANGUAGES
        assert "rust" not in CENSUS_LANGUAGES


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
