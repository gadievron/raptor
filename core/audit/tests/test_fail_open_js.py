"""Fail-open channel, phase-3 JS/TS leg.

Handler-outcome classification on the javascript/typescript grammars
(catch clauses + promise ``.catch`` swallows), the unawaited /
floating-promise call-site leg, dispatch through
``run_fail_open_check``, the census extension, and the
parser-absent degradation contract (``language-unsupported``, never a
guess). Hermetic — fixtures in-test, no LLM, no subprocesses.

Fixtures deliberately hardcode target-like names (``verifyToken``,
``checkPermission``) — they *simulate targets*, so the vocabulary
policy does not apply to them.
"""

from __future__ import annotations

import pytest

from core.audit.fail_open_census import CENSUS_LANGUAGES, run_fail_open_census
from core.audit.fail_open_lang import (
    JS_LANGUAGES,
    SUPPORTED_LANGUAGES,
    js_function_returns_promise,
    js_function_span,
    js_function_throws,
    js_handlers,
    js_unawaited_sites,
)
from core.audit.fail_open_verify import (
    REASON_ASYNC_UNPROVABLE,
    REASON_HYPOTHESIS_UNBINDABLE,
    REASON_LANGUAGE_UNSUPPORTED,
    REASON_ROLE_UNBOUND,
    RULE_HANDLER_OUTCOME,
    RULE_UNAWAITED,
    run_fail_open_check,
)
from core.testing import requires_ts


def _write(tmp_path, rel, text):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    return p


AUTH_JS = """
function verifyToken(tok) {
  if (!tok) throw new AuthError("no token");
  return true;
}
function login(req, res, next) {
  try {
    verifyToken(req.token);
  } catch (e) {
  }
  next();
}
"""

PROMISE_JS = """
async function checkPermission(req) {
  if (!req.user) throw new Error("denied");
}
function gate(req, res, next) {
  checkPermission(req).catch(() => {});
  next();
}
"""

UNAWAITED_JS = """
async function validateBody(req) {
  if (!req.body) throw new Error("invalid");
}
function handle(req, res, next) {
  validateBody(req);
  next();
}
"""


@requires_ts("javascript")
class TestJsHandlers:
    def test_empty_catch_is_pass(self):
        handlers = js_handlers(AUTH_JS, "auth.js")
        catches = [h for h in handlers if h.idiom.startswith("catch_")]
        assert catches and catches[0].outcome_kind == "pass"
        assert catches[0].broad          # JS catch has no type filter
        assert catches[0].caught == ["<any>"]
        assert catches[0].enclosing_function == "login"
        assert "verifyToken" in catches[0].try_calls

    def test_promise_catch_empty_arrow_is_pass(self):
        handlers = js_handlers(PROMISE_JS, "mw.js")
        promise = [h for h in handlers
                   if h.idiom.startswith("promise_catch")]
        assert promise and promise[0].outcome_kind == "pass"
        assert "checkPermission" in promise[0].try_calls

    def test_rethrow_is_fail_closed(self):
        src = AUTH_JS.replace(
            "  } catch (e) {\n  }",
            "  } catch (e) {\n    throw e;\n  }",
        )
        handlers = js_handlers(src, "auth.js")
        catches = [h for h in handlers if h.idiom.startswith("catch_")]
        assert catches and catches[0].is_fail_closed
        assert catches[0].permissive_value == "re-throws"

    def test_restrictive_return_is_fail_closed(self):
        src = AUTH_JS.replace(
            "  } catch (e) {\n  }",
            "  } catch (e) {\n    return false;\n  }",
        )
        handlers = js_handlers(src, "auth.js")
        catches = [h for h in handlers if h.idiom.startswith("catch_")]
        assert catches and catches[0].is_fail_closed

    def test_return_true_is_permissive(self):
        src = AUTH_JS.replace(
            "  } catch (e) {\n  }",
            "  } catch (e) {\n    return true;\n  }",
        )
        handlers = js_handlers(src, "auth.js")
        catches = [h for h in handlers if h.idiom.startswith("catch_")]
        assert catches and catches[0].outcome_kind == "return_permissive"

    def test_loud_log_is_undecided(self):
        src = AUTH_JS.replace(
            "  } catch (e) {\n  }",
            "  } catch (e) {\n    logger.error(e);\n  }",
        )
        handlers = js_handlers(src, "auth.js")
        catches = [h for h in handlers if h.idiom.startswith("catch_")]
        assert catches
        assert catches[0].outcome_kind == "fallback_action"
        assert catches[0].permissive_value == "loud-log-and-continue"

    def test_quiet_log_only_is_permissive(self):
        src = AUTH_JS.replace(
            "  } catch (e) {\n  }",
            "  } catch (e) {\n    console.debug(e);\n  }",
        )
        handlers = js_handlers(src, "auth.js")
        catches = [h for h in handlers if h.idiom.startswith("catch_")]
        assert catches and catches[0].outcome_kind == "quiet_log_only"
        assert catches[0].is_permissive

    def test_nested_function_throw_does_not_fail_close(self):
        src = AUTH_JS.replace(
            "  } catch (e) {\n  }",
            "  } catch (e) {\n"
            "    setHandler(() => { throw e; });\n  }",
        )
        handlers = js_handlers(src, "auth.js")
        catches = [h for h in handlers if h.idiom.startswith("catch_")]
        assert catches and not catches[0].is_fail_closed

    def test_arrow_expression_body_literal_default(self):
        src = PROMISE_JS.replace(
            ".catch(() => {})", ".catch(() => null)",
        )
        handlers = js_handlers(src, "mw.js")
        promise = [h for h in handlers
                   if h.idiom.startswith("promise_catch")]
        assert promise and promise[0].is_fail_closed  # resolves to null

    def test_function_throws_and_async_witnesses(self):
        assert js_function_throws(AUTH_JS, "verifyToken") == ["AuthError"]
        assert js_function_returns_promise(PROMISE_JS, "checkPermission")
        assert not js_function_returns_promise(AUTH_JS, "verifyToken")

    def test_function_span(self):
        span = js_function_span(AUTH_JS, "login")
        assert span is not None and span[0] < span[1]

    def test_parser_absent_returns_none(self, monkeypatch):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        assert js_handlers(AUTH_JS, "auth.js") is None
        assert js_unawaited_sites(UNAWAITED_JS, "u.js",
                                  "validateBody") is None


@requires_ts("javascript")
class TestJsUnawaitedSites:
    def test_floating_promise_is_unguarded(self):
        sites = js_unawaited_sites(UNAWAITED_JS, "u.js", "validateBody")
        assert sites and sites[0].verdict == "unguarded"
        assert sites[0].shape == "floating-promise"

    def test_awaited_is_guarded(self):
        src = UNAWAITED_JS.replace(
            "  validateBody(req);", "  await validateBody(req);",
        )
        sites = js_unawaited_sites(src, "u.js", "validateBody")
        assert sites and sites[0].verdict == "guarded"
        assert sites[0].shape == "awaited"

    def test_catch_chained_is_guarded(self):
        src = UNAWAITED_JS.replace(
            "  validateBody(req);",
            "  validateBody(req).catch(next);",
        )
        sites = js_unawaited_sites(src, "u.js", "validateBody")
        assert sites and sites[0].verdict == "guarded"
        assert sites[0].shape == ".catch-chained"

    def test_finally_alone_stays_unguarded(self):
        src = UNAWAITED_JS.replace(
            "  validateBody(req);",
            "  validateBody(req).finally(cleanup);",
        )
        sites = js_unawaited_sites(src, "u.js", "validateBody")
        assert sites and sites[0].verdict == "unguarded"

    def test_void_discard_is_unguarded(self):
        src = UNAWAITED_JS.replace(
            "  validateBody(req);", "  void validateBody(req);",
        )
        sites = js_unawaited_sites(src, "u.js", "validateBody")
        assert sites and sites[0].verdict == "unguarded"
        assert sites[0].shape == "void-discard"

    def test_returned_is_guarded(self):
        src = UNAWAITED_JS.replace(
            "  validateBody(req);", "  return validateBody(req);",
        )
        sites = js_unawaited_sites(src, "u.js", "validateBody")
        assert sites and sites[0].verdict == "guarded"
        assert sites[0].shape == "propagated"

    def test_captured_binding_is_undecided(self):
        src = UNAWAITED_JS.replace(
            "  validateBody(req);", "  const p = validateBody(req);",
        )
        sites = js_unawaited_sites(src, "u.js", "validateBody")
        assert sites and sites[0].verdict == "undecided"

    def test_span_confines_sites(self):
        sites = js_unawaited_sites(
            UNAWAITED_JS, "u.js", "validateBody", function_span=(1, 3),
        )
        assert sites == []


@requires_ts("javascript")
class TestJsChannelDispatch:
    def test_catch_swallow_confirmed(self, tmp_path):
        _write(tmp_path, "auth.js", AUTH_JS)
        res = run_fail_open_check(
            tmp_path, "auth.js", "login",
            "the empty catch swallows the exception from "
            "`verifyToken` and login fails open",
        )
        assert res.outcome == "confirmed"
        assert res.rule_id.startswith(RULE_HANDLER_OUTCOME)
        assert res.language == "javascript"
        assert res.fallible and res.fallible["evidence"] == "throws"

    def test_promise_catch_swallow_confirmed(self, tmp_path):
        _write(tmp_path, "mw.js", PROMISE_JS)
        res = run_fail_open_check(
            tmp_path, "mw.js", "gate",
            "errors from checkPermission are swallowed by the empty "
            "catch handler and the request proceeds — fails open",
        )
        assert res.outcome == "confirmed"
        assert res.handler and res.handler["idiom"].startswith(
            "promise_catch")

    def test_fail_closed_handler_refutes(self, tmp_path):
        src = AUTH_JS.replace(
            "  } catch (e) {\n  }",
            "  } catch (e) {\n    throw e;\n  }",
        )
        _write(tmp_path, "auth.js", src)
        res = run_fail_open_check(
            tmp_path, "auth.js", "login",
            "the catch swallows the verifyToken exception, fails open",
        )
        assert res.outcome == "refuted"
        assert "re-throws" in res.reason

    def test_unawaited_confirmed(self, tmp_path):
        _write(tmp_path, "u.js", UNAWAITED_JS)
        res = run_fail_open_check(
            tmp_path, "u.js", "handle",
            "`validateBody` is a floating promise — never awaited, "
            "its rejection is silently ignored",
        )
        assert res.outcome == "confirmed"
        assert res.rule_id.startswith(RULE_UNAWAITED)
        assert res.sites and res.sites[0].shape == "floating-promise"

    def test_unawaited_refuted_when_awaited(self, tmp_path):
        src = UNAWAITED_JS.replace(
            "  validateBody(req);", "  await validateBody(req);",
        ).replace("function handle", "async function handle")
        _write(tmp_path, "u.js", src)
        res = run_fail_open_check(
            tmp_path, "u.js", "handle",
            "`validateBody` promise is never awaited, rejection "
            "ignored — floating promise",
        )
        assert res.outcome == "refuted"

    def test_unawaited_sync_callee_is_async_unprovable(self, tmp_path):
        src = UNAWAITED_JS.replace("async function validateBody",
                                   "function validateBody")
        _write(tmp_path, "u.js", src)
        res = run_fail_open_check(
            tmp_path, "u.js", "handle",
            "`validateBody` is never awaited — floating promise",
        )
        assert res.outcome == "inconclusive"
        assert REASON_ASYNC_UNPROVABLE in res.reason

    def test_no_handler_is_unbindable(self, tmp_path):
        _write(tmp_path, "plain.js", """
function verifyThing(req, res, next) {
  check(req);
  next();
}
""")
        res = run_fail_open_check(
            tmp_path, "plain.js", "verifyThing",
            "exception swallowed silently, fails open",
        )
        assert res.outcome == "inconclusive"
        assert REASON_HYPOTHESIS_UNBINDABLE in res.reason

    def test_role_unbound_without_any_vocabulary(self, tmp_path):
        _write(tmp_path, "misc.js", """
function tick(a, b) {
  try {
    bump(a);
  } catch (e) {
  }
}
""")
        res = run_fail_open_check(
            tmp_path, "misc.js", "tick",
            "the empty catch swallows the exception and fails open",
        )
        assert res.outcome == "inconclusive"
        assert REASON_ROLE_UNBOUND in res.reason

    def test_typescript_suffix_dispatches(self, tmp_path):
        _write(tmp_path, "auth.ts", AUTH_JS)
        res = run_fail_open_check(
            tmp_path, "auth.ts", "login",
            "empty catch swallows verifyToken exception, fails open",
        )
        assert res.language == "typescript"
        assert res.outcome == "confirmed"


class TestJsDegradation:
    """Parser-absent honesty: loud refusal, never a fabricated
    verdict (hermetic — no grammar needed)."""

    def test_language_unsupported_when_parser_absent(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        _write(tmp_path, "auth.js", AUTH_JS)
        res = run_fail_open_check(
            tmp_path, "auth.js", "login",
            "empty catch swallows verifyToken exception, fails open",
        )
        assert res.outcome == "inconclusive"
        assert REASON_LANGUAGE_UNSUPPORTED in res.reason

    def test_unawaited_language_unsupported_when_parser_absent(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.fail_open_lang as fol
        monkeypatch.setattr(fol, "_ts_parser", lambda lang: None)
        _write(tmp_path, "u.js", UNAWAITED_JS)
        res = run_fail_open_check(
            tmp_path, "u.js", "handle",
            "`validateBody` is never awaited — floating promise",
        )
        assert res.outcome == "inconclusive"
        assert REASON_LANGUAGE_UNSUPPORTED in res.reason

    def test_supported_language_registry(self):
        assert JS_LANGUAGES <= SUPPORTED_LANGUAGES
        assert JS_LANGUAGES <= CENSUS_LANGUAGES


@requires_ts("javascript")
class TestJsCensus:
    def test_js_catch_seeds_a_lead(self):
        result = run_fail_open_census({"auth.js": AUTH_JS})
        leads = result["leads"]
        assert leads, result["telemetry"]
        lead = leads[0]
        assert lead["file"] == "auth.js"
        assert lead["function"] == "login"
        assert lead["idiom"] == "catch_pass"
        assert result["telemetry"]["by_language"].get("javascript") == 1

    def test_promise_catch_seeds_a_lead(self):
        result = run_fail_open_census({"mw.js": PROMISE_JS})
        idioms = {ld["idiom"] for ld in result["leads"]}
        assert "promise_catch_pass" in idioms


@requires_ts("javascript")
class TestExpressHookMechanics:
    def test_middleware_signature_binds_tier_b(self, tmp_path):
        # No naming stem on the callee: role comes from the express
        # (req, res, next) hook mechanics on the enclosing function.
        _write(tmp_path, "mw.js", """
function gatekeeper(req, res, next) {
  try {
    ensureEntitled(req);
  } catch (e) {
  }
  next();
}
function ensureEntitled(req) {
  if (!req.user) throw new Error("denied");
}
""")
        res = run_fail_open_check(
            tmp_path, "mw.js", "gatekeeper",
            "the empty catch swallows the ensureEntitled exception "
            "and the middleware fails open",
        )
        assert res.outcome == "confirmed"
        assert res.role and res.role["source"] == "framework_registry"
        # Registry-grade role: the plain (not -naming) rule id.
        assert res.rule_id == RULE_HANDLER_OUTCOME


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
