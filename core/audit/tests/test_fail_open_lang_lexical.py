"""Fail-open handler classification: lexical hygiene.

A fail-closed classification is a REFUTATION receipt downstream
(``fail_open_verify`` emits 'refuted' when the sole handler is
fail-closed), so it must be earned against code, not prose:

* comment/string text naming an abort verb must not flip a permissive
  swallow to fail-closed (all four language legs);
* a raise/throw inside a nested def/lambda or a locally-caught nested
  try does not terminate the handler — control demonstrably
  continues;
* the per-try subtree walks must not be O(depth x size) — a 74KB file
  of nested trys stalled the census for 175s.

Fixtures deliberately hardcode target-like names — they *simulate
targets*, so the vocabulary policy does not apply to them.
"""

from __future__ import annotations

import time

from core.audit.fail_open_lang import (
    OUTCOME_FAIL_CLOSED,
    go_recover_handlers,
    java_handlers,
    js_handlers,
    python_handlers,
)
from core.testing import requires_ts


def _kinds(handlers):
    return [(h.outcome_kind, h.permissive_value) for h in handlers]


class TestPythonHandlerLexicalHygiene:
    def test_abort_comment_does_not_flip_except_pass(self):
        # Regression PoC: '# never sys.exit here' made a permissive
        # swallow read fail-closed -> tool-stamped 'refuted'.
        src = (
            "def g(t):\n"
            "    try:\n"
            "        verify(t)\n"
            "    except Exception:\n"
            "        pass  # never sys.exit here\n"
        )
        assert _kinds(python_handlers(src, "a.py")) == [("pass", "")]

    def test_abort_in_string_literal_is_inert(self):
        src = (
            "def g(t):\n"
            "    try:\n"
            "        verify(t)\n"
            "    except Exception:\n"
            "        msg = 'call sys.exit later'\n"
        )
        (kind, _v), = _kinds(python_handlers(src, "a.py"))
        assert kind != OUTCOME_FAIL_CLOSED

    def test_real_abort_still_fail_closed(self):
        src = (
            "def g(t):\n"
            "    try:\n"
            "        verify(t)\n"
            "    except Exception:\n"
            "        sys.exit(1)\n"
        )
        assert _kinds(python_handlers(src, "a.py")) == [
            ("fail_closed", "aborts"),
        ]

    def test_raise_in_nested_def_does_not_terminate_handler(self):
        # Regression PoC (a): control continues to `return True`, yet
        # the raw ast.walk crossed the def boundary and stamped
        # 're-raises'.
        src = (
            "def g():\n"
            "    try:\n"
            "        w()\n"
            "    except Exception:\n"
            "        def cleanup():\n"
            "            raise ValueError()\n"
            "        return True\n"
        )
        (kind, _v), = _kinds(python_handlers(src, "a.py"))
        assert kind != OUTCOME_FAIL_CLOSED

    def test_raise_swallowed_by_nested_try_is_not_fail_closed(self):
        # Regression PoC (b): the nested except catches the raise
        # locally — control continues.
        src = (
            "def g():\n"
            "    try:\n"
            "        w()\n"
            "    except Exception:\n"
            "        try:\n"
            "            raise ValueError()\n"
            "        except ValueError:\n"
            "            pass\n"
            "        return True\n"
        )
        outer = python_handlers(src, "a.py")[0]
        assert outer.outcome_kind != OUTCOME_FAIL_CLOSED

    def test_raise_in_nested_finally_still_fail_closed(self):
        # A raise in a nested try's FINALLY propagates out.
        src = (
            "def g():\n"
            "    try:\n"
            "        w()\n"
            "    except Exception:\n"
            "        try:\n"
            "            x()\n"
            "        except ValueError:\n"
            "            pass\n"
            "        finally:\n"
            "            raise RuntimeError()\n"
        )
        outer = python_handlers(src, "a.py")[0]
        assert outer.outcome_kind == OUTCOME_FAIL_CLOSED

    def test_bare_reraise_and_conditional_raise_stay_fail_closed(self):
        src = (
            "def g():\n"
            "    try:\n"
            "        w()\n"
            "    except Exception as e:\n"
            "        if bad(e):\n"
            "            raise\n"
        )
        assert python_handlers(src, "a.py")[0].outcome_kind == \
            OUTCOME_FAIL_CLOSED


@requires_ts("java")
class TestJavaCatchLexicalHygiene:
    def test_abort_comment_does_not_flip_return_true(self):
        # Regression PoC (a): '/* System.exit(1) would be too harsh */'
        # in a permissive return-true swallow read as 'aborts'.
        src = (
            "class A { boolean m() {\n"
            "  try { return check(); }\n"
            "  catch (Exception e) {\n"
            "    /* System.exit(1) would be too harsh */\n"
            "    return true; }\n"
            "} }\n"
        )
        (h,) = java_handlers(src, "A.java")
        assert h.outcome_kind == "return_permissive"

    def test_throw_swallowed_by_nested_try_is_not_fail_closed(self):
        # Regression PoC (b): the nested catch catches the throw
        # locally; `return true` executes.
        src = (
            "class A { boolean m() {\n"
            "  try { return check(); }\n"
            "  catch (Exception e) {\n"
            "    try { throw new RuntimeException(); }\n"
            "    catch (RuntimeException r) { }\n"
            "    return true;\n"
            "  }\n"
            "} }\n"
        )
        handlers = java_handlers(src, "A.java")
        outer = [h for h in handlers if h.caught == ["Exception"]]
        assert outer and outer[0].outcome_kind != OUTCOME_FAIL_CLOSED

    def test_real_rethrow_and_abort_stay_fail_closed(self):
        src = (
            "class A {\n"
            "  boolean m() { try { return check(); }\n"
            "    catch (Exception e) { throw new "
            "IllegalStateException(e); } }\n"
            "  boolean n() { try { return check(); }\n"
            "    catch (Exception e) { System.exit(1); "
            "return false; } }\n"
            "}\n"
        )
        kinds = {(h.enclosing_function, h.outcome_kind, h.permissive_value)
                 for h in java_handlers(src, "A.java")}
        assert ("m", "fail_closed", "re-throws") in kinds
        assert ("n", "fail_closed", "aborts") in kinds

    def test_throw_in_lambda_stays_excluded(self):
        src = (
            "class A { boolean m() {\n"
            "  try { return check(); }\n"
            "  catch (Exception e) {\n"
            "    Runnable r = () -> { throw new RuntimeException(); };\n"
            "    return true; }\n"
            "} }\n"
        )
        (h,) = java_handlers(src, "A.java")
        assert h.outcome_kind != OUTCOME_FAIL_CLOSED


@requires_ts("javascript")
class TestJsHandlerLexicalHygiene:
    def test_abort_comment_does_not_flip_return_true(self):
        # Regression PoC: '// never process.exit( here' read as 'aborts'
        # (the throw check was boundary-aware, the abort check not).
        src = (
            "function m() {\n"
            "  try { return check(); }\n"
            "  catch (e) { // never process.exit( here\n"
            "    return true; }\n"
            "}\n"
        )
        (h,) = js_handlers(src, "a.js")
        assert h.outcome_kind == "return_permissive"

    def test_throw_swallowed_by_nested_try_is_not_fail_closed(self):
        src = (
            "function m() {\n"
            "  try { return check(); }\n"
            "  catch (e) {\n"
            "    try { throw new Error('x'); } catch (i) {}\n"
            "    return true;\n"
            "  }\n"
            "}\n"
        )
        handlers = js_handlers(src, "a.js")
        outer = [h for h in handlers if h.enclosing_function == "m"]
        assert all(h.outcome_kind != OUTCOME_FAIL_CLOSED for h in outer)

    def test_real_abort_and_rethrow_stay_fail_closed(self):
        src = (
            "function o() { try { return check(); } "
            "catch (e) { throw e; } }\n"
            "function p() { try { return check(); } "
            "catch (e) { process.exit(1); } }\n"
        )
        kinds = {(h.enclosing_function, h.outcome_kind)
                 for h in js_handlers(src, "a.js")}
        assert ("o", "fail_closed") in kinds
        assert ("p", "fail_closed") in kinds


@requires_ts("go")
class TestGoRecoverLexicalHygiene:
    def test_panic_comment_does_not_flip_recover_swallow(self):
        # Regression PoC: '/* do not panic() here */' flipped a
        # recover-and-grant-access handler to fail-closed
        # 're-panics' -> the real fail-open was 'refuted'.
        src = (
            "package main\n"
            "func m(req *Req) {\n"
            "    defer func() {\n"
            "        if r := recover(); r != nil {\n"
            "            grantAccess(req) /* do not panic() here */\n"
            "        }\n"
            "    }()\n"
            "    work(req)\n"
            "}\n"
        )
        (h,) = go_recover_handlers(src, "a.go")
        assert h.outcome_kind == "recover_continue"

    def test_recover_only_in_comment_is_not_a_handler(self):
        src = (
            "package main\n"
            "func m() {\n"
            "    defer func() {\n"
            "        cleanup() // recover() intentionally omitted\n"
            "    }()\n"
            "}\n"
        )
        assert go_recover_handlers(src, "a.go") == []

    def test_real_repanic_and_abort_stay_fail_closed(self):
        src = (
            "package main\n"
            "func n() {\n"
            "    defer func() { if r := recover(); r != nil "
            "{ panic(r) } }()\n"
            "}\n"
            "func p() {\n"
            "    defer func() { if r := recover(); r != nil "
            "{ os.Exit(1) } }()\n"
            "}\n"
        )
        got = {(h.enclosing_function, h.outcome_kind, h.permissive_value)
               for h in go_recover_handlers(src, "a.go")}
        assert ("n", "fail_closed", "re-panics") in got
        assert ("p", "fail_closed", "aborts") in got

    def test_panic_in_nested_func_literal_stays_excluded(self):
        src = (
            "package main\n"
            "func m() {\n"
            "    defer func() {\n"
            "        if r := recover(); r != nil {\n"
            "            h := func() { panic(r) }\n"
            "            _ = h\n"
            "        }\n"
            "    }()\n"
            "}\n"
        )
        (h,) = go_recover_handlers(src, "a.go")
        assert h.outcome_kind == "recover_continue"


# ---------------------------------------------------------------------------
# Regression: nested trys must not be O(depth x size)
# ---------------------------------------------------------------------------


@requires_ts("java")
class TestNestedTryScaling:
    def test_deeply_nested_trys_complete_quickly(self):
        # Pre-fix: per-try subtree call re-walks + per-try
        # node.parent chains measured 175s at k=2000 (74KB). The
        # single-pass call index + carried enclosing-function state
        # is O(n log n): whole-file handling in well under 10s even
        # on slow CI.
        k = 1200
        src = (
            "class A { void m() { "
            + ("try { g(); " * k)
            + ("} catch (Exception e) { } " * k)
            + "} }"
        )
        t0 = time.monotonic()
        handlers = java_handlers(src, "A.java")
        elapsed = time.monotonic() - t0
        assert len(handlers) == k
        assert elapsed < 10, f"nested-try walk took {elapsed:.1f}s"
        # The innermost try body still sees its call.
        assert all("g" in h.try_calls for h in handlers)
        assert all(h.enclosing_function == "m" for h in handlers)


@requires_ts("go")
class TestGoDeferCallExclusion:
    def test_try_calls_exclude_the_defer_literal_itself(self):
        src = (
            "package main\n"
            "func m() {\n"
            "    defer func() { if r := recover(); r != nil "
            "{ handleIt() } }()\n"
            "    work()\n"
            "    verifyToken()\n"
            "}\n"
        )
        (h,) = go_recover_handlers(src, "a.go")
        assert "work" in h.try_calls
        assert "verifyToken" in h.try_calls
        assert "handleIt" not in h.try_calls
