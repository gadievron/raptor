"""Fail-open analyzers retain receipts and defer unused line snapshots."""

import builtins
import sys
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from core.audit import fail_open_lang as lang
from core.source.lines import SourceLineSnapshot, split_lines
from core.testing import requires_ts
from core.testing.module_views import module_function_view


HANDLERS = [
    pytest.param("python", "python_handlers", "def owner():\n try:\n  work()\n except Exception:\n  pass\n", id="python"),
    pytest.param("java", "java_handlers", "class C { void owner() { try { work(); } catch (Exception e) {} } }", marks=requires_ts("java"), id="java"),
    pytest.param("go", "go_recover_handlers", "package owned\nfunc owner() { defer func() { recover() }(); work() }", marks=requires_ts("go"), id="go"),
    pytest.param("javascript", "js_handlers", "function owner() { try { work(); } catch(e) {} }", marks=requires_ts("javascript"), id="javascript"),
    pytest.param("kotlin", "kotlin_handlers", "fun owner() { try { work() } catch(e: Exception) {} }", marks=requires_ts("kotlin"), id="kotlin"),
    pytest.param("csharp", "csharp_handlers", "class C { void Owner() { try { Work(); } catch (Exception e) {} } }", marks=requires_ts("csharp"), id="csharp"),
    pytest.param("swift", "swift_handlers", "func owner() { do { try work() } catch {} }", marks=requires_ts("swift"), id="swift"),
]
CALLS = [
    pytest.param("c", "c_ignored_return_sites", "int owner(void) { check(); return 0; }", marks=requires_ts("c"), id="c-ignore"),
    pytest.param("c", "c_tristate_sites", "int owner(void) { if (check()) return 1; return 0; }", marks=requires_ts("c"), id="c-tristate"),
    pytest.param("go", "go_discard_sites", "package owned\nfunc owner() { check() }", marks=requires_ts("go"), id="go"),
    pytest.param("javascript", "js_unawaited_sites", "function owner() { check(); }", marks=requires_ts("javascript"), id="javascript"),
    pytest.param("rust", "rust_discard_sites", "fn owner() { check(); }", marks=requires_ts("rust"), id="rust"),
    pytest.param("swift", "swift_erasure_sites", "func owner() { _ = try? check() }", marks=requires_ts("swift"), id="swift"),
]


def padded(language, body):
    prefix = "# padding\n" if language == "python" else "// padding\n"
    return prefix * 2000 + body


@contextmanager
def preparations():
    if sys.getprofile() is not None:
        pytest.skip("profiling hook already owned")
    seen = []

    def observe(frame, event, arg):
        if (event == "call" and frame.f_code is split_lines.__code__ and frame.f_back is not None
                and frame.f_back.f_code is SourceLineSnapshot.get.__code__):
            seen.append(frame.f_locals["text"])

    try:
        sys.setprofile(observe)
        yield seen
    finally:
        sys.setprofile(None)


@pytest.mark.parametrize("language,function,body", HANDLERS)
@pytest.mark.parametrize("retained", [False, True], ids=["no-handler", "handler"])
def test_handler_snapshots_only_materialize_for_receipts(language, function, body, retained):
    source = padded(language, body if retained else "")
    with preparations() as seen:
        results = getattr(lang, function)(source, "owned")
    assert results is not None
    assert bool(results) is retained
    assert len(seen) == ((2 if language == "python" else 1) if retained else 0)


@pytest.mark.parametrize("language,function,body", CALLS)
@pytest.mark.parametrize("retained", [False, True], ids=["other-callee", "matching-callee"])
def test_call_snapshots_only_materialize_for_matching_callees(language, function, body, retained):
    source = padded(language, body)
    with preparations() as seen:
        results = getattr(lang, function)(source, "owned", "check" if retained else "missing")
    assert results is not None
    assert bool(results) is retained
    assert len(seen) == int(retained)


@pytest.mark.parametrize("function,language,body", [
    pytest.param("go_discard_sites", "go", "package owned\nfunc owner() { check() }", marks=requires_ts("go"), id="go"),
    pytest.param("js_unawaited_sites", "javascript", "function owner() { check(); }", marks=requires_ts("javascript"), id="javascript"),
    pytest.param("rust_discard_sites", "rust", "fn owner() { check(); }", marks=requires_ts("rust"), id="rust"),
    pytest.param("swift_erasure_sites", "swift", "func owner() { _ = try? check() }", marks=requires_ts("swift"), id="swift"),
])
def test_deferred_allocation_failure_keeps_original_refusal(function, language, body):
    class AllocationFailure:
        def __init__(self, *args):
            pass

        def get(self):
            raise MemoryError("owned deferred allocation failure")

    view = module_function_view(lang, bindings={"SourceLineSnapshot": AllocationFailure})
    assert getattr(view, function)(padded(language, body), "owned", "check") is None


def test_python_sanitizer_cannot_replace_its_already_bound_splitter():
    seen = []

    def first(source):
        seen.append("raw")
        vars(view)["split_lines"] = second
        return ["raw"]

    def second(source):
        seen.append("view")
        return ["view"]

    def unwanted(source):
        pytest.fail("sanitizer replaced the already-bound view splitter")

    def sanitized(source, **kwargs):
        seen.append("sanitize")
        vars(view)["split_lines"] = unwanted
        return source

    def import_local(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "source_view" and level == 1:
            return SimpleNamespace(sanitized_view=sanitized)
        return builtins.__import__(name, globals, locals, fromlist, level)

    view = module_function_view(lang, bindings={"split_lines": first}, import_hook=import_local)
    assert view.python_handlers("def owner():\n pass\n", "owned.py") == []
    assert seen == ["raw", "sanitize", "view"]


@requires_ts("javascript")
def test_classifier_callback_cannot_replace_captured_source_rows():
    source = padded("javascript", "function owner() { try { work(); } catch(e) {} }")
    original = lang._classify_js_handler_body
    unwanted = []

    def split(text):
        unwanted.append(text)
        return ["wrong"]

    def classify(*args):
        vars(view)["split_lines"] = split
        return original(*args)

    view = module_function_view(lang, bindings={"_classify_js_handler_body": classify})
    results = view.js_handlers(source, "owned.js")
    assert len(results) == 1
    assert "function owner()" in results[0].evidence_snippet
    assert unwanted == []


@pytest.mark.parametrize("function,classifier,language,body", [
    pytest.param("go_discard_sites", "_classify_go_call_site", "go", "package owned\nfunc owner() { check() }", marks=requires_ts("go"), id="go"),
    pytest.param("js_unawaited_sites", "_classify_js_unawaited_site", "javascript", "function owner() { check(); }", marks=requires_ts("javascript"), id="javascript"),
    pytest.param("rust_discard_sites", "_classify_rust_call_site", "rust", "fn owner() { check(); }", marks=requires_ts("rust"), id="rust"),
    pytest.param("swift_erasure_sites", "_classify_swift_call_site", "swift", "func owner() { _ = try? check() }", marks=requires_ts("swift"), id="swift"),
])
def test_classifier_failures_remain_outside_preparation_refusal(function, classifier, language, body):
    def fail(*args):
        raise ValueError("owned classifier failure")

    view = module_function_view(lang, bindings={classifier: fail})
    with pytest.raises(ValueError, match="owned classifier failure"):
        getattr(view, function)(padded(language, body), "owned", "check")
