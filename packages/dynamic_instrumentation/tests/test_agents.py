"""Agent JS generation - parameters must be injected as JSON literals (never
raw string interpolation) so target-derived names can't break out of the JS."""

import json

from packages.dynamic_instrumentation import agents


def test_trace_agent_embeds_symbols_as_json():
    js = agents.trace_agent(["foo", "bar"])
    assert '["foo", "bar"]' in js
    assert "Interceptor.attach" in js
    assert "DebugSymbol.fromName" in js
    # Frida 17 API (not the removed Module.findExportByName(null, ...)).
    assert "findGlobalExportByName" in js


def test_trace_agent_quote_injection_is_neutralised():
    # A symbol containing a quote must be JSON-escaped, not break the JS.
    evil = 'x"); doSomethingEvil(("'
    js = agents.trace_agent([evil])
    assert json.dumps([evil]) in js
    # the raw unescaped payload must not appear verbatim as JS
    assert 'doSomethingEvil((")' not in js.replace(json.dumps([evil]), "")


def test_coverage_agent_hooks_main_and_follows_stalker():
    js = agents.coverage_agent()
    assert "Stalker.follow" in js
    assert "DebugSymbol.fromName('main')" in js
    assert "enumerateModules" in js
    assert "null" in js  # WANT defaults to null (cover main module)


def test_coverage_agent_module_filter_is_json():
    js = agents.coverage_agent(["libssl", "libcrypto"])
    assert json.dumps(["libssl", "libcrypto"]) in js
