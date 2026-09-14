"""Mixed-install containment: grammar wheel present, runtime absent.

Grammar wheels declare no dependency on the tree_sitter runtime, so
``import_grammar`` can succeed on an install where ``tree_sitter``
itself is missing. The loader must answer None in that state — the
unguarded ``Language(...)`` wrap used to raise NameError (not
ImportError), escaping consumers' ImportError-only catches and
crashing the audit sink-guard extraction instead of degrading to the
regex path.
"""

from __future__ import annotations

import types

from core.inventory import extractors


def _simulate_mixed_install(monkeypatch) -> None:
    """tree_sitter runtime absent + a grammar wheel importable."""
    fake_grammar = types.SimpleNamespace(language=lambda: object())
    monkeypatch.setattr(
        extractors._ts_cache, "import_grammar", lambda name: fake_grammar,
    )
    monkeypatch.setattr(extractors, "_TS_AVAILABLE", False)
    monkeypatch.delattr(extractors, "Language", raising=False)


def test_ts_language_mixed_install_returns_none(monkeypatch):
    _simulate_mixed_install(monkeypatch)
    assert extractors._ts_language("python") is None


def test_ts_parser_for_mixed_install_returns_none(monkeypatch):
    _simulate_mixed_install(monkeypatch)
    # Fresh per-thread cache so a parser from other tests can't mask
    # the loader path.
    monkeypatch.setattr(
        extractors._TS_PARSER_LOCAL, "parsers", {}, raising=False,
    )
    assert extractors._ts_parser_for("python") is None


def test_audit_sink_guard_extraction_degrades(monkeypatch):
    """The consumer surface: extract_sink_guards must fall back to
    the no-parser path ([]), not crash, when the shared loader is in
    the mixed-install state."""
    import core.audit.condition_extraction as ce

    def _boom(lang):
        raise NameError("name 'Language' is not defined")

    monkeypatch.setattr(extractors, "_ts_parser_for", _boom)
    monkeypatch.setattr(ce, "_TS_AVAILABLE", False)

    assert ce._get_parser("python") is None
    guards = ce.extract_sink_guards(
        "import os\n\nif ok:\n    os.system(cmd)\n",
        "app.py",
        sink_names=frozenset({"system"}),
    )
    assert guards == []
