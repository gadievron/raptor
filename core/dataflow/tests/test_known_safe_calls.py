"""Tests for the Tier 1B curated known-safe call table."""

from __future__ import annotations

from core.dataflow import known_safe_calls as ksc


def test_find_exact_match_python_pathtrav():
    e = ksc.find("werkzeug.security.safe_join", "pathtrav", "python")
    assert e is not None
    assert e.input_arg_kind == "validate"


def test_find_returns_none_for_wrong_sink_class():
    """html.escape is xss-safe, NOT pathtrav-safe."""
    assert ksc.find("html.escape", "pathtrav", "python") is None
    assert ksc.find("html.escape", "xss", "python") is not None


def test_find_returns_none_for_wrong_language():
    """werkzeug is Python-only; same-named call from another language
    must not match."""
    assert ksc.find("werkzeug.security.safe_join", "pathtrav", "java") is None


def test_find_returns_none_for_unknown_library():
    """Any library not in the curated table -> None (Tier 1B then
    declines).  This is the trust-surface gate."""
    assert ksc.find("evil.library.taint", "xss", "python") is None
    assert ksc.find("not.in.table", "pathtrav", "python") is None


def test_jsts_entries_match_both_languages():
    """validator.escape + DOMPurify.sanitize cover both JS and TS."""
    for lang in ("javascript", "typescript"):
        assert ksc.find("validator.escape", "xss", lang) is not None
        assert ksc.find("DOMPurify.sanitize", "xss", lang) is not None


def test_every_entry_has_soundness_note():
    """Adding entries without a justification is a soundness anti-
    pattern; pin it down so a future PR can't sneak one in."""
    for e in ksc.all_entries():
        assert e.soundness_note and len(e.soundness_note) >= 50, (
            f"{e.library_call} missing or too short soundness_note"
        )


def test_every_entry_has_valid_input_arg_kind():
    valid = {"transform", "validate"}
    for e in ksc.all_entries():
        assert e.input_arg_kind in valid, (
            f"{e.library_call} has invalid input_arg_kind={e.input_arg_kind!r}"
        )


def test_every_entry_has_valid_sink_class():
    valid = {"pathtrav", "xss", "cmdi", "sqli"}
    for e in ksc.all_entries():
        assert e.sink_class in valid, (
            f"{e.library_call} has invalid sink_class={e.sink_class!r}"
        )


def test_no_duplicate_entries():
    """No two entries with the same (library_call, sink_class, language)
    triple — would shadow each other under find()."""
    seen = set()
    for e in ksc.all_entries():
        for lang in e.languages:
            key = (e.library_call, e.sink_class, lang)
            assert key not in seen, f"duplicate entry for {key}"
            seen.add(key)
