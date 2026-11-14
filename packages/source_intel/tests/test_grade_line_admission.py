"""Invalid grade coordinates do not need a source view."""

import pytest

from packages.source_intel import _source_view
from packages.source_intel.analyze import _classify_call_site_grade, _classify_abort_grade


@pytest.mark.parametrize("line", [-1, -1000, 0, None])
def test_invalid_grade_line_avoids_source_lookup(line, monkeypatch):
    def forbidden_view(*args):
        raise AssertionError("invalid line must not request source parsing")

    monkeypatch.setattr(_source_view, "sanitized_lines", forbidden_view)
    assert _classify_call_site_grade("owned.c", line) == "same_function"


def test_valid_grade_line_uses_owned_view(monkeypatch):
    calls = []

    def owned_view(path):
        calls.append(path)
        return ["int owned() {", "capable();", "}"]

    monkeypatch.setattr(_source_view, "sanitized_lines", owned_view)
    assert _classify_call_site_grade("owned.c", 2) == "dominates"
    assert calls == ["owned.c"]
    assert _classify_abort_grade is _classify_call_site_grade


def test_past_end_grade_line_retains_fallback(monkeypatch):
    monkeypatch.setattr(_source_view, "sanitized_lines", lambda _: ["int owned;"])
    assert _classify_call_site_grade("owned.c", 2) == "same_function"


def test_missing_grade_path_avoids_source_lookup(monkeypatch):
    def forbidden_view(*args):
        raise AssertionError("missing path must not request a source view")

    monkeypatch.setattr(_source_view, "sanitized_lines", forbidden_view)
    assert _classify_call_site_grade("", 2) == "same_function"
