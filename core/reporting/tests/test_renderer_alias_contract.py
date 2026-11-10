"""Renderer registration cannot create an unreachable format behind an alias."""
import pytest

from core.reporting import renderers


def test_registration_refuses_existing_alias_without_mutating_registry(monkeypatch):
    original = dict(renderers._RENDERERS)
    monkeypatch.setattr(renderers, "_RENDERERS", dict(original))
    candidate = renderers.Renderer("md", ".custom", "application/test", lambda document: None)
    with pytest.raises(ValueError, match="reserved alias"):
        renderers.register_renderer(candidate)
    assert renderers._RENDERERS == original
    assert renderers.get_renderer("md") is renderers.get_renderer("markdown")


def test_distinct_extension_name_remains_reachable_and_aliases_deduplicate(monkeypatch):
    from core.reporting.options import ReportOptions
    monkeypatch.setattr(renderers, "_RENDERERS", dict(renderers._RENDERERS))
    candidate = renderers.Renderer("md_custom", ".custom", "application/test", lambda document: None)
    renderers.register_renderer(candidate)
    assert renderers.get_renderer("md_custom") is candidate
    assert "md_custom" in renderers.available_formats()
    assert ReportOptions(("md_custom", "md", "markdown")).validate().formats == ("md_custom", "markdown")


def test_canonical_duplicate_still_refused_without_replacement(monkeypatch):
    original = renderers.get_renderer("markdown")
    monkeypatch.setattr(renderers, "_RENDERERS", dict(renderers._RENDERERS))
    with pytest.raises(ValueError, match="already registered"):
        renderers.register_renderer(renderers.Renderer("markdown", ".custom", "application/test", lambda document: None))
    assert renderers.get_renderer("markdown") is original
