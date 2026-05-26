"""Tests for resolved-model capture: extract_resolved_model + the client's
fired-models accumulator (provenance Phase 2)."""

import threading
import unittest
from types import SimpleNamespace

from core.llm.client import LLMClient
from core.llm.providers import extract_resolved_model


class TestExtractResolvedModel(unittest.TestCase):

    def test_openai_anthropic_style_model_attr(self):
        resp = SimpleNamespace(model="gemini-2.5-pro-002")
        self.assertEqual(extract_resolved_model(resp), "gemini-2.5-pro-002")

    def test_gemini_style_model_version_attr(self):
        # No `.model`, but `.model_version` (google-genai shape).
        resp = SimpleNamespace(model_version="gemini-2.5-pro-002")
        self.assertEqual(extract_resolved_model(resp), "gemini-2.5-pro-002")

    def test_empty_model_falls_through_to_model_version(self):
        resp = SimpleNamespace(model="", model_version="snap-1")
        self.assertEqual(extract_resolved_model(resp), "snap-1")

    def test_none_and_missing_return_none(self):
        self.assertIsNone(extract_resolved_model(None))
        self.assertIsNone(extract_resolved_model(SimpleNamespace()))

    def test_non_string_model_ignored(self):
        # A non-string `.model` (e.g. an enum/object) is not a snapshot id.
        resp = SimpleNamespace(model=123)
        self.assertIsNone(extract_resolved_model(resp))

    def test_attribute_access_raising_is_swallowed(self):
        class Hostile:
            @property
            def model(self):
                raise RuntimeError("boom")
        # Must not propagate — provenance capture cannot break generation.
        self.assertIsNone(extract_resolved_model(Hostile()))


def _bare_client() -> LLMClient:
    """Client built via __new__ (skips __init__), with only the lock the
    accumulator needs — mirrors the dispatcher/test construction path the
    defensive methods must tolerate."""
    c = LLMClient.__new__(LLMClient)
    c._stats_lock = threading.RLock()
    return c


class TestFiredModels(unittest.TestCase):

    def test_empty_when_nothing_fired(self):
        self.assertEqual(_bare_client().get_fired_models(), [])

    def test_dedup_and_count(self):
        c = _bare_client()
        c._record_fired_model("gemini", "gemini-2.5-pro", "gemini-2.5-pro-002", "primary")
        c._record_fired_model("gemini", "gemini-2.5-pro", "gemini-2.5-pro-002", "primary")
        fired = c.get_fired_models()
        self.assertEqual(len(fired), 1)
        entry = fired[0]
        self.assertEqual(entry["calls"], 2)
        self.assertEqual(entry["resolved"], "gemini-2.5-pro-002")
        self.assertEqual(entry["role"], "primary")
        self.assertEqual(entry["provider"], "gemini")

    def test_role_and_resolved_distinguish_entries(self):
        c = _bare_client()
        c._record_fired_model("gemini", "gemini-2.5-pro", "snap-a", "primary")
        c._record_fired_model("gemini", "gemini-2.5-flash", None, "fallback")
        fired = c.get_fired_models()
        self.assertEqual(len(fired), 2)
        # Alias-only (resolved=None) is preserved, never guessed.
        flash = [e for e in fired if e["alias"] == "gemini-2.5-flash"][0]
        self.assertIsNone(flash["resolved"])
        self.assertEqual(flash["role"], "fallback")

    def test_record_never_raises_without_lock(self):
        # A client missing even _stats_lock must not crash recording.
        c = LLMClient.__new__(LLMClient)
        c._record_fired_model("p", "a", None, "primary")  # no exception
        # get_fired_models also tolerant.
        self.assertEqual(c.get_fired_models(), [])


if __name__ == "__main__":
    unittest.main()
