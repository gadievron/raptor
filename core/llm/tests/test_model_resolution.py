"""Tests for ``core/llm/model_resolution`` — Anthropic alias resolution.

The resolver maps unversioned aliases like ``claude-haiku-4-5`` to the
most recent versioned snapshot Anthropic publishes
(``claude-haiku-4-5-20251001``) so SDK calls don't 404. Failures fall
through to verbatim — the SDK still surfaces a clear error for
genuinely unknown names.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from core.llm import model_resolution
from core.llm.model_resolution import (
    resolve_anthropic,
    _fetch_inventory,
    _reset_cache_for_tests,
    _seed_cache_for_tests,
)


@pytest.fixture(autouse=True)
def _isolated_cache():
    """Each test starts with an empty resolver cache."""
    _reset_cache_for_tests()
    yield
    _reset_cache_for_tests()


# ---------------------------------------------------------------------------
# Pure resolution logic — drives the cache directly
# ---------------------------------------------------------------------------


class TestResolutionLogic:

    def test_exact_match_returned_verbatim(self):
        _seed_cache_for_tests([
            "claude-haiku-4-5-20251001",
            "claude-sonnet-4-6-20251015",
        ])
        # Operator pinned a specific snapshot — must not be rewritten.
        assert resolve_anthropic("claude-haiku-4-5-20251001", "k") == "claude-haiku-4-5-20251001"

    def test_alias_resolves_to_only_snapshot(self):
        _seed_cache_for_tests(["claude-haiku-4-5-20251001"])
        assert resolve_anthropic("claude-haiku-4-5", "k") == "claude-haiku-4-5-20251001"

    def test_alias_resolves_to_most_recent_snapshot(self):
        """Lex-max == most recent because the suffix is YYYYMMDD."""
        _seed_cache_for_tests([
            "claude-haiku-4-5-20251001",
            "claude-haiku-4-5-20260315",
            "claude-haiku-4-5-20251215",
        ])
        assert resolve_anthropic("claude-haiku-4-5", "k") == "claude-haiku-4-5-20260315"

    def test_ambiguous_family_alias_returns_verbatim(self):
        """``claude`` alone is too vague — the next segment in each
        candidate is a family name (``haiku``, ``opus``, ``sonnet``),
        not a date. Silent resolution would pick a "random" family
        via lex-max; better to 404 with the alias the user typed."""
        _seed_cache_for_tests([
            "claude-haiku-4-5-20251001",
            "claude-opus-4-1-20260101",
            "claude-sonnet-4-6-20260201",
        ])
        assert resolve_anthropic("claude", "k") == "claude"

    def test_ambiguous_major_version_alias_returns_verbatim(self):
        """``claude-opus`` spans multiple major versions — next
        segment is the major version digit, not a date. Verbatim."""
        _seed_cache_for_tests([
            "claude-opus-3-20240115",
            "claude-opus-4-1-20260101",
        ])
        assert resolve_anthropic("claude-opus", "k") == "claude-opus"

    def test_ambiguous_minor_version_alias_returns_verbatim(self):
        """``claude-opus-4`` spans multiple minor versions — next
        segment is the minor version digit, not a date. Verbatim."""
        _seed_cache_for_tests([
            "claude-opus-4-1-20260101",
            "claude-opus-4-2-20260315",
        ])
        assert resolve_anthropic("claude-opus-4", "k") == "claude-opus-4"

    def test_unambiguous_alias_resolves_even_with_other_families_present(self):
        """``claude-haiku-4-5`` is one date away from a canonical ID;
        the presence of unrelated families in the inventory doesn't
        derail it."""
        _seed_cache_for_tests([
            "claude-haiku-4-5-20251001",
            "claude-opus-4-1-20260101",
            "claude-sonnet-4-6-20260201",
        ])
        assert resolve_anthropic("claude-haiku-4-5", "k") == "claude-haiku-4-5-20251001"

    def test_no_prefix_match_returns_verbatim(self):
        _seed_cache_for_tests(["claude-haiku-4-5-20251001"])
        assert resolve_anthropic("claude-opus-9", "k") == "claude-opus-9"

    def test_empty_inventory_returns_verbatim(self):
        _seed_cache_for_tests([])
        assert resolve_anthropic("claude-haiku-4-5", "k") == "claude-haiku-4-5"


# ---------------------------------------------------------------------------
# Cache behaviour — fetch happens at most once per process
# ---------------------------------------------------------------------------


class TestCacheBehaviour:

    def test_fetch_runs_once_on_repeated_resolves(self):
        """Multiple resolve calls trigger only one inventory fetch."""
        with patch.object(
            model_resolution, "_fetch_inventory",
            return_value=["claude-haiku-4-5-20251001"],
        ) as fake_fetch:
            assert resolve_anthropic("claude-haiku-4-5", "k") == "claude-haiku-4-5-20251001"
            assert resolve_anthropic("claude-haiku-4-5", "k") == "claude-haiku-4-5-20251001"
            assert resolve_anthropic("claude-sonnet-4-6", "k") == "claude-sonnet-4-6"
        assert fake_fetch.call_count == 1

    def test_fetch_not_attempted_without_api_key(self):
        with patch.object(model_resolution, "_fetch_inventory") as fake_fetch:
            # No api_key — resolver short-circuits, no network attempt.
            assert resolve_anthropic("claude-haiku-4-5", None) == "claude-haiku-4-5"
        fake_fetch.assert_not_called()

    def test_fetch_exception_falls_through_to_verbatim(self):
        """Network blip at startup must not break config reads."""
        with patch.object(
            model_resolution, "_fetch_inventory",
            side_effect=RuntimeError("connection refused"),
        ):
            # Verbatim, no exception propagates.
            assert resolve_anthropic("claude-haiku-4-5", "k") == "claude-haiku-4-5"
            # And the failure is latched — no retry on next call.
            assert resolve_anthropic("claude-haiku-4-5", "k") == "claude-haiku-4-5"


# ---------------------------------------------------------------------------
# Network layer — _fetch_inventory parses the real /v1/models shape
# ---------------------------------------------------------------------------


class TestFetchInventory:

    def _mock_response(self, status: int, body: dict | None = None):
        m = MagicMock()
        m.status_code = status
        m.json.return_value = body or {}
        return m

    def test_parses_id_field_from_each_entry(self):
        body = {
            "data": [
                {"id": "claude-haiku-4-5-20251001", "type": "model"},
                {"id": "claude-sonnet-4-6-20251015", "type": "model"},
            ],
        }
        with patch("requests.get", return_value=self._mock_response(200, body)):
            assert _fetch_inventory("k") == [
                "claude-haiku-4-5-20251001",
                "claude-sonnet-4-6-20251015",
            ]

    def test_non_200_returns_empty(self):
        with patch("requests.get", return_value=self._mock_response(401)):
            assert _fetch_inventory("bad-key") == []

    def test_malformed_entries_are_skipped(self):
        body = {
            "data": [
                {"id": "claude-haiku-4-5-20251001"},
                {"no_id": "weird-entry"},
                "string-not-dict",
                {"id": 12345},  # non-string id
            ],
        }
        with patch("requests.get", return_value=self._mock_response(200, body)):
            assert _fetch_inventory("k") == ["claude-haiku-4-5-20251001"]


# ---------------------------------------------------------------------------
# Integration — _read_config_models rewrites Anthropic entries
# ---------------------------------------------------------------------------


class TestReadConfigIntegration:

    def test_anthropic_alias_rewritten_in_returned_entries(
        self, tmp_path, monkeypatch,
    ):
        import json

        from core.llm.detection import _read_config_models

        _seed_cache_for_tests(["claude-haiku-4-5-20251001"])

        config = tmp_path / "models.json"
        config.write_text(json.dumps({
            "models": [
                {"provider": "gemini", "model": "gemini-2.5-pro", "api_key": "g"},
                {"provider": "anthropic", "model": "claude-haiku-4-5", "api_key": "a"},
            ]
        }))
        monkeypatch.setenv("RAPTOR_CONFIG", str(config))

        entries = _read_config_models()
        anthropic = next(e for e in entries if e["provider"] == "anthropic")
        gemini = next(e for e in entries if e["provider"] == "gemini")

        assert anthropic["model"] == "claude-haiku-4-5-20251001"
        # Operator's input preserved for diagnostics.
        assert anthropic["_configured_model"] == "claude-haiku-4-5"
        # Gemini entries untouched.
        assert gemini["model"] == "gemini-2.5-pro"
        assert "_configured_model" not in gemini

    def test_already_pinned_anthropic_entry_not_marked_resolved(
        self, tmp_path, monkeypatch,
    ):
        import json

        from core.llm.detection import _read_config_models

        _seed_cache_for_tests(["claude-haiku-4-5-20251001"])

        config = tmp_path / "models.json"
        config.write_text(json.dumps({
            "models": [
                {"provider": "anthropic", "model": "claude-haiku-4-5-20251001", "api_key": "a"},
            ]
        }))
        monkeypatch.setenv("RAPTOR_CONFIG", str(config))

        entries = _read_config_models()
        assert entries[0]["model"] == "claude-haiku-4-5-20251001"
        # No "configured_model" marker — there was no rewrite to record.
        assert "_configured_model" not in entries[0]

    def test_anthropic_entry_without_key_passes_through_unchanged(
        self, tmp_path, monkeypatch,
    ):
        """A configured-but-unkeyed entry can't trigger a fetch and
        must not be rewritten. Some operators stage entries with the
        key resolved later via env var."""
        import json

        from core.llm.detection import _read_config_models

        _seed_cache_for_tests(["claude-haiku-4-5-20251001"])

        config = tmp_path / "models.json"
        config.write_text(json.dumps({
            "models": [
                {"provider": "anthropic", "model": "claude-haiku-4-5"},
            ]
        }))
        monkeypatch.setenv("RAPTOR_CONFIG", str(config))
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

        entries = _read_config_models()
        # No key in entry and none in env — resolver can't fetch, so we
        # leave the alias as-is. The downstream LLM call will fail with
        # the same error mode as before this feature shipped.
        assert entries[0]["model"] == "claude-haiku-4-5"

    def test_resolution_failure_does_not_break_config_read(
        self, tmp_path, monkeypatch,
    ):
        """If the resolver raises, _read_config_models must still
        return the raw entries — config reads can never be the thing
        that breaks because Anthropic's models endpoint is down."""
        import json

        from core.llm.detection import _read_config_models

        config = tmp_path / "models.json"
        config.write_text(json.dumps({
            "models": [
                {"provider": "anthropic", "model": "claude-haiku-4-5", "api_key": "a"},
            ]
        }))
        monkeypatch.setenv("RAPTOR_CONFIG", str(config))

        with patch.object(
            model_resolution, "_fetch_inventory",
            side_effect=RuntimeError("nope"),
        ):
            entries = _read_config_models()
            # Verbatim passthrough; no crash, no rewrite.
            assert entries[0]["model"] == "claude-haiku-4-5"
            assert "_configured_model" not in entries[0]
