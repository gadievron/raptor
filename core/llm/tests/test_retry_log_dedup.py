"""End-to-end regression test for the retry-failure log dedup.

Pre-fix each upstream failure produced 4 operator-visible lines
(dispatcher request.error INFO + provider 'X completion failed'
ERROR + client 'Attempt N/M failed' WARNING + client 'Retrying'
INFO). Post-fix only the WARNING survives at operator-visible
levels; the rest demote to DEBUG.

These tests exercise the CLIENT path of the dedup — they patch
the LLMClient's logger methods and count emissions per level
after a forced provider failure. The dispatcher path is covered
by ``test_log_quiet.py``; the provider path's demotion is
verified by inspecting the source-level log calls (see
``test_provider_completion_failed_uses_debug`` below).

The RaptorLogger sets ``propagate=False`` (see
``core/logging/__init__.py:RaptorLogger``), so ``caplog`` does
not capture from it; ``monkeypatch.setattr`` on each level
method is the working capture strategy.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig


def _captured_logger(monkeypatch, module):
    """Patch every log-level method on ``module.logger`` and return
    a dict that collects per-level message strings as the test
    runs. Restored automatically by monkeypatch on test teardown."""
    captured: dict = {
        "debug": [], "info": [], "warning": [], "error": [],
    }
    # Each level captured in its own list — bind the level into
    # the closure via a default-arg trick (avoids the classic
    # late-binding-loop bug).
    for level in ("debug", "info", "warning", "error"):
        def _make_sink(_level=level):
            def _sink(msg, *args, **kwargs):
                # Honour %-formatting the way logger.warning("x %s", y) would.
                try:
                    rendered = str(msg) % args if args else str(msg)
                except (TypeError, ValueError):
                    rendered = str(msg)
                captured[_level].append(rendered)
            return _sink
        monkeypatch.setattr(module.logger, level, _make_sink())
    return captured


def _model(provider: str, name: str) -> ModelConfig:
    return ModelConfig(
        provider=provider, model_name=name, api_key="test-key",
    )


def _config(primary: ModelConfig, *, max_retries: int = 3) -> LLMConfig:
    return LLMConfig(
        primary_model=primary, fallback_models=[],
        enable_caching=False, max_retries=max_retries,
        enable_fallback=False,
    )


class TestClientRetryLogCluster:
    """One operator-visible WARNING per attempt; no 'Retrying' INFO
    or other interstitial chatter."""

    def test_three_attempts_emit_only_warnings(self, monkeypatch):
        # Setup: single model, 3 retries, every attempt fails with
        # a RETRYABLE error ("timeout" matches _is_retryable_error's
        # pattern set; non-retryable errors break after attempt 1).
        # Patch time.sleep to instant — the retry backoff would
        # otherwise add 6+ seconds per test.
        import core.llm.client as client_mod
        monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)

        primary = _model("anthropic", "primary")
        config = _config(primary, max_retries=3)
        client = LLMClient(config)

        cap = _captured_logger(monkeypatch, client_mod)

        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = RuntimeError(
                "simulated timeout from upstream",
            )
            mock_get.return_value = prov
            with pytest.raises(Exception):
                client.generate("test prompt")

        # Operator-visible WARNINGs: 3 'Attempt N/3 failed' + 1
        # 'All attempts failed' terminal. No fallback model, so
        # no 'Falling back to:' line.
        attempt_warnings = [
            m for m in cap["warning"]
            if "Attempt" in m and "failed for" in m
        ]
        assert len(attempt_warnings) == 3, (
            f"expected 3 'Attempt N/3 failed' warnings, got: "
            f"{attempt_warnings}"
        )
        assert any(
            "All attempts failed" in m for m in cap["warning"]
        ), f"expected 'All attempts failed' warning, got: {cap['warning']}"

        # CRITICAL: no 'Retrying ...' INFO. Pre-fix this fired
        # twice (between attempts 1→2 and 2→3); post-fix it's DEBUG.
        retrying_infos = [m for m in cap["info"] if "Retrying" in m]
        assert retrying_infos == [], (
            f"'Retrying ...' should now be DEBUG; got INFO: "
            f"{retrying_infos}"
        )

        # The DEBUG counterpart of the demoted "Retrying
        # <provider>/<model>" line should fire — confirms the
        # demotion is a level change, not deletion. Use a
        # specific match (mentions the attempt counter) so the
        # pre-existing "Retrying in Ns..." backoff DEBUG line
        # isn't counted.
        retrying_attempt_debugs = [
            m for m in cap["debug"]
            if "Retrying" in m and "(attempt" in m
        ]
        assert len(retrying_attempt_debugs) == 2, (
            f"expected 2 'Retrying ... (attempt N/3)' DEBUG lines "
            f"between attempts, got: {retrying_attempt_debugs}"
        )

    def test_single_attempt_emits_one_warning_no_retrying(
        self, monkeypatch,
    ):
        # max_retries=1 → one attempt, no 'Retrying' anywhere.
        primary = _model("anthropic", "primary")
        config = _config(primary, max_retries=1)
        client = LLMClient(config)

        import core.llm.client as client_mod
        cap = _captured_logger(monkeypatch, client_mod)

        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = RuntimeError("simulated timeout")
            mock_get.return_value = prov
            with pytest.raises(Exception):
                client.generate("test")

        attempt_warnings = [
            m for m in cap["warning"]
            if "Attempt" in m and "failed for" in m
        ]
        assert len(attempt_warnings) == 1
        # No 'Retrying' at any level (only one attempt).
        assert not any(
            "Retrying" in m
            for level in cap.values()
            for m in level
        )


class TestProviderCompletionFailedDemoted:
    """Source-level verification: each provider's ``except``
    block uses ``logger.debug`` (not ``logger.error``) for the
    'X completion failed' line.

    Source inspection rather than runtime — exercising the real
    provider's except block would need an HTTP-level failure
    against the dispatcher, which is integration-test territory.
    A future refactor that flips one of these back to ERROR (or
    deletes the log entirely) surfaces here at unit-test cost.
    """

    def test_openai_uses_debug_for_completion_failed(self):
        self._assert_uses_debug_not_error("OpenAI completion failed")

    def test_anthropic_uses_debug_for_completion_failed(self):
        self._assert_uses_debug_not_error("Anthropic completion failed")

    def test_gemini_uses_debug_for_completion_failed(self):
        self._assert_uses_debug_not_error("Gemini completion failed")

    def _assert_uses_debug_not_error(self, message_prefix: str):
        from pathlib import Path
        providers_src = (
            Path(__file__).resolve().parents[1] / "providers.py"
        ).read_text()
        # Find the line containing the message; assert the
        # preceding logger call on that or the previous line is
        # `.debug(` not `.error(`. Cheap regex sufficient — full
        # AST would over-engineer this guard.
        lines = providers_src.splitlines()
        for i, line in enumerate(lines):
            if message_prefix in line:
                # The logger call could be on this line or on the
                # previous line (multi-line call). Look back up to
                # 2 lines for the logger.X( token.
                context = "\n".join(lines[max(0, i - 2): i + 1])
                assert ".debug(" in context, (
                    f"{message_prefix!r} should be logged at DEBUG "
                    f"(LLMClient retry loop emits the WARNING); "
                    f"found context:\n{context}"
                )
                assert ".error(" not in context, (
                    f"{message_prefix!r} found at ERROR level — "
                    f"would double up with the LLMClient WARNING. "
                    f"Context:\n{context}"
                )
                return
        pytest.fail(
            f"could not find {message_prefix!r} in providers.py — "
            f"the log line may have been moved or renamed; "
            f"update the test"
        )
