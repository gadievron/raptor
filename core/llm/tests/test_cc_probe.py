"""Tests for core.llm.cc_probe — claudecode pre-flight probe."""

from __future__ import annotations

import json
import subprocess

import pytest

from core.llm import cc_probe
from core.llm.cc_probe import (
    extract_model_from_envelope,
    probe_cc_session_model,
)


class TestExtractModel:
    def test_single_model(self):
        env = {"modelUsage": {"anthropic.claude-mythos-5": {
            "outputTokens": 5}}}
        assert extract_model_from_envelope(env) == (
            "anthropic.claude-mythos-5"
        )

    def test_main_model_wins_over_helper(self):
        env = {"modelUsage": {
            "claude-haiku-4-5": {"outputTokens": 3},
            "anthropic.claude-mythos-5": {"outputTokens": 812},
        }}
        assert extract_model_from_envelope(env) == (
            "anthropic.claude-mythos-5"
        )

    def test_missing_usage(self):
        assert extract_model_from_envelope({}) is None
        assert extract_model_from_envelope({"modelUsage": {}}) is None

    def test_usage_without_token_counts(self):
        env = {"modelUsage": {"m1": {}}}
        assert extract_model_from_envelope(env) == "m1"


class TestCachePathOverride:
    def test_env_override_redirects_cache_path(self, monkeypatch, tmp_path):
        """RAPTOR_CC_PROBE_CACHE pins the on-disk probe cache away from
        ~/.raptor/cache — the isolation seam for tests and sandboxed
        runs (read at import time, hence the reload)."""
        import importlib
        from pathlib import Path

        monkeypatch.setenv(
            "RAPTOR_CC_PROBE_CACHE", str(tmp_path / "probe.json"),
        )
        try:
            mod = importlib.reload(cc_probe)
            assert mod._CACHE_PATH == tmp_path / "probe.json"
        finally:
            monkeypatch.delenv("RAPTOR_CC_PROBE_CACHE")
            mod = importlib.reload(cc_probe)
        assert mod._CACHE_PATH == (
            Path.home() / ".raptor" / "cache" / "cc-probe.json"
        )


class TestProbe:
    @pytest.fixture(autouse=True)
    def _no_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            cc_probe, "_CACHE_PATH", tmp_path / "cc-probe.json",
        )

    def _fake_run(self, monkeypatch, *, stdout="", returncode=0,
                  raise_exc=None):
        calls = []

        def run(cmd, **kwargs):
            calls.append((cmd, kwargs))
            if raise_exc is not None:
                raise raise_exc
            return subprocess.CompletedProcess(
                cmd, returncode, stdout=stdout, stderr="",
            )

        monkeypatch.setattr(cc_probe.subprocess, "run", run)
        return calls

    def test_success_returns_model_and_caches(self, monkeypatch):
        envelope = json.dumps({
            "type": "result", "is_error": False,
            "modelUsage": {"anthropic.claude-mythos-5": {
                "outputTokens": 4}},
        })
        calls = self._fake_run(monkeypatch, stdout=envelope)
        got = probe_cc_session_model("/usr/bin/true")
        assert got == "anthropic.claude-mythos-5"
        assert len(calls) == 1
        # Second call served from cache — no new subprocess.
        got2 = probe_cc_session_model("/usr/bin/true")
        assert got2 == "anthropic.claude-mythos-5"
        assert len(calls) == 1

    def test_nonzero_exit_returns_none(self, monkeypatch):
        self._fake_run(monkeypatch, returncode=1)
        assert probe_cc_session_model("/usr/bin/true") is None

    def test_timeout_returns_none(self, monkeypatch):
        self._fake_run(
            monkeypatch,
            raise_exc=subprocess.TimeoutExpired(["claude"], 1),
        )
        assert probe_cc_session_model("/usr/bin/true") is None

    def test_no_envelope_returns_none(self, monkeypatch):
        self._fake_run(monkeypatch, stdout="not json at all")
        assert probe_cc_session_model("/usr/bin/true") is None

    def test_missing_binary_returns_none(self, monkeypatch):
        monkeypatch.setattr(cc_probe.shutil, "which", lambda _: None)
        assert probe_cc_session_model(None) is None

    def test_env_signature_change_invalidates_cache(self, monkeypatch):
        envelope = json.dumps({
            "modelUsage": {"model-a": {"outputTokens": 4}},
        })
        calls = self._fake_run(monkeypatch, stdout=envelope)
        monkeypatch.setenv("ANTHROPIC_MODEL", "model-a")
        assert probe_cc_session_model("/usr/bin/true") == "model-a"
        monkeypatch.setenv("ANTHROPIC_MODEL", "model-b")
        assert probe_cc_session_model("/usr/bin/true") == "model-a"
        assert len(calls) == 2  # cache miss on signature change

    def test_proxy_env_change_invalidates_cache(self, monkeypatch):
        """Proxy env changes liveness, not just model choice — a
        cached verdict must not outlive the route it was probed
        under."""
        envelope = json.dumps({
            "modelUsage": {"model-a": {"outputTokens": 4}},
        })
        calls = self._fake_run(monkeypatch, stdout=envelope)
        monkeypatch.setenv("HTTPS_PROXY", "http://proxy-a:3128")
        assert probe_cc_session_model("/usr/bin/true") == "model-a"
        assert probe_cc_session_model("/usr/bin/true") == "model-a"
        assert len(calls) == 1  # warm
        monkeypatch.setenv("NO_PROXY", "localhost,127.0.0.1")
        assert probe_cc_session_model("/usr/bin/true") == "model-a"
        assert len(calls) == 2  # cache miss on proxy change


class TestCachedRead:
    """cached_cc_session_model — cache-only, never spawns a probe."""

    @pytest.fixture(autouse=True)
    def _no_cache(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            cc_probe, "_CACHE_PATH", tmp_path / "cc-probe.json",
        )
        self._cache_path = tmp_path / "cc-probe.json"

    def test_cold_cache_returns_none_without_probing(self, monkeypatch):
        from core.llm.cc_probe import cached_cc_session_model

        def boom(*a, **k):
            raise AssertionError("cache-only read must not spawn claude")

        monkeypatch.setattr(cc_probe.subprocess, "run", boom)
        monkeypatch.setattr(
            cc_probe.shutil, "which", lambda name: "/usr/bin/claude",
        )
        assert cached_cc_session_model() is None

    def test_warm_cache_returns_model(self, monkeypatch):
        from core.llm.cc_probe import cached_cc_session_model

        monkeypatch.setattr(
            cc_probe.shutil, "which", lambda name: "/usr/bin/claude",
        )
        sig = cc_probe._backend_signature("/usr/bin/claude")
        cc_probe._write_cache(sig, "backend.claude-model-id")
        monkeypatch.setattr(
            cc_probe.subprocess, "run",
            lambda *a, **k: (_ for _ in ()).throw(AssertionError),
        )
        assert cached_cc_session_model() == "backend.claude-model-id"

    def test_no_claude_binary_returns_none(self, monkeypatch):
        from core.llm.cc_probe import cached_cc_session_model

        monkeypatch.setattr(cc_probe.shutil, "which", lambda name: None)
        assert cached_cc_session_model() is None
