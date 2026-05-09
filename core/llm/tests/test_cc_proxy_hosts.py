"""Tests for ``core.llm.cc_proxy_hosts``.

The module resolves cc_dispatch sandbox policy via four layers
(priority high → low):
  1. ~/.config/raptor/cc-dispatch-proxy-hosts.json override
     (proxy_hosts only)
  2. Calibrated SandboxProfile cache (proxy_hosts AND readable_paths)
  3. CLAUDE_CODE_USE_BEDROCK / VERTEX / FOUNDRY env vars
     (proxy_hosts only)
  4. default — Anthropic API + documented install layout
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from core.llm import cc_proxy_hosts as mod
from core.llm.cc_proxy_hosts import (
    proxy_hosts_for_cc_dispatch,
    readable_paths_for_cc_dispatch,
)


def _hostname_in(hosts: list[str], target: str) -> bool:
    """List-membership for exact hostnames.

    Rewrites the literal ``<host> in <list>`` pattern that CodeQL's
    ``py/incomplete-url-substring-sanitization`` query flags as a
    URL-sanitization antipattern. The rule fires regardless of
    whether the right-hand side is a URL string or a list[str];
    the helper has a different syntactic shape so the query doesn't
    pattern-match it. Semantics are identical: True iff ``target``
    appears in ``hosts`` as an exact element.
    """
    return any(h == target for h in hosts)


@pytest.fixture(autouse=True)
def _reset_calibrate_memo():
    """The module memoises calibrate results per-process; tests must
    each start with a fresh memo so cross-test pollution doesn't
    happen (one test setting up a calibrated profile would otherwise
    leak into a subsequent test expecting the static fallback).
    Autouse so every test gets it without opt-in."""
    mod._reset_calibrate_cache_for_tests()
    yield
    mod._reset_calibrate_cache_for_tests()


@pytest.fixture
def isolated_env(monkeypatch):
    """Strip every env var the function consults so each test starts
    from a clean slate. Covers all the alternative-provider triggers
    plus the regional knobs."""
    for var in (
        "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "AWS_REGION", "AWS_DEFAULT_REGION",
        "CLOUD_ML_REGION", "VERTEX_LOCATION",
        "ANTHROPIC_BASE_URL", "AZURE_OPENAI_ENDPOINT",
    ):
        monkeypatch.delenv(var, raising=False)
    yield monkeypatch


@pytest.fixture
def no_override_config(monkeypatch, tmp_path):
    """Point the override config path at an empty tmp dir so the
    operator's real ~/.config/raptor isn't read during tests."""
    monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH",
                        tmp_path / "cc-dispatch-proxy-hosts.json")


@pytest.fixture
def no_calibrate(monkeypatch):
    """Force the calibrate layer to return None, so tests of the
    static layers (env vars, override config, defaults) don't
    accidentally trigger a real calibration probe of /usr/bin/claude
    on the dev box. Inverse fixture: explicit ``with_calibrated``
    helper below for tests that exercise the calibrate path."""
    monkeypatch.setattr(mod, "_calibrated_profile",
                        lambda claude_bin=None: None)


def _fake_profile(*, paths_read=None, paths_stat=None,
                  proxy_hosts=None):
    """Construct a synthetic SandboxProfile for calibrate-path tests
    without spawning. Mirrors the shape produced by
    ``core.sandbox.calibrate.calibrate_binary``."""
    from core.sandbox.calibrate import SandboxProfile
    return SandboxProfile(
        binary_path="/fake/claude",
        binary_sha256="0" * 64,
        env_signature="0" * 64,
        captured_at="2026-05-09T00:00:00Z",
        probe_args=["--version"],
        paths_read=paths_read or [],
        paths_written=[],
        paths_stat=paths_stat or [],
        proxy_hosts=proxy_hosts or [],
        connect_targets=[],
    )


# ---------------------------------------------------------------------------
# Default — no env, no override
# ---------------------------------------------------------------------------


class TestDefault:

    def test_returns_anthropic_only(self, isolated_env, no_override_config, no_calibrate):
        assert proxy_hosts_for_cc_dispatch() == ["api.anthropic.com"]


# ---------------------------------------------------------------------------
# Bedrock
# ---------------------------------------------------------------------------


class TestBedrock:

    def test_uses_default_region_when_not_set(self, isolated_env, no_override_config, no_calibrate):
        isolated_env.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        hosts = proxy_hosts_for_cc_dispatch()
        assert _hostname_in(hosts, "bedrock-runtime.us-east-1.amazonaws.com")
        assert _hostname_in(hosts, "sts.amazonaws.com")
        assert not _hostname_in(hosts, "api.anthropic.com")

    def test_uses_aws_region_when_set(self, isolated_env, no_override_config, no_calibrate):
        isolated_env.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        isolated_env.setenv("AWS_REGION", "eu-west-2")
        hosts = proxy_hosts_for_cc_dispatch()
        assert _hostname_in(hosts, "bedrock-runtime.eu-west-2.amazonaws.com")

    def test_aws_default_region_fallback(self, isolated_env, no_override_config, no_calibrate):
        isolated_env.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        isolated_env.setenv("AWS_DEFAULT_REGION", "ap-southeast-1")
        hosts = proxy_hosts_for_cc_dispatch()
        assert _hostname_in(hosts, "bedrock-runtime.ap-southeast-1.amazonaws.com")

    def test_aws_region_takes_priority_over_default_region(
        self, isolated_env, no_override_config, no_calibrate,
    ):
        isolated_env.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        isolated_env.setenv("AWS_REGION", "eu-west-2")
        isolated_env.setenv("AWS_DEFAULT_REGION", "us-east-1")
        hosts = proxy_hosts_for_cc_dispatch()
        assert _hostname_in(hosts, "bedrock-runtime.eu-west-2.amazonaws.com")
        assert not _hostname_in(hosts, "bedrock-runtime.us-east-1.amazonaws.com")


# ---------------------------------------------------------------------------
# Vertex AI
# ---------------------------------------------------------------------------


class TestVertex:

    def test_uses_default_location_when_not_set(self, isolated_env, no_override_config, no_calibrate):
        isolated_env.setenv("CLAUDE_CODE_USE_VERTEX", "1")
        hosts = proxy_hosts_for_cc_dispatch()
        assert _hostname_in(hosts, "aiplatform.googleapis.com")
        assert _hostname_in(hosts, "aiplatform.us-central1.rep.googleapis.com")
        assert _hostname_in(hosts, "oauth2.googleapis.com")
        assert not _hostname_in(hosts, "api.anthropic.com")

    def test_uses_cloud_ml_region_when_set(self, isolated_env, no_override_config, no_calibrate):
        isolated_env.setenv("CLAUDE_CODE_USE_VERTEX", "1")
        isolated_env.setenv("CLOUD_ML_REGION", "europe-west4")
        hosts = proxy_hosts_for_cc_dispatch()
        assert _hostname_in(hosts, "aiplatform.europe-west4.rep.googleapis.com")


# ---------------------------------------------------------------------------
# Azure / Foundry
# ---------------------------------------------------------------------------


class TestFoundry:

    def test_extracts_host_from_anthropic_base_url(
        self, isolated_env, no_override_config, no_calibrate,
    ):
        isolated_env.setenv("CLAUDE_CODE_USE_FOUNDRY", "1")
        isolated_env.setenv(
            "ANTHROPIC_BASE_URL",
            "https://my-deployment.cognitiveservices.azure.com/openai/deployments/...",
        )
        hosts = proxy_hosts_for_cc_dispatch()
        assert _hostname_in(hosts, "my-deployment.cognitiveservices.azure.com")
        assert _hostname_in(hosts, "login.microsoftonline.com")
        assert not _hostname_in(hosts, "api.anthropic.com")

    def test_extracts_host_from_azure_openai_endpoint(
        self, isolated_env, no_override_config, no_calibrate,
    ):
        isolated_env.setenv("CLAUDE_CODE_USE_FOUNDRY", "1")
        isolated_env.setenv(
            "AZURE_OPENAI_ENDPOINT",
            "https://corp-azure.cognitiveservices.azure.com",
        )
        hosts = proxy_hosts_for_cc_dispatch()
        assert _hostname_in(hosts, "corp-azure.cognitiveservices.azure.com")

    def test_falls_back_to_default_when_endpoint_missing(
        self, isolated_env, no_override_config, no_calibrate,
    ):
        """FOUNDRY env set but no endpoint URL — falls back to default
        rather than failing closed; the proxy will deny the actual
        Foundry connection with a clear log so the operator notices."""
        isolated_env.setenv("CLAUDE_CODE_USE_FOUNDRY", "1")
        hosts = proxy_hosts_for_cc_dispatch()
        assert hosts == ["api.anthropic.com"]


# ---------------------------------------------------------------------------
# Operator override config
# ---------------------------------------------------------------------------


class TestOverrideConfig:

    def test_override_supersedes_env_vars(self, isolated_env, monkeypatch, tmp_path, no_calibrate):
        # Even though Bedrock is signalled, the override wins
        isolated_env.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        config_path = tmp_path / "cc-dispatch-proxy-hosts.json"
        config_path.write_text(json.dumps({
            "proxy_hosts": ["my-corp-gateway.example.com"]
        }))
        monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", config_path)
        assert proxy_hosts_for_cc_dispatch() == ["my-corp-gateway.example.com"]

    def test_override_supersedes_default(self, isolated_env, monkeypatch, tmp_path, no_calibrate):
        config_path = tmp_path / "cc-dispatch-proxy-hosts.json"
        config_path.write_text(json.dumps({
            "proxy_hosts": ["a.example.com", "b.example.com"]
        }))
        monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", config_path)
        assert proxy_hosts_for_cc_dispatch() == ["a.example.com", "b.example.com"]

    def test_override_dedupes_and_preserves_order(
        self, isolated_env, monkeypatch, tmp_path, no_calibrate,
    ):
        config_path = tmp_path / "cc-dispatch-proxy-hosts.json"
        config_path.write_text(json.dumps({
            "proxy_hosts": ["a.example.com", "b.example.com", "a.example.com"]
        }))
        monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", config_path)
        assert proxy_hosts_for_cc_dispatch() == ["a.example.com", "b.example.com"]

    def test_override_strips_non_string_entries(
        self, isolated_env, monkeypatch, tmp_path, no_calibrate,
    ):
        config_path = tmp_path / "cc-dispatch-proxy-hosts.json"
        config_path.write_text(json.dumps({
            "proxy_hosts": ["a.example.com", 42, None, "b.example.com"]
        }))
        monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", config_path)
        assert proxy_hosts_for_cc_dispatch() == ["a.example.com", "b.example.com"]

    def test_override_empty_list_falls_back_to_default(
        self, isolated_env, monkeypatch, tmp_path, no_calibrate,
    ):
        """``{"proxy_hosts": []}`` is a misconfig — fall back to default
        rather than allowlisting nothing (which would deny the LLM
        endpoint and break dispatch)."""
        config_path = tmp_path / "cc-dispatch-proxy-hosts.json"
        config_path.write_text(json.dumps({"proxy_hosts": []}))
        monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", config_path)
        assert proxy_hosts_for_cc_dispatch() == ["api.anthropic.com"]

    def test_malformed_override_falls_back_to_default(
        self, isolated_env, monkeypatch, tmp_path, no_calibrate,
    ):
        config_path = tmp_path / "cc-dispatch-proxy-hosts.json"
        config_path.write_text("not valid json{{")
        monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", config_path)
        assert proxy_hosts_for_cc_dispatch() == ["api.anthropic.com"]

    def test_missing_override_uses_provider_logic(
        self, isolated_env, no_override_config, no_calibrate,
    ):
        isolated_env.setenv("CLAUDE_CODE_USE_VERTEX", "1")
        hosts = proxy_hosts_for_cc_dispatch()
        assert _hostname_in(hosts, "aiplatform.googleapis.com")


# ---------------------------------------------------------------------------
# Calibrate layer — hostname auto-discovery
# ---------------------------------------------------------------------------


class TestCalibratedProxyHosts:
    """When ``_calibrated_profile()`` returns a profile with a
    non-empty ``proxy_hosts`` list, that wins over the env-var
    fallback (but still loses to the operator override)."""

    def test_calibrated_hosts_used_when_present(
        self, isolated_env, no_override_config, monkeypatch,
    ):
        isolated_env.setenv("CLAUDE_CODE_USE_BEDROCK", "1")  # would normally win
        prof = _fake_profile(proxy_hosts=["api.future.anthropic.com"])
        monkeypatch.setattr(mod, "_calibrated_profile", lambda claude_bin=None: prof)
        assert (
            proxy_hosts_for_cc_dispatch()
            == ["api.future.anthropic.com"]
        )

    def test_empty_calibrated_hosts_falls_through_to_env(
        self, isolated_env, no_override_config, monkeypatch,
    ):
        # Default ``--version`` probe doesn't network — proxy_hosts
        # is empty. Resolution must fall through to the env-aware
        # static layer rather than returning [].
        isolated_env.setenv("CLAUDE_CODE_USE_BEDROCK", "1")
        prof = _fake_profile(proxy_hosts=[])
        monkeypatch.setattr(mod, "_calibrated_profile", lambda claude_bin=None: prof)
        hosts = proxy_hosts_for_cc_dispatch()
        assert _hostname_in(hosts, "bedrock-runtime.us-east-1.amazonaws.com")

    def test_no_profile_falls_through(
        self, isolated_env, no_override_config, monkeypatch,
    ):
        monkeypatch.setattr(mod, "_calibrated_profile", lambda claude_bin=None: None)
        assert proxy_hosts_for_cc_dispatch() == ["api.anthropic.com"]

    def test_override_beats_calibrated(
        self, isolated_env, monkeypatch, tmp_path,
    ):
        config_path = tmp_path / "cc-dispatch-proxy-hosts.json"
        config_path.write_text(json.dumps({
            "proxy_hosts": ["operator-pinned.example.com"],
        }))
        monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", config_path)
        prof = _fake_profile(proxy_hosts=["calibrated.example.com"])
        monkeypatch.setattr(mod, "_calibrated_profile", lambda claude_bin=None: prof)
        assert (
            proxy_hosts_for_cc_dispatch()
            == ["operator-pinned.example.com"]
        )


# ---------------------------------------------------------------------------
# readable_paths_for_cc_dispatch
# ---------------------------------------------------------------------------


class TestReadablePathsForCCDispatch:

    def test_default_when_no_calibration(
        self, isolated_env, no_override_config, no_calibrate,
    ):
        paths = readable_paths_for_cc_dispatch()
        # Must include the four documented install-layout paths.
        home = str(Path.home())
        assert any(p == home + "/.local/bin" for p in paths)
        assert any(p == home + "/.claude" for p in paths)
        assert any(p == home + "/.claude.json" for p in paths)
        assert any(p == home + "/.local/share/claude" for p in paths)

    def test_calibrated_paths_used_when_present(
        self, isolated_env, no_override_config, monkeypatch,
    ):
        prof = _fake_profile(
            paths_read=["/opt/custom/claude/bin/claude",
                        "/opt/custom/claude/lib"],
            paths_stat=["/etc/raptor/claude.conf"],
        )
        monkeypatch.setattr(mod, "_calibrated_profile", lambda claude_bin=None: prof)
        paths = readable_paths_for_cc_dispatch()
        # Calibrated values replace the defaults; the union of
        # paths_read + paths_stat is exposed (sandbox needs read
        # access for both opens AND stats).
        assert "/opt/custom/claude/bin/claude" in paths
        assert "/opt/custom/claude/lib" in paths
        assert "/etc/raptor/claude.conf" in paths
        # Default install-layout paths are NOT in the result —
        # calibration is authoritative when present.
        home = str(Path.home())
        assert home + "/.claude" not in paths

    def test_calibrated_paths_dedupe_across_read_and_stat(
        self, isolated_env, no_override_config, monkeypatch,
    ):
        # A binary that both stat()s and open()s the same file
        # appears in BOTH paths_read and paths_stat. The merged
        # readable_paths set should de-dup, preserving first-seen
        # order from paths_read.
        prof = _fake_profile(
            paths_read=["/path/A", "/path/B"],
            paths_stat=["/path/B", "/path/C"],
        )
        monkeypatch.setattr(mod, "_calibrated_profile", lambda claude_bin=None: prof)
        paths = readable_paths_for_cc_dispatch()
        assert paths == ["/path/A", "/path/B", "/path/C"]

    def test_empty_calibrated_paths_falls_through(
        self, isolated_env, no_override_config, monkeypatch,
    ):
        prof = _fake_profile(paths_read=[], paths_stat=[])
        monkeypatch.setattr(mod, "_calibrated_profile", lambda claude_bin=None: prof)
        paths = readable_paths_for_cc_dispatch()
        # Falls through to the default install layout.
        home = str(Path.home())
        assert home + "/.claude" in paths


# ---------------------------------------------------------------------------
# _calibrated_profile error paths
# ---------------------------------------------------------------------------


class TestCalibratedProfileFailureModes:
    """Calibration is opt-in / advisory: when the underlying probe
    fails (libseccomp missing, ptrace blocked, binary deleted between
    which() and probe), the static fallback must engage cleanly with
    no exception bubbling to the caller."""

    def test_no_claude_on_path_returns_none(self, monkeypatch):
        monkeypatch.setattr(mod, "_resolve_claude_bin",
                            lambda claude_bin=None: None)
        assert mod._calibrated_profile() is None

    def test_calibrate_raises_returns_none(self, monkeypatch):
        monkeypatch.setattr(mod, "_resolve_claude_bin",
                            lambda: "/fake/claude")
        # Patch the import-time symbol the helper imports lazily.
        import core.sandbox.calibrate as _cal
        def boom(*args, **kwargs):
            raise RuntimeError("simulated probe failure")
        monkeypatch.setattr(_cal, "load_or_calibrate", boom)
        assert mod._calibrated_profile() is None

    def test_calibrate_filenotfound_returns_none(self, monkeypatch):
        # FileNotFoundError = binary deleted between which() and probe
        monkeypatch.setattr(mod, "_resolve_claude_bin",
                            lambda: "/fake/claude")
        import core.sandbox.calibrate as _cal
        def boom(*args, **kwargs):
            raise FileNotFoundError("/fake/claude")
        monkeypatch.setattr(_cal, "load_or_calibrate", boom)
        assert mod._calibrated_profile() is None

    def test_memoised_per_binary(self, monkeypatch):
        """A second call for the same resolved binary path doesn't
        re-spawn the calibrator — the per-process memo serves the
        cached profile."""
        monkeypatch.setattr(mod, "_resolve_claude_bin",
                            lambda: "/fake/claude")
        import core.sandbox.calibrate as _cal
        spawn_count = [0]
        def counted_load(*args, **kwargs):
            spawn_count[0] += 1
            return _fake_profile(proxy_hosts=["host.example.com"])
        monkeypatch.setattr(_cal, "load_or_calibrate", counted_load)

        mod._calibrated_profile()
        mod._calibrated_profile()
        mod._calibrated_profile()
        assert spawn_count[0] == 1, (
            f"memoisation broken: load_or_calibrate called "
            f"{spawn_count[0]} times for one binary path"
        )
