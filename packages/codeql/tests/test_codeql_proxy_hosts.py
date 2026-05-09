"""Tests for ``packages.codeql.codeql_proxy_hosts``.

The module resolves CodeQL pack-download sandbox policy via three
layers (priority high → low):

  1. ``~/.config/raptor/codeql-proxy-hosts.json`` override
  2. Calibrated SandboxProfile (proxy_hosts AND readable_paths)
  3. Default GitHub Container Registry hosts + documented install
     layout

Symmetric with ``core/llm/cc_proxy_hosts`` for cc_dispatch — same
shape, same fallback behaviour, same memoisation contract.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from packages.codeql import codeql_proxy_hosts as mod
from packages.codeql.codeql_proxy_hosts import (
    proxy_hosts_for_codeql,
    readable_paths_for_codeql,
)


def _hostname_in(hosts: list[str], target: str) -> bool:
    """List-membership for exact hostnames.

    Same shape as ``test_cc_proxy_hosts._hostname_in`` — sidesteps
    CodeQL's ``py/incomplete-url-substring-sanitization`` query
    which pattern-matches ``<host> in <var>`` even when ``<var>``
    is a list[str] of hostnames rather than a URL.
    """
    return any(h == target for h in hosts)


@pytest.fixture(autouse=True)
def _reset_calibrate_memo():
    """Per-process memo isolation. Autouse so cross-test pollution
    can't leak a calibrated profile into a static-fallback test.
    Mirrors the cc_proxy_hosts test layout."""
    mod._reset_calibrate_cache_for_tests()
    yield
    mod._reset_calibrate_cache_for_tests()


@pytest.fixture
def isolated_env(monkeypatch):
    """Strip every env var the calibrate cache key consults so
    each test starts from a clean slate."""
    for var in mod._CODEQL_ENV_KEYS:
        monkeypatch.delenv(var, raising=False)
    yield monkeypatch


@pytest.fixture
def no_override_config(monkeypatch, tmp_path):
    """Point the override config path at an empty tmp dir so the
    operator's real ``~/.config/raptor`` isn't read during tests."""
    monkeypatch.setattr(
        mod, "_OVERRIDE_CONFIG_PATH",
        tmp_path / "codeql-proxy-hosts.json",
    )


@pytest.fixture
def no_calibrate(monkeypatch):
    """Force the calibrate layer to return None so static-fallback
    tests don't accidentally trigger a real calibration probe of
    /usr/bin/codeql on the dev box."""
    monkeypatch.setattr(
        mod, "_calibrated_profile",
        lambda codeql_bin=None: None,
    )


def _fake_profile(*, paths_read=None, paths_stat=None,
                  proxy_hosts=None):
    """Construct a synthetic SandboxProfile for calibrate-path
    tests without spawning. Mirrors the production shape from
    ``core.sandbox.calibrate.calibrate_binary``."""
    from core.sandbox.calibrate import SandboxProfile
    return SandboxProfile(
        binary_path="/fake/codeql",
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
# Default — no env, no override, no calibrate
# ---------------------------------------------------------------------------


class TestDefaultProxyHosts:

    def test_returns_documented_pack_download_hosts(
        self, isolated_env, no_override_config, no_calibrate,
    ):
        hosts = proxy_hosts_for_codeql()
        # Every host the historical hardcoded ``query_runner.py``
        # list shipped with must be present — the migration is
        # behaviour-preserving.
        for required in (
            "ghcr.io",
            "codeload.github.com",
            "objects.githubusercontent.com",
            "pkg-containers.githubusercontent.com",
        ):
            assert _hostname_in(hosts, required), (
                f"default proxy_hosts missing {required!r} — "
                f"breaks codeql pack download out of the box"
            )

    def test_returns_a_fresh_list(
        self, isolated_env, no_override_config, no_calibrate,
    ):
        # Caller-side mutation of the returned list must not leak
        # back into the module-level default tuple.
        hosts = proxy_hosts_for_codeql()
        hosts.append("attacker.example")
        hosts2 = proxy_hosts_for_codeql()
        assert not _hostname_in(hosts2, "attacker.example"), (
            "default-host fetcher must return a fresh list each "
            "call, not share state with prior callers"
        )


# ---------------------------------------------------------------------------
# Calibrated layer
# ---------------------------------------------------------------------------


class TestCalibratedProxyHosts:

    def test_calibrated_hosts_used_when_present(
        self, isolated_env, no_override_config, monkeypatch,
    ):
        prof = _fake_profile(
            proxy_hosts=["ghe.corp.example", "objects.ghe.corp.example"],
        )
        monkeypatch.setattr(
            mod, "_calibrated_profile",
            lambda codeql_bin=None: prof,
        )
        hosts = proxy_hosts_for_codeql()
        # Calibrated values replace the hardcoded GHCR set —
        # operator on enterprise GHE gets THEIR registry, not
        # vanilla github.
        assert hosts == ["ghe.corp.example", "objects.ghe.corp.example"]
        # Vanilla ghcr.io is NOT in the result; calibration is
        # authoritative when present.
        assert not _hostname_in(hosts, "ghcr.io")

    def test_empty_calibrated_falls_through_to_default(
        self, isolated_env, no_override_config, monkeypatch,
    ):
        # ``codeql --version`` doesn't network → empty proxy_hosts
        # in the cached profile. Resolution must fall through to
        # the hardcoded default (NOT return [] which would deny
        # every CONNECT and break pack download).
        prof = _fake_profile(proxy_hosts=[])
        monkeypatch.setattr(
            mod, "_calibrated_profile",
            lambda codeql_bin=None: prof,
        )
        hosts = proxy_hosts_for_codeql()
        assert _hostname_in(hosts, "ghcr.io")

    def test_no_profile_falls_through(
        self, isolated_env, no_override_config, monkeypatch,
    ):
        monkeypatch.setattr(
            mod, "_calibrated_profile",
            lambda codeql_bin=None: None,
        )
        hosts = proxy_hosts_for_codeql()
        assert _hostname_in(hosts, "ghcr.io")


# ---------------------------------------------------------------------------
# Override config
# ---------------------------------------------------------------------------


class TestOverrideConfig:

    def test_override_supersedes_calibrate_and_default(
        self, isolated_env, monkeypatch, tmp_path,
    ):
        config_path = tmp_path / "codeql-proxy-hosts.json"
        config_path.write_text(json.dumps({
            "proxy_hosts": ["ghe.corp.example"],
        }))
        monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", config_path)

        # Even with a calibrated profile in place, override wins.
        prof = _fake_profile(proxy_hosts=["calibrated.example"])
        monkeypatch.setattr(
            mod, "_calibrated_profile",
            lambda codeql_bin=None: prof,
        )

        assert proxy_hosts_for_codeql() == ["ghe.corp.example"]

    def test_override_dedupes_and_strips_non_strings(
        self, isolated_env, monkeypatch, tmp_path, no_calibrate,
    ):
        config_path = tmp_path / "codeql-proxy-hosts.json"
        config_path.write_text(json.dumps({
            "proxy_hosts": [
                "a.example", 42, None, "b.example", "a.example",
            ],
        }))
        monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", config_path)
        assert proxy_hosts_for_codeql() == ["a.example", "b.example"]

    def test_empty_override_falls_back(
        self, isolated_env, monkeypatch, tmp_path, no_calibrate,
    ):
        config_path = tmp_path / "codeql-proxy-hosts.json"
        config_path.write_text(json.dumps({"proxy_hosts": []}))
        monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", config_path)
        # Empty override is a misconfig — fall through rather than
        # allowlisting nothing (which would deny every pack
        # download). Same shape as cc_proxy_hosts.
        hosts = proxy_hosts_for_codeql()
        assert _hostname_in(hosts, "ghcr.io")

    def test_malformed_override_falls_back(
        self, isolated_env, monkeypatch, tmp_path, no_calibrate,
    ):
        config_path = tmp_path / "codeql-proxy-hosts.json"
        config_path.write_text("not valid json{{")
        monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", config_path)
        hosts = proxy_hosts_for_codeql()
        assert _hostname_in(hosts, "ghcr.io")


# ---------------------------------------------------------------------------
# readable_paths_for_codeql
# ---------------------------------------------------------------------------


class TestReadablePathsForCodeQL:

    def test_default_when_no_calibration(
        self, isolated_env, no_override_config, no_calibrate,
    ):
        paths = readable_paths_for_codeql()
        home = str(Path.home())
        # The three documented install-layout dirs.
        assert _hostname_in(paths, home + "/.codeql")
        assert _hostname_in(paths, home + "/.cache/codeql")
        assert _hostname_in(paths, home + "/.config/codeql")

    def test_calibrated_paths_used_when_present(
        self, isolated_env, no_override_config, monkeypatch,
    ):
        prof = _fake_profile(
            paths_read=["/opt/codeql-2.21/codeql"],
            paths_stat=["/etc/codeql/global.conf"],
        )
        monkeypatch.setattr(
            mod, "_calibrated_profile",
            lambda codeql_bin=None: prof,
        )
        paths = readable_paths_for_codeql()
        assert _hostname_in(paths, "/opt/codeql-2.21/codeql")
        assert _hostname_in(paths, "/etc/codeql/global.conf")
        # Default paths are NOT present — calibration is
        # authoritative when populated.
        home = str(Path.home())
        assert not _hostname_in(paths, home + "/.codeql")

    def test_calibrated_paths_dedupe_across_read_and_stat(
        self, isolated_env, no_override_config, monkeypatch,
    ):
        prof = _fake_profile(
            paths_read=["/path/A", "/path/B"],
            paths_stat=["/path/B", "/path/C"],
        )
        monkeypatch.setattr(
            mod, "_calibrated_profile",
            lambda codeql_bin=None: prof,
        )
        paths = readable_paths_for_codeql()
        assert paths == ["/path/A", "/path/B", "/path/C"]


# ---------------------------------------------------------------------------
# _calibrated_profile failure modes
# ---------------------------------------------------------------------------


class TestCalibratedProfileFailureModes:
    """Calibration is opt-in / advisory: every failure mode the
    underlying probe can hit must degrade silently to the static
    fallback rather than bubbling an exception to the caller."""

    def test_no_codeql_on_path_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            mod, "_resolve_codeql_bin", lambda: None,
        )
        assert mod._calibrated_profile() is None

    def test_calibrate_raises_returns_none(self, monkeypatch):
        monkeypatch.setattr(
            mod, "_resolve_codeql_bin", lambda: "/fake/codeql",
        )
        import core.sandbox.calibrate as _cal

        def boom(*args, **kwargs):
            raise RuntimeError("simulated probe failure")

        monkeypatch.setattr(_cal, "load_or_calibrate", boom)
        assert mod._calibrated_profile() is None

    def test_calibrate_filenotfound_returns_none(self, monkeypatch):
        # FileNotFoundError = binary deleted between which() and
        # probe (race against codeql self-update).
        monkeypatch.setattr(
            mod, "_resolve_codeql_bin", lambda: "/fake/codeql",
        )
        import core.sandbox.calibrate as _cal

        def boom(*args, **kwargs):
            raise FileNotFoundError("/fake/codeql")

        monkeypatch.setattr(_cal, "load_or_calibrate", boom)
        assert mod._calibrated_profile() is None

    def test_calibrate_timeout_returns_none(self, monkeypatch):
        # subprocess.TimeoutExpired = sandboxed `codeql --version`
        # exceeded the 20s probe cap (rare but observable on cold
        # systems / large CodeQL bundles). Must not propagate to
        # query_runner — fall through to the static default.
        import subprocess as _subprocess
        monkeypatch.setattr(
            mod, "_resolve_codeql_bin", lambda: "/fake/codeql",
        )
        import core.sandbox.calibrate as _cal

        def boom(*args, **kwargs):
            raise _subprocess.TimeoutExpired(
                ["/fake/codeql", "--version"], 20,
            )

        monkeypatch.setattr(_cal, "load_or_calibrate", boom)
        assert mod._calibrated_profile() is None

    def test_memoised_per_binary(self, monkeypatch):
        """A second call for the same resolved binary path doesn't
        re-spawn the calibrator — the per-process memo serves the
        cached profile. ``codeql analyze`` paths can dispatch
        several pack downloads in succession; per-call calibrate
        cost would dwarf the actual download otherwise."""
        monkeypatch.setattr(
            mod, "_resolve_codeql_bin", lambda: "/fake/codeql",
        )
        import core.sandbox.calibrate as _cal
        spawn_count = [0]

        def counted_load(*args, **kwargs):
            spawn_count[0] += 1
            return _fake_profile(proxy_hosts=["ghcr.example"])

        monkeypatch.setattr(_cal, "load_or_calibrate", counted_load)

        mod._calibrated_profile()
        mod._calibrated_profile()
        mod._calibrated_profile()
        assert spawn_count[0] == 1, (
            f"memoisation broken: load_or_calibrate called "
            f"{spawn_count[0]} times for one binary path"
        )


# ---------------------------------------------------------------------------
# Migration: query_runner.py routes pack-download proxy_hosts
# through this module
# ---------------------------------------------------------------------------


class TestQueryRunnerMigrationWiring:
    """The migration must route ``codeql pack download`` through
    ``proxy_hosts_for_codeql``. Fail this test if a future change
    re-introduces a hardcoded host list at the call site."""

    def test_query_runner_imports_proxy_hosts_for_codeql(self):
        # Source-level pin — the import statement is the contract.
        # If a contributor removes the import (intending to revert
        # to hardcoded), this test catches it before the rest of
        # the suite races to find the resulting behaviour drift.
        import inspect
        from packages.codeql import query_runner

        src = inspect.getsource(query_runner)
        assert "proxy_hosts_for_codeql" in src, (
            "query_runner.py must route proxy_hosts through "
            "codeql_proxy_hosts.proxy_hosts_for_codeql; the "
            "calibrate-aware policy is the load-bearing change"
        )

    def test_query_runner_no_longer_hardcodes_pack_hosts(self):
        # Belt-and-braces: the historic hardcoded set should not
        # appear as a literal list inside an unconditional
        # ``proxy_hosts=[...]`` call site any more. Allow it as a
        # default in codeql_proxy_hosts.py (where it's a single
        # source of truth), but not inline at the call site.
        import inspect
        from packages.codeql import query_runner

        src = inspect.getsource(query_runner)
        # Search for the canonical hardcoded triple. If it appears
        # AS A LITERAL LIST, the migration was reverted.
        signature = (
            '"ghcr.io",            # CodeQL packs hosted here'
        )
        assert signature not in src, (
            "query_runner.py contains the pre-migration hardcoded "
            "host list — the call site should use "
            "proxy_hosts_for_codeql() instead"
        )
