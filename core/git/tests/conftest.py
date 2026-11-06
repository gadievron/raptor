"""Shared fixtures for ``core.git`` tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_git_proxy_hosts_override(tmp_path, monkeypatch):
    """Point the operator proxy-hosts override at a per-test path.

    ``clone_repository`` / ``fetch_commit`` resolve their egress
    allowlist through ``proxy_hosts_for_git()``, which reads the REAL
    ``~/.config/raptor/git-proxy-hosts.json``. On a host where the
    operator has an override configured (documented use: private
    mirrors that ban the public forges) every test asserting the
    static default hosts would fail — env-dependent without gating.
    Redirect the config path so tests always see "no override" unless
    they write one themselves (test_proxy_hosts.py re-patches with its
    own fixture, which layers cleanly on top of this one).
    """
    from core.git import _proxy_hosts as mod

    monkeypatch.setattr(
        mod, "_OVERRIDE_CONFIG_PATH",
        tmp_path / "git-proxy-hosts-isolated.json",
    )


@pytest.fixture(autouse=True)
def _owned_tool_scratch():
    from core.testing.scratch_state import isolated_scratch_keepalive

    with isolated_scratch_keepalive():
        yield
