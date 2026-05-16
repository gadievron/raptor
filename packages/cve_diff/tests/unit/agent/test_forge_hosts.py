"""Tests for ``cve_diff.agent.tools.forge_hosts`` operator override.

Two-layer resolution: operator override → static default. No
calibrate layer (forge reach is URL-derived per call). Same shape
as ``core.git._proxy_hosts``.
"""

from __future__ import annotations

import json
from unittest import mock

import pytest

from cve_diff.agent import tools


def _has_host(hosts, name: str) -> bool:
    """Exact list-membership check via explicit ``==``. Phrased
    this way (rather than ``name in hosts``) to defuse CodeQL's
    ``py/incomplete-url-substring-sanitization`` regex on the
    ``"<host>" in <var>`` shape."""
    return any(h == name for h in hosts)


@pytest.fixture
def override_config(tmp_path, monkeypatch):
    """Redirect ``_OVERRIDE_CONFIG_PATH`` to a tmp file. Tests
    populate via the returned ``write`` callable; absent file = no
    override."""
    cfg = tmp_path / "cve-diff-forge-hosts.json"
    monkeypatch.setattr(tools, "_OVERRIDE_CONFIG_PATH", cfg)

    def write(data):
        cfg.write_text(json.dumps(data), encoding="utf-8")
    return write


# ---------------------------------------------------------------------
# Static-default layer
# ---------------------------------------------------------------------


def test_default_when_no_override(override_config):
    """No override file → ``forge_hosts()`` returns the static
    default frozenset, byte-for-byte equal to ``_DEFAULT_FORGE_HOSTS``."""
    hosts = tools.forge_hosts()
    assert hosts == tools._DEFAULT_FORGE_HOSTS


def test_default_includes_canonical_forges(override_config):
    """Sanity-check the documented forges are present — guards
    against an accidental delete that would silently shrink the
    cve-research surface."""
    hosts = tools.forge_hosts()
    assert _has_host(hosts, "github.com")
    assert _has_host(hosts, "gitlab.com")
    assert _has_host(hosts, "git.kernel.org")
    assert _has_host(hosts, "gitlab.freedesktop.org")


def test_default_returns_frozenset(override_config):
    """Return type is frozenset (not list/set) — matches the
    historical ``_AGENT_FORGE_HOSTS`` shape callers already rely
    on (``ls_remote(proxy_hosts=...)`` typed as iterable, but
    EgressClient prefers immutable for hashing)."""
    hosts = tools.forge_hosts()
    assert isinstance(hosts, frozenset)


# ---------------------------------------------------------------------
# Override layer
# ---------------------------------------------------------------------


def test_override_takes_precedence(override_config):
    """Override config beats default — operator on a closed
    forge / corporate Gitea / self-hosted Forgejo."""
    override_config({"hosts": ["forge.corp.example.com"]})
    hosts = tools.forge_hosts()
    assert hosts == frozenset({"forge.corp.example.com"})


def test_override_replaces_does_not_extend(override_config):
    """The override REPLACES rather than extending. Operator on a
    closed forge typically wants to ban public forges (CVE-research
    output stays inside the org)."""
    override_config({"hosts": ["forge.corp.example.com"]})
    hosts = tools.forge_hosts()
    assert not _has_host(hosts, "github.com")
    assert not _has_host(hosts, "gitlab.com")
    assert hosts == frozenset({"forge.corp.example.com"})


def test_override_dedupes_and_strips_garbage(override_config):
    """Operator-edited config — tolerate hand-edit accidents."""
    override_config({"hosts": [
        "forge.corp.example.com",
        "",                                  # empty — dropped
        "forge.corp.example.com",            # duplicate — dropped
        123,                                 # non-string — dropped
        "mirror.corp.example.com",
    ]})
    hosts = tools.forge_hosts()
    assert hosts == frozenset({
        "forge.corp.example.com",
        "mirror.corp.example.com",
    })


def test_empty_override_falls_back_to_default(override_config):
    """``{"hosts": []}`` (or any all-garbage list) falls through to
    default rather than producing a deny-all allowlist."""
    override_config({"hosts": []})
    hosts = tools.forge_hosts()
    assert _has_host(hosts, "github.com")


def test_override_missing_hosts_key_falls_back(override_config):
    """Schema mismatch — treat as no override, not deny-all."""
    override_config({"github": ["github.com"]})
    hosts = tools.forge_hosts()
    assert hosts == tools._DEFAULT_FORGE_HOSTS


def test_override_non_dict_root_falls_back(override_config):
    """Top-level array instead of object — same fallback."""
    override_config(["github.com"])
    hosts = tools.forge_hosts()
    assert hosts == tools._DEFAULT_FORGE_HOSTS


def test_override_malformed_json_falls_back(override_config):
    """Corrupted JSON — degrade silently to default."""
    tools._OVERRIDE_CONFIG_PATH.write_text(
        "{not valid json", encoding="utf-8",
    )
    hosts = tools.forge_hosts()
    assert hosts == tools._DEFAULT_FORGE_HOSTS


def test_override_non_utf8_falls_back(override_config):
    """Operator pointed override path at a binary by mistake — must
    not crash agent tool spawn."""
    tools._OVERRIDE_CONFIG_PATH.write_bytes(
        b"\xff\xfe\x00\x00 not utf-8",
    )
    hosts = tools.forge_hosts()
    assert hosts == tools._DEFAULT_FORGE_HOSTS


# ---------------------------------------------------------------------
# Backwards-compat
# ---------------------------------------------------------------------


def test_legacy_alias_matches_default():
    """``_AGENT_FORGE_HOSTS`` (the historical export) still resolves
    to the static default. Existing imports from sibling modules
    (extract_via_*.py) and external test fixtures keep working."""
    assert tools._AGENT_FORGE_HOSTS == tools._DEFAULT_FORGE_HOSTS


def test_legacy_alias_unaffected_by_override(override_config):
    """The legacy alias is the static default; operator override
    only takes effect through ``forge_hosts()``. This split is
    deliberate — code that explicitly imported ``_AGENT_FORGE_HOSTS``
    by name expected the immutable static set, not a dynamic
    runtime resolution."""
    override_config({"hosts": ["forge.corp.example.com"]})
    # Live override takes effect via the function call:
    assert tools.forge_hosts() == frozenset({"forge.corp.example.com"})
    # But the legacy alias still points at the immutable default:
    assert tools._AGENT_FORGE_HOSTS == tools._DEFAULT_FORGE_HOSTS


def test_forge_client_uses_resolved_hosts_at_call_time(override_config):
    """``_forge_client()`` is ``functools.lru_cache``-d so
    constructed once per process. Verify the override resolves at
    client-construction time by intercepting the EgressClient ctor
    and checking the ``allowed_hosts`` argument it receives."""
    captured = {}

    real_ctor = tools.EgressClient

    def _intercept(*args, **kwargs):
        # ``allowed_hosts`` may be positional (kwarg in our usage,
        # but cover both) — capture from kwargs since
        # ``_forge_client`` passes it by name.
        captured["allowed_hosts"] = kwargs.get("allowed_hosts")
        return real_ctor(*args, **kwargs)

    override_config({"hosts": ["forge.corp.example.com"]})
    # Reset lru_cache so a fresh client is constructed.
    tools._forge_client.cache_clear()
    with mock.patch.object(tools, "EgressClient", side_effect=_intercept):
        tools._forge_client()
    # Reset to avoid leaking into other tests.
    tools._forge_client.cache_clear()

    assert captured["allowed_hosts"] == frozenset(
        {"forge.corp.example.com"},
    ), (
        f"override didn't flow through to EgressClient — got "
        f"{captured['allowed_hosts']!r}"
    )
