"""Tests for ``core.git._proxy_hosts``.

Two-layer resolution: operator override → static default. No
calibrate layer (git's network reach is URL-derived per call,
not binary-scoped).
"""

from __future__ import annotations

import json

import pytest

from core.git import _proxy_hosts as mod


def _has_host(hosts: list, name: str) -> bool:
    """Exact list-membership check via explicit ``==``. Phrased
    this way (rather than ``name in hosts``) to defuse CodeQL's
    ``py/incomplete-url-substring-sanitization`` regex, which
    fires on the ``"<host>" in <var>`` shape regardless of
    whether ``<var>`` is a list (this case — exact == match)
    or a URL string (the substring-sanitization vulnerability
    the rule actually targets)."""
    return any(h == name for h in hosts)


@pytest.fixture
def override_config(tmp_path, monkeypatch):
    """Redirect ``_OVERRIDE_CONFIG_PATH`` to a tmp file. Tests call
    the returned ``write`` to populate it; absent file = no override."""
    cfg = tmp_path / "git-proxy-hosts.json"
    monkeypatch.setattr(mod, "_OVERRIDE_CONFIG_PATH", cfg)

    def write(data):
        cfg.write_text(json.dumps(data), encoding="utf-8")
    return write


def test_default_when_no_override(override_config):
    """Cold path: no override file → public-forge default returned
    verbatim, in declared order."""
    hosts = mod.proxy_hosts_for_git()
    assert hosts == [
        "github.com", "gitlab.com",
        "codeload.github.com", "objects.githubusercontent.com",
        "raw.githubusercontent.com", "media.githubusercontent.com",
    ]


def test_returns_fresh_list_each_call(override_config):
    """Caller-mutation safety: ``ls_remote`` callers append the URL's
    host to the returned list, so a shared mutable default would leak
    cross-call. Verify each call returns a new list."""
    a = mod.proxy_hosts_for_git()
    b = mod.proxy_hosts_for_git()
    assert a == b
    assert a is not b
    a.append("mutation.example.com")
    c = mod.proxy_hosts_for_git()
    assert "mutation.example.com" not in c


def test_override_takes_precedence(override_config):
    """Override config beats default — operator on a private mirror
    bans public clones (supply-chain hygiene boundary)."""
    override_config({"hosts": ["git.corp.example.com"]})
    assert mod.proxy_hosts_for_git() == ["git.corp.example.com"]


def test_override_replaces_does_not_extend(override_config):
    """The override REPLACES rather than extending the default. An
    operator who configured override:[mirror] doesn't expect public
    github to remain reachable — that would weaken the supply-chain
    boundary they're trying to enforce."""
    override_config({"hosts": ["git.corp.example.com"]})
    hosts = mod.proxy_hosts_for_git()
    assert not _has_host(hosts, "github.com")
    assert hosts == ["git.corp.example.com"]


def test_override_dedupes_and_strips_garbage(override_config):
    """Operator-edited config; tolerate hand-edit accidents."""
    override_config({"hosts": [
        "git.corp.example.com",
        "",                             # empty — dropped
        "git.corp.example.com",         # duplicate — dropped
        123,                            # non-string — dropped
        "mirror.corp.example.com",
    ]})
    assert mod.proxy_hosts_for_git() == [
        "git.corp.example.com", "mirror.corp.example.com",
    ]


def test_empty_override_falls_back_to_default(override_config):
    """``{"hosts": []}`` (or any all-garbage list) falls through to
    the default rather than producing a deny-all allowlist —
    operators wouldn't write that intentionally."""
    override_config({"hosts": []})
    hosts = mod.proxy_hosts_for_git()
    # Falls through to defaults.
    assert _has_host(hosts, "github.com")


def test_override_missing_hosts_key_falls_back(override_config):
    """Schema mismatch: operator wrote the wrong shape (e.g.
    ``{"github": [...]}``). Treat as no override, not as deny-all."""
    override_config({"github": ["github.com"]})
    hosts = mod.proxy_hosts_for_git()
    assert _has_host(hosts, "github.com")
    assert len(hosts) >= 6  # default set


def test_override_non_dict_root_falls_back(override_config):
    """Top-level array instead of object — same fallback."""
    override_config(["github.com"])
    hosts = mod.proxy_hosts_for_git()
    assert _has_host(hosts, "github.com")
    assert len(hosts) >= 6


def test_override_malformed_json_falls_back(override_config):
    """Corrupted JSON: degrade silently to the default rather than
    crash the clone path. Production failure is loud at the proxy
    if the resolved allowlist mismatches the URL."""
    mod._OVERRIDE_CONFIG_PATH.write_text("{not valid json", encoding="utf-8")
    hosts = mod.proxy_hosts_for_git()
    assert _has_host(hosts, "github.com")


def test_override_non_utf8_falls_back(override_config):
    """Operator pointed override path at a binary by mistake — must
    not crash the clone path."""
    mod._OVERRIDE_CONFIG_PATH.write_bytes(b"\xff\xfe\x00\x00 not utf-8")
    hosts = mod.proxy_hosts_for_git()
    assert _has_host(hosts, "github.com")


def test_clone_module_uses_helper():
    """``core.git.clone`` routes through ``proxy_hosts_for_git`` —
    the wiring is alive, not just the helper module."""
    from core.git import clone as clone_mod
    assert hasattr(clone_mod, "_proxy_hosts_for_git")
    # Sanity check: the helper is the same callable we imported here.
    assert clone_mod._proxy_hosts_for_git is mod.proxy_hosts_for_git


def test_clone_module_preserves_legacy_proxy_hosts_constant():
    """Backwards-compat: callers / tests that referenced
    ``core.git.clone._PROXY_HOSTS`` directly still work. The constant
    points at the static default tuple (override config NOT applied),
    matching pre-change semantics."""
    from core.git import clone as clone_mod
    assert clone_mod._PROXY_HOSTS == (
        "github.com", "gitlab.com",
        "codeload.github.com", "objects.githubusercontent.com",
        "raw.githubusercontent.com", "media.githubusercontent.com",
    )
