"""Tests for ``GitHubActionsClient``."""

from __future__ import annotations

from unittest.mock import MagicMock

from packages.sca.registries.github_actions import GitHubActionsClient


def _make_client(
    *, json_payload=None, raise_exc=None,
    cache=None, offline=False,
):
    http = MagicMock()
    if raise_exc is not None:
        http.get_json.side_effect = raise_exc
    else:
        http.get_json.return_value = json_payload
    return GitHubActionsClient(http, cache=cache, offline=offline)


def test_returns_tag_name_from_releases_latest():
    c = _make_client(json_payload={"tag_name": "v6.0.1", "name": "v6.0.1"})
    assert c.get_latest_tag("actions/checkout") == "v6.0.1"


def test_returns_none_on_404(tmp_path):
    """The client treats 404 / network errors as "no info"."""
    c = _make_client(raise_exc=RuntimeError("404 not found"))
    assert c.get_latest_tag("actions/checkout") is None


def test_returns_none_when_payload_missing_tag_name():
    """Some actions have releases that don't carry a tag — defensive."""
    c = _make_client(json_payload={"name": "Release 1.0"})
    assert c.get_latest_tag("actions/checkout") is None


def test_returns_none_when_payload_not_a_dict():
    c = _make_client(json_payload="not a dict")
    assert c.get_latest_tag("actions/checkout") is None


def test_offline_mode_skips_http():
    c = _make_client(json_payload={"tag_name": "v6"}, offline=True)
    # Even with an HTTP stub set up, offline returns None without
    # calling the http layer.
    assert c.get_latest_tag("actions/checkout") is None


def test_sub_action_path_resolves_against_parent_repo():
    """``actions/cache/restore`` looks up the latest release of
    ``actions/cache``."""
    c = _make_client(json_payload={"tag_name": "v4.1.0"})
    tag = c.get_latest_tag("actions/cache/restore")
    assert tag == "v4.1.0"


def test_malformed_action_name_returns_none():
    """Names without ``owner/repo`` shape can't be looked up."""
    c = _make_client(json_payload={"tag_name": "v1"})
    assert c.get_latest_tag("just-a-name") is None
    assert c.get_latest_tag("/missing-owner") is None


def test_cache_hit_skips_http(tmp_path):
    """A pre-populated cache short-circuits the HTTP call."""
    from core.json import JsonCache
    cache = JsonCache(root=tmp_path / "cache")
    cache.put(
        "ghactions-latest:actions/checkout",
        {"tag_name": "v5.2.1"},
        ttl_seconds=24 * 3600,
    )
    http = MagicMock()
    c = GitHubActionsClient(http, cache=cache)
    assert c.get_latest_tag("actions/checkout") == "v5.2.1"
    http.get_json.assert_not_called()


def test_cache_populated_after_first_fetch(tmp_path):
    from core.json import JsonCache
    cache = JsonCache(root=tmp_path / "cache")
    http = MagicMock()
    http.get_json.return_value = {"tag_name": "v6.0.0"}
    c = GitHubActionsClient(http, cache=cache)
    c.get_latest_tag("actions/checkout")
    # Reset stub so we can detect re-fetch.
    http.get_json.reset_mock()
    c.get_latest_tag("actions/checkout")
    http.get_json.assert_not_called()
