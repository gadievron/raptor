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
    # Key uses the percent-encoded slug (injective cache identity).
    cache.put(
        "ghactions-latest:actions%2Fcheckout",
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


# ---------------------------------------------------------------------------
# Negative-caching discipline (transient vs authoritative failures)
# ---------------------------------------------------------------------------

def test_latest_tag_transient_failure_not_negative_cached(tmp_path):
    """A 5xx / rate-limit must not be cached as 'repo has no
    releases' for a whole TTL — the next call retries."""
    from core.http import HttpError
    from core.json import JsonCache
    cache = JsonCache(root=tmp_path / "cache")
    http = MagicMock()
    http.get_json.side_effect = HttpError("503", status=503)
    c = GitHubActionsClient(http, cache=cache)
    assert c.get_latest_tag("actions/checkout") is None
    # Outage over.
    http.get_json.side_effect = None
    http.get_json.return_value = {"tag_name": "v6"}
    assert c.get_latest_tag("actions/checkout") == "v6"


def test_latest_tag_404_still_negative_cached(tmp_path):
    """Authoritative 404 (repo cuts no releases) keeps the
    negative-cache behaviour — no re-query within the TTL."""
    from core.http import HttpError
    from core.json import JsonCache
    cache = JsonCache(root=tmp_path / "cache")
    http = MagicMock()
    http.get_json.side_effect = HttpError("404", status=404)
    c = GitHubActionsClient(http, cache=cache)
    assert c.get_latest_tag("actions/checkout") is None
    http.get_json.reset_mock()
    http.get_json.side_effect = None
    assert c.get_latest_tag("actions/checkout") is None
    http.get_json.assert_not_called()


# ---------------------------------------------------------------------------
# Branch protection: a 404 is only meaningful when authenticated
# ---------------------------------------------------------------------------

def test_branch_protection_anonymous_404_returns_none(monkeypatch, tmp_path):
    """The branch-protection API 404s to EVERY anonymous request
    regardless of the branch's real posture — an anonymous 404 must
    not become (or cache) the not_found sentinel the caller turns
    into an 'unprotected branch' finding."""
    from core.http import HttpError
    from core.json import JsonCache
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    cache = JsonCache(root=tmp_path / "cache")
    http = MagicMock()
    http.get_json.side_effect = HttpError("404 Not Found", status=404)
    c = GitHubActionsClient(http, cache=cache)
    assert c.get_branch_protection("owner/repo", "main") is None
    # Nothing cached: once a token appears, the same client must
    # re-ask instead of serving the anonymous miss.
    http.get_json.reset_mock()
    http.get_json.side_effect = HttpError("404 Not Found", status=404)
    c2 = GitHubActionsClient(http, cache=cache, github_token="tok")
    assert c2.get_branch_protection("owner/repo", "main") == {
        "_sentinel": "not_found",
    }
    http.get_json.assert_called_once()


def test_branch_protection_authed_404_is_the_not_found_sentinel(
    tmp_path,
):
    """With a token, a 404 is GitHub affirmatively saying 'no
    protection rule' — the sentinel flows to the caller (which emits
    the missing-protection finding) and is cached."""
    from core.http import HttpError
    from core.json import JsonCache
    cache = JsonCache(root=tmp_path / "cache")
    http = MagicMock()
    http.get_json.side_effect = HttpError("404 Not Found", status=404)
    c = GitHubActionsClient(http, cache=cache, github_token="tok")
    assert c.get_branch_protection("owner/repo", "main") == {
        "_sentinel": "not_found",
    }
    http.get_json.reset_mock()
    assert c.get_branch_protection("owner/repo", "main") == {
        "_sentinel": "not_found",
    }
    http.get_json.assert_not_called()   # served from cache


def test_branch_protection_real_response_passes_through(monkeypatch):
    """Direction two: a genuine API response reporting protection
    WITHOUT required signatures still reaches the caller (which
    emits the missing_signed_commits finding) — with or without a
    token."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    payload = {"required_signatures": {"enabled": False}}
    c = _make_client(json_payload=payload)
    assert c.get_branch_protection("owner/repo", "main") == payload


def test_branch_protection_transient_failure_returns_none(tmp_path):
    """5xx / network with a token: no answer, nothing cached — a
    blip must not suppress (or fabricate) the finding for a TTL."""
    from core.http import HttpError
    from core.json import JsonCache
    cache = JsonCache(root=tmp_path / "cache")
    http = MagicMock()
    http.get_json.side_effect = HttpError("502", status=502)
    c = GitHubActionsClient(http, cache=cache, github_token="tok")
    assert c.get_branch_protection("owner/repo", "main") is None
    http.get_json.side_effect = None
    http.get_json.return_value = {"required_signatures": {"enabled": True}}
    assert c.get_branch_protection("owner/repo", "main") == {
        "required_signatures": {"enabled": True},
    }


def test_token_sent_as_authorization_header():
    http = MagicMock()
    http.get_json.return_value = {"tag_name": "v6"}
    c = GitHubActionsClient(http, github_token="tok-123")
    c.get_latest_tag("actions/checkout")
    _, kwargs = http.get_json.call_args
    assert kwargs["headers"] == {"Authorization": "Bearer tok-123"}


def test_hostile_owner_repo_rejected_before_fetch(monkeypatch):
    """Traversal-shaped slugs from a scanned workflow must not steer
    the API request — rejected before any HTTP call."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    http = MagicMock()
    c = GitHubActionsClient(http)
    assert c.get_repo_info("owner/..") is None
    assert c.get_branch_protection("owner/..", "main") is None
    assert c.get_branch_protection("owner/repo", "..") is None
    http.get_json.assert_not_called()
    # A branch legitimately containing ``/`` (release/1.0) is fine —
    # it is percent-encoded into ONE path segment, not rejected.
    http.get_json.return_value = {"required_signatures": {"enabled": True}}
    c.get_branch_protection("owner/repo", "release/1.0")
    url = http.get_json.call_args[0][0]
    assert "/branches/release%2F1.0/protection" in url
