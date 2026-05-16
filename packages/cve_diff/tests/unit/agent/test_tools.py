"""Tests for agent/tools.py.

Each tool must:
 - return a string (errors become JSON-in-string, never raise)
 - ship a valid anthropic_schema (name + description + input_schema)
"""
from __future__ import annotations

import json

import pytest

from core.http import HttpError
from cve_diff.agent import tools as tools_mod
from cve_diff.agent.tools import TOOLS, Tool


def test_catalog_unique_names() -> None:
    names = [t.name for t in TOOLS]
    assert len(names) == len(set(names))
    assert len(TOOLS) >= 12  # plan target (13 after deleting extract_shas_from_text)


@pytest.mark.parametrize("tool", TOOLS, ids=lambda t: t.name)
def test_tool_schema_shape(tool: Tool) -> None:
    schema = tool.anthropic_schema()
    assert schema["name"] == tool.name
    assert isinstance(schema["description"], str) and len(schema["description"]) > 20
    assert schema["input_schema"]["type"] == "object"


def test_err_wraps() -> None:
    out = json.loads(tools_mod._err("boom"))
    assert out == {"error": "boom"}


# --- check_diff_shape (Track 3: shape-check before submit) ---

def test_check_diff_shape_requires_both() -> None:
    assert "error" in json.loads(tools_mod._check_diff_shape_impl("", "abc"))
    assert "error" in json.loads(tools_mod._check_diff_shape_impl("a/b", ""))


def test_check_diff_shape_returns_source_for_code_files(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod.github_client, "get_commit",
                        lambda slug, sha: {"sha": sha, "files": [{"filename": "src/foo.c"}]})
    monkeypatch.setattr(tools_mod.github_client, "get_commit_files",
                        lambda slug, sha: ["src/foo.c", "src/foo.h"])
    monkeypatch.setattr(tools_mod.github_client, "get_languages",
                        lambda slug: {"C": 1000})
    out = json.loads(tools_mod._check_diff_shape_impl("acme/widget", "deadbeef" * 5))
    assert out["shape"] == "source"
    assert out["files_total"] == 2
    assert out["files_sample"] == ["src/foo.c", "src/foo.h"]


def test_check_diff_shape_returns_packaging_only(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod.github_client, "get_commit",
                        lambda slug, sha: {"sha": sha, "files": [{"filename": "debian/changelog"}]})
    monkeypatch.setattr(tools_mod.github_client, "get_commit_files",
                        lambda slug, sha: ["debian/changelog", "debian/control"])
    monkeypatch.setattr(tools_mod.github_client, "get_languages",
                        lambda slug: {"C": 1000})
    out = json.loads(tools_mod._check_diff_shape_impl("acme/widget", "deadbeef" * 5))
    assert out["shape"] == "packaging_only"


def test_check_diff_shape_returns_notes_only(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod.github_client, "get_commit",
                        lambda slug, sha: {"sha": sha, "files": [{"filename": "CHANGELOG.md"}]})
    monkeypatch.setattr(tools_mod.github_client, "get_commit_files",
                        lambda slug, sha: ["CHANGELOG.md"])
    monkeypatch.setattr(tools_mod.github_client, "get_languages",
                        lambda slug: {"Ruby": 1000})
    out = json.loads(tools_mod._check_diff_shape_impl("acme/widget", "deadbeef" * 5))
    assert out["shape"] == "notes_only"


def test_check_diff_shape_flags_empty_diff(monkeypatch) -> None:
    """0-file commits (tag / merge / re-tag) get a distinct shape so
    the agent doesn't submit a SHA whose diff would be empty."""
    monkeypatch.setattr(tools_mod.github_client, "get_commit",
                        lambda slug, sha: {"sha": sha, "files": []})
    monkeypatch.setattr(tools_mod.github_client, "get_commit_files",
                        lambda slug, sha: [])
    out = json.loads(tools_mod._check_diff_shape_impl("acme/widget", "deadbeef" * 5))
    assert out["shape"] == "empty_diff"
    assert out["files_total"] == 0


def test_check_diff_shape_handles_404(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod.github_client, "get_commit",
                        lambda slug, sha: None)
    out = json.loads(tools_mod._check_diff_shape_impl("nope/nope", "deadbeef" * 5))
    assert "error" in out


def test_osv_raw_requires_cve_id() -> None:
    out = json.loads(tools_mod._osv_raw_impl(""))
    assert "error" in out


def test_nvd_raw_requires_cve_id() -> None:
    out = json.loads(tools_mod._nvd_raw_impl(""))
    assert "error" in out


def test_git_ls_remote_rejects_non_http() -> None:
    out = json.loads(tools_mod._git_ls_remote_impl("git@github.com:foo/bar"))
    assert "error" in out


def test_http_fetch_rejects_non_http() -> None:
    out = json.loads(tools_mod._http_fetch_impl("file:///etc/passwd"))
    assert "error" in out


def test_gh_commit_detail_requires_both() -> None:
    assert "error" in json.loads(tools_mod._gh_commit_detail_impl("", "abc"))
    assert "error" in json.loads(tools_mod._gh_commit_detail_impl("a/b", ""))


def test_deterministic_hints_requires_cve_id() -> None:
    out = json.loads(tools_mod._deterministic_hints_impl(""))
    assert "error" in out


def test_gitlab_commit_requires_all() -> None:
    out = json.loads(tools_mod._gitlab_commit_impl("", "g/p", "abc"))
    assert "error" in out


def test_cgit_fetch_requires_all() -> None:
    out = json.loads(tools_mod._cgit_fetch_impl("https://example.org", "", "abc"))
    assert "error" in out


def test_gh_search_requires_query() -> None:
    assert "error" in json.loads(tools_mod._gh_search_repos_impl(""))
    assert "error" in json.loads(tools_mod._gh_search_commits_impl("   "))


def test_fetch_distro_advisory_requires_cve_id() -> None:
    out = json.loads(tools_mod._fetch_distro_advisory_impl(""))
    assert "error" in out


def test_oracle_check_requires_all_args() -> None:
    out = json.loads(tools_mod._oracle_check_impl("", "slug", "sha"))
    assert "error" in out
    out = json.loads(tools_mod._oracle_check_impl("CVE-2023-0210", "", "sha"))
    assert "error" in out
    out = json.loads(tools_mod._oracle_check_impl("CVE-2023-0210", "slug", ""))
    assert "error" in out


def test_gh_get_delegates_to_http_client(monkeypatch) -> None:
    """_gh_get delegates to _http_client().get_json() with correct retries."""
    calls: list[dict] = []

    class _StubClient:
        def get_json(self, url, *, timeout, headers=None, retries=0, **kw):
            calls.append({"url": url, "retries": retries})
            return {"ok": True}

    monkeypatch.setattr(tools_mod, "_http_client", lambda: _StubClient())
    monkeypatch.setattr(tools_mod.github_client, "_bucket", lambda: type("B", (), {"try_acquire": lambda self: True})())
    monkeypatch.setattr(tools_mod.github_client, "_headers", lambda: {"Authorization": "Bearer test"})

    out = tools_mod._gh_get("/test", {"per_page": "20"})
    assert out == {"ok": True}
    assert len(calls) == 1
    assert "per_page=20" in calls[0]["url"]
    assert calls[0]["retries"] == tools_mod._GH_RETRIES


def test_gh_get_returns_none_on_http_error(monkeypatch) -> None:
    """HttpError from the client maps to None."""
    class _StubClient:
        def get_json(self, url, **kw):
            raise HttpError("rate limited", status=429)

    monkeypatch.setattr(tools_mod, "_http_client", lambda: _StubClient())
    monkeypatch.setattr(tools_mod.github_client, "_bucket", lambda: type("B", (), {"try_acquire": lambda self: True})())

    assert tools_mod._gh_get("/test") is None


def test_gh_get_returns_none_when_bucket_exhausted(monkeypatch) -> None:
    """Rate-limit bucket refusal returns None without making an HTTP call."""
    monkeypatch.setattr(tools_mod.github_client, "_bucket", lambda: type("B", (), {"try_acquire": lambda self: False})())
    assert tools_mod._gh_get("/test") is None


# ============================================================================
# BEHAVIOR TESTS: each tool exercised with realistic mocked HTTP responses.
# Mocks are at the core.http client boundary, not at the SUT — the tool's
# parsing / extraction / transformation logic IS exercised.
# ============================================================================


class _StubHttpClient:
    """Mock core.http client returning canned responses for get_json/get_bytes."""

    def __init__(self, json_data=None, raw_bytes=b"", status=200, error=None):
        self._json = json_data
        self._bytes = raw_bytes
        self._status = status
        self._error = error

    def get_json(self, url, *, timeout=30, headers=None, retries=0, **kw):
        if self._error:
            raise self._error
        if self._status == 404:
            raise HttpError("not found", status=404)
        if self._status != 200:
            raise HttpError(f"http {self._status}", status=self._status)
        if self._json is None:
            raise HttpError("Response is not valid JSON: ...")
        return self._json

    def get_bytes(self, url, *, timeout=30, max_bytes=50*1024*1024, headers=None, retries=0, **kw):
        if self._error:
            raise self._error
        if self._status != 200:
            raise HttpError(f"http {self._status}", status=self._status)
        return self._bytes[:max_bytes]


# --- osv_raw ----------------------------------------------------------------

def test_osv_raw_parses_200_payload(monkeypatch) -> None:
    payload = {"id": "CVE-2023-38545", "references": [{"url": "https://x.com/y"}]}
    monkeypatch.setattr(tools_mod, "_http_client", lambda: _StubHttpClient(json_data=payload))
    out = json.loads(tools_mod._osv_raw_impl("CVE-2023-38545"))
    assert out["id"] == "CVE-2023-38545"
    assert "references" in out


def test_osv_raw_returns_not_found_on_404(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod, "_http_client", lambda: _StubHttpClient(status=404))
    out = json.loads(tools_mod._osv_raw_impl("CVE-9999-0000"))
    assert out == {"not_found": True, "cve_id": "CVE-9999-0000"}


def test_osv_raw_returns_error_on_non_json(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod, "_http_client", lambda: _StubHttpClient(json_data=None))
    out = json.loads(tools_mod._osv_raw_impl("CVE-X"))
    assert "error" in out


# --- nvd_raw ----------------------------------------------------------------

def test_nvd_raw_returns_payload(monkeypatch) -> None:
    fake_payload = {"vulnerabilities": [{"cve": {"id": "CVE-2024-1234"}}]}
    monkeypatch.setattr(tools_mod._nvd, "get_payload", lambda cve_id: fake_payload)
    out = json.loads(tools_mod._nvd_raw_impl("CVE-2024-1234"))
    assert out["vulnerabilities"][0]["cve"]["id"] == "CVE-2024-1234"


def test_nvd_raw_returns_not_found_when_no_payload(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod._nvd, "get_payload", lambda cve_id: None)
    out = json.loads(tools_mod._nvd_raw_impl("CVE-X"))
    assert out["not_found"] is True


# --- osv_expand_aliases -----------------------------------------------------

def test_osv_expand_aliases_extracts_ghsa_list(monkeypatch) -> None:
    payload = {"id": "CVE-2024-1234", "aliases": ["GHSA-aaaa-bbbb-cccc", "DSA-1234-1"]}
    monkeypatch.setattr(tools_mod, "_http_client", lambda: _StubHttpClient(json_data=payload))
    out = json.loads(tools_mod._osv_expand_aliases_impl("CVE-2024-1234"))
    assert "GHSA-aaaa-bbbb-cccc" in out["aliases"]
    assert out["primary_id"] == "CVE-2024-1234"


def test_osv_expand_aliases_returns_empty_on_404(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod, "_http_client", lambda: _StubHttpClient(status=404))
    out = json.loads(tools_mod._osv_expand_aliases_impl("CVE-9999-0000"))
    assert out["aliases"] == []


# --- deterministic_hints ----------------------------------------------------

def test_deterministic_hints_extracts_github_commit_from_osv_refs(monkeypatch) -> None:
    osv = {
        "references": [
            {"url": "https://github.com/foo/bar/commit/abc1234567890def1234567890abcdef12345678"},
            {"url": "https://nvd.nist.gov/something"},  # no slug+sha — should be skipped
        ],
        "affected": [],
    }
    monkeypatch.setattr(tools_mod, "_http_client", lambda: _StubHttpClient(json_data=osv))
    monkeypatch.setattr(tools_mod._nvd, "get_payload", lambda cve_id: None)
    out = json.loads(tools_mod._deterministic_hints_impl("CVE-2024-X"))
    assert any(h["slug"] == "foo/bar" and "osv_reference" in h["source"] for h in out["hints"])


def test_deterministic_hints_extracts_kernel_shortlink(monkeypatch) -> None:
    osv = {
        "references": [
            {"url": "https://git.kernel.org/linus/c/abcdef0123456789abcdef0123456789abcdef01"},
        ],
        "affected": [],
    }
    monkeypatch.setattr(tools_mod, "_http_client", lambda: _StubHttpClient(json_data=osv))
    monkeypatch.setattr(tools_mod._nvd, "get_payload", lambda cve_id: None)
    out = json.loads(tools_mod._deterministic_hints_impl("CVE-2024-X"))
    assert any(h["slug"] == "torvalds/linux" and "kernel_shortlink" in h["source"] for h in out["hints"])


def test_deterministic_hints_dedupes_same_slug_sha(monkeypatch) -> None:
    osv = {
        "references": [
            {"url": "https://github.com/foo/bar/commit/abc1234567890def1234567890abcdef12345678"},
            {"url": "https://github.com/foo/bar/commit/abc1234567890def1234567890abcdef12345678"},
        ],
        "affected": [],
    }
    monkeypatch.setattr(tools_mod, "_http_client", lambda: _StubHttpClient(json_data=osv))
    monkeypatch.setattr(tools_mod._nvd, "get_payload", lambda cve_id: None)
    out = json.loads(tools_mod._deterministic_hints_impl("CVE-X"))
    matches = [h for h in out["hints"] if h["slug"] == "foo/bar"]
    assert len(matches) == 1


# --- gh_search_repos / gh_search_commits ------------------------------------

def test_gh_search_repos_parses_results(monkeypatch) -> None:
    fake = {"items": [{"full_name": "org/repo", "description": "test", "stargazers_count": 42, "language": "Python", "archived": False, "created_at": "2020-01-01"}]}
    monkeypatch.setattr(tools_mod, "_gh_get", lambda path, params=None: fake)
    out = json.loads(tools_mod._gh_search_repos_impl("openssl"))
    assert out["items"][0]["slug"] == "org/repo"
    assert out["items"][0]["stars"] == 42


def test_gh_search_commits_parses_commits(monkeypatch) -> None:
    fake = {"items": [{"repository": {"full_name": "org/repo"}, "sha": "abc123", "commit": {"message": "fix CVE-X"}}]}
    monkeypatch.setattr(tools_mod, "_gh_get", lambda path, params=None: fake)
    out = json.loads(tools_mod._gh_search_commits_impl("CVE-X"))
    assert out["items"][0]["slug"] == "org/repo"
    assert out["items"][0]["sha"] == "abc123"
    assert "CVE-X" in out["items"][0]["message"]


def test_gh_search_returns_error_on_rate_limit(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod, "_gh_get", lambda path, params=None: None)
    out = json.loads(tools_mod._gh_search_repos_impl("openssl"))
    assert "error" in out


# --- gh_commit_detail -------------------------------------------------------

def test_gh_commit_detail_parses_payload(monkeypatch) -> None:
    monkeypatch.setattr(
        tools_mod.github_client, "get_commit",
        lambda slug, sha: {"commit": {"message": "fix CVE-X"}, "parents": [{"sha": "deadbeef"}]},
    )
    monkeypatch.setattr(
        tools_mod.github_client, "get_commit_files",
        lambda slug, sha: ["src/foo.c", "tests/bar_test.c"],
    )
    out = json.loads(tools_mod._gh_commit_detail_impl("foo/bar", "abc1234"))
    assert out["slug"] == "foo/bar"
    assert "CVE-X" in out["message"]
    assert out["files"] == ["src/foo.c", "tests/bar_test.c"]
    assert "deadbeef" in out["parents"]


def test_gh_commit_detail_returns_error_when_not_found(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod.github_client, "get_commit", lambda slug, sha: None)
    out = json.loads(tools_mod._gh_commit_detail_impl("foo/bar", "abc1234"))
    assert "error" in out


# --- gh_list_commits_by_path ------------------------------------------------

def test_gh_list_commits_by_path_parses(monkeypatch) -> None:
    fake = [
        {"sha": "aaa111", "commit": {"message": "first", "committer": {"date": "2024-01-01"}}},
        {"sha": "bbb222", "commit": {"message": "second", "committer": {"date": "2024-02-01"}}},
    ]
    monkeypatch.setattr(tools_mod, "_gh_get", lambda path, params=None: fake)
    out = json.loads(tools_mod._gh_list_commits_by_path_impl("foo/bar", "src/foo.c"))
    assert len(out["commits"]) == 2
    assert out["commits"][0]["sha"] == "aaa111"
    assert "2024-01-01" in out["commits"][0]["date"]


# --- gh_compare -------------------------------------------------------------

def test_gh_compare_extracts_status_and_files(monkeypatch) -> None:
    fake = {
        "status": "ahead",
        "ahead_by": 3,
        "behind_by": 0,
        "files": [{"filename": "src/a.c"}, {"filename": "src/b.c"}],
    }
    monkeypatch.setattr(tools_mod, "_gh_get", lambda path, params=None: fake)
    out = json.loads(tools_mod._gh_compare_impl("foo/bar", "abc", "def"))
    assert out["status"] == "ahead"
    assert out["ahead_by"] == 3
    assert "src/a.c" in out["files"]


# --- git_ls_remote ----------------------------------------------------------

def test_git_ls_remote_parses_refs(monkeypatch) -> None:
    """Post-substrate-migration: ``_git_ls_remote_impl`` calls
    :func:`core.git.ls_remote`. Stub the helper directly so this
    test asserts the tool's args→output shaping, not the substrate
    (substrate has its own E2E + unit tests in
    ``core/git/tests/test_clone.py``)."""
    fake_refs = [
        ("abc1234567890abc1234567890abc1234567890a", "refs/heads/main"),
        ("def1234567890def1234567890def1234567890b", "refs/tags/v1.0"),
    ]
    import core.git
    monkeypatch.setattr(
        core.git, "ls_remote",
        lambda url, **kw: fake_refs,
    )
    # Use a host that's in ``_AGENT_FORGE_HOSTS`` so the real helper's
    # allowlist check would pass too — keeps the test honest.
    out = json.loads(tools_mod._git_ls_remote_impl(
        "https://git.kernel.org/foo.git",
    ))
    assert len(out["refs"]) == 2
    assert out["refs"][0]["sha"].startswith("abc1234567890")
    assert out["refs"][0]["ref"] == "refs/heads/main"


def test_git_ls_remote_handles_failure(monkeypatch) -> None:
    """Substrate raises ``RuntimeError`` on git-failure; tool wraps
    in JSON error."""
    import core.git

    def _raise(*a, **kw):
        raise RuntimeError("fatal: bad URL")

    monkeypatch.setattr(core.git, "ls_remote", _raise)
    out = json.loads(tools_mod._git_ls_remote_impl(
        "https://git.kernel.org/missing",
    ))
    assert "error" in out


def test_git_ls_remote_rejects_url_outside_forge_allowlist() -> None:
    """Pre-substrate-migration the tool accepted any ``http(s)://``
    URL — SSRF surface. Now the substrate's URL/proxy checks reject
    URLs whose host isn't in ``_AGENT_FORGE_HOSTS``. No subprocess
    fires; ``ls_remote`` raises ``ValueError`` and the tool wraps
    it in a JSON error."""
    out = json.loads(tools_mod._git_ls_remote_impl(
        "https://evil.example.com/foo",
    ))
    assert "error" in out
    assert "allowlist" in out["error"]


# --- gitlab_commit ----------------------------------------------------------

def test_gitlab_commit_extracts_fields(monkeypatch) -> None:
    """Post-substrate-migration: ``_gitlab_commit_impl`` calls
    ``_forge_client().get_json``. Stub the client at the seam so this
    test asserts the tool's payload-shaping, not ``EgressClient`` plumbing
    (covered by ``core/http`` tests)."""
    payload = {"id": "abcdef0123", "short_id": "abcdef0", "title": "Fix CVE",
               "message": "details", "parent_ids": ["xxx111"],
               "created_at": "2024-01-01"}

    class _StubClient:
        def get_json(self, url, *, timeout, retries=0):
            return payload

    monkeypatch.setattr(tools_mod, "_forge_client", lambda: _StubClient())
    out = json.loads(tools_mod._gitlab_commit_impl(
        "https://gitlab.freedesktop.org", "group/project", "abcdef0123",
    ))
    assert out["id"] == "abcdef0123"
    assert out["title"] == "Fix CVE"
    assert "xxx111" in out["parent_ids"]


# --- cgit_fetch -------------------------------------------------------------

def test_cgit_fetch_caps_body(monkeypatch) -> None:
    """Post-substrate-migration: ``_cgit_fetch_impl`` calls
    ``_forge_client().get_bytes``. Stub at the seam and use a host that's
    in ``_AGENT_FORGE_HOSTS`` so the test resembles the real call shape."""
    big = b"x" * (tools_mod._MAX_BYTES * 4)

    class _StubClient:
        def get_bytes(self, url, *, timeout, max_bytes, retries=0):
            return big[:max_bytes]

    monkeypatch.setattr(tools_mod, "_forge_client", lambda: _StubClient())
    out = json.loads(tools_mod._cgit_fetch_impl(
        "https://git.kernel.org", "y/z", "abc",
    ))
    assert len(out["body"]) <= tools_mod._MAX_BYTES


# --- http_fetch -------------------------------------------------------------

def test_http_fetch_caps_body_and_returns_url(monkeypatch) -> None:
    big = b"y" * (tools_mod._MAX_BYTES * 4)
    monkeypatch.setattr(tools_mod, "_forge_client", lambda: _StubHttpClient(raw_bytes=big))
    out = json.loads(tools_mod._http_fetch_impl("https://example.com/page"))
    assert out["status"] == 200
    assert out["url"] == "https://example.com/page"
    assert len(out["body"]) <= tools_mod._MAX_BYTES


# --- oracle_check -----------------------------------------------------------

def test_oracle_check_returns_match_exact(monkeypatch) -> None:
    from packages.osv.verdicts import OracleVerdict, Verdict

    def fake_verify(cve_id, slug, sha):
        return OracleVerdict(
            cve_id=cve_id, picked_slug=slug, picked_sha=sha,
            verdict=Verdict.MATCH_EXACT, source="osv",
            expected_slugs=("foo/bar",), expected_shas=(sha,),
        )

    monkeypatch.setattr("cve_diff.oracle.cross_check._verify_one", fake_verify)
    out = json.loads(tools_mod._oracle_check_impl("CVE-X", "foo/bar", "abc123"))
    assert out["verdict"] == "match_exact"
    assert out["is_pass"] is True


def test_oracle_check_returns_likely_hallucination_with_expected_slugs(monkeypatch) -> None:
    from packages.osv.verdicts import OracleVerdict, Verdict

    def fake_verify(cve_id, slug, sha):
        return OracleVerdict(
            cve_id=cve_id, picked_slug=slug, picked_sha=sha,
            verdict=Verdict.LIKELY_HALLUCINATION, source="osv",
            expected_slugs=("cifsd-team/ksmbd",),
            expected_shas=("8824b7af409f51f1316e92e9887c2fd48c0b26d6",),
        )

    monkeypatch.setattr("cve_diff.oracle.cross_check._verify_one", fake_verify)
    out = json.loads(tools_mod._oracle_check_impl("CVE-2023-0210", "torvalds/linux", "797805d81baa"))
    assert out["verdict"] == "likely_hallucination"
    assert "cifsd-team/ksmbd" in out["expected_slugs"]
    assert out["is_pass"] is False


