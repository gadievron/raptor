"""Tests for agent/tools.py.

Each tool must:
 - return a string (errors become JSON-in-string, never raise)
 - ship a valid anthropic_schema (name + description + input_schema)
"""
from __future__ import annotations

import json

import pytest

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


def test_gh_get_retries_on_429_then_succeeds(monkeypatch) -> None:
    """_gh_get must respect Retry-After on 429 then succeed on the next attempt."""
    calls: list[tuple[int, str]] = []

    class _Resp:
        def __init__(self, status: int, payload: dict | None = None, retry_after: str = "") -> None:
            self.status_code = status
            self._payload = payload or {}
            self.headers = {"Retry-After": retry_after} if retry_after else {}
        def json(self) -> dict:
            return self._payload

    responses = [
        _Resp(429, retry_after="0"),
        _Resp(200, {"ok": True}),
    ]

    def fake_get(url: str, **kw):
        calls.append((len(calls), url))
        return responses[len(calls) - 1]

    monkeypatch.setattr(tools_mod.requests, "get", fake_get)
    monkeypatch.setattr(tools_mod.time, "sleep", lambda _s: None)
    # Force the rate-limit bucket to always allow.
    monkeypatch.setattr(tools_mod.github_client, "_bucket", lambda: type("B", (), {"try_acquire": lambda self: True})())

    out = tools_mod._gh_get("/test")
    assert out == {"ok": True}
    assert len(calls) == 2  # 1 retry after 429


def test_gh_get_retries_on_5xx(monkeypatch) -> None:
    """_gh_get must retry on transient 5xx server errors."""
    class _Resp:
        def __init__(self, status: int, payload: dict | None = None) -> None:
            self.status_code = status
            self._payload = payload or {}
            self.headers = {}
        def json(self) -> dict:
            return self._payload

    responses = [_Resp(503), _Resp(502), _Resp(200, {"ok": True})]
    call_count = [0]

    def fake_get(url: str, **kw):
        i = call_count[0]
        call_count[0] += 1
        return responses[i]

    monkeypatch.setattr(tools_mod.requests, "get", fake_get)
    monkeypatch.setattr(tools_mod.time, "sleep", lambda _s: None)
    monkeypatch.setattr(tools_mod.github_client, "_bucket", lambda: type("B", (), {"try_acquire": lambda self: True})())

    out = tools_mod._gh_get("/test")
    assert out == {"ok": True}
    assert call_count[0] == 3


def test_gh_get_fails_fast_on_4xx_other_than_429(monkeypatch) -> None:
    """4xx other than 429 (404, 403, etc.) is a final answer — no retry."""
    class _Resp:
        status_code = 404
        headers: dict = {}
        def json(self): return {}

    call_count = [0]
    def fake_get(url: str, **kw):
        call_count[0] += 1
        return _Resp()

    monkeypatch.setattr(tools_mod.requests, "get", fake_get)
    monkeypatch.setattr(tools_mod.time, "sleep", lambda _s: None)
    monkeypatch.setattr(tools_mod.github_client, "_bucket", lambda: type("B", (), {"try_acquire": lambda self: True})())

    out = tools_mod._gh_get("/test")
    assert out is None
    assert call_count[0] == 1  # no retries on 404


# ============================================================================
# BEHAVIOR TESTS: each tool exercised with realistic mocked HTTP responses.
# Mocks are at the requests / subprocess / underlying-client boundary, not at
# the SUT — the tool's parsing / extraction / transformation logic IS exercised.
# ============================================================================


class _Resp:
    """Minimal requests.Response-shaped object for monkeypatching."""
    def __init__(self, status_code=200, json_data=None, text="", url=""):
        self.status_code = status_code
        self._json = json_data
        self.text = text
        self.url = url or ""
        self.headers: dict = {}

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


# --- osv_raw ----------------------------------------------------------------

def test_osv_raw_parses_200_payload(monkeypatch) -> None:
    payload = {"id": "CVE-2023-38545", "references": [{"url": "https://x.com/y"}]}
    monkeypatch.setattr(tools_mod.requests, "get", lambda *a, **kw: _Resp(200, json_data=payload))
    out = json.loads(tools_mod._osv_raw_impl("CVE-2023-38545"))
    assert out["id"] == "CVE-2023-38545"
    assert "references" in out


def test_osv_raw_returns_not_found_on_404(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod.requests, "get", lambda *a, **kw: _Resp(404))
    out = json.loads(tools_mod._osv_raw_impl("CVE-9999-0000"))
    assert out == {"not_found": True, "cve_id": "CVE-9999-0000"}


def test_osv_raw_returns_error_on_non_json(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod.requests, "get", lambda *a, **kw: _Resp(200, json_data=None))
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
    monkeypatch.setattr(tools_mod.requests, "get", lambda *a, **kw: _Resp(200, json_data=payload))
    out = json.loads(tools_mod._osv_expand_aliases_impl("CVE-2024-1234"))
    assert "GHSA-aaaa-bbbb-cccc" in out["aliases"]
    assert out["primary_id"] == "CVE-2024-1234"


def test_osv_expand_aliases_returns_empty_on_404(monkeypatch) -> None:
    monkeypatch.setattr(tools_mod.requests, "get", lambda *a, **kw: _Resp(404))
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
    monkeypatch.setattr(tools_mod.requests, "get", lambda *a, **kw: _Resp(200, json_data=osv))
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
    monkeypatch.setattr(tools_mod.requests, "get", lambda *a, **kw: _Resp(200, json_data=osv))
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
    monkeypatch.setattr(tools_mod.requests, "get", lambda *a, **kw: _Resp(200, json_data=osv))
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
    class _Proc:
        returncode = 0
        stdout = "abc1234\trefs/heads/main\ndef5678\trefs/tags/v1.0\n"
        stderr = ""

    monkeypatch.setattr(tools_mod.subprocess, "run", lambda *a, **kw: _Proc())
    out = json.loads(tools_mod._git_ls_remote_impl("https://example.org/foo.git"))
    assert len(out["refs"]) == 2
    assert out["refs"][0] == {"sha": "abc1234", "ref": "refs/heads/main"}


def test_git_ls_remote_handles_failure(monkeypatch) -> None:
    class _Proc:
        returncode = 128
        stdout = ""
        stderr = "fatal: bad URL"

    monkeypatch.setattr(tools_mod.subprocess, "run", lambda *a, **kw: _Proc())
    out = json.loads(tools_mod._git_ls_remote_impl("https://example.org/missing"))
    assert "error" in out


# --- gitlab_commit ----------------------------------------------------------

def test_gitlab_commit_extracts_fields(monkeypatch) -> None:
    payload = {"id": "abcdef0123", "short_id": "abcdef0", "title": "Fix CVE", "message": "details", "parent_ids": ["xxx111"], "created_at": "2024-01-01"}
    monkeypatch.setattr(tools_mod.requests, "get", lambda *a, **kw: _Resp(200, json_data=payload))
    out = json.loads(tools_mod._gitlab_commit_impl("https://gitlab.freedesktop.org", "group/project", "abcdef0123"))
    assert out["id"] == "abcdef0123"
    assert out["title"] == "Fix CVE"
    assert "xxx111" in out["parent_ids"]


# --- cgit_fetch -------------------------------------------------------------

def test_cgit_fetch_caps_body(monkeypatch) -> None:
    big = "x" * (tools_mod._MAX_BYTES * 4)
    monkeypatch.setattr(tools_mod.requests, "get", lambda *a, **kw: _Resp(200, text=big, url="https://x.org/y"))
    out = json.loads(tools_mod._cgit_fetch_impl("https://x.org", "y/z", "abc"))
    assert len(out["body"]) <= tools_mod._MAX_BYTES


# --- http_fetch -------------------------------------------------------------

def test_http_fetch_caps_body_and_returns_url(monkeypatch) -> None:
    big = "y" * (tools_mod._MAX_BYTES * 4)
    monkeypatch.setattr(tools_mod.requests, "get", lambda *a, **kw: _Resp(200, text=big, url="https://final.example/redirected"))
    out = json.loads(tools_mod._http_fetch_impl("https://example.com/page"))
    assert out["status"] == 200
    assert out["url"] == "https://final.example/redirected"
    assert len(out["body"]) <= tools_mod._MAX_BYTES


# --- oracle_check -----------------------------------------------------------

def test_oracle_check_returns_match_exact(monkeypatch) -> None:
    from tools.oracle.types import OracleVerdict, Verdict

    def fake_verify(cve_id, slug, sha):
        return OracleVerdict(
            cve_id=cve_id, picked_slug=slug, picked_sha=sha,
            verdict=Verdict.MATCH_EXACT, source="osv",
            expected_slugs=("foo/bar",), expected_shas=(sha,),
        )

    monkeypatch.setattr("tools.oracle.cross_check._verify_one", fake_verify)
    out = json.loads(tools_mod._oracle_check_impl("CVE-X", "foo/bar", "abc123"))
    assert out["verdict"] == "match_exact"
    assert out["is_pass"] is True


def test_oracle_check_returns_likely_hallucination_with_expected_slugs(monkeypatch) -> None:
    from tools.oracle.types import OracleVerdict, Verdict

    def fake_verify(cve_id, slug, sha):
        return OracleVerdict(
            cve_id=cve_id, picked_slug=slug, picked_sha=sha,
            verdict=Verdict.LIKELY_HALLUCINATION, source="osv",
            expected_slugs=("cifsd-team/ksmbd",),
            expected_shas=("8824b7af409f51f1316e92e9887c2fd48c0b26d6",),
        )

    monkeypatch.setattr("tools.oracle.cross_check._verify_one", fake_verify)
    out = json.loads(tools_mod._oracle_check_impl("CVE-2023-0210", "torvalds/linux", "797805d81baa"))
    assert out["verdict"] == "likely_hallucination"
    assert "cifsd-team/ksmbd" in out["expected_slugs"]
    assert out["is_pass"] is False


