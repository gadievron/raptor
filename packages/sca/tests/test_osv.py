"""Tests for ``packages.sca.osv``.

Uses an in-process fake HttpClient so tests don't touch the network and
run on every commit. The fake records every call so assertions can
verify caching prevented re-fetches.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from core.json import JsonCache
from core.http import HttpError
from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.osv import (
    OSV_VULN_URL_TEMPLATE,
    OsvClient,
    _oss_fuzz_candidates,
    parse_osv_record,
)


# ---------------------------------------------------------------------------
# Fake HTTP client
# ---------------------------------------------------------------------------

class FakeHttp:
    def __init__(
        self,
        batch_results: List[List[str]] | None = None,
        vuln_records: Dict[str, Dict[str, Any]] | None = None,
        post_error: Exception | None = None,
        get_error: Exception | None = None,
    ) -> None:
        self.batch_results = batch_results or []
        self.vuln_records = vuln_records or {}
        self.post_error = post_error
        self.get_error = get_error
        self.posts: List[tuple[str, dict]] = []
        self.gets: List[str] = []

    def post_json(self, url: str, body: dict, timeout: int = 30) -> dict:
        self.posts.append((url, body))
        if self.post_error:
            raise self.post_error
        return {
            "results": [
                {"vulns": [{"id": vid} for vid in slot]}
                for slot in self.batch_results
            ],
        }

    def get_json(self, url: str, timeout: int = 30) -> dict:
        self.gets.append(url)
        if self.get_error:
            raise self.get_error
        # Resolve which vuln id was requested.
        for vid, record in self.vuln_records.items():
            if url == OSV_VULN_URL_TEMPLATE.format(vid):
                return record
        raise HttpError(f"unknown URL in fake: {url}", status=404)

    def get_bytes(self, url: str, timeout: int = 30, max_bytes: int = 0) -> bytes:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _dep(name: str, version: str | None = "1.0.0", ecosystem: str = "npm") -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("./x"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:npm/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


_LOG4J_RECORD = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "modified": "2024-01-01T00:00:00Z",
    "published": "2021-12-10T00:00:00Z",
    "aliases": ["CVE-2021-44228"],
    "summary": "Log4Shell",
    "details": "Remote code execution.",
    "affected": [
        {
            "package": {"ecosystem": "Maven",
                        "name": "org.apache.logging.log4j:log4j-core"},
            "ranges": [
                {"type": "ECOSYSTEM",
                 "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]},
            ],
        },
    ],
    "severity": [
        {"type": "CVSS_V3",
         "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
    ],
    "references": [{"type": "WEB", "url": "https://example.com"}],
}


# ---------------------------------------------------------------------------
# parse_osv_record
# ---------------------------------------------------------------------------

def test_parse_osv_record_extracts_core_fields() -> None:
    a = parse_osv_record(_LOG4J_RECORD)
    assert a.osv_id == "GHSA-jfh8-c2jp-5v3q"
    assert "CVE-2021-44228" in a.aliases
    assert a.summary == "Log4Shell"
    assert a.fixed_versions == ["2.15.0"]
    assert a.severity is not None
    assert a.severity.severity == "critical"
    assert a.severity.score >= 9.0
    assert a.references == ["https://example.com"]
    assert a.published is not None
    assert len(a.affected) == 1
    assert a.affected[0].type == "ECOSYSTEM"


def test_parse_osv_record_missing_id_raises() -> None:
    with pytest.raises(ValueError):
        parse_osv_record({"summary": "x"})


def test_parse_osv_record_unknown_severity_type_skipped() -> None:
    record = dict(_LOG4J_RECORD)
    record["severity"] = [{"type": "CVSS_V2", "score": "AV:N/AC:L"}]
    a = parse_osv_record(record)
    assert a.severity is None


def test_parse_osv_record_invalid_dates_become_none() -> None:
    record = dict(_LOG4J_RECORD)
    record["modified"] = "not-a-date"
    record["published"] = ""
    a = parse_osv_record(record)
    assert a.modified is None
    assert a.published is None


# ---------------------------------------------------------------------------
# OsvClient — happy path
# ---------------------------------------------------------------------------

def test_query_batch_happy_path(tmp_path: Path) -> None:
    deps = [_dep("lodash"), _dep("safe", version="2.0.0")]
    http = FakeHttp(
        batch_results=[["GHSA-jfh8-c2jp-5v3q"], []],
        vuln_records={"GHSA-jfh8-c2jp-5v3q": _LOG4J_RECORD},
    )
    client = OsvClient(http, JsonCache(root=tmp_path))

    results = client.query_batch(deps)

    assert len(results) == 2
    by_key = {r.dep_key: r for r in results}
    assert by_key["npm:lodash@1.0.0"].advisories[0].osv_id == "GHSA-jfh8-c2jp-5v3q"
    assert by_key["npm:safe@2.0.0"].advisories == []
    assert len(http.posts) == 1


def test_query_batch_skips_unversioned_deps(tmp_path: Path) -> None:
    deps = [_dep("noversion", version=None), _dep("lodash")]
    http = FakeHttp(
        batch_results=[[]],     # only the versioned dep is queried
        vuln_records={},
    )
    client = OsvClient(http, JsonCache(root=tmp_path))
    results = client.query_batch(deps)

    assert len(results) == 1
    assert results[0].dep_key == "npm:lodash@1.0.0"
    assert http.posts and len(http.posts[0][1]["queries"]) == 1


def test_query_batch_dedups_repeated_deps(tmp_path: Path) -> None:
    deps = [_dep("lodash"), _dep("lodash"), _dep("lodash")]
    http = FakeHttp(batch_results=[[]], vuln_records={})
    client = OsvClient(http, JsonCache(root=tmp_path))
    client.query_batch(deps)
    # Only one query was sent — the repeated key is collapsed.
    assert len(http.posts[0][1]["queries"]) == 1


# ---------------------------------------------------------------------------
# OsvClient — caching
# ---------------------------------------------------------------------------

def test_warm_cache_skips_remote(tmp_path: Path) -> None:
    deps = [_dep("lodash")]
    http = FakeHttp(
        batch_results=[["GHSA-jfh8-c2jp-5v3q"]],
        vuln_records={"GHSA-jfh8-c2jp-5v3q": _LOG4J_RECORD},
    )
    cache = JsonCache(root=tmp_path)
    client = OsvClient(http, cache)
    client.query_batch(deps)

    # Second run with same deps + same cache: zero new HTTP calls.
    http2 = FakeHttp()
    client2 = OsvClient(http2, cache)
    results = client2.query_batch(deps)
    assert results[0].advisories[0].osv_id == "GHSA-jfh8-c2jp-5v3q"
    assert http2.posts == []
    assert http2.gets == []


def test_offline_with_cold_cache_returns_empty(tmp_path: Path) -> None:
    deps = [_dep("lodash")]
    http = FakeHttp()
    client = OsvClient(http, JsonCache(root=tmp_path), offline=True)
    results = client.query_batch(deps)
    assert results[0].advisories == []
    # Offline mode never calls the network.
    assert http.posts == []
    assert http.gets == []


# ---------------------------------------------------------------------------
# OsvClient — failure modes
# ---------------------------------------------------------------------------

def test_querybatch_http_error_yields_empty(tmp_path: Path) -> None:
    deps = [_dep("lodash")]
    http = FakeHttp(post_error=HttpError("boom"))
    client = OsvClient(http, JsonCache(root=tmp_path))
    results = client.query_batch(deps)
    assert results[0].advisories == []


def test_vuln_hydration_error_drops_only_that_id(tmp_path: Path) -> None:
    deps = [_dep("lodash"), _dep("other")]
    http = FakeHttp(
        batch_results=[["GHSA-bad"], ["GHSA-jfh8-c2jp-5v3q"]],
        vuln_records={"GHSA-jfh8-c2jp-5v3q": _LOG4J_RECORD},
        # GHSA-bad will trigger a 404 in get_json.
    )
    client = OsvClient(http, JsonCache(root=tmp_path))
    results = client.query_batch(deps)
    by_key = {r.dep_key: r for r in results}
    assert by_key["npm:lodash@1.0.0"].advisories == []
    assert by_key["npm:other@1.0.0"].advisories[0].osv_id == "GHSA-jfh8-c2jp-5v3q"


def test_malformed_querybatch_response_treated_as_no_vuln(tmp_path: Path) -> None:
    deps = [_dep("lodash"), _dep("other")]

    class WrongShapeHttp(FakeHttp):
        def post_json(self, url: str, body: dict, timeout: int = 30) -> dict:
            self.posts.append((url, body))
            return {"results": "not a list"}

    http = WrongShapeHttp()
    client = OsvClient(http, JsonCache(root=tmp_path))
    results = client.query_batch(deps)
    assert all(r.advisories == [] for r in results)


# ---------------------------------------------------------------------------
# OSS-Fuzz fallback for C/C++ deps
# ---------------------------------------------------------------------------


def test_osssfuzz_candidates_for_vcpkg():
    dep = _dep("openssl", "3.0.0", ecosystem="vcpkg")
    assert _oss_fuzz_candidates(dep) == ["openssl"]


def test_osssfuzz_candidates_for_conancenter():
    dep = _dep("openssl", "3.0.0", ecosystem="ConanCenter")
    assert _oss_fuzz_candidates(dep) == ["openssl"]


def test_osssfuzz_candidates_for_github_takes_repo_basename():
    """github ecosystem name is "owner/repo"; OSS-Fuzz uses repo
    basename for projects hosted at github.com/X/X."""
    dep = _dep("openssl/openssl", "abcdef", ecosystem="GitHub")
    assert _oss_fuzz_candidates(dep) == ["openssl"]


def test_osssfuzz_candidates_for_github_no_owner():
    """Defensive: a malformed GitHub name without a slash falls
    back to the name as-is rather than producing an empty
    string."""
    dep = _dep("singlename", "abc", ecosystem="GitHub")
    assert _oss_fuzz_candidates(dep) == ["singlename"]


def test_osssfuzz_candidates_for_pypi_returns_empty():
    """Non-C/C++ ecosystems get no fallback — OSS-Fuzz indexes
    C/C++ projects, querying it for npm/PyPI/etc would be noise."""
    dep = _dep("requests", "2.30.0", ecosystem="PyPI")
    assert _oss_fuzz_candidates(dep) == []


def test_osssfuzz_candidates_strips_conan_subname():
    """Conan-style ``openssl/3.0.0`` packed names get split if a
    caller passes the unstripped form."""
    dep = _dep("openssl/3.0.0", "1", ecosystem="ConanCenter")
    assert _oss_fuzz_candidates(dep) == ["openssl"]


def test_osssfuzz_fallback_fires_when_primary_empty(
    tmp_path: Path,
) -> None:
    """vcpkg dep with no primary hit → OSS-Fuzz fallback queries.
    Verified by FakeHttp recording two distinct POSTs: one for
    vcpkg ecosystem (empty), one for OSS-Fuzz (hits)."""
    dep = _dep("openssl", "3.0.0", ecosystem="vcpkg")

    posts: List[dict] = []
    osssfuzz_record = {
        "id": "OSV-2024-001",
        "aliases": [],
        "summary": "test",
        "details": "",
        "affected": [],
        "references": [],
    }

    class TrackingHttp(FakeHttp):
        def post_json(self, url, body, timeout=30):
            posts.append(body)
            # Primary vcpkg query → empty; OSS-Fuzz query → hit.
            eco = body["queries"][0]["package"]["ecosystem"]
            if eco == "vcpkg":
                return {"results": [{"vulns": []}]}
            return {"results": [{"vulns": [{"id": "OSV-2024-001"}]}]}

        def get_json(self, url, timeout=30):
            for vid, record in {"OSV-2024-001": osssfuzz_record}.items():
                if vid in url:
                    return record
            raise HttpError(f"unknown URL: {url}", status=404)

    http = TrackingHttp()
    client = OsvClient(http, JsonCache(root=tmp_path))
    results = client.query_batch([dep])
    assert len(results) == 1
    assert len(results[0].advisories) == 1
    assert results[0].advisories[0].osv_id == "OSV-2024-001"
    # Two HTTP calls: primary vcpkg + OSS-Fuzz fallback.
    assert len(posts) == 2
    primary_eco = posts[0]["queries"][0]["package"]["ecosystem"]
    fallback_eco = posts[1]["queries"][0]["package"]["ecosystem"]
    assert primary_eco == "vcpkg"
    assert fallback_eco == "OSS-Fuzz"


def test_osssfuzz_fallback_skipped_when_primary_has_hits(
    tmp_path: Path,
) -> None:
    """When the primary query returns advisories, the fallback
    must NOT fire — saves a network round-trip and keeps results
    deterministic."""
    dep = _dep("openssl", "3.0.0", ecosystem="vcpkg")

    posts: List[dict] = []

    class TrackingHttp(FakeHttp):
        def post_json(self, url, body, timeout=30):
            posts.append(body)
            return {"results": [{"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q"}]}]}

        def get_json(self, url, timeout=30):
            return _LOG4J_RECORD

    http = TrackingHttp()
    client = OsvClient(http, JsonCache(root=tmp_path))
    client.query_batch([dep])
    # Only the primary query was made.
    assert len(posts) == 1
    assert posts[0]["queries"][0]["package"]["ecosystem"] == "vcpkg"


def test_osssfuzz_fallback_not_fired_for_non_cpp_ecosystem(
    tmp_path: Path,
) -> None:
    """An empty-result PyPI dep doesn't trigger OSS-Fuzz fallback
    — PyPI deps don't have C/C++ analogues."""
    dep = _dep("nonexistent", "1.0", ecosystem="PyPI")

    posts: List[dict] = []

    class TrackingHttp(FakeHttp):
        def post_json(self, url, body, timeout=30):
            posts.append(body)
            return {"results": [{"vulns": []}]}

        def get_json(self, url, timeout=30):
            raise HttpError("not used", status=404)

    http = TrackingHttp()
    client = OsvClient(http, JsonCache(root=tmp_path))
    client.query_batch([dep])
    assert len(posts) == 1


def test_osssfuzz_fallback_caches_result(tmp_path: Path) -> None:
    """Second query for the same C/C++ dep hits the cache for
    BOTH primary AND OSS-Fuzz — no network calls."""
    dep = _dep("openssl", "3.0.0", ecosystem="vcpkg")

    posts: List[dict] = []
    record = {
        "id": "OSV-2024-001", "aliases": [], "summary": "x",
        "details": "", "affected": [], "references": [],
    }

    class TrackingHttp(FakeHttp):
        def post_json(self, url, body, timeout=30):
            posts.append(body)
            eco = body["queries"][0]["package"]["ecosystem"]
            if eco == "vcpkg":
                return {"results": [{"vulns": []}]}
            return {"results": [{"vulns": [{"id": "OSV-2024-001"}]}]}

        def get_json(self, url, timeout=30):
            return record

    http = TrackingHttp()
    cache = JsonCache(root=tmp_path)

    client1 = OsvClient(http, cache)
    client1.query_batch([dep])
    first_post_count = len(posts)

    # Second client, same cache: should hit cache for both
    # primary AND fallback queries.
    client2 = OsvClient(http, cache)
    client2.query_batch([dep])
    assert len(posts) == first_post_count, (
        f"expected no new HTTP calls but got "
        f"{len(posts) - first_post_count} new posts"
    )


def test_osssfuzz_fallback_skipped_in_offline_mode(
    tmp_path: Path,
) -> None:
    """Offline mode skips the fallback — the offline DB doesn't
    index OSS-Fuzz separately."""
    dep = _dep("openssl", "3.0.0", ecosystem="vcpkg")
    http = FakeHttp()
    client = OsvClient(http, JsonCache(root=tmp_path), offline=True)
    results = client.query_batch([dep])
    assert results[0].advisories == []
    # No HTTP calls in offline mode.
    assert http.posts == []


def test_osssfuzz_fallback_dedupes_with_primary_ids(
    tmp_path: Path,
) -> None:
    """If the primary AND fallback both return the same osv_id
    (rare; could happen if the same advisory exists under both
    ecosystems), pass-2 vuln hydration dedupes via the
    sorted-set construction."""
    # Force the scenario: primary returns ID X, fallback also
    # returns ID X. dep_to_ids[key] would have ["X", "X"] but
    # all_ids = sorted(set(...)) collapses to ["X"].
    dep = _dep("openssl", "3.0.0", ecosystem="vcpkg")

    record = {
        "id": "OSV-DUP", "aliases": [], "summary": "x",
        "details": "", "affected": [], "references": [],
    }

    class DupHttp(FakeHttp):
        def post_json(self, url, body, timeout=30):
            self.posts.append((url, body))
            return {"results": [{"vulns": [{"id": "OSV-DUP"}]}]}

        def get_json(self, url, timeout=30):
            return record

    http = DupHttp()
    client = OsvClient(http, JsonCache(root=tmp_path))
    results = client.query_batch([dep])
    # Primary returns hits → fallback should NOT fire (per the
    # earlier test), so this checks only one round-trip.
    # Even if fallback DID fire (in some hypothetical scenario),
    # the dedup at pass 2 would collapse the duplicate ID.
    assert len(results[0].advisories) == 1
    assert results[0].advisories[0].osv_id == "OSV-DUP"


# ---------------------------------------------------------------------------
# Multi-ecosystem batch — non-OSV ecosystems must not poison the batch
# ---------------------------------------------------------------------------


def test_query_batch_filters_unsupported_ecosystems(tmp_path: Path) -> None:
    """OSV's /querybatch returns HTTP 400 "Invalid ecosystem" if ANY
    query in the batch carries an ecosystem OSV doesn't index. With
    no filtering, one such dep silently returns empty for every
    legitimate dep in the same batch — the actual production bug
    that hid 120+ PyPI vulns on saleor's multi-manifest scan
    (.gitmodules + Debian + PyPI + npm in one tree).

    Filter pre-batch so only OSV-queryable ecosystems hit the API,
    and unsupported ecosystems get an empty cached entry without
    poisoning the rest.
    """
    deps = [
        _dep("django", ecosystem="PyPI", version="3.0.6"),
        # ``Debian`` is what Dockerfile-FROM scanning surfaces for
        # apt-installed binaries; OSV doesn't index it. Picked over
        # ``GitHub`` so the OSS-Fuzz fallback (which retries
        # GitHub-eco deps with a candidate-name) doesn't fire and
        # confuse the post-count assertion below.
        _dep("openssl-libs", ecosystem="Debian", version="1.1.1"),
        _dep("lodash", ecosystem="npm", version="4.17.20"),
    ]
    http = FakeHttp(
        # Only PyPI + npm should reach the batch — 2 slots, not 3.
        batch_results=[["GHSA-real-pypi"], ["GHSA-real-npm"]],
        vuln_records={
            "GHSA-real-pypi": {
                "id": "GHSA-real-pypi", "summary": "django bug",
                "affected": [{"package": {"name": "django",
                                            "ecosystem": "PyPI"},
                              "ranges": []}],
            },
            "GHSA-real-npm": {
                "id": "GHSA-real-npm", "summary": "lodash bug",
                "affected": [{"package": {"name": "lodash",
                                            "ecosystem": "npm"},
                              "ranges": []}],
            },
        },
    )
    client = OsvClient(http, JsonCache(root=tmp_path))
    results = client.query_batch(deps)

    by_key = {r.dep_key: r for r in results}
    # PyPI + npm got their advisories.
    assert (by_key["PyPI:django@3.0.6"].advisories[0].osv_id
            == "GHSA-real-pypi")
    assert (by_key["npm:lodash@4.17.20"].advisories[0].osv_id
            == "GHSA-real-npm")
    # Debian-eco dep recorded but with empty advisory list.
    assert by_key["Debian:openssl-libs@1.1.1"].advisories == []

    # The /querybatch HTTP call must have included exactly 2
    # queries — the Debian one was filtered out before the post.
    assert len(http.posts) == 1
    posted_body = http.posts[0][1]
    posted_queries = posted_body["queries"]
    assert len(posted_queries) == 2, (
        f"Debian-eco dep must not have reached /querybatch — body "
        f"contained {len(posted_queries)} queries: "
        f"{[q['package']['ecosystem'] for q in posted_queries]}"
    )
    posted_ecosystems = {q["package"]["ecosystem"] for q in posted_queries}
    assert "Debian" not in posted_ecosystems


def test_query_batch_translates_cargo_to_crates_io(tmp_path: Path) -> None:
    """OSV uses ``crates.io`` as the Rust ecosystem identifier and
    rejects ``Cargo`` with HTTP 400 "Invalid ecosystem" — silently
    zeroing every Cargo dep's advisory lookup. RAPTOR's internal
    naming stays ``Cargo`` (matches Cargo.lock / PURL type / rust-lang
    upstream); the OSV client must translate at the query boundary.
    """
    deps = [
        _dep("time", ecosystem="Cargo", version="0.2.20"),
        _dep("django", ecosystem="PyPI", version="3.0.6"),
    ]
    http = FakeHttp(
        batch_results=[["GHSA-cargo-time"], ["GHSA-pypi-django"]],
        vuln_records={
            "GHSA-cargo-time": {
                "id": "GHSA-cargo-time", "summary": "time segfault",
                "affected": [{"package": {"name": "time",
                                            "ecosystem": "crates.io"},
                              "ranges": []}],
            },
            "GHSA-pypi-django": {
                "id": "GHSA-pypi-django", "summary": "django bug",
                "affected": [{"package": {"name": "django",
                                            "ecosystem": "PyPI"},
                              "ranges": []}],
            },
        },
    )
    client = OsvClient(http, JsonCache(root=tmp_path))
    results = client.query_batch(deps)

    by_key = {r.dep_key: r for r in results}
    # Cargo dep keyed internally with ``Cargo:`` prefix — unchanged.
    assert (by_key["Cargo:time@0.2.20"].advisories[0].osv_id
            == "GHSA-cargo-time")

    # The wire-level ecosystem must be ``crates.io`` (OSV-canonical).
    posted_body = http.posts[0][1]
    posted_ecosystems = {
        q["package"]["ecosystem"] for q in posted_body["queries"]
    }
    assert "crates.io" in posted_ecosystems
    assert "Cargo" not in posted_ecosystems, (
        f"Cargo must be translated to crates.io before reaching "
        f"OSV; got {posted_ecosystems}"
    )
