"""Tests for ``packages.sca.refresh_typosquat_lists``.

Stubs the HttpClient to return canned popularity-feed responses so no
real network fires in CI. Validates per-ecosystem parsing + the
orchestrator's idempotence + diff-aware writes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest

from core.http import HttpError, SizeLimitExceeded
from packages.sca.refresh_typosquat_lists import (
    _ANVAKA_NPM_RANK,
    _CRATES_API,
    _HUGOVK_TOP_PYPI,
    _NPM_MAX_BYTES,
    _PACKAGIST_POPULAR,
    _get_json,
    fetch_crates,
    fetch_npm,
    fetch_packagist,
    fetch_pypi,
    main,
    refresh_all,
)


class _StubHttp:
    """Records URLs hit + returns canned JSON per URL prefix."""

    def __init__(self, responses: Dict[str, Any]) -> None:
        # ``responses`` maps URL substring → response dict.
        self._responses = responses
        self.calls: List[str] = []

    def get_json(self, url: str, *args, **kwargs) -> Any:
        self.calls.append(url)
        for key, body in self._responses.items():
            if key in url:
                if isinstance(body, list):
                    if not body:
                        raise RuntimeError(f"no more responses for {url}")
                    return body.pop(0)
                return body
        raise RuntimeError(f"no canned response for {url}")


# ---------------------------------------------------------------------------
# Per-fetcher parsing
# ---------------------------------------------------------------------------

def test_fetch_pypi_modern_format():
    """hugovk modern format: rows = [{'project': name, 'download_count': N}]."""
    http = _StubHttp({_HUGOVK_TOP_PYPI: {
        "rows": [
            {"project": "Requests", "download_count": 999},
            {"project": "boto3", "download_count": 888},
            {"project": "PyYAML", "download_count": 777},
        ],
    }})
    out = fetch_pypi(http, top_n=10)
    # Lowercased + deduped + sorted.
    assert out == ["boto3", "pyyaml", "requests"]


def test_fetch_pypi_top_n_truncates():
    http = _StubHttp({_HUGOVK_TOP_PYPI: {"rows": [
        {"project": f"pkg-{i}"} for i in range(20)
    ]}})
    out = fetch_pypi(http, top_n=5)
    assert len(out) == 5


def test_fetch_npm_anvaka_format():
    """anvaka npmrank: ``{"tags": {...}, "rank": {name: score}}`` where a
    HIGHER score = more depended-upon = more popular. Scores arrive as
    strings; take the top N by descending score."""
    http = _StubHttp({_ANVAKA_NPM_RANK: {
        "tags": {"0": ["ignored", "structural", "key"]},
        "rank": {"lodash": "9.5", "react": "8.0", "express": "7.0",
                 "obscure": "0.0001"},
    }})
    out = fetch_npm(http, top_n=3)
    assert set(out) == {"lodash", "react", "express"}
    assert "obscure" not in out


def test_fetch_npm_handles_non_dict():
    """Server returned a list (corrupt response) → empty result."""
    http = _StubHttp({_ANVAKA_NPM_RANK: ["not", "a", "dict"]})
    assert fetch_npm(http, top_n=10) == []


def test_fetch_npm_missing_rank_table():
    """Only the 'tags' index present (no 'rank' table) → empty, not a crash."""
    http = _StubHttp({_ANVAKA_NPM_RANK: {"tags": {"0": ["a", "b"]}}})
    assert fetch_npm(http, top_n=10) == []


def test_fetch_npm_skips_non_numeric_scores():
    """A non-floatable score is skipped, not fatal."""
    http = _StubHttp({_ANVAKA_NPM_RANK: {"rank": {
        "good": "5.0", "bad": "not-a-number", "alsogood": "3.0",
    }}})
    assert fetch_npm(http, top_n=10) == ["alsogood", "good"]


def test_fetch_crates_paginates():
    """Multi-page fetch: page 1 returns full per_page, page 2 partial,
    loop terminates on the partial page."""
    pages = [
        # per_page=2 → page 1 must have 2 items to trigger continuation
        {"crates": [{"name": "serde"}, {"name": "tokio"}]},
        {"crates": [{"name": "rand"}]},   # partial → stop
    ]
    http = _StubHttp({_CRATES_API: pages})
    out = fetch_crates(http, top_n=10, per_page=2)
    assert set(out) == {"serde", "tokio", "rand"}
    assert len([c for c in http.calls if "crates" in c]) == 2


def test_fetch_crates_partial_page_terminates():
    """A page < per_page items signals last page; no extra fetch."""
    pages = [
        {"crates": [{"name": "a"}, {"name": "b"}]},   # full page (per_page=2)
        {"crates": [{"name": "c"}]},                   # < per_page → stop
    ]
    http = _StubHttp({_CRATES_API: pages})
    fetch_crates(http, top_n=10, per_page=2)
    # Should have hit page 1 + page 2 = 2 URLs.
    assert len(http.calls) == 2


def test_fetch_packagist_follows_next():
    pages = [
        {"packages": [{"name": "monolog/monolog"}], "next": "..."},
        {"packages": [{"name": "symfony/console"}]},   # no next → stop
    ]
    http = _StubHttp({_PACKAGIST_POPULAR: pages})
    out = fetch_packagist(http, top_n=10)
    assert set(out) == {"monolog/monolog", "symfony/console"}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def test_refresh_all_writes_canonical_files(tmp_path: Path):
    http = _StubHttp({
        _HUGOVK_TOP_PYPI: {"rows": [{"project": "requests"}]},
        _ANVAKA_NPM_RANK: {"rank": {"lodash": "9.0"}},
        _CRATES_API: [
            {"crates": [{"name": "serde"}]},
            {"crates": []},   # terminator for the loop
        ],
        _PACKAGIST_POPULAR: {"packages": [{"name": "monolog/monolog"}]},
    })
    results = refresh_all(http, top_n=10, data_dir=tmp_path)
    assert all(s == "updated" for s in results.values()), results
    assert (tmp_path / "popular" / "PyPI.json").exists()
    assert (tmp_path / "popular" / "npm.json").exists()
    assert (tmp_path / "popular" / "Cargo.json").exists()
    assert (tmp_path / "popular" / "Packagist.json").exists()
    pypi_out = json.loads((tmp_path / "popular" / "PyPI.json").read_text())
    assert pypi_out == ["requests"]


def test_refresh_all_idempotent_when_unchanged(tmp_path: Path):
    """Running twice with the same upstream data must produce
    ``unchanged`` on the second pass — drives the workflow's
    'no diff, no PR' logic.

    Each fetcher consumes ONE list entry per refresh_all call
    (because the partial-page short-circuit terminates after the
    first page when the response is small).
    """
    http = _StubHttp({
        _HUGOVK_TOP_PYPI: [
            {"rows": [{"project": "requests"}]},
            {"rows": [{"project": "requests"}]},
        ],
        _ANVAKA_NPM_RANK: [
            {"rank": {"lodash": "9.0"}}, {"rank": {"lodash": "9.0"}},
        ],
        _CRATES_API: [
            {"crates": [{"name": "serde"}]},   # run 1
            {"crates": [{"name": "serde"}]},   # run 2
        ],
        _PACKAGIST_POPULAR: [
            {"packages": [{"name": "m/m"}]},
            {"packages": [{"name": "m/m"}]},
        ],
    })
    refresh_all(http, top_n=10, data_dir=tmp_path)
    second = refresh_all(http, top_n=10, data_dir=tmp_path)
    assert all(s == "unchanged" for s in second.values()), second


def test_refresh_all_failure_isolation(tmp_path: Path):
    """One ecosystem's source down must not block the others."""
    http = _StubHttp({
        _HUGOVK_TOP_PYPI: {"rows": [{"project": "requests"}]},
        # _ANVAKA_NPM_RANK: deliberately not in responses → fetch raises
        _CRATES_API: [{"crates": [{"name": "serde"}]}, {"crates": []}],
        _PACKAGIST_POPULAR: {"packages": [{"name": "m/m"}]},
    })
    results = refresh_all(http, top_n=10, data_dir=tmp_path)
    assert results["PyPI.json"] == "updated"
    assert results["npm.json"].startswith("failed:")
    assert results["Cargo.json"] == "updated"
    assert results["Packagist.json"] == "updated"


def test_refresh_all_only_filter(tmp_path: Path):
    http = _StubHttp({
        _HUGOVK_TOP_PYPI: {"rows": [{"project": "requests"}]},
    })
    results = refresh_all(http, top_n=10, data_dir=tmp_path, only=["PyPI"])
    assert results["PyPI.json"] == "updated"
    assert results["npm.json"] == "skipped"
    assert results["Cargo.json"] == "skipped"


def test_refresh_all_empty_response_treated_as_failure(tmp_path: Path):
    """A source returning {} (parseable but empty) shouldn't overwrite
    the bundled list with [] — that would silently disarm typosquat."""
    http = _StubHttp({
        _HUGOVK_TOP_PYPI: {"rows": []},
        _ANVAKA_NPM_RANK: {"rank": {"lodash": "9.0"}},
        _CRATES_API: [{"crates": [{"name": "serde"}]}, {"crates": []}],
        _PACKAGIST_POPULAR: {"packages": [{"name": "m/m"}]},
    })
    results = refresh_all(http, top_n=10, data_dir=tmp_path)
    assert results["PyPI.json"] == "failed: empty result"
    assert not (tmp_path / "popular" / "PyPI.json").exists()


# ---------------------------------------------------------------------------
# Transient-failure retry + size cap (_get_json)
# ---------------------------------------------------------------------------

class _FlakyHttp:
    """Raises ``exc`` for the first ``fail_times`` calls, then returns ``body``.
    Records the ``max_bytes`` passed on each call."""

    def __init__(self, body: Any, exc: Exception, fail_times: int) -> None:
        self.body = body
        self.exc = exc
        self.fail_times = fail_times
        self.calls = 0
        self.max_bytes_seen: List[Any] = []

    def get_json(self, url: str, *, retries: int = 0,
                 max_bytes: Any = None, **kw: Any) -> Any:
        self.calls += 1
        self.max_bytes_seen.append(max_bytes)
        if self.calls <= self.fail_times:
            raise self.exc
        return self.body


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Keep the retry backoff from slowing the suite."""
    monkeypatch.setattr(
        "packages.sca.refresh_typosquat_lists.time.sleep", lambda *_: None)


def test_get_json_retries_transient_non_json():
    """A non-JSON 200 surfaces as HttpError (parse sits outside the client's
    own retry loop). ``_get_json`` retries it and eventually succeeds."""
    http = _FlakyHttp({"ok": 1},
                      HttpError("Response is not valid JSON: "
                                "Expecting value: line 1 column 1 (char 0)"),
                      fail_times=2)
    assert _get_json(http, "https://example/x", attempts=3) == {"ok": 1}
    assert http.calls == 3


def test_get_json_gives_up_after_attempts():
    http = _FlakyHttp({"ok": 1}, HttpError("still bad"), fail_times=99)
    with pytest.raises(HttpError):
        _get_json(http, "https://example/x", attempts=3)
    assert http.calls == 3


def test_get_json_does_not_retry_size_limit():
    """A too-large response won't shrink on retry — re-raise immediately so
    the caller raises ``max_bytes`` instead."""
    http = _FlakyHttp({"ok": 1}, SizeLimitExceeded("too big"), fail_times=99)
    with pytest.raises(SizeLimitExceeded):
        _get_json(http, "https://example/x", attempts=3)
    assert http.calls == 1


def test_fetch_npm_requests_large_cap():
    """npmrank.json is ~85 MB > the 50 MB default — fetch_npm must lift the
    cap so the read doesn't trip SizeLimitExceeded."""
    http = _FlakyHttp({"rank": {"lodash": "9.0"}},
                      HttpError("unused"), fail_times=0)
    fetch_npm(http, top_n=5)
    assert http.max_bytes_seen[0] == _NPM_MAX_BYTES


# ---------------------------------------------------------------------------
# Write-failure status + main() exit semantics
# ---------------------------------------------------------------------------

def test_refresh_all_write_failure_marked_distinctly(tmp_path, monkeypatch):
    """An unwritable target is a *hard* failure (distinct ``write-failed:``
    status), not a soft per-source fetch failure."""
    http = _StubHttp({_HUGOVK_TOP_PYPI: {"rows": [{"project": "requests"}]}})

    def boom(*a, **k):
        raise PermissionError("read-only filesystem")

    monkeypatch.setattr(Path, "write_text", boom)
    results = refresh_all(http, top_n=10, data_dir=tmp_path, only=["PyPI"])
    assert results["PyPI.json"].startswith("write-failed:")


def _main_with_results(monkeypatch, tmp_path, results):
    monkeypatch.setattr(
        "packages.sca.refresh_typosquat_lists.refresh_all",
        lambda *a, **k: results)
    return main(["--data-dir", str(tmp_path)])


def test_main_partial_fetch_failure_is_soft(monkeypatch, tmp_path):
    """One source down among successes → exit 0 (the cron just omits it)."""
    rc = _main_with_results(monkeypatch, tmp_path, {
        "PyPI.json": "updated", "npm.json": "failed: HttpError: blip",
        "Cargo.json": "unchanged", "Packagist.json": "updated"})
    assert rc == 0


def test_main_total_fetch_outage_is_hard(monkeypatch, tmp_path):
    rc = _main_with_results(monkeypatch, tmp_path, {
        "PyPI.json": "failed: x", "npm.json": "failed: y",
        "Cargo.json": "failed: z", "Packagist.json": "failed: w"})
    assert rc == 1


def test_main_write_failure_is_hard(monkeypatch, tmp_path):
    rc = _main_with_results(monkeypatch, tmp_path, {
        "PyPI.json": "updated",
        "npm.json": "write-failed: PermissionError: read-only"})
    assert rc == 1


def test_main_all_skipped_is_ok(monkeypatch, tmp_path):
    """``--only`` filtering everything out → nothing attempted → exit 0."""
    rc = _main_with_results(monkeypatch, tmp_path, {
        "PyPI.json": "skipped", "npm.json": "skipped"})
    assert rc == 0
