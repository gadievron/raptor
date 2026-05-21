"""Tests for ``packages.sca.refresh_typosquat_lists``.

Stubs the HttpClient to return canned popularity-feed responses so no
real network fires in CI. Validates per-ecosystem parsing + the
orchestrator's idempotence + diff-aware writes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


from packages.sca.refresh_typosquat_lists import (
    _ANVAKA_NPM_RANK,
    _CRATES_API,
    _HUGOVK_TOP_PYPI,
    _PACKAGIST_POPULAR,
    fetch_crates,
    fetch_npm,
    fetch_packagist,
    fetch_pypi,
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
    http = _StubHttp({_ANVAKA_NPM_RANK: {
        "lodash": 1, "react": 2, "express": 3, "obscure": 9999,
    }})
    out = fetch_npm(http, top_n=3)
    assert set(out) == {"lodash", "react", "express"}
    assert "obscure" not in out


def test_fetch_npm_handles_non_dict():
    """Server returned a list (corrupt response) → empty result."""
    http = _StubHttp({_ANVAKA_NPM_RANK: ["not", "a", "dict"]})
    assert fetch_npm(http, top_n=10) == []


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
        _ANVAKA_NPM_RANK: {"lodash": 1},
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
            {"lodash": 1}, {"lodash": 1},
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
        _ANVAKA_NPM_RANK: {"lodash": 1},
        _CRATES_API: [{"crates": [{"name": "serde"}]}, {"crates": []}],
        _PACKAGIST_POPULAR: {"packages": [{"name": "m/m"}]},
    })
    results = refresh_all(http, top_n=10, data_dir=tmp_path)
    assert results["PyPI.json"] == "failed: empty result"
    assert not (tmp_path / "popular" / "PyPI.json").exists()
