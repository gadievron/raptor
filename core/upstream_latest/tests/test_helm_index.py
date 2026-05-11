"""Tests for ``core.upstream_latest.helm_index``."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from core.http import HttpError
from core.upstream_latest.github_releases import (
    NoStableVersionsFound,
    UpstreamLookupError,
)
from core.upstream_latest.helm_index import latest_chart_version


# Skip everything if PyYAML isn't available — same fallback as
# the production code.
yaml = pytest.importorskip("yaml")


class _StubHttp:
    def __init__(self, payloads: Dict[str, bytes]):
        self._payloads = payloads

    def get_bytes(self, url: str, **kw):
        if url in self._payloads:
            return self._payloads[url]
        raise HttpError(f"stub: no payload for {url}")


def _idx(*, entries: Dict[str, List[Dict[str, Any]]]) -> bytes:
    return yaml.safe_dump(
        {"apiVersion": "v1", "entries": entries}
    ).encode("utf-8")


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

def test_latest_chart_version_picks_highest_stable() -> None:
    """Multiple versions in the index → highest stable wins."""
    http = _StubHttp({
        "https://charts.example.com/index.yaml":
            _idx(entries={
                "postgresql": [
                    {"version": "13.4.4"},
                    {"version": "13.4.3"},
                    {"version": "14.0.0"},
                ],
            }),
    })
    assert latest_chart_version(
        "https://charts.example.com", "postgresql", http=http,
    ) == "14.0.0"


def test_latest_chart_version_filters_pre_releases() -> None:
    """Pre-release / variant shapes skipped via the shared
    ``_version_filter``."""
    http = _StubHttp({
        "https://charts.example.com/index.yaml":
            _idx(entries={
                "redis": [
                    {"version": "7.0.0-rc.1"},     # pre-release
                    {"version": "7.0.0-beta.1"},    # pre-release
                    {"version": "6.2.0"},           # stable winner
                ],
            }),
    })
    assert latest_chart_version(
        "https://charts.example.com", "redis", http=http,
    ) == "6.2.0"


def test_repo_url_trailing_slash_tolerated() -> None:
    """Many Chart.yaml entries write the URL with a trailing
    slash. Normalize correctly."""
    http = _StubHttp({
        "https://charts.example.com/index.yaml":
            _idx(entries={"foo": [{"version": "1.0.0"}]}),
    })
    assert latest_chart_version(
        "https://charts.example.com/",     # trailing /
        "foo", http=http,
    ) == "1.0.0"


def test_full_index_url_accepted_as_is() -> None:
    """When the operator already wrote
    ``https://example.com/index.yaml``, don't double-suffix it."""
    http = _StubHttp({
        "https://example.com/index.yaml":
            _idx(entries={"x": [{"version": "1.0"}]}),
    })
    assert latest_chart_version(
        "https://example.com/index.yaml", "x", http=http,
    ) == "1.0"


# ---------------------------------------------------------------------------
# Error paths
# ---------------------------------------------------------------------------

def test_chart_not_in_entries_raises() -> None:
    """Index doesn't list the chart name → ``UpstreamLookupError``.
    Caller decides whether to skip or fallback."""
    http = _StubHttp({
        "https://charts.example.com/index.yaml":
            _idx(entries={"other-chart": [{"version": "1.0.0"}]}),
    })
    with pytest.raises(UpstreamLookupError) as exc_info:
        latest_chart_version(
            "https://charts.example.com", "missing-chart", http=http,
        )
    assert "missing-chart" in str(exc_info.value)


def test_all_versions_pre_release_raises() -> None:
    """Chart exists but every version is pre-release →
    ``NoStableVersionsFound``."""
    http = _StubHttp({
        "https://charts.example.com/index.yaml":
            _idx(entries={
                "x": [
                    {"version": "1.0.0-rc.1"},
                    {"version": "1.0.0-beta.1"},
                ],
            }),
    })
    with pytest.raises(NoStableVersionsFound):
        latest_chart_version(
            "https://charts.example.com", "x", http=http,
        )


def test_http_failure_wraps_to_upstream_lookup_error() -> None:
    """Network failure → ``UpstreamLookupError`` (consistent with
    ``github_releases`` + ``oci_tags`` shape)."""
    http = _StubHttp({})  # nothing → HttpError on get_bytes
    with pytest.raises(UpstreamLookupError):
        latest_chart_version(
            "https://offline.example.com", "x", http=http,
        )


def test_malformed_yaml_raises() -> None:
    """Index returned non-YAML bytes → ``UpstreamLookupError``."""
    http = _StubHttp({
        "https://example.com/index.yaml":
            b"this: is: not: valid: yaml: : :",
    })
    with pytest.raises(UpstreamLookupError):
        latest_chart_version("https://example.com", "x", http=http)


def test_chart_entry_without_version_field_raises() -> None:
    """Entry exists but no version key → ``UpstreamLookupError``."""
    http = _StubHttp({
        "https://example.com/index.yaml":
            _idx(entries={"x": [{"name": "x", "digest": "sha"}]}),
    })
    with pytest.raises(UpstreamLookupError) as exc_info:
        latest_chart_version("https://example.com", "x", http=http)
    assert "version" in str(exc_info.value)
