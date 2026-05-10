"""Tests for ``core.cve.epss.EpssClient``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import pytest

from core.cve.epss import EPSS_URL, EpssClient
from core.http import HttpError
from core.json import JsonCache


class FakeHttp:
    """Stub ``HttpClient`` that returns a canned payload (or raises)."""

    def __init__(self, payload: Dict[str, Any] | None = None,
                 error: Exception | None = None) -> None:
        self.payload = payload
        self.error = error
        self.gets: list[str] = []

    def post_json(self, *a, **k):
        raise NotImplementedError

    def get_json(self, url: str, timeout: int = 30) -> dict:
        self.gets.append(url)
        if self.error:
            raise self.error
        return self.payload or {}

    def get_bytes(self, *a, **k):
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Basic lookup
# ---------------------------------------------------------------------------


class TestEpssBasic:
    def test_basic_lookup(self, tmp_path: Path) -> None:
        payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97559"}]}
        http = FakeHttp(payload=payload)
        epss = EpssClient(http, JsonCache(root=tmp_path))
        assert epss.scores(["CVE-2021-44228"]) == {"CVE-2021-44228": 0.97559}

    def test_score_convenience(self, tmp_path: Path) -> None:
        payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97559"}]}
        epss = EpssClient(
            FakeHttp(payload=payload), JsonCache(root=tmp_path),
        )
        assert epss.score("CVE-2021-44228") == 0.97559

    def test_missing_cve_omitted_from_result(self, tmp_path: Path) -> None:
        payload = {"data": []}
        epss = EpssClient(
            FakeHttp(payload=payload), JsonCache(root=tmp_path),
        )
        assert epss.scores(["CVE-9999-99999"]) == {}

    def test_dedup_normalises_case(self, tmp_path: Path) -> None:
        payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97"}]}
        http = FakeHttp(payload=payload)
        epss = EpssClient(http, JsonCache(root=tmp_path))
        epss.scores(["CVE-2021-44228", "cve-2021-44228"])
        # Only one CVE in the URL.
        assert http.gets[0].count("CVE-2021-44228") == 1


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


class TestEpssCaching:
    def test_warm_cache_skips_network(self, tmp_path: Path) -> None:
        cache = JsonCache(root=tmp_path)
        payload = {"data": [{"cve": "CVE-2021-44228", "epss": "0.97559"}]}
        EpssClient(FakeHttp(payload=payload), cache).scores(
            ["CVE-2021-44228"],
        )
        http2 = FakeHttp(payload={})
        epss2 = EpssClient(http2, cache)
        assert epss2.scores(["CVE-2021-44228"]) == {
            "CVE-2021-44228": 0.97559,
        }
        assert http2.gets == []

    def test_no_score_sentinel_avoids_refetch(
        self, tmp_path: Path,
    ) -> None:
        """A CVE the API has no data for is cached as a sentinel so
        the next run doesn't refetch it."""
        cache = JsonCache(root=tmp_path)
        EpssClient(
            FakeHttp(payload={"data": []}), cache,
        ).scores(["CVE-X"])
        http2 = FakeHttp(
            payload={"data": [{"cve": "CVE-X", "epss": "0.5"}]},
        )
        epss2 = EpssClient(http2, cache)
        # Sentinel is honoured: empty result, no network call.
        assert epss2.scores(["CVE-X"]) == {}
        assert http2.gets == []

    def test_offline_cold_cache_returns_empty(
        self, tmp_path: Path,
    ) -> None:
        http = FakeHttp(error=HttpError("should not be called"))
        epss = EpssClient(
            http, JsonCache(root=tmp_path), offline=True,
        )
        assert epss.scores(["CVE-2021-44228"]) == {}
        assert http.gets == []


# ---------------------------------------------------------------------------
# Batching
# ---------------------------------------------------------------------------


class TestEpssBatching:
    def test_batch_chunking_caps_url_length(
        self, tmp_path: Path,
    ) -> None:
        payload = {"data": [
            {"cve": f"CVE-2021-{i:05d}", "epss": "0.5"}
            for i in range(150)
        ]}
        http = FakeHttp(payload=payload)
        epss = EpssClient(http, JsonCache(root=tmp_path))
        epss.scores([f"CVE-2021-{i:05d}" for i in range(150)])
        # Default batch size is 100 → exactly 2 chunked GET calls.
        assert len(http.gets) == 2

    def test_each_chunk_uses_epss_url(self, tmp_path: Path) -> None:
        payload = {"data": [
            {"cve": f"CVE-2021-{i:05d}", "epss": "0.5"}
            for i in range(50)
        ]}
        http = FakeHttp(payload=payload)
        epss = EpssClient(http, JsonCache(root=tmp_path))
        epss.scores([f"CVE-2021-{i:05d}" for i in range(50)])
        assert http.gets[0].startswith(EPSS_URL)


# ---------------------------------------------------------------------------
# Error / malformed response handling
# ---------------------------------------------------------------------------


class TestEpssErrors:
    def test_network_error_returns_empty(self, tmp_path: Path) -> None:
        epss = EpssClient(
            FakeHttp(error=HttpError("boom")),
            JsonCache(root=tmp_path),
        )
        assert epss.scores(["CVE-2021-44228"]) == {}

    def test_invalid_score_skipped(self, tmp_path: Path) -> None:
        payload = {"data": [
            {"cve": "CVE-A", "epss": "not-a-number"},
            {"cve": "CVE-B", "epss": "0.5"},
        ]}
        epss = EpssClient(
            FakeHttp(payload=payload), JsonCache(root=tmp_path),
        )
        assert epss.scores(["CVE-A", "CVE-B"]) == {"CVE-B": 0.5}

    def test_non_dict_response_returns_empty(self, tmp_path: Path) -> None:
        http = FakeHttp(payload="not a dict")  # type: ignore[arg-type]
        epss = EpssClient(http, JsonCache(root=tmp_path))
        assert epss.scores(["CVE-A"]) == {}

    def test_non_list_data_returns_empty(self, tmp_path: Path) -> None:
        http = FakeHttp(payload={"data": "not a list"})
        epss = EpssClient(http, JsonCache(root=tmp_path))
        assert epss.scores(["CVE-A"]) == {}

    def test_non_dict_entries_skipped(self, tmp_path: Path) -> None:
        payload = {"data": [
            "string entry",
            42,
            None,
            {"cve": "CVE-OK", "epss": "0.5"},
        ]}
        epss = EpssClient(
            FakeHttp(payload=payload), JsonCache(root=tmp_path),
        )
        assert epss.scores(["CVE-OK"]) == {"CVE-OK": 0.5}

    def test_non_string_cve_field_skipped(self, tmp_path: Path) -> None:
        payload = {"data": [
            {"cve": 12345, "epss": "0.9"},
            {"cve": "CVE-OK", "epss": "0.5"},
        ]}
        epss = EpssClient(
            FakeHttp(payload=payload), JsonCache(root=tmp_path),
        )
        assert epss.scores(["CVE-OK"]) == {"CVE-OK": 0.5}


# ---------------------------------------------------------------------------
# Hostile / adversarial inputs
# ---------------------------------------------------------------------------


class TestEpssAdversarial:
    def test_empty_input_returns_empty(self, tmp_path: Path) -> None:
        http = FakeHttp(payload={"data": []})
        epss = EpssClient(http, JsonCache(root=tmp_path))
        assert epss.scores([]) == {}
        assert http.gets == []

    def test_non_string_input_filtered(self, tmp_path: Path) -> None:
        http = FakeHttp(payload={"data": []})
        epss = EpssClient(http, JsonCache(root=tmp_path))
        # ints / None / empty strings get filtered before the API call.
        epss.scores([None, "", 0, "CVE-VALID"])  # type: ignore[list-item]
        # One GET, one CVE in the URL.
        assert len(http.gets) == 1
        assert "CVE-VALID" in http.gets[0]
        assert "None" not in http.gets[0]

    def test_huge_cve_id_does_not_crash(self, tmp_path: Path) -> None:
        # 100KB CVE id — gets uppercased + URL-included; doesn't blow
        # up the client or the (mocked) HTTP layer.
        big_cve = "CVE-" + "9" * 100_000
        epss = EpssClient(
            FakeHttp(payload={"data": []}), JsonCache(root=tmp_path),
        )
        # Doesn't raise.
        result = epss.scores([big_cve])
        assert result == {}

    def test_mixed_case_cves_normalised_in_cache(
        self, tmp_path: Path,
    ) -> None:
        cache = JsonCache(root=tmp_path)
        EpssClient(
            FakeHttp(payload={"data": [{"cve": "CVE-1", "epss": "0.5"}]}),
            cache,
        ).scores(["cve-1"])
        # Cache hit on the upper-case key — second call no network.
        http2 = FakeHttp(payload={})
        epss2 = EpssClient(http2, cache)
        assert epss2.scores(["CVE-1"]) == {"CVE-1": 0.5}
        assert http2.gets == []
