"""Tests for ``core.cve.kev.KevClient``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict


from core.cve.kev import KEV_URL, KevClient
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


_PAYLOAD = {
    "vulnerabilities": [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
        {"cveID": "CVE-2017-5638"},
    ],
}


# ---------------------------------------------------------------------------
# Basic lookup
# ---------------------------------------------------------------------------


class TestKevBasic:
    def test_contains_known_cve(self, tmp_path: Path) -> None:
        http = FakeHttp(payload=_PAYLOAD)
        kev = KevClient(http, JsonCache(root=tmp_path))
        assert kev.contains("CVE-2021-44228") is True
        assert kev.contains("cve-2021-44228") is True   # case-insensitive
        assert kev.contains("CVE-9999-99999") is False

    def test_contains_loads_lazily(self, tmp_path: Path) -> None:
        http = FakeHttp(payload=_PAYLOAD)
        kev = KevClient(http, JsonCache(root=tmp_path))
        assert kev.is_loaded() is False
        assert http.gets == []
        kev.contains("CVE-2021-44228")
        assert kev.is_loaded() is True
        assert http.gets == [KEV_URL]

    def test_alternate_cve_id_field(self, tmp_path: Path) -> None:
        # Older snapshots use ``cve_id`` instead of ``cveID``.
        payload = {"vulnerabilities": [{"cve_id": "CVE-2020-0001"}]}
        kev = KevClient(
            FakeHttp(payload=payload), JsonCache(root=tmp_path),
        )
        assert kev.contains("CVE-2020-0001") is True


# ---------------------------------------------------------------------------
# Caching
# ---------------------------------------------------------------------------


class TestKevCaching:
    def test_warm_cache_skips_network(self, tmp_path: Path) -> None:
        cache = JsonCache(root=tmp_path)
        http1 = FakeHttp(payload=_PAYLOAD)
        KevClient(http1, cache).contains("CVE-2021-44228")
        http2 = FakeHttp(payload={})    # would fail to find anything
        kev2 = KevClient(http2, cache)
        assert kev2.contains("CVE-2021-44228") is True
        assert http2.gets == []

    def test_offline_cold_cache_returns_false(
        self, tmp_path: Path,
    ) -> None:
        http = FakeHttp(error=HttpError("should not be called"))
        kev = KevClient(
            http, JsonCache(root=tmp_path), offline=True,
        )
        assert kev.contains("CVE-2021-44228") is False
        assert http.gets == []


# ---------------------------------------------------------------------------
# Error / malformed handling
# ---------------------------------------------------------------------------


class TestKevErrors:
    def test_network_error_degrades_gracefully(
        self, tmp_path: Path,
    ) -> None:
        http = FakeHttp(error=HttpError("offline"))
        kev = KevClient(http, JsonCache(root=tmp_path))
        assert kev.contains("CVE-2021-44228") is False
        assert kev.is_loaded() is True

    def test_malformed_payload_yields_empty_set(
        self, tmp_path: Path,
    ) -> None:
        http = FakeHttp(payload={"unexpected": "shape"})
        kev = KevClient(http, JsonCache(root=tmp_path))
        assert kev.contains("CVE-2021-44228") is False
        assert kev.is_loaded() is True

    def test_non_dict_response_yields_empty_set(
        self, tmp_path: Path,
    ) -> None:
        http = FakeHttp(payload="not a dict")  # type: ignore[arg-type]
        kev = KevClient(http, JsonCache(root=tmp_path))
        assert kev.contains("CVE-2021-44228") is False

    def test_non_list_vulnerabilities_yields_empty_set(
        self, tmp_path: Path,
    ) -> None:
        http = FakeHttp(payload={"vulnerabilities": "not a list"})
        kev = KevClient(http, JsonCache(root=tmp_path))
        assert kev.contains("CVE-2021-44228") is False

    def test_non_dict_entries_skipped(self, tmp_path: Path) -> None:
        payload = {"vulnerabilities": [
            "string entry",
            42,
            None,
            {"cveID": "CVE-OK"},
        ]}
        kev = KevClient(
            FakeHttp(payload=payload), JsonCache(root=tmp_path),
        )
        assert kev.contains("CVE-OK") is True

    def test_non_string_cve_id_skipped(self, tmp_path: Path) -> None:
        payload = {"vulnerabilities": [
            {"cveID": 12345},
            {"cveID": "CVE-OK"},
        ]}
        kev = KevClient(
            FakeHttp(payload=payload), JsonCache(root=tmp_path),
        )
        assert kev.contains("CVE-OK") is True


# ---------------------------------------------------------------------------
# Hostile / adversarial inputs
# ---------------------------------------------------------------------------


class TestKevAdversarial:
    def test_empty_id_returns_false(self, tmp_path: Path) -> None:
        kev = KevClient(
            FakeHttp(payload=_PAYLOAD), JsonCache(root=tmp_path),
        )
        assert kev.contains("") is False
        # No network fetch when the input is empty.
        assert kev.is_loaded() is False

    def test_huge_cve_id_does_not_crash(self, tmp_path: Path) -> None:
        big_cve = "CVE-" + "9" * 100_000
        kev = KevClient(
            FakeHttp(payload=_PAYLOAD), JsonCache(root=tmp_path),
        )
        # Lazy-load fires; doesn't crash; not in payload.
        assert kev.contains(big_cve) is False

    def test_payload_with_huge_vuln_list(self, tmp_path: Path) -> None:
        # 10K entries — set construction is O(N), no quadratic
        # behaviour.
        payload = {"vulnerabilities": [
            {"cveID": f"CVE-2020-{i:05d}"} for i in range(10_000)
        ]}
        http = FakeHttp(payload=payload)
        kev = KevClient(http, JsonCache(root=tmp_path))
        assert kev.contains("CVE-2020-00000") is True
        assert kev.contains("CVE-2020-09999") is True
        assert kev.contains("CVE-2020-10000") is False

    def test_unicode_cve_id_does_not_crash(self, tmp_path: Path) -> None:
        kev = KevClient(
            FakeHttp(payload=_PAYLOAD), JsonCache(root=tmp_path),
        )
        # Unicode lookup — not in the catalog; doesn't crash.
        assert kev.contains("CVE-2020-Ω") is False
