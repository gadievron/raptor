"""Tests for ``core.cve.vulnrichment.VulnrichmentClient``."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import pytest

from core.cve.vulnrichment import (
    SSVCDecision,
    VulnrichmentClient,
    _decode_ssvc,
    _url_for_cve,
)
from core.http import HttpError
from core.json import JsonCache


class FakeHttp:
    """Stub ``HttpClient`` returning per-URL canned responses.

    Built to mirror ``test_kev.FakeHttp`` so the proxy-shape
    parity story matches operator expectations: every
    ``core.cve.*`` client takes a caller-injected HTTP /cache
    pair and tests it via the same fixture pattern.
    """

    def __init__(
        self,
        responses: Dict[str, Any] | None = None,
        errors: Dict[str, Exception] | None = None,
    ) -> None:
        self.responses = responses or {}
        self.errors = errors or {}
        self.gets: List[str] = []

    def get_json(self, url: str, timeout: int = 30) -> dict:
        self.gets.append(url)
        if url in self.errors:
            raise self.errors[url]
        return self.responses.get(url, {})

    def post_json(self, *a, **k):
        raise NotImplementedError

    def get_bytes(self, *a, **k):
        raise NotImplementedError


# ---------------------------------------------------------------------------
# URL building
# ---------------------------------------------------------------------------

class TestUrlForCve:
    """``_url_for_cve`` shards CVE IDs into Vulnrichment's
    bucketed layout: ``<year>/<NNNxxx>/CVE-...``. CVEs below
    1000 sit in ``0xxx``; everything else in
    ``floor(num/1000)xxx``."""

    def test_high_number(self):
        assert _url_for_cve("CVE-2024-12345") == (
            "https://raw.githubusercontent.com/cisagov/vulnrichment/"
            "HEAD/2024/12xxx/CVE-2024-12345.json"
        )

    def test_low_number_uses_0xxx(self):
        assert _url_for_cve("CVE-2024-500") == (
            "https://raw.githubusercontent.com/cisagov/vulnrichment/"
            "HEAD/2024/0xxx/CVE-2024-500.json"
        )

    def test_case_insensitive_input(self):
        a = _url_for_cve("cve-2024-1000")
        b = _url_for_cve("CVE-2024-1000")
        assert a == b

    def test_malformed_returns_none(self):
        assert _url_for_cve("not-a-cve") is None
        assert _url_for_cve("CVE-202X-1000") is None
        assert _url_for_cve("") is None
        # Strict CVE-YYYY-NNN shape — extra component is rejected.
        assert _url_for_cve("CVE-2024-1000-extra") is None


# ---------------------------------------------------------------------------
# SSVC decoder
# ---------------------------------------------------------------------------

def _vulnrichment_record(
    exploitation: str = "poc",
    automatable: str = "no",
    technical_impact: str = "total",
) -> dict:
    """Synthesise a Vulnrichment-shaped record carrying the
    given SSVC option values. The actual CVE-JSON-5 schema has
    far more fields; we include only what
    ``_decode_ssvc`` reads so the test contract is precise."""
    return {
        "cveMetadata": {"cveId": "CVE-2024-1000"},
        "containers": {
            "adp": [
                {
                    "providerMetadata": {"shortName": "CISA-ADP"},
                    "metrics": [
                        {
                            "other": {
                                "content": {
                                    "options": [
                                        {"Exploitation": exploitation},
                                        {"Automatable": automatable},
                                        {
                                            "Technical Impact":
                                                technical_impact,
                                        },
                                    ],
                                },
                            },
                        },
                    ],
                },
            ],
        },
    }


class TestDecodeSsvc:
    def test_all_three_fields_extracted(self):
        d = _decode_ssvc(_vulnrichment_record(
            exploitation="poc",
            automatable="yes",
            technical_impact="total",
        ))
        assert d == SSVCDecision(
            exploitation="poc",
            automatable="yes",
            technical_impact="total",
        )

    def test_exploitation_active_recognised(self):
        d = _decode_ssvc(_vulnrichment_record(exploitation="active"))
        assert d.exploitation == "active"
        assert d.is_active is True
        assert d.has_exploit is True

    def test_exploitation_poc_has_exploit_not_active(self):
        d = _decode_ssvc(_vulnrichment_record(exploitation="poc"))
        assert d.has_exploit is True
        assert d.is_active is False

    def test_exploitation_none_no_exploit_signal(self):
        d = _decode_ssvc(_vulnrichment_record(exploitation="none"))
        assert d.exploitation == "none"
        assert d.has_exploit is False
        assert d.is_active is False

    def test_case_normalised_to_lowercase(self):
        """SSVC enum spellings vary across upstream entries —
        we lowercase so the risk formula's string comparisons
        don't trip."""
        d = _decode_ssvc(_vulnrichment_record(
            exploitation="POC", automatable="YES",
            technical_impact="TOTAL",
        ))
        assert d.exploitation == "poc"
        assert d.automatable == "yes"
        assert d.technical_impact == "total"

    def test_missing_adp_container_returns_none(self):
        # Record has no ADP container at all (CISA hasn't
        # enriched this entry yet).
        assert _decode_ssvc({"containers": {}}) is None

    def test_non_cisa_adp_provider_skipped(self):
        # If a different ADP (e.g. another federal agency)
        # populates the container without an SSVC, we shouldn't
        # claim CISA's score.
        record = _vulnrichment_record()
        record["containers"]["adp"][0]["providerMetadata"][
            "shortName"
        ] = "Other-ADP"
        assert _decode_ssvc(record) is None

    def test_missing_exploitation_field_returns_none(self):
        # Some Vulnrichment entries have CVSS / CWE enrichment
        # but no SSVC scorecard yet. ``_decode_ssvc`` must
        # return None rather than fabricate a default — the
        # risk formula should treat "no signal" differently
        # from "exploitation=none".
        record = {
            "containers": {
                "adp": [{
                    "providerMetadata": {"shortName": "CISA-ADP"},
                    "metrics": [{"other": {"content": {
                        "options": [{"Automatable": "no"}],
                    }}}],
                }],
            },
        }
        assert _decode_ssvc(record) is None

    def test_garbage_input_returns_none(self):
        # Defensive: any unexpected shape → None, never an
        # exception. The lookup runs against a fed-from-the-
        # internet JSON document; we never want a malformed
        # entry to take down the scan.
        assert _decode_ssvc(None) is None
        assert _decode_ssvc("string") is None
        assert _decode_ssvc(42) is None
        assert _decode_ssvc({"containers": "not a dict"}) is None


# ---------------------------------------------------------------------------
# Client end-to-end (HTTP + cache)
# ---------------------------------------------------------------------------

class TestVulnrichmentClient:
    def test_lookup_hits_canonical_url(self, tmp_path: Path):
        url = (
            "https://raw.githubusercontent.com/cisagov/vulnrichment/"
            "HEAD/2024/12xxx/CVE-2024-12345.json"
        )
        http = FakeHttp(responses={
            url: _vulnrichment_record(exploitation="active"),
        })
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        d = client.lookup("CVE-2024-12345")
        assert d is not None
        assert d.exploitation == "active"
        assert http.gets == [url]

    def test_lookup_caches_in_process(self, tmp_path: Path):
        """Second lookup of the same CVE must NOT re-hit HTTP.
        Pin the per-process memo so a single SCA run with many
        findings citing the same CVE pays the network cost
        once."""
        url = (
            "https://raw.githubusercontent.com/cisagov/vulnrichment/"
            "HEAD/2024/12xxx/CVE-2024-12345.json"
        )
        http = FakeHttp(responses={
            url: _vulnrichment_record(exploitation="poc"),
        })
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        client.lookup("CVE-2024-12345")
        client.lookup("CVE-2024-12345")
        client.lookup("cve-2024-12345")    # case-folds to same key
        assert http.gets == [url], (
            f"expected one HTTP call, got {len(http.gets)}: "
            f"{http.gets}"
        )

    def test_lookup_uses_disk_cache_across_clients(
        self, tmp_path: Path,
    ):
        """Cold-start: client A fetches and writes to JsonCache;
        client B (new process simulation) reads from disk
        without hitting HTTP."""
        url = (
            "https://raw.githubusercontent.com/cisagov/vulnrichment/"
            "HEAD/2024/12xxx/CVE-2024-12345.json"
        )
        cache = JsonCache(root=tmp_path)
        http_a = FakeHttp(responses={
            url: _vulnrichment_record(exploitation="poc"),
        })
        VulnrichmentClient(http_a, cache).lookup("CVE-2024-12345")

        http_b = FakeHttp()      # would error if hit, returns {}
        d = VulnrichmentClient(http_b, cache).lookup("CVE-2024-12345")
        assert d is not None
        assert d.exploitation == "poc"
        assert http_b.gets == [], (
            "disk cache should have served the second client; "
            f"actual gets: {http_b.gets}"
        )

    def test_404_returns_none_and_caches_negative(
        self, tmp_path: Path,
    ):
        """CISA hasn't enriched every CVE. The upstream 404 must
        return ``None`` AND cache a negative marker so a repeat
        lookup within the negative-TTL window doesn't re-probe."""
        url = (
            "https://raw.githubusercontent.com/cisagov/vulnrichment/"
            "HEAD/2024/12xxx/CVE-2024-12345.json"
        )
        http = FakeHttp(errors={
            url: HttpError("404 Not Found"),
        })
        cache = JsonCache(root=tmp_path)
        client = VulnrichmentClient(http, cache)
        assert client.lookup("CVE-2024-12345") is None
        assert http.gets == [url]

        # Second client (fresh process) — must read the negative
        # marker from disk, not re-probe.
        http2 = FakeHttp(errors={
            url: HttpError("404 Not Found"),
        })
        client2 = VulnrichmentClient(http2, cache)
        assert client2.lookup("CVE-2024-12345") is None
        assert http2.gets == [], (
            f"negative cache miss; client2 re-probed: {http2.gets}"
        )

    def test_transient_error_not_cached(self, tmp_path: Path):
        """5xx / transport errors must NOT cache — a brief
        network blip shouldn't black-hole the CVE for a week.
        The next call gets a fresh attempt."""
        url = (
            "https://raw.githubusercontent.com/cisagov/vulnrichment/"
            "HEAD/2024/12xxx/CVE-2024-12345.json"
        )
        cache = JsonCache(root=tmp_path)
        http_fail = FakeHttp(errors={
            url: HttpError("connection reset"),
        })
        # First call: fails, returns None, doesn't cache.
        c1 = VulnrichmentClient(http_fail, cache)
        assert c1.lookup("CVE-2024-12345") is None

        # Second client + working HTTP must succeed (no
        # negative cache to block it).
        http_ok = FakeHttp(responses={
            url: _vulnrichment_record(exploitation="active"),
        })
        c2 = VulnrichmentClient(http_ok, cache)
        d = c2.lookup("CVE-2024-12345")
        assert d is not None
        assert d.exploitation == "active"

    def test_offline_with_cold_cache_returns_none(
        self, tmp_path: Path,
    ):
        """``offline=True`` + nothing on disk → ``None`` and no
        network call attempted."""
        http = FakeHttp()
        client = VulnrichmentClient(
            http, JsonCache(root=tmp_path), offline=True,
        )
        assert client.lookup("CVE-2024-12345") is None
        assert http.gets == []

    def test_malformed_cve_returns_none(self, tmp_path: Path):
        http = FakeHttp()
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        assert client.lookup("not-a-cve") is None
        assert client.lookup("") is None
        assert http.gets == []


# ---------------------------------------------------------------------------
# SSVCDecision properties
# ---------------------------------------------------------------------------

class TestSSVCDecisionProperties:
    @pytest.mark.parametrize("exploitation,active,has_exp", [
        ("active", True, True),
        ("poc", False, True),
        ("none", False, False),
    ])
    def test_properties(self, exploitation, active, has_exp):
        d = SSVCDecision(
            exploitation=exploitation,
            automatable=None,
            technical_impact=None,
        )
        assert d.is_active is active
        assert d.has_exploit is has_exp
