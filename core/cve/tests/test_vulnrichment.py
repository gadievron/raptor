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

    def test_unicode_digit_cve_returns_none(self, tmp_path: Path):
        """Superscript "²" passes ``str.isdigit()`` but crashes
        ``int()`` — the id must be refused up front, per the
        "malformed → None" contract."""
        http = FakeHttp()
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        assert client.lookup("CVE-2024-1²3") is None
        # Non-ASCII decimal digits (Unicode Nd) survive int() but are
        # not valid CVE ids either — the ASCII regex refuses them.
        assert client.lookup("CVE-2024-١٢٣٤") is None
        assert http.gets == []

    def test_path_degenerate_cve_returns_none(self, tmp_path: Path):
        """Ids like ".." would otherwise reach the cache-key layer
        and raise there, before the URL builder's own shape check."""
        http = FakeHttp()
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        assert client.lookup("..") is None
        assert client.lookup("a//b") is None
        assert http.gets == []


# ---------------------------------------------------------------------------
# Hostile / undecodable records — per-id decode boundary
# ---------------------------------------------------------------------------

def _hostile_record() -> dict:
    """CVE-JSON-5 shaped record whose ADP entry carries a truthy
    non-dict where a dict is expected — the class of shape drift a
    hostile upstream (or a CDN error page mimicking the schema) can
    ship inside an otherwise well-formed 200 body."""
    return {"containers": {"adp": [
        {"providerMetadata": "CISA-ADP", "metrics": []},
    ]}}


class TestDecodeBoundary:
    URL = (
        "https://raw.githubusercontent.com/cisagov/vulnrichment/"
        "HEAD/2024/12xxx/CVE-2024-12345.json"
    )

    def test_hostile_subshapes_return_none(self):
        """A truthy non-dict one level down must not escape the
        "any unexpected shape returns None" contract."""
        shapes = [
            _hostile_record(),
            {"containers": {"adp": [
                {"providerMetadata": {"shortName": "CISA-ADP"},
                 "metrics": [{"other": "junk"}]}]}},
            {"containers": {"adp": [
                {"providerMetadata": {"shortName": "CISA-ADP"},
                 "metrics": [{"other": {"content": [1, 2]}}]}]}},
            {"containers": {"adp": [
                {"providerMetadata": {"shortName": 42},
                 "metrics": "junk"}]}},
        ]
        for record in shapes:
            assert _decode_ssvc(record) is None

    def test_hostile_record_degrades_and_never_enters_cache(
        self, tmp_path: Path,
    ):
        """One hostile 200 body degrades that id to no-signal AND
        never becomes a disk-cache entry — a record that can't
        decode must not stick for the positive TTL."""
        http = FakeHttp(responses={self.URL: _hostile_record()})
        cache = JsonCache(root=tmp_path)
        assert VulnrichmentClient(http, cache).lookup(
            "CVE-2024-12345",
        ) is None
        # An offline second client must see a cold cache, not a
        # poisoned entry replaying for 7 days.
        offline = VulnrichmentClient(FakeHttp(), cache, offline=True)
        assert offline.lookup("CVE-2024-12345") is None

    def test_poisoned_cache_entry_is_evicted_not_served(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """A pre-existing poisoned entry (written before the
        validate-before-cache gate existed, or by a future decoder
        drift) is evicted on decode failure — never replayed for the
        rest of its TTL."""
        import core.cve.vulnrichment as vr

        cache = JsonCache(root=tmp_path)
        cache.put(
            "vulnrichment/CVE-2024-12345",
            _vulnrichment_record(),
            ttl_seconds=7 * 24 * 3600,
        )

        def _boom(record):
            raise AttributeError("decoder drift")

        with monkeypatch.context() as m:
            m.setattr(vr, "_decode_ssvc", _boom)
            http = FakeHttp(
                responses={self.URL: _vulnrichment_record()},
            )
            # Must degrade, not raise — and evict the poison.
            assert VulnrichmentClient(http, cache).lookup(
                "CVE-2024-12345",
            ) is None
        assert cache.get(
            "vulnrichment/CVE-2024-12345", ttl_seconds=7 * 24 * 3600,
        ) is None, "poisoned entry must be evicted, not served"

        # With the decoder healthy again, a fresh client recovers.
        http2 = FakeHttp(responses={self.URL: _vulnrichment_record()})
        d = VulnrichmentClient(http2, cache).lookup("CVE-2024-12345")
        assert d is not None
        assert http2.gets == [self.URL]

    def test_lookup_many_one_undecodable_id_degrades_only_that_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """The decode sits inside the per-id boundary: one hostile
        record must not sink the whole batch (pool path, >4 ids)."""
        import core.cve.vulnrichment as vr

        cves = [f"CVE-2024-{90101 + i}" for i in range(6)]
        bad = cves[3]
        responses = {_url(c): _vulnrichment_record() for c in cves}
        responses[_url(bad)] = {"_marker": bad, **_vulnrichment_record()}

        real_decode = _decode_ssvc

        def _selective(record):
            if isinstance(record, dict) and record.get("_marker") == bad:
                raise AttributeError("hostile record")
            return real_decode(record)

        monkeypatch.setattr(vr, "_decode_ssvc", _selective)
        client = VulnrichmentClient(
            FakeHttp(responses=responses), JsonCache(root=tmp_path),
        )
        out = client.lookup_many(cves, max_workers=2)
        assert set(out) == set(cves) - {bad}

    def test_lookup_many_cached_hit_decode_is_guarded(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ):
        """The cached-hit decode lane in ``lookup_many`` is equally
        per-id guarded: a poisoned disk entry degrades that id (and
        is evicted), the rest of the batch resolves."""
        import core.cve.vulnrichment as vr

        cves = ["CVE-2024-91201", "CVE-2024-91202"]
        bad = cves[0]
        cache = JsonCache(root=tmp_path)
        cache.put(
            f"vulnrichment/{bad}",
            {"_marker": bad, **_vulnrichment_record()},
            ttl_seconds=7 * 24 * 3600,
        )

        real_decode = _decode_ssvc

        def _selective(record):
            if isinstance(record, dict) and record.get("_marker") == bad:
                raise AttributeError("hostile record")
            return real_decode(record)

        monkeypatch.setattr(vr, "_decode_ssvc", _selective)
        responses = {_url(c): _vulnrichment_record() for c in cves}
        responses[_url(bad)] = {"_marker": bad, **_vulnrichment_record()}
        client = VulnrichmentClient(
            FakeHttp(responses=responses), cache,
        )
        out = client.lookup_many(cves)
        assert set(out) == {cves[1]}
        assert cache.get(
            f"vulnrichment/{bad}", ttl_seconds=7 * 24 * 3600,
        ) is None, "poisoned entry must be evicted"


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


# ---------------------------------------------------------------------------
# lookup_many — scan-wide batched lookup
# ---------------------------------------------------------------------------

def _url(cve: str) -> str:
    u = _url_for_cve(cve)
    assert u is not None
    return u


class TestLookupMany:
    """``lookup_many`` is the scan-scale entry point: cache hits are
    free, uncached fetches run on a bounded pool under an optional
    network budget spent in input order."""

    def test_resolves_all_and_counts_requests(self, tmp_path: Path):
        cves = [f"CVE-2024-{10000 + i}" for i in range(6)]
        http = FakeHttp(responses={
            _url(c): _vulnrichment_record(exploitation="active")
            for c in cves
        })
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        out = client.lookup_many(cves)
        assert set(out) == set(cves)
        assert all(d.exploitation == "active" for d in out.values())
        # One GET per CVE (6 ids exercises the thread-pool path;
        # order across workers is unspecified).
        assert sorted(http.gets) == sorted(_url(c) for c in cves)

    def test_budget_spent_in_input_order(self, tmp_path: Path):
        cves = ["CVE-2024-30001", "CVE-2024-30002", "CVE-2024-30003"]
        http = FakeHttp(responses={
            _url(c): _vulnrichment_record() for c in cves
        })
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        out = client.lookup_many(cves, fetch_budget=2)
        assert set(out) == set(cves[:2])
        assert http.gets == [_url(c) for c in cves[:2]]

    def test_cached_ids_do_not_consume_budget(self, tmp_path: Path):
        """Disk-cache hits resolve for free: with CVE-1 already
        cached, a budget of 1 still fetches CVE-2."""
        cves = ["CVE-2024-40001", "CVE-2024-40002"]
        cache = JsonCache(root=tmp_path)
        warm = FakeHttp(responses={_url(cves[0]): _vulnrichment_record()})
        VulnrichmentClient(warm, cache).lookup(cves[0])

        http = FakeHttp(responses={_url(cves[1]): _vulnrichment_record()})
        client = VulnrichmentClient(http, cache)
        out = client.lookup_many(cves, fetch_budget=1)
        assert set(out) == set(cves)
        assert http.gets == [_url(cves[1])]

    def test_second_call_uses_memo(self, tmp_path: Path):
        cves = ["CVE-2024-50001", "CVE-2024-50002"]
        http = FakeHttp(responses={
            _url(c): _vulnrichment_record() for c in cves
        })
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        client.lookup_many(cves)
        n = len(http.gets)
        out = client.lookup_many(cves)
        assert len(http.gets) == n
        assert set(out) == set(cves)
        # ...and the single-CVE path shares the memo too.
        assert client.lookup(cves[0]) is not None
        assert len(http.gets) == n

    def test_skipped_ids_are_not_memoised(self, tmp_path: Path):
        """An over-budget skip must stay retryable: a later direct
        ``lookup`` (or the next run) still fetches it."""
        cves = ["CVE-2024-60001", "CVE-2024-60002"]
        http = FakeHttp(responses={
            _url(c): _vulnrichment_record() for c in cves
        })
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        out = client.lookup_many(cves, fetch_budget=1)
        assert set(out) == {cves[0]}
        d = client.lookup(cves[1])
        assert d is not None
        assert http.gets == [_url(c) for c in cves]

    def test_offline_serves_cache_only(self, tmp_path: Path):
        cves = ["CVE-2024-70001", "CVE-2024-70002"]
        cache = JsonCache(root=tmp_path)
        warm = FakeHttp(responses={_url(cves[0]): _vulnrichment_record()})
        VulnrichmentClient(warm, cache).lookup(cves[0])

        http = FakeHttp()
        client = VulnrichmentClient(http, cache, offline=True)
        out = client.lookup_many(cves)
        assert set(out) == {cves[0]}
        assert http.gets == []

    def test_malformed_ids_skipped(self, tmp_path: Path):
        http = FakeHttp(responses={
            _url("CVE-2024-80001"): _vulnrichment_record(),
        })
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        out = client.lookup_many(
            ["CVE-2024-80001", "..", "a//b", "", None, 42],  # type: ignore[list-item]
        )
        assert set(out) == {"CVE-2024-80001"}
        assert http.gets == [_url("CVE-2024-80001")]

    def test_one_failure_degrades_only_that_id(self, tmp_path: Path):
        """A raising fetch (transport surprise, hostile response)
        must not sink its batchmates — that id is simply absent."""
        cves = [f"CVE-2024-{90001 + i}" for i in range(6)]
        responses = {_url(c): _vulnrichment_record() for c in cves[1:]}
        http = FakeHttp(
            responses=responses,
            errors={_url(cves[0]): RuntimeError("connection reset")},
        )
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        out = client.lookup_many(cves)
        assert set(out) == set(cves[1:])

    def test_budget_truncation_logs_one_summary_line(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture,
    ):
        cves = [f"CVE-2024-{20001 + i}" for i in range(10)]
        http = FakeHttp(responses={
            _url(c): _vulnrichment_record() for c in cves
        })
        client = VulnrichmentClient(http, JsonCache(root=tmp_path))
        with caplog.at_level("INFO", logger="core.cve.vulnrichment"):
            client.lookup_many(cves, fetch_budget=3)
        budget_lines = [
            r for r in caplog.records if "budget" in r.getMessage()
        ]
        assert len(budget_lines) == 1
        assert "skipped 7" in budget_lines[0].getMessage()
