"""Tests for :mod:`cve_env.tools.nvd_lookup`."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

from cve_env.tools.nvd_lookup import CVE_ID_RE, nvd_lookup
from cve_env.tools.web_fetch import FetchResult


def _fetch_ok(body: str) -> FetchResult:
    return FetchResult(
        ok=True, url="https://nvd/x", status=200, body=body, body_bytes=len(body)
    )


def _fetch_fail(reason: str) -> FetchResult:
    return FetchResult(ok=False, url="https://nvd/x", status=0, body="", reason=reason)


def test_cve_id_regex_accepts_canonical() -> None:
    assert CVE_ID_RE.match("CVE-2018-7600")
    assert CVE_ID_RE.match("CVE-2021-44228")


def test_cve_id_regex_rejects_malformed() -> None:
    assert not CVE_ID_RE.match("cve-2018-7600")  # case-sensitive
    assert not CVE_ID_RE.match("CVE-123-456")
    assert not CVE_ID_RE.match("garbage")


def test_nvd_lookup_rejects_invalid_id() -> None:
    r = nvd_lookup("not-a-cve")
    assert r.ok is False
    assert "not a valid CVE ID" in r.reason


@patch("cve_env.tools.nvd_lookup.web_fetch")
def test_nvd_lookup_propagates_fetch_failure(mock_fetch: Any) -> None:
    mock_fetch.return_value = _fetch_fail("HTTP 503")
    r = nvd_lookup("CVE-2018-7600")
    assert r.ok is False
    assert "503" in r.reason or "nvd fetch failed" in r.reason


@patch("cve_env.tools.nvd_lookup.web_fetch")
def test_nvd_lookup_handles_malformed_json(mock_fetch: Any) -> None:
    mock_fetch.return_value = _fetch_ok("{not json")
    r = nvd_lookup("CVE-2018-7600")
    assert r.ok is False
    assert "json decode" in r.reason


@patch("cve_env.tools.nvd_lookup.web_fetch")
def test_nvd_lookup_handles_empty_result(mock_fetch: Any) -> None:
    mock_fetch.return_value = _fetch_ok(json.dumps({"vulnerabilities": []}))
    r = nvd_lookup("CVE-2018-7600")
    assert r.ok is False
    assert "no vulnerabilities" in r.reason


def _nvd_payload(
    *,
    cve_id: str = "CVE-2018-7600",
    description: str = "Drupal RCE",
    cpes: list[tuple[str, str, str]] | None = None,
    references: list[str] | None = None,
    cvss: tuple[float, str] | None = (9.8, "CRITICAL"),
) -> str:
    cpe_matches = [
        {
            "vulnerable": True,
            "criteria": f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*",
        }
        for (vendor, product, version) in (cpes or [("drupal", "drupal", "8.5.0")])
    ]
    metrics: dict[str, Any] = {}
    if cvss is not None:
        base, sev = cvss
        metrics = {
            "cvssMetricV31": [{"cvssData": {"baseScore": base, "baseSeverity": sev}}]
        }
    return json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": cve_id,
                        "published": "2018-03-29T00:00:00.000",
                        "lastModified": "2020-01-01T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": description}],
                        "configurations": [{"nodes": [{"cpeMatch": cpe_matches}]}],
                        "references": [{"url": r} for r in (references or [])],
                        "metrics": metrics,
                    }
                }
            ]
        }
    )


@patch("cve_env.tools.nvd_lookup.web_fetch")
def test_nvd_lookup_happy_path(mock_fetch: Any) -> None:
    mock_fetch.return_value = _fetch_ok(
        _nvd_payload(
            description="Remote code execution in Drupal core.",
            cpes=[("drupal", "drupal", "8.5.0")],
            references=["https://www.drupal.org/sa-core-2018-002"],
            cvss=(9.8, "CRITICAL"),
        )
    )
    r = nvd_lookup("CVE-2018-7600")
    assert r.ok is True
    assert r.cve_id == "CVE-2018-7600"
    assert "Drupal" in r.description
    assert r.cvss_base_score == 9.8
    assert r.cvss_severity == "CRITICAL"
    assert len(r.cpes) == 1
    assert r.cpes[0]["product"] == "drupal"
    assert r.cpes[0]["version"] == "8.5.0"
    assert r.references == ["https://www.drupal.org/sa-core-2018-002"]


@patch("cve_env.tools.nvd_lookup.web_fetch")
def test_nvd_lookup_dedupes_cpes(mock_fetch: Any) -> None:
    mock_fetch.return_value = _fetch_ok(
        _nvd_payload(
            cpes=[
                ("drupal", "drupal", "8.5.0"),
                ("drupal", "drupal", "8.5.0"),  # duplicate
                ("drupal", "drupal", "8.4.0"),
            ]
        )
    )
    r = nvd_lookup("CVE-2018-7600")
    assert r.ok is True
    versions = [c["version"] for c in r.cpes]
    assert versions == ["8.5.0", "8.4.0"]


@patch("cve_env.tools.nvd_lookup.web_fetch")
def test_nvd_lookup_without_cvss_metrics(mock_fetch: Any) -> None:
    mock_fetch.return_value = _fetch_ok(_nvd_payload(cvss=None))
    r = nvd_lookup("CVE-2018-7600")
    assert r.ok is True
    assert r.cvss_base_score is None


@patch("cve_env.tools.nvd_lookup.web_fetch")
def test_nvd_lookup_v2_fallback(mock_fetch: Any) -> None:
    payload = json.loads(_nvd_payload(cvss=None))
    payload["vulnerabilities"][0]["cve"]["metrics"] = {
        "cvssMetricV2": [{"cvssData": {"baseScore": 6.5}, "baseSeverity": "MEDIUM"}]
    }
    mock_fetch.return_value = _fetch_ok(json.dumps(payload))
    r = nvd_lookup("CVE-2018-7600")
    assert r.ok is True
    assert r.cvss_base_score == 6.5
    assert r.cvss_severity == "MEDIUM"


# Phase 17.2: OSV.dev fallback ----------------------------------------


@patch("cve_env.tools.nvd_lookup.web_fetch")
def test_osv_fallback_when_nvd_throttled(mock_fetch: Any) -> None:
    """When NVD returns rate_limited, fall back to OSV.dev."""
    osv_payload = {
        "id": "CVE-2014-0160",
        "summary": "Heartbleed",
        "details": "TLS heartbeat read overflow.",
        "modified": "2026-04-16T06:17:18Z",
        "published": "2014-04-07T22:55:03Z",
        "affected": [
            {
                "package": {"ecosystem": "Debian:11", "name": "openssl"},
                "ranges": [{"events": [{"introduced": "1.0.1"}, {"fixed": "1.0.1g"}]}],
            }
        ],
        "references": [{"url": "https://heartbleed.com"}],
    }
    nvd_fail = FetchResult(
        ok=False,
        url="https://nvd/x",
        status=429,
        reason="429",
        reason_class="rate_limited",
    )
    osv_ok = _fetch_ok(json.dumps(osv_payload))
    mock_fetch.side_effect = [nvd_fail, osv_ok]
    r = nvd_lookup("CVE-2014-0160")
    assert r.ok is True
    assert r.cve_id == "CVE-2014-0160"
    assert "Heartbleed" in r.description or "heartbeat" in r.description.lower()
    assert "via OSV.dev fallback" in r.reason
    assert any(c["product"] == "openssl" for c in r.cpes)


@patch("cve_env.tools.nvd_lookup.web_fetch")
def test_osv_fallback_description_is_sanitized(mock_fetch: Any) -> None:
    """A-completeness (2026-05-31): the OSV.dev fallback path builds
    description from `details`/`summary` and previously returned it
    UNSANITIZED — a second AUP-trigger injection site bypassing the
    sanitizer that the NVD path (_extract_description) goes through. The
    OSV description must be sanitized too; build info must survive."""
    osv_payload = {
        "id": "CVE-2099-00001",
        "summary": "Acme CMS issue",
        "details": (
            "An arbitrary file upload vulnerability in Acme CMS 3.1.0 allows "
            "attackers to execute arbitrary code via a crafted file."
        ),
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "acme-cms"},
                "ranges": [{"events": [{"introduced": "3.1.0"}]}],
            }
        ],
    }
    nvd_fail = FetchResult(
        ok=False,
        url="https://nvd/x",
        status=429,
        reason="429",
        reason_class="rate_limited",
    )
    osv_ok = _fetch_ok(json.dumps(osv_payload))
    mock_fetch.side_effect = [nvd_fail, osv_ok]
    r = nvd_lookup("CVE-2099-00001")
    assert r.ok is True
    lo = r.description.lower()
    for phrase in ("attackers", "arbitrary", "execute", "crafted"):
        assert phrase not in lo, (
            f"OSV description not sanitized ({phrase!r}): {r.description!r}"
        )
    assert "3.1.0" in r.description, f"version must survive: {r.description!r}"


@patch("cve_env.tools.nvd_lookup.web_fetch")
def test_osv_fallback_when_nvd_returns_no_entry(mock_fetch: Any) -> None:
    """When NVD has no entry for the CVE, OSV may still have it."""
    osv_payload = {"id": "CVE-2024-99999", "summary": "fresh CVE", "details": "x"}
    nvd_empty = _fetch_ok(json.dumps({"vulnerabilities": []}))
    osv_ok = _fetch_ok(json.dumps(osv_payload))
    mock_fetch.side_effect = [nvd_empty, osv_ok]
    r = nvd_lookup("CVE-2024-99999")
    assert r.ok is True
    assert r.cve_id == "CVE-2024-99999"


@patch("cve_env.tools.nvd_lookup.web_fetch")
def test_osv_fallback_silently_fails_when_osv_also_down(mock_fetch: Any) -> None:
    """If both NVD AND OSV fail, return the original NVD failure."""
    nvd_fail = FetchResult(
        ok=False,
        url="https://nvd/x",
        status=429,
        reason="429",
        reason_class="rate_limited",
    )
    osv_fail = FetchResult(
        ok=False,
        url="https://osv/x",
        status=500,
        reason="500",
        reason_class="transport",
    )
    mock_fetch.side_effect = [nvd_fail, osv_fail]
    r = nvd_lookup("CVE-2014-0160")
    assert r.ok is False
    assert r.reason_class == "rate_limited"  # original NVD class preserved
