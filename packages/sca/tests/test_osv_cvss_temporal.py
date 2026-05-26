"""Regression: OSV records carrying CVSS vectors with temporal /
environmental suffixes must produce a critical severity, not the
"no CVSS available" fallback.

OSV records routinely ship vectors like Log4Shell's
``CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H`` — the trailing
``/E:H`` is the (optional) temporal Exploit Code Maturity metric.
This file pins the OSV→Advisory layer's behaviour against that
shape; ``packages/cvss/tests/test_calculator.py`` covers the
calculator itself.
"""

from __future__ import annotations

from packages.sca.osv import parse_osv_record


def test_temporal_suffix_does_not_lose_severity() -> None:
    record = {
        "id": "GHSA-jfh8-c2jp-5v3q",
        "summary": "Log4Shell",
        "details": "",
        "aliases": ["CVE-2021-44228"],
        "affected": [],
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:H",
        }],
        "references": [],
    }
    advisory = parse_osv_record(record)
    assert advisory.severity is not None
    assert advisory.severity.severity == "critical"
    assert advisory.severity.score >= 9.0
    # The original vector with /E:H is preserved on the advisory so
    # downstream consumers see the publisher's full string, not a
    # base-only re-emission.
    assert advisory.severity.vector.endswith("/E:H")


def test_environmental_metrics_do_not_lose_severity() -> None:
    record = {
        "id": "GHSA-test",
        "summary": "test",
        "details": "",
        "aliases": [],
        "affected": [],
        "severity": [{
            "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/CR:H/IR:H/AR:H",
        }],
        "references": [],
    }
    advisory = parse_osv_record(record)
    assert advisory.severity is not None
    assert advisory.severity.severity == "critical"
