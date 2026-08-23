"""Tests for the cvefix env-verification overlay reader."""

from __future__ import annotations

import json
from pathlib import Path

from core.recall.env_overlay import (
    SIDECAR_SUFFIX,
    corpus_env_summary,
    load_overlay,
)

CVE_A = "CVE-2018-7600"
CVE_B = "CVE-2019-11043"
CVE_C = "CVE-2021-41773"


def _sidecar(tmp_path: Path, cve: str, **fields) -> Path:
    data = {"cve_id": cve, "status": "success",
            "profile": "deployed-infrastructure"}
    data.update(fields)
    p = tmp_path / f"{cve}{SIDECAR_SUFFIX}"
    p.write_text(json.dumps(data))
    return p


class TestLoadOverlay:
    def test_missing_dir_is_empty_not_an_error(self, tmp_path):
        assert load_overlay(tmp_path / "nope") == {}
        assert load_overlay(None) == {}

    def test_loads_by_cve_id(self, tmp_path):
        _sidecar(tmp_path, CVE_A, verification="env-verified")
        _sidecar(tmp_path, CVE_B, give_up_reason="arch_incompatible")
        overlay = load_overlay(tmp_path)
        assert set(overlay) == {CVE_A, CVE_B}
        assert overlay[CVE_A]["verification"] == "env-verified"

    def test_corrupt_sidecar_skipped_without_hiding_rest(self, tmp_path):
        _sidecar(tmp_path, CVE_A, verification="env-verified")
        (tmp_path / f"{CVE_B}{SIDECAR_SUFFIX}").write_text("{broken")
        (tmp_path / f"noid{SIDECAR_SUFFIX}").write_text("{}")
        overlay = load_overlay(tmp_path)
        assert set(overlay) == {CVE_A}


class TestSummary:
    def test_buckets_and_tiers(self, tmp_path):
        _sidecar(tmp_path, CVE_A, verification="env-verified")
        _sidecar(tmp_path, CVE_B, status="unresolvable",
                 give_up_reason="arch_incompatible")
        overlay = load_overlay(tmp_path)
        summary = corpus_env_summary([CVE_A, CVE_B, CVE_C], overlay)
        assert summary["total"] == 3
        assert summary["verified"] == 1
        assert summary["missed"] == 1
        assert summary["unattempted"] == 1
        assert summary["by_tier"] == {"env-verified": 1}
        assert summary["verified_cves"] == [CVE_A]
        assert summary["missed_cves"] == [CVE_B]
        assert summary["unattempted_cves"] == [CVE_C]

    def test_unknown_future_tier_tolerated(self, tmp_path):
        _sidecar(tmp_path, CVE_A, verification="repro-verified")
        summary = corpus_env_summary([CVE_A], load_overlay(tmp_path))
        assert summary["verified"] == 1
        assert summary["by_tier"] == {"repro-verified": 1}

    def test_empty_overlay_reports_all_unattempted(self):
        summary = corpus_env_summary([CVE_A, CVE_B], {})
        assert summary["verified"] == 0
        assert summary["unattempted"] == 2
