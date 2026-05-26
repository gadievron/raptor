"""Tests for ``packages.sca.whatif`` (the ``raptor-sca upgrade`` subcommand)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest

from packages.sca import whatif
from core.json import JsonCache
from packages.sca.osv import OSV_QUERY_BATCH_URL, OSV_VULN_URL_TEMPLATE


_VULN_OLD = {
    "id": "GHSA-old",
    "modified": "2024-01-01T00:00:00Z",
    "aliases": ["CVE-2020-OLD"],
    "summary": "Issue patched in 2.0",
    "details": "",
    "affected": [{
        "package": {"ecosystem": "npm", "name": "x"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
    }],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "references": [],
}

_VULN_NEW = {
    "id": "GHSA-new",
    "modified": "2024-06-01T00:00:00Z",
    "aliases": ["CVE-2024-NEW"],
    "summary": "Regression in 2.x",
    "details": "",
    "affected": [{
        "package": {"ecosystem": "npm", "name": "x"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "2.0"}, {"fixed": "3.0"}]}],
    }],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"}],
    "references": [],
}


class StubHttp:
    """Routes OSV/KEV/EPSS calls based on the query body."""

    def __init__(
        self,
        version_to_vulns: Dict[str, List[str]],
        records: Dict[str, Dict[str, Any]],
    ) -> None:
        self.posts: List[Tuple[str, dict]] = []
        self.gets: List[str] = []
        self._v_to_vulns = version_to_vulns
        self._records = records

    def post_json(self, url: str, body: dict, timeout: int = 30) -> dict:
        self.posts.append((url, body))
        if url == OSV_QUERY_BATCH_URL:
            results = []
            for q in body["queries"]:
                v = q.get("version", "")
                ids = self._v_to_vulns.get(v, [])
                results.append({"vulns": [{"id": i} for i in ids]})
            return {"results": results}
        raise RuntimeError(f"unexpected POST {url}")

    def get_json(self, url: str, timeout: int = 30) -> dict:
        self.gets.append(url)
        for vid, rec in self._records.items():
            if url == OSV_VULN_URL_TEMPLATE.format(vid):
                return rec
        if "cisa.gov" in url:
            return {"vulnerabilities": []}
        if "first.org" in url:
            return {"data": []}
        raise RuntimeError(f"unexpected GET {url}")

    def get_bytes(self, *a, **k):
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Pairwise mode
# ---------------------------------------------------------------------------

def test_pairwise_unparseable_version_exits_2(tmp_path: Path, capsys) -> None:
    """Operator typos in CI pipelines (``npm lodash 4.17.4 4.17.x``)
    used to silently emit "0 resolved, 0 regressed" and exit 0 —
    the gate would falsely report a clean upgrade. Validate the
    version pair against the ecosystem comparator BEFORE the OSV
    network call so an unparseable version surfaces as exit 2."""
    http = StubHttp(version_to_vulns={}, records={})
    cache = JsonCache(root=tmp_path)
    rc = whatif.main(["npm", "lodash", "not-a-version", "also-bad"],
                      http=http, cache=cache)
    assert rc == 2
    out = capsys.readouterr().out
    assert "Error" in out
    assert "unparseable" in out
    # No bogus "0 resolved" summary in the output.
    assert "Resolved: **0**" not in out


def test_pairwise_clean_resolution(tmp_path: Path, capsys) -> None:
    """1.0 has GHSA-old, 2.5 has none → upgrade resolves all, no regressions."""
    http = StubHttp(
        version_to_vulns={"1.0": ["GHSA-old"], "2.5": []},
        records={"GHSA-old": _VULN_OLD},
    )
    cache = JsonCache(root=tmp_path)
    rc = whatif.main(["npm", "x", "1.0", "2.5"],
                     http=http, cache=cache)
    assert rc == 0
    out = capsys.readouterr().out
    assert "Resolved: **1**" in out
    assert "Regressed: **0**" in out
    assert "GHSA-old" in out


def test_pairwise_regression_returns_one(tmp_path: Path, capsys) -> None:
    """1.0 has GHSA-old (fixed in 2.0), 2.5 has GHSA-new — net upgrade
    is a trade-off."""
    http = StubHttp(
        version_to_vulns={"1.0": ["GHSA-old"], "2.5": ["GHSA-new"]},
        records={"GHSA-old": _VULN_OLD, "GHSA-new": _VULN_NEW},
    )
    cache = JsonCache(root=tmp_path)
    rc = whatif.main(["npm", "x", "1.0", "2.5"], http=http, cache=cache)
    assert rc == 1
    out = capsys.readouterr().out
    assert "Advisories resolved by the upgrade" in out
    assert "Advisories newly applicable" in out
    assert "GHSA-old" in out and "GHSA-new" in out


def test_pairwise_identical_advisories_no_progress(tmp_path: Path, capsys) -> None:
    http = StubHttp(
        version_to_vulns={"1.0": ["GHSA-old"], "1.1": ["GHSA-old"]},
        records={"GHSA-old": _VULN_OLD},
    )
    cache = JsonCache(root=tmp_path)
    rc = whatif.main(["npm", "x", "1.0", "1.1"], http=http, cache=cache)
    assert rc == 0
    out = capsys.readouterr().out
    assert "the upgrade resolves nothing" in out


def test_pairwise_dedups_by_cve_alias(tmp_path: Path, capsys) -> None:
    """If GHSA-old (CVE-2020-OLD) on 1.0 and PYSEC-old (CVE-2020-OLD) on
    2.5 both refer to the same CVE, the upgrade is *not* a resolution."""
    pysec = dict(_VULN_OLD)
    pysec = {**_VULN_OLD, "id": "PYSEC-old", "aliases": ["CVE-2020-OLD"]}
    http = StubHttp(
        version_to_vulns={"1.0": ["GHSA-old"], "2.5": ["PYSEC-old"]},
        records={"GHSA-old": _VULN_OLD, "PYSEC-old": pysec},
    )
    cache = JsonCache(root=tmp_path)
    rc = whatif.main(["npm", "x", "1.0", "2.5"], http=http, cache=cache)
    assert rc == 0   # nothing resolved, nothing regressed
    out = capsys.readouterr().out
    assert "Resolved: **0**" in out and "Regressed: **0**" in out


# ---------------------------------------------------------------------------
# Candidates mode
# ---------------------------------------------------------------------------

def test_candidates_table_picks_smallest_full_resolver(
    tmp_path: Path, capsys,
) -> None:
    """Three candidates; only 2.5 resolves the open advisory."""
    http = StubHttp(
        version_to_vulns={
            "1.0": ["GHSA-old"],
            "1.5": ["GHSA-old"],
            "2.0": ["GHSA-old"],
            "2.5": [],
        },
        records={"GHSA-old": _VULN_OLD},
    )
    cache = JsonCache(root=tmp_path)
    rc = whatif.main(
        ["npm", "x", "1.0",
         "--candidate", "1.5",
         "--candidate", "2.0",
         "--candidate", "2.5"],
        http=http, cache=cache,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "Comparing **3** candidate" in out
    assert "1.5 resolves 0/1" in out
    assert "2.0 resolves 0/1" in out
    assert "2.5 resolves 1/1" in out
    assert "Upgrade to **2.5**" in out


def test_candidates_no_full_resolver_returns_one(
    tmp_path: Path, capsys,
) -> None:
    http = StubHttp(
        version_to_vulns={
            "1.0": ["GHSA-old"],
            "1.5": ["GHSA-old"],
            "2.0": ["GHSA-old"],
        },
        records={"GHSA-old": _VULN_OLD},
    )
    cache = JsonCache(root=tmp_path)
    rc = whatif.main(
        ["npm", "x", "1.0",
         "--candidate", "1.5", "--candidate", "2.0"],
        http=http, cache=cache,
    )
    assert rc == 1
    assert "No candidate resolves" in capsys.readouterr().out


def test_candidates_with_clean_base_summarises_each(
    tmp_path: Path, capsys,
) -> None:
    http = StubHttp(
        version_to_vulns={"1.0": [], "1.5": [], "2.0": []},
        records={},
    )
    cache = JsonCache(root=tmp_path)
    rc = whatif.main(
        ["npm", "x", "1.0",
         "--candidate", "1.5", "--candidate", "2.0"],
        http=http, cache=cache,
    )
    assert rc == 0
    out = capsys.readouterr().out
    assert "No advisories on the current version" in out


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

def test_requires_to_or_candidate(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        whatif.main(["npm", "x", "1.0"],
                    http=StubHttp({}, {}), cache=JsonCache(root=tmp_path))


def test_writes_report_to_out(tmp_path: Path, capsys) -> None:
    out = tmp_path / "whatif.md"
    http = StubHttp(version_to_vulns={"1.0": [], "2.0": []}, records={})
    cache = JsonCache(root=tmp_path / "cache")
    whatif.main(["npm", "x", "1.0", "2.0", "--out", str(out)],
                http=http, cache=cache)
    assert out.exists()
    assert "raptor-sca upgrade" in out.read_text()


# ---------------------------------------------------------------------------
# --explain (LLM upgrade impact)
# ---------------------------------------------------------------------------

def test_explain_appends_llm_section_when_available(tmp_path: Path, capsys) -> None:
    """When --explain is set and LLM is available, the report gains an impact section."""
    from unittest.mock import patch as _patch, MagicMock

    http = StubHttp(version_to_vulns={"1.0": [], "2.0": []}, records={})
    cache = JsonCache(root=tmp_path / "cache")

    mock_verdict = MagicMock()
    mock_verdict.verdict = "safe"
    mock_verdict.confidence = "high"
    mock_verdict.summary = "No call sites found for x"
    mock_verdict.breaking_changes = []

    with _patch("packages.sca.llm.get_llm_client") as mock_get:
        mock_get.return_value = MagicMock()
        with _patch("packages.sca.llm.upgrade_impact_review.assess_upgrade_impact",
                     return_value=mock_verdict):
            whatif.main(
                ["npm", "x", "1.0", "2.0", "--explain", "--target", str(tmp_path)],
                http=http, cache=cache,
            )
    captured = capsys.readouterr()
    assert "Upgrade impact (LLM)" in captured.out
    assert "safe" in captured.out


def test_explain_degrades_when_no_llm(tmp_path: Path, capsys) -> None:
    """--explain without LLM shows a degradation notice."""
    from unittest.mock import patch as _patch

    http = StubHttp(version_to_vulns={"1.0": [], "2.0": []}, records={})
    cache = JsonCache(root=tmp_path / "cache")

    with _patch("packages.sca.llm.get_llm_client", return_value=None):
        with _patch("packages.sca.llm.upgrade_impact_review.assess_upgrade_impact") as mock_assess:
            whatif.main(
                ["npm", "x", "1.0", "2.0", "--explain", "--target", str(tmp_path)],
                http=http, cache=cache,
            )
    captured = capsys.readouterr()
    assert "No LLM available" in captured.out
    mock_assess.assert_not_called()
