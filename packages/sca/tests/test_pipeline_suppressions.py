"""End-to-end: suppression overlay flows through the pipeline into
``findings.json`` and the markdown report respects the suppressed flag.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.json import JsonCache
from packages.sca.osv import OSV_QUERY_BATCH_URL, OSV_VULN_URL_TEMPLATE
from packages.sca.pipeline import RunOptions, run_sca


_VULN_RECORD = {
    "id": "GHSA-fake",
    "modified": "2024-01-01T00:00:00Z",
    "aliases": ["CVE-2099-FAKE"],
    "summary": "Synthetic CVE for the suppression test",
    "details": "",
    "affected": [{
        "package": {"ecosystem": "PyPI", "name": "vuln-pkg"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
    }],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "references": [],
}


class StubHttp:
    def __init__(self) -> None:
        self.posts = []
        self.gets = []

    def post_json(self, url, body, timeout=30):
        self.posts.append((url, body))
        if url == OSV_QUERY_BATCH_URL:
            return {"results": [{"vulns": [{"id": "GHSA-fake"}]}
                                 for _ in body["queries"]]}
        raise RuntimeError(url)

    def get_json(self, url, timeout=30):
        self.gets.append(url)
        if url == OSV_VULN_URL_TEMPLATE.format("GHSA-fake"):
            return _VULN_RECORD
        if "cisa.gov" in url:
            return {"vulnerabilities": []}
        if "first.org" in url:
            return {"data": []}
        raise RuntimeError(url)

    def get_bytes(self, *a, **k):
        raise NotImplementedError


def _build_target(tmp_path: Path, *, suppress_yaml: str | None = None) -> Path:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "requirements.txt").write_text("vuln-pkg==1.0.0\n",
                                              encoding="utf-8")
    if suppress_yaml is not None:
        (target / ".raptor-sca-suppress.yml").write_text(
            suppress_yaml, encoding="utf-8",
        )
    return target


def test_suppression_flows_into_findings_json(tmp_path: Path) -> None:
    target = _build_target(tmp_path, suppress_yaml="""
version: 1
suppressions:
  - advisory_id: CVE-2099-FAKE
    reason: accepted risk for the test
""")
    out = tmp_path / "out"
    cache = JsonCache(root=tmp_path / "cache")
    result = run_sca(target, out, RunOptions(enable_llm_review=False, enable_triage=False),
                     http=StubHttp(), cache=cache)
    assert result.suppressed_findings >= 1

    rows = json.loads(result.findings_path.read_text())
    sca_rows = [r for r in rows
                if r["vuln_type"] == "sca:vulnerable_dependency"]
    assert sca_rows
    assert all(r["suppressed"] is True for r in sca_rows)
    assert sca_rows[0]["suppression_reason"] == "accepted risk for the test"


def test_no_suppression_file_means_no_suppressed_findings(
    tmp_path: Path,
) -> None:
    target = _build_target(tmp_path)
    out = tmp_path / "out"
    cache = JsonCache(root=tmp_path / "cache")
    result = run_sca(target, out, RunOptions(enable_llm_review=False, enable_triage=False),
                     http=StubHttp(), cache=cache)
    assert result.suppressed_findings == 0


def test_suppression_disabled_via_options(tmp_path: Path) -> None:
    target = _build_target(tmp_path, suppress_yaml="""
version: 1
suppressions:
  - advisory_id: CVE-2099-FAKE
    reason: would suppress if enabled
""")
    out = tmp_path / "out"
    cache = JsonCache(root=tmp_path / "cache")
    result = run_sca(
        target, out, RunOptions(enable_suppressions=False),
        http=StubHttp(), cache=cache,
    )
    assert result.suppressed_findings == 0
    rows = json.loads(result.findings_path.read_text())
    sca_rows = [r for r in rows
                if r["vuln_type"] == "sca:vulnerable_dependency"]
    assert all(not r["suppressed"] for r in sca_rows)


def test_report_summary_lists_suppressed_count(tmp_path: Path) -> None:
    target = _build_target(tmp_path, suppress_yaml="""
version: 1
suppressions:
  - advisory_id: CVE-2099-FAKE
    reason: ack
""")
    out = tmp_path / "out"
    cache = JsonCache(root=tmp_path / "cache")
    run_sca(target, out, RunOptions(enable_llm_review=False, enable_triage=False), http=StubHttp(), cache=cache)
    md = (out / "report.md").read_text()
    assert "Suppressed" in md
    assert "(suppressed: ack)" in md
