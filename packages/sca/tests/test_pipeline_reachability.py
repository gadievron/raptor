"""Pipeline-level test: reachability flows into the emitted findings."""

from __future__ import annotations

import json
from pathlib import Path

from core.json import JsonCache
from packages.sca.osv import OSV_QUERY_BATCH_URL, OSV_VULN_URL_TEMPLATE
from packages.sca.pipeline import RunOptions, run_sca
from packages.sca.tests.test_pipeline import StubHttp


def test_reachability_imported_threaded_into_findings_json(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    out = tmp_path / "out"
    target.mkdir()
    (target / "pom.xml").write_text(
        '<project xmlns="http://maven.apache.org/POM/4.0.0">'
        '<dependencies><dependency>'
        '<groupId>org.apache.logging.log4j</groupId>'
        '<artifactId>log4j-core</artifactId>'
        '<version>2.14.1</version>'
        '</dependency></dependencies></project>',
        encoding="utf-8",
    )

    http = StubHttp()
    cache = JsonCache(root=tmp_path / "cache")
    result = run_sca(target, out, RunOptions(enable_llm_review=False, enable_triage=False), http=http, cache=cache)
    assert result.vuln_findings == 1
    rows = json.loads(result.findings_path.read_text())
    sca_row = [r for r in rows if r["vuln_type"] == "sca:vulnerable_dependency"][0]
    # Maven isn't supported by reachability yet — must be honest about it.
    assert sca_row["sca"]["reachability"]["verdict"] == "not_evaluated"


def test_reachability_imported_for_used_python_dep(tmp_path: Path) -> None:
    """Build a Python project with a known-vuln dep that's actually
    imported, plus stubbed OSV data; the finding should land
    ``imported``."""
    target = tmp_path / "repo"
    out = tmp_path / "out"
    target.mkdir()
    (target / "requirements.txt").write_text(
        "vuln-pkg==1.0.0\n", encoding="utf-8",
    )
    (target / "src").mkdir()
    (target / "src" / "main.py").write_text(
        "import vuln_pkg\nvuln_pkg.do_thing()\n", encoding="utf-8",
    )

    class Http(StubHttp):
        VULN_RECORD = {
            "id": "GHSA-fake",
            "modified": "2024-01-01T00:00:00Z",
            "published": "2024-01-01T00:00:00Z",
            "aliases": [],
            "summary": "Fake advisory",
            "details": "",
            "affected": [{
                "package": {"ecosystem": "PyPI", "name": "vuln-pkg"},
                "ranges": [{"type": "ECOSYSTEM",
                            "events": [{"introduced": "0"},
                                       {"fixed": "2.0.0"}]}],
            }],
            "severity": [],
            "references": [],
        }

        def post_json(self, url, body, timeout=30):
            self.posts.append((url, body))
            if url == OSV_QUERY_BATCH_URL:
                return {"results":
                        [{"vulns": [{"id": "GHSA-fake"}]} for _ in body["queries"]]}
            raise RuntimeError(url)

        def get_json(self, url, timeout=30):
            self.gets.append(url)
            if url == OSV_VULN_URL_TEMPLATE.format("GHSA-fake"):
                return self.VULN_RECORD
            if "cisa.gov" in url:
                return {"vulnerabilities": []}
            if "first.org" in url:
                return {"data": []}
            raise RuntimeError(url)

    http = Http()
    cache = JsonCache(root=tmp_path / "cache")
    result = run_sca(target, out, RunOptions(enable_llm_review=False, enable_triage=False), http=http, cache=cache)
    rows = json.loads(result.findings_path.read_text())
    sca_row = [r for r in rows if r["vuln_type"] == "sca:vulnerable_dependency"][0]
    assert sca_row["sca"]["reachability"]["verdict"] == "imported"
    # Evidence carries the importing file.
    assert any("src/main.py" in line
               for line in sca_row["sca"]["reachability"]["evidence"])


def test_no_reachability_flag_skips_scan(tmp_path: Path) -> None:
    """``--no-reachability`` keeps verdicts at not_evaluated even when
    OSV finds advisories."""
    target = tmp_path / "repo"
    out = tmp_path / "out"
    target.mkdir()
    (target / "requirements.txt").write_text("vuln-pkg==1.0.0\n",
                                             encoding="utf-8")

    class Http(StubHttp):
        VULN_RECORD = {
            "id": "GHSA-fake",
            "modified": "2024-01-01T00:00:00Z",
            "aliases": [],
            "summary": "x",
            "details": "",
            "affected": [{"package": {"ecosystem": "PyPI", "name": "vuln-pkg"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": "2.0"}]}]}],
            "severity": [], "references": [],
        }

        def post_json(self, url, body, timeout=30):
            self.posts.append((url, body))
            return {"results":
                    [{"vulns": [{"id": "GHSA-fake"}]} for _ in body["queries"]]}

        def get_json(self, url, timeout=30):
            self.gets.append(url)
            if url == OSV_VULN_URL_TEMPLATE.format("GHSA-fake"):
                return self.VULN_RECORD
            return {"vulnerabilities": []} if "cisa.gov" in url else {"data": []}

    http = Http()
    cache = JsonCache(root=tmp_path / "cache")
    result = run_sca(
        target, out,
        RunOptions(enable_reachability=False,
                   enable_llm_review=False, enable_triage=False),
        http=http, cache=cache,
    )
    rows = json.loads(result.findings_path.read_text())
    sca_row = [r for r in rows if r["vuln_type"] == "sca:vulnerable_dependency"][0]
    assert sca_row["sca"]["reachability"]["verdict"] == "not_evaluated"
