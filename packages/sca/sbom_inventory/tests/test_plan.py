from copy import deepcopy
import hashlib
import json

import pytest

from core.http import HttpError
from core.json import JsonCache
from core.testing.logging_state import isolated_cli_logging
from packages.sca.kinds import VULNERABLE_DEPENDENCY
from packages.sca.osv import OsvClient
from packages.sca.sbom_inventory.cli import main
from packages.sca.sbom_inventory.model import Inventory, Record
from packages.sca.sbom_inventory.plan import build_plan
from packages.sca.sbom_inventory.plan_inputs import read_findings
from packages.sca.tests.test_whatif import StubHttp, _VULN_OLD, _VULN_NEW


def inventory(*extra, purl="pkg:npm/x@1.0", version="1.0"):
    return Inventory("test", "a" * 64, records=[Record("one", "x", version, "library", purl=purl), *extra])


def finding(**values):
    sca = dict(ecosystem="npm", name="x", version="1.0", purl="pkg:npm/x@1.0", fixed_version="2.0",
               all_advisories=[{"id": "GHSA-old", "aliases": ["CVE-2020-OLD"], "fixed_versions": ["2.0", "3.0"]}])
    sca.update(values)
    return {"vuln_type": VULNERABLE_DEPENDENCY, "finding_id": "one-finding", "sca": sca}


def load(tmp_path, rows):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(rows))
    return read_findings(path)


def plan(tmp_path, rows=None, inv=None, **options):
    compact, sha = load(tmp_path, rows if rows is not None else [finding()])
    return build_plan(inv or inventory(), compact, sha, **options)


def client(tmp_path, http=None, *, offline=False):
    return OsvClient(http or StubHttp({"1.0": ["GHSA-old"], "2.0": ["GHSA-new"], "3.0": []},
                                    {"GHSA-old": _VULN_OLD, "GHSA-new": _VULN_NEW}),
                     JsonCache(root=tmp_path / "cache"), offline=offline)


def test_saved_plan_is_a_proposal_and_preserves_occurrences(tmp_path):
    inv = inventory(Record("two", "x", "1.0", "library", purl="pkg:npm/x@1.0"))
    before = deepcopy(inv)
    report = plan(tmp_path, inv=inv)
    package = report["packages"][0]
    assert package["occurrences"] == ["one", "two"]
    assert package["proposed_version"] == "2.0"
    assert {row["status"] for row in package["candidates"]} == {"not_checked"}
    assert report["exit_code"] == 0 and report["mode"] == "saved_findings"
    assert inv == before


def test_candidate_checks_reject_regression_and_choose_clear_option(tmp_path):
    report = plan(tmp_path, osv=client(tmp_path))
    package = report["packages"][0]
    assert package["proposed_version"] == "3.0"
    assert package["status"] == "candidate_available_for_review"
    first, second = package["candidates"]
    assert first["resolved"] == ["CVE-2020-OLD"]
    assert first["introduced"] == ["CVE-2024-NEW"]
    assert first["remaining"] == ["CVE-2024-NEW"]
    assert second["status"] == "no_known_advisories"
    assert report["exit_code"] == 0


def test_no_candidate_clears_known_advisories_returns_one(tmp_path):
    report = plan(tmp_path, osv=client(tmp_path), max_candidates=1)
    assert report["exit_code"] == 1
    assert report["packages"][0]["status"] == "no_candidate_clears_known_advisories"
    assert report["packages"][0]["proposed_version"] is None


def test_missing_offline_cache_never_means_clear(tmp_path):
    report = plan(tmp_path, osv=client(tmp_path, offline=True))
    assert report["exit_code"] == 2
    assert report["packages"][0]["proposed_version"] is None
    assert all(row["status"] == "lookup_unavailable" for row in report["packages"][0]["candidates"])


def test_failed_query_and_query_budget_are_unavailable(tmp_path):
    class FailedHttp(StubHttp):
        def post_json(self, *args, **kwargs):
            raise HttpError("unavailable")
    report = plan(tmp_path, osv=client(tmp_path, FailedHttp({}, {})))
    assert report["exit_code"] == 2
    report = plan(tmp_path, osv=client(tmp_path), max_queries=1)
    assert report["exit_code"] == 2
    assert "budget" in report["packages"][0]["candidates"][0]["gaps"][0]


def test_missing_invalid_or_nonforward_fixes_remain_explicit(tmp_path):
    for value in (None, "garbage", "0.5", "1.0"):
        report = plan(tmp_path, [finding(fixed_version=value, all_advisories=[{"id": "A", "fixed_versions": []}])])
        package = report["packages"][0]
        assert package["proposed_version"] is None and package["status"] == "no_applicable_fix"
        assert package["gaps"]


def test_wrong_snapshot_is_unmatched_instead_of_applied(tmp_path):
    report = plan(tmp_path, [finding(purl="pkg:npm/other@1.0")], osv=client(tmp_path))
    assert report["summary"]["unmatched_findings"] == 1 and report["exit_code"] == 2
    assert report["packages"][0]["proposed_version"] is None


def test_suppressed_findings_remain_visible_without_proposals(tmp_path):
    row = finding()
    row["suppressed"] = True
    package = plan(tmp_path, [row])["packages"][0]
    assert package["suppressed_findings"] == 1
    assert package["advisories"][0]["suppressed"]
    assert package["proposed_version"] is None and not package["candidates"]


def test_scan_health_and_unsupported_inventory_are_not_coverage_claims(tmp_path):
    inv = inventory(Record("unknown", "unknown", "1", "library"))
    health = {"vuln_type": "sca:scan_health:advisory_lookup_unavailable", "description": "query failed"}
    report = plan(tmp_path, [health], inv=inv, osv=client(tmp_path))
    assert report["exit_code"] == 2 and report["scan_gaps"][0]["reason"] == "query failed"
    assert report["packages"][0]["status"] == "no_reported_vulnerabilities"
    assert report["packages"][1]["status"] == "inventory_coordinates_unavailable"


def test_findings_projection_discards_large_descriptions_and_fingerprints_original(tmp_path):
    row = finding()
    row["description"] = "large description " * 10000
    rows, sha = load(tmp_path, [row, {"vuln_type": "sca:license:unknown", "description": row["description"]}])
    assert len(rows) == 1 and "description" not in rows[0]
    assert sha == hashlib.sha256((tmp_path / "findings.json").read_bytes()).hexdigest()


@pytest.mark.parametrize("raw", ['[NaN]', '[{"sca":{},"sca":{}}]', '[null]', '{}'])
def test_bad_findings_are_refused(tmp_path, raw):
    path = tmp_path / "findings.json"
    path.write_text(raw)
    with pytest.raises(ValueError):
        read_findings(path)


@isolated_cli_logging()
def test_cli_saved_plan_writes_reports_and_never_changes_inputs(cdx, write_json, tmp_path, monkeypatch, capsys):
    from packages import sca
    def unexpected_network(*args, **kwargs):
        raise AssertionError("saved plan must not create an HTTP client")
    monkeypatch.setattr(sca, "default_client", unexpected_network)
    cdx["components"][0].update(name="x", version="1.0", purl="pkg:npm/x@1.0")
    source = write_json(cdx)
    load(tmp_path, [finding()])
    findings = tmp_path / "findings.json"
    before = (source.read_bytes(), findings.read_bytes())
    out = tmp_path / "plan"
    assert main(["plan", str(source), "--findings", str(findings), "--out", str(out), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert json.loads((out / "upgrade-plan.json").read_text()) == report
    assert "not assessed" in (out / "upgrade-plan.md").read_text()
    assert before == (source.read_bytes(), findings.read_bytes())
    assert main(["plan", str(source), "--findings", str(findings), "--out", str(out)]) == 2
    assert "already exists" in capsys.readouterr().err


def test_distro_proposals_use_source_versions_not_binary_versions(tmp_path):
    purl = "pkg:deb/ubuntu/libsample-bin@1.0-9?distro=ubuntu-22.04&upstream=sample%401.0-1"
    inv = inventory(purl=purl, version="1.0-9")
    raw = finding(ecosystem="Ubuntu:22.04:LTS", name="libsample-bin", version="1.0-9", purl=purl,
                  fixed_version="1.0-2", advisory_package={"ecosystem": "Ubuntu:22.04:LTS", "name": "sample", "version": "1.0-1"},
                  all_advisories=[{"id": "USN-example", "fixed_versions": ["1.0-2"]}])
    package = plan(tmp_path, [raw], inv=inv)["packages"][0]
    assert package["target_scope"] == "source_package"
    assert package["query"]["name"] == "sample" and package["query"]["version"] == "1.0-1"
    assert package["installed_version"] == "1.0-9" and package["proposed_version"] == "1.0-2"
    http = StubHttp({}, {})
    report = plan(tmp_path, [raw], inv=inv, osv=client(tmp_path, http))
    assert report["exit_code"] == 0
    queries = http.posts[0][1]["queries"]
    assert {q["version"] for q in queries} == {"1.0-1", "1.0-2"}
    assert all(q["package"]["name"] == "sample" for q in queries)


def test_unscoped_distro_candidates_remain_unavailable(tmp_path):
    purl = "pkg:deb/debian/x@1.0"
    raw = finding(ecosystem="Debian", purl=purl)
    http = StubHttp({}, {})
    report = plan(tmp_path, [raw], inv=inventory(purl=purl), osv=client(tmp_path, http))
    assert report["exit_code"] == 2 and not http.posts
    assert report["packages"][0]["candidates"][0]["status"] == "lookup_unavailable"


def test_candidate_limit_keeps_the_recorded_combined_proposal(tmp_path):
    raw = finding(fixed_version="3.0")
    package = plan(tmp_path, [raw], max_candidates=1)["packages"][0]
    assert [row["version"] for row in package["candidates"]] == ["3.0"]
    assert package["gaps"]


def test_conflicting_advisory_coordinates_block_candidate_recommendations(tmp_path):
    raw = finding(advisory_package={"ecosystem": "npm", "name": "other", "version": "1.0"})
    http = StubHttp({}, {})
    report = plan(tmp_path, [raw], osv=client(tmp_path, http))
    assert report["exit_code"] == 2 and not http.posts
    assert report["packages"][0]["proposed_version"] is None


@isolated_cli_logging()
def test_plan_help_has_examples_and_offline_missing_data_is_reported(cdx, write_json, tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        main(["plan", "--help"])
    assert error.value.code == 0 and capsys.readouterr().out.count("raptor-sca sbom plan") >= 3
    cdx["components"][0].update(name="x", version="1.0", purl="pkg:npm/x@1.0")
    source = write_json(cdx)
    load(tmp_path, [finding()])
    assert main(["plan", str(source), "--findings", str(tmp_path / "findings.json"), "--check-candidates",
                 "--offline", "--cache-root", str(tmp_path / "cache"), "--format", "json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["packages"][0]["status"] == "candidate_verdict_unavailable"


def test_real_sbom_scan_findings_feed_the_plan(cdx, write_json, tmp_path, monkeypatch):
    from packages.sca.pipeline import RunOptions, run_sca
    from packages.sca.sbom_inventory.inventory import read_inventory
    from packages.sca.sbom_inventory.source import Source
    cdx["components"][0].update(name="x", version="1.0", purl="pkg:npm/x@1.0")
    source = write_json(cdx)
    repo = tmp_path / "repo"
    repo.mkdir()
    output = tmp_path / "scan"
    http = StubHttp({"1.0": ["GHSA-old"]}, {"GHSA-old": _VULN_OLD})
    from packages.sca.sbom_import import read_sbom
    cache = JsonCache(root=tmp_path / "cache")
    OsvClient(http, cache).query_batch(read_sbom(source).dependencies)
    monkeypatch.setattr("packages.sca.pipeline.sca_cache_root", lambda: tmp_path / "cache")
    run_sca(repo, output, RunOptions(sbom_input=source, offline=True, cache_root=tmp_path / "cache", enable_license_policy=False,
                                   enable_kev=False, enable_epss=False, enable_reachability=False,
                                   enable_supply_chain=False),
            http=http, cache=cache)
    with Source(output / "sbom.cdx.json") as src:
        inv, _ = read_inventory(src)
    findings, digest = read_findings(output / "findings.json")
    report = build_plan(inv, findings, digest)
    assert report["summary"]["with_reported_advisories"] == 1
    assert not report["unmatched_findings"]
    assert report["packages"][0]["proposed_version"] == "2.0"
