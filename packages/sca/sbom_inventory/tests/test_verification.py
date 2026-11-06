from copy import deepcopy
import hashlib
import json

import pytest

from core.json import JsonCache
from core.testing.logging_state import isolated_cli_logging
from packages.sca.osv import OsvClient
from packages.sca.sbom_inventory.advisory_coverage import query_key, read_coverage, write_coverage
from packages.sca.sbom_inventory.cli import main
from packages.sca.sbom_inventory.model import Inventory, Record
from packages.sca.sbom_inventory.plan import build_plan
from packages.sca.sbom_inventory.plan_inputs import PackagePlan, _finding, inventory_plans
from packages.sca.sbom_inventory.verification import read_plan, verify_plan
from packages.sca.sbom_inventory.tests.test_plan import finding, inventory, StubHttp


def saved_plan(inv=None, rows=None):
    return build_plan(inv or inventory(), [_finding(row) for row in (rows if rows is not None else [finding()])], "b" * 64)


def current(version="2.0", *, id="new", purl=None):
    return Inventory("test", "c" * 64, records=[Record(id, "x", version, "library", purl=purl or "pkg:npm/x@" + version)])


def coverage_for(inv, *, unavailable=False):
    from packages.sca.distro import advisory_dependency
    _, deps = inventory_plans(inv)
    result = {}
    for dep in deps.values():
        query = advisory_dependency(dep)
        row = dict(ecosystem=dep.ecosystem, name=dep.name, version=dep.version, purl=dep.purl,
                   query=dict(ecosystem=query.ecosystem, name=query.name, version=query.version),
                   status="unavailable" if unavailable else "checked", reason="test unavailable" if unavailable else "")
        result[query_key(row)] = row
    return result


def verify(inv=None, rows=(), *, before=None, coverage=None, errors=()):
    inv = inv or current()
    baseline = deepcopy(before or saved_plan())
    baseline["packages"] = [PackagePlan(**row) if isinstance(row, dict) else row for row in baseline["packages"]]
    return verify_plan(baseline, "d" * 64, inv, [_finding(row) for row in rows], "e" * 64,
                       coverage=coverage_for(inv) if coverage is None else coverage, coverage_errors=errors)


def test_target_and_resolved_advisory_require_positive_current_coverage():
    report = verify()
    assert report["exit_code"] == 0 and report["status"] == "verified"
    assert report["packages"][0]["status"] == "target_met"
    assert report["advisories"]["resolved"][0]["id"] == "GHSA-OLD"
    missing = verify(coverage={})
    assert missing["exit_code"] == 2 and not missing["advisories"]["resolved"]
    assert missing["advisories"]["not_reported"]


def test_failed_coverage_empty_findings_are_not_clear():
    inv = current()
    report = verify(inv, coverage=coverage_for(inv, unavailable=True))
    assert report["exit_code"] == 2 and report["summary"]["uncovered_package_groups"] == 1
    assert not report["advisories"]["resolved"]


def test_unchanged_target_and_remaining_advisory_need_attention():
    report = verify(current("1.0"), [finding()])
    assert report["exit_code"] == 1 and report["packages"][0]["status"] == "target_not_met"
    assert report["advisories"]["remaining"] and not report["advisories"]["resolved"]


def test_new_advisory_at_target_is_reported():
    row = finding(version="2.0", purl="pkg:npm/x@2.0", all_advisories=[{"id": "NEW", "aliases": []}])
    report = verify(rows=[row])
    assert report["exit_code"] == 1 and report["advisories"]["newly_reported"][0]["id"] == "NEW"
    assert report["summary"]["targets_met"] == 1


def test_suppression_is_not_a_resolution():
    row = finding(version="2.0", purl="pkg:npm/x@2.0")
    row["suppressed"] = True
    report = verify(rows=[row])
    assert report["exit_code"] == 1 and report["advisories"]["suppression_added"]
    assert not report["advisories"]["resolved"]


def test_missing_package_is_not_evidence_of_file_removal():
    inv = Inventory("test", "c" * 64)
    report = verify(inv)
    assert report["exit_code"] == 1 and report["packages"][0]["status"] == "not_observed"
    assert report["advisories"]["not_observed"] and not report["advisories"]["resolved"]


def test_mixed_current_versions_are_partial_not_successful():
    inv = current()
    inv.records.append(Record("old-copy", "x", "1.0", "library", purl="pkg:npm/x@1.0"))
    report = verify(inv)
    assert report["exit_code"] == 1 and report["packages"][0]["status"] == "partially_met"


def test_ambiguous_multi_version_baselines_remain_unknown():
    inv = inventory(Record("other", "x", "1.5", "library", purl="pkg:npm/x@1.5"))
    rows = [finding(), finding(version="1.5", purl="pkg:npm/x@1.5")]
    report = verify(before=saved_plan(inv, rows))
    assert report["exit_code"] == 2 and all(row["status"] == "ambiguous" for row in report["packages"])


def test_current_scan_gaps_and_unmatched_findings_are_visible():
    health = {"vuln_type": "sca:scan_health:advisory_lookup_unavailable", "description": "coverage missing"}
    report = verify(rows=[health, finding(name="other", purl="pkg:npm/other@2.0", version="2.0")])
    assert report["exit_code"] == 2 and report["unmatched_findings"]
    assert report["coverage"]["new_gap_kinds"]
    assert not report["advisories"]["resolved"]


def test_read_plan_refuses_bad_formats_and_duplicate_occurrences(tmp_path):
    path = tmp_path / "plan.json"
    report = saved_plan()
    path.write_text(json.dumps(report))
    parsed, _ = read_plan(path)
    assert parsed["packages"][0].proposed_version == "2.0"
    for mutate in (lambda r: r.update(schema_version=2), lambda r: r["packages"].append(deepcopy(r["packages"][0]))):
        bad = deepcopy(report)
        mutate(bad)
        path.write_text(json.dumps(bad))
        with pytest.raises(ValueError):
            read_plan(path)


def test_coverage_receipts_bind_both_outputs_and_record_missing_data(tmp_path):
    sbom = tmp_path / "sbom.cdx.json"
    findings = tmp_path / "findings.json"
    sbom.write_text("{}")
    findings.write_text("[]")
    path = tmp_path / "advisory-coverage.json"
    _, deps = inventory_plans(current())
    client = OsvClient(StubHttp({}, {}), JsonCache(root=tmp_path / "cache"))
    results = client.query_batch(list(deps.values()))
    write_coverage(path, list(deps.values()), client, results, {"sbom.cdx.json": sbom, "findings.json": findings})
    digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
    index, _, errors = read_coverage(path, digest(sbom), digest(findings))
    assert not errors and list(index.values())[0]["status"] == "checked"
    findings.write_text("[{}]")
    assert read_coverage(path, digest(sbom), digest(findings))[2]
    assert read_coverage(tmp_path / "absent", digest(sbom), digest(findings))[2]


def test_source_target_uses_source_version_and_keeps_binary_version_distinct():
    old_purl = "pkg:deb/ubuntu/libsample-bin@1.0-9?distro=ubuntu-22.04&upstream=sample%401.0-1"
    new_purl = "pkg:deb/ubuntu/libsample-bin@1.0-10?distro=ubuntu-22.04&upstream=sample%401.0-2"
    old = inventory(purl=old_purl, version="1.0-9")
    raw = finding(ecosystem="Ubuntu:22.04:LTS", name="libsample-bin", version="1.0-9", purl=old_purl,
                  fixed_version="1.0-2", advisory_package={"ecosystem": "Ubuntu:22.04:LTS", "name": "sample", "version": "1.0-1"},
                  all_advisories=[{"id": "USN-test", "fixed_versions": ["1.0-2"]}])
    report = verify(current("1.0-10", purl=new_purl), before=saved_plan(old, [raw]))
    assert report["exit_code"] == 0
    outcome = report["packages"][0]
    assert outcome["target_scope"] == "source_package" and outcome["status"] == "target_met"
    assert outcome["current"][0]["query"]["version"] == "1.0-2"
    assert outcome["current"][0]["version"] == "1.0-10"


@isolated_cli_logging()
def test_cli_missing_coverage_reports_unknown_and_exports_without_mutating_inputs(cdx, write_json, tmp_path, capsys, monkeypatch):
    from packages import sca
    def no_network(*args, **kwargs):
        raise AssertionError("verification is offline")
    monkeypatch.setattr(sca, "default_client", no_network)
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(saved_plan()))
    cdx["components"][0].update(name="x", version="2.0", purl="pkg:npm/x@2.0")
    source = write_json(cdx)
    findings = tmp_path / "findings.json"
    findings.write_text("[]")
    before = [p.read_bytes() for p in (path, source, findings)]
    out = tmp_path / "verification"
    assert main(["verify-plan", str(path), str(source), "--findings", str(findings), "--out", str(out), "--format", "json"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "unavailable" and report["packages"][0]["status"] == "target_met"
    assert json.loads((out / "upgrade-verification.json").read_text()) == report
    assert "not reported" in (out / "upgrade-verification.md").read_text().lower()
    assert before == [p.read_bytes() for p in (path, source, findings)]


def test_stable_occurrence_ids_disambiguate_multiple_versions():
    old = inventory(Record("other", "x", "1.5", "library", purl="pkg:npm/x@1.5"))
    after = current("2.0", id="one")
    after.records.append(Record("other", "x", "3.0", "library", purl="pkg:npm/x@3.0"))
    report = verify(after, before=saved_plan(old, [finding(), finding(version="1.5", purl="pkg:npm/x@1.5")]))
    assert report["exit_code"] == 0 and report["summary"]["targets_met"] == 2


@isolated_cli_logging()
def test_real_scan_plan_rebuild_verify_loop_is_offline_and_hash_bound(cdx, write_json, tmp_path, monkeypatch, capsys):
    from core.json import save_json
    from packages.sca import pipeline
    from packages.sca.sbom_import import read_sbom
    from packages.sca.sbom_inventory.inventory import read_inventory
    from packages.sca.sbom_inventory.plan_inputs import read_findings
    from packages.sca.sbom_inventory.source import Source
    from packages.sca.sbom_inventory.tests.test_plan import _VULN_OLD
    cache = JsonCache(root=tmp_path / "cache")
    monkeypatch.setattr(pipeline, "sca_cache_root", lambda: tmp_path / "cache")
    repo = tmp_path / "repo"
    repo.mkdir()
    http = StubHttp({"1.0": ["GHSA-old"], "2.0": []}, {"GHSA-old": _VULN_OLD})
    cdx["components"].append({"type": "file", "name": "payload", "bom-ref": "file"})
    for version, label in (("1.0", "baseline"), ("2.0", "rebuilt")):
        cdx["components"][0].update(name="x", version=version, purl="pkg:npm/x@" + version)
        source = write_json(cdx, name=label + ".json")
        OsvClient(http, cache).query_batch(read_sbom(source).dependencies)
        pipeline.run_sca(repo, tmp_path / label, pipeline.RunOptions(
            sbom_input=source, offline=True, cache_root=tmp_path / "cache", enable_license_policy=False,
            enable_kev=False, enable_epss=False, enable_reachability=False, enable_supply_chain=False),
            http=http, cache=cache)
    baseline = tmp_path / "baseline"
    rebuilt = tmp_path / "rebuilt"
    with Source(baseline / "sbom.cdx.json") as src:
        inv, _ = read_inventory(src)
    rows, sha = read_findings(baseline / "findings.json")
    plan_path = tmp_path / "upgrade-plan.json"
    save_json(plan_path, build_plan(inv, rows, sha))
    def no_network(*args, **kwargs):
        raise AssertionError("verification must not create a network client")
    monkeypatch.setattr("packages.sca.default_client", no_network)
    capsys.readouterr()
    assert main(["verify-plan", str(plan_path), str(rebuilt / "sbom.cdx.json"), "--findings",
                 str(rebuilt / "findings.json"), "--format", "json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == "verified" and report["summary"]["targets_met"] == 1
    assert report["summary"]["resolved_advisories"] == 1 and report["sources"]["coverage_sha256"]
    # Modifying either scanned output invalidates the positive receipt.
    with (rebuilt / "findings.json").open("a") as stream:
        stream.write("\n")
    assert main(["verify-plan", str(plan_path), str(rebuilt / "sbom.cdx.json"), "--findings",
                 str(rebuilt / "findings.json"), "--format", "json"]) == 2
    assert json.loads(capsys.readouterr().out)["coverage"]["errors"]


def test_unmatched_baseline_findings_prevent_a_verified_claim():
    before = saved_plan()
    before["unmatched_findings"] = [{"finding_id": "other", "reason": "baseline identity not matched"}]
    report = verify(before=before)
    assert report["exit_code"] == 2 and report["summary"]["unmatched_findings"] == 1
    assert not report["advisories"]["resolved"]


@isolated_cli_logging()
def test_verification_help_has_two_examples(capsys):
    with pytest.raises(SystemExit) as error:
        main(["verify-plan", "--help"])
    assert error.value.code == 0
    assert capsys.readouterr().out.count("raptor-sca sbom verify-plan") >= 3


def test_binary_version_without_declared_source_is_not_source_fix_proof():
    old_purl = "pkg:deb/ubuntu/x@1.0-9?distro=ubuntu-22.04&upstream=x%401.0-1"
    old = inventory(purl=old_purl, version="1.0-9")
    raw = finding(ecosystem="Ubuntu:22.04:LTS", version="1.0-9", purl=old_purl,
                  fixed_version="1.0-2", advisory_package={"ecosystem": "Ubuntu:22.04:LTS", "name": "x", "version": "1.0-1"},
                  all_advisories=[{"id": "USN-test", "fixed_versions": ["1.0-2"]}])
    # Both inventories use the same package/source name. Without explicit
    # source coordinates, treating the binary version as the source would
    # otherwise satisfy the comparison by accident.
    rebuilt = current("1.0-10", purl="pkg:deb/ubuntu/x@1.0-10?distro=ubuntu-22.04")
    from packages.sca.sbom_inventory.verification import _target
    from packages.sca.sbom_inventory.plan_inputs import inventory_plans
    baseline = PackagePlan(**saved_plan(old, [raw])["packages"][0])
    groups, dependencies = inventory_plans(rebuilt)
    target = _target(baseline, list(enumerate(groups)), dependencies, ambiguous=False)
    assert target["status"] == "unavailable"
    report = verify(rebuilt, before=saved_plan(old, [raw]))
    assert report["exit_code"] == 2 and not report["advisories"]["resolved"]


@pytest.mark.parametrize("planned", [True, False])
def test_ambiguous_groups_are_recorded_once_without_cartesian_expansion(planned):
    old = Inventory("test", "a" * 64, records=[
        Record("old-" + str(i), "x", "1." + str(i), "library", purl="pkg:npm/x@1." + str(i)) for i in range(4)])
    after = Inventory("test", "c" * 64, records=[
        Record("new-" + str(i), "x", "2." + str(i), "library", purl="pkg:npm/x@2." + str(i)) for i in range(5)])
    before = saved_plan(old, [finding(version=row.version, purl=row.purl) for row in old.records])
    if not planned:
        for row in before["packages"]:
            row["proposed_version"] = None
    report = verify(after, before=before)
    if planned:
        assert report["exit_code"] == 2
    assert sum(len(row["current"]) for row in report["packages"]) <= len(old.records) + len(after.records)
    assert all(row["notes"] for row in report["packages"])
    assert len(report["ambiguous_groups"]) == 1
    assert len(report["ambiguous_groups"][0]["current"]) == len(after.records)


def test_coalesced_occurrences_are_not_repeated_for_each_baseline_version():
    old = Inventory("test", "a" * 64, records=[
        Record("copy-" + str(i), "x", "1." + str(i), "library", purl="pkg:npm/x@1." + str(i)) for i in range(3)])
    after = Inventory("test", "c" * 64, records=[
        Record(row.id, "x", "2.0", "library", purl="pkg:npm/x@2.0") for row in old.records])
    before = saved_plan(old, [finding(version=row.version, purl=row.purl) for row in old.records])
    report = verify(after, before=before)
    assert report["exit_code"] == 0
    observed = [ref for row in report["packages"] for current in row["current"] for ref in current["occurrences"]]
    assert sorted(observed) == sorted(row.id for row in old.records)


@pytest.mark.parametrize("container", ["file", "directory", "zip"])
@isolated_cli_logging()
def test_verification_refuses_snapshot_claimed_scan_fingerprints(tmp_path, capsys, container):
    import zipfile
    from core.json import save_json
    plan = tmp_path / "plan.json"
    save_json(plan, saved_plan())
    rebuilt = current()
    document = rebuilt.to_dict()
    # A recorded source fingerprint must never substitute for hashing the
    # current scan document. Snapshot records can differ from their source.
    snapshot = tmp_path / "snapshot.json"
    save_json(snapshot, document)
    if container == "directory":
        snapshot = tmp_path / "snapshot"
        snapshot.mkdir()
        save_json(snapshot / "inventory.json", document)
    elif container == "zip":
        archive = tmp_path / "snapshot.zip"
        with zipfile.ZipFile(archive, "w") as stream:
            stream.write(snapshot, "inventory.json")
        snapshot = archive
    assert main(["verify-plan", str(plan), str(snapshot), "--findings", str(tmp_path / "findings.json")]) == 2
    assert "original emitted CycloneDX or SPDX document" in capsys.readouterr().err
