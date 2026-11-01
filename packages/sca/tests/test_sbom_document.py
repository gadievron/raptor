"""Retained inventories, scan coverage, and faithful CycloneDX enrichment."""
from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from pathlib import Path
import json
import subprocess
import sys

import pytest

from packages.sca.license import LicensePolicy, evaluate
from packages.sca.sbom import build_bom
from packages.sca.sbom_import import read_cyclonedx
from packages.sca.sbom_spdx import render_sbom_spdx


@pytest.fixture
def document():
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 4,
        "serialNumber": "urn:uuid:00000000-0000-0000-0000-000000000001",
        "metadata": {"component": {"type": "container", "name": "example/image",
            "bom-ref": "image", "version": "sha256:" + "a" * 64,
            "hashes": [{"alg": "SHA-256", "content": "a" * 64}]},
            "lifecycles": [{"phase": "post-build"}],
            "tools": [{"vendor": "example", "name": "producer", "version": "1"}]},
        "components": [
            {"type": "library", "name": "parent", "bom-ref": "parent", "purl": "pkg:pypi/parent@1",
             "licenses": [{"license": {"id": "BSD-2-Clause", "url": "https://example.org/LICENSE",
                                       "text": {"content": "original copyright notice"}}},
                          {"license": {"id": "GPL-2.0-only"}}],
             "hashes": [{"alg": "SHA-256", "content": "b" * 64}],
             "externalReferences": [{"type": "distribution", "url": "https://example.org/source-1.tar.gz"}],
             "properties": [{"name": "example:source-version", "value": "1"}],
             "components": [{"type": "library", "name": "child", "bom-ref": "child",
                             "purl": "pkg:pypi/child@2", "scope": "excluded"}]},
            {"type": "data", "name": "sample.dat", "bom-ref": "data",
             "licenses": [{"license": {"id": "MPL-2.0"}}]},
        ],
        "dependencies": [{"ref": "image", "dependsOn": ["parent"]},
                         {"ref": "parent", "dependsOn": ["child"]},
                         {"ref": "child", "dependsOn": []}],
    }


def imported(tmp_path, doc):
    path = tmp_path / "input.cdx.json"
    path.write_text(json.dumps(doc))
    return read_cyclonedx(path)


def test_retains_inventory_separately_from_graph_aware_scan_view(tmp_path, document):
    source = imported(tmp_path, document)
    assert source.document == document
    assert [(d.name, d.direct) for d in source.dependencies] == [("parent", True), ("child", False)]
    assert source.dependencies[1].scope == "excluded"
    assert len(source.license_dependencies) == 1
    assert source.license_dependencies[0].name == "sample.dat"
    assert "not vulnerability-matched" in source.warnings[0]
    before = deepcopy(source.document)
    output = build_bom(deps=source.dependencies, source_bom=source)
    assert source.document == before  # enrichment must not mutate the input
    assert output["components"] == document["components"]
    assert output["dependencies"] == document["dependencies"]
    assert output["metadata"]["component"] == document["metadata"]["component"]
    assert output["metadata"]["lifecycles"] == document["metadata"]["lifecycles"]
    assert output["metadata"]["tools"][0] == document["metadata"]["tools"][0]
    assert output["serialNumber"] == document["serialNumber"]
    assert output["version"] == 5


def test_multiple_licences_reach_policy_without_inventing_an_expression(tmp_path, document):
    source = imported(tmp_path, document)
    dep = source.dependencies[0]
    assert dep.declared_license is None  # no misleading single-licence answer
    assert dep.license_declarations == ("BSD-2-Clause", "GPL-2.0-only")
    policy = LicensePolicy(allow={"BSD-2-Clause"}, deny={"GPL-2.0-only", "MPL-2.0"}, on_unknown="allow")
    findings = evaluate(source.dependencies + source.license_dependencies, policy)
    assert {f.spdx for f in findings} == {"GPL-2.0-only", "MPL-2.0"}
    both = evaluate([dep], LicensePolicy(deny={"BSD-2-Clause", "GPL-2.0-only"}))
    assert len(both) == len({f.finding_id for f in both}) == 2
    assert build_bom(deps=[dep])["components"][0]["licenses"] == [
        {"license": {"id": "BSD-2-Clause"}}, {"license": {"id": "GPL-2.0-only"}}]
    spdx = render_sbom_spdx(deps=[dep], target_name="example")["packages"][0]
    assert spdx["licenseDeclared"] == "NOASSERTION"
    assert "GPL-2.0-only" in spdx["licenseComments"]


def test_duplicate_occurrences_do_not_hide_licences_or_required_scope(tmp_path):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "same", "bom-ref": "dev", "scope": "optional",
         "purl": "pkg:pypi/same@1", "licenses": [{"license": {"id": "MIT"}}]},
        {"type": "library", "name": "same", "bom-ref": "runtime", "scope": "required",
         "purl": "pkg:pypi/same@1", "licenses": [{"license": {"id": "GPL-2.0-only"}}]},
    ]}
    source = imported(tmp_path, doc)
    assert build_bom(deps=source.dependencies, source_bom=source)["components"] == doc["components"]
    assert evaluate(source.dependencies, LicensePolicy(deny={"GPL-2.0-only"}))[0].spdx == "GPL-2.0-only"
    plain = build_bom(deps=source.dependencies)
    assert plain["components"][0]["scope"] == "required"
    excluded = replace(source.dependencies[0], scope="excluded")
    assert build_bom(deps=[excluded])["components"][0]["scope"] == "excluded"


@pytest.mark.parametrize("purl, ecosystem", [
    ("pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1?arch=amd64&distro=ubuntu-22.04", "Ubuntu"),
    ("pkg:deb/debian/libssl3@3.0.2-1?distro=debian-12", "Debian"),
    ("pkg:apk/alpine/zlib@1.3.1-r0?distro=alpine-3.20.1", "Alpine:v3.20"),
])
def test_uses_distro_context_but_preserves_complete_purl(tmp_path, purl, ecosystem):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "package", "purl": purl}]}
    source = imported(tmp_path, doc)
    assert source.dependencies[0].ecosystem == ecosystem
    assert source.dependencies[0].purl == purl
    assert "bom-ref" not in source.document["components"][0]
    assert "unknown" in source.dependencies[0].source_extra["sbom_directness"]
    output = build_bom(deps=source.dependencies, source_bom=source)
    assert output["components"][0]["purl"] == purl
    assert output["components"][0]["bom-ref"]


def test_unknown_distro_retains_inventory_and_reports_scan_gap(tmp_path):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "zlib", "purl": "pkg:apk/alpine/zlib@1.3.1-r0"}]}
    source = imported(tmp_path, doc)
    assert source.dependencies == []
    assert len(source.warnings) == 1
    assert build_bom(deps=[], source_bom=source)["components"][0]["purl"] == doc["components"][0]["purl"]


@pytest.mark.parametrize("change, message", [
    (lambda d: d.update(specVersion="99.0"), "specVersion"),
    (lambda d: d.update(components={}), "components must be an array"),
    (lambda d: d["components"].append({"name": "dup", "bom-ref": "parent"}), "duplicate"),
    (lambda d: d["dependencies"][0]["dependsOn"].append("unknown"), "dangling"),
    (lambda d: d["dependencies"].append(d["dependencies"][0]), "duplicate"),
    (lambda d: d["components"][0].update(scope=[]), "scope"),
    (lambda d: d["metadata"].update(tools=None), "tools"),
    (lambda d: d["components"][0].update(licenses=[{"expression": "MIT"}, {"license": {"id": "GPL-2.0-only"}}]), "only choice"),
])
def test_invalid_structures_fail_closed(tmp_path, document, change, message):
    change(document)
    with pytest.raises(ValueError, match=message):
        imported(tmp_path, document)


def test_duplicate_json_keys_and_invalid_utf8_do_not_silently_change_evidence(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('{"bomFormat":"CycloneDX","specVersion":"1.5","components":[],"components":[]}')
    with pytest.raises(ValueError, match="duplicate SBOM object key"):
        read_cyclonedx(path)
    path.write_bytes(b'{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"name":"\xff"}}')
    with pytest.raises(ValueError, match="UTF-8"):
        read_cyclonedx(path)


def test_signed_input_stays_unchanged_and_modified_output_drops_invalid_signature(tmp_path, document):
    document["signature"] = {"algorithm": "HS256", "value": "example"}
    source = imported(tmp_path, document)
    assert source.document == document
    assert any("signature" in w for w in source.warnings)
    output = build_bom(deps=source.dependencies, source_bom=source)
    assert "signature" not in output
    assert source.document["signature"] == document["signature"]


def test_graph_cycles_terminate_and_keep_direct_root_children(tmp_path, document):
    document["dependencies"][-1]["dependsOn"] = ["parent"]
    source = imported(tmp_path, document)
    assert [(d.name, d.direct) for d in source.dependencies] == [("parent", True), ("child", False)]


def test_existing_vex_and_every_duplicate_occurrence_survive_enrichment(tmp_path, document):
    from packages.sca.tests.test_sbom import _adv
    from packages.sca.findings import build_vuln_findings
    from packages.sca.osv import OsvResult
    first = document["components"][0]
    clone = deepcopy(first)
    clone.pop("components")
    clone["bom-ref"] = "second-occurrence"
    document["components"].append(clone)
    source = imported(tmp_path, document)
    dep = source.dependencies[0]
    findings = build_vuln_findings([dep], [OsvResult(dep_key=dep.key(), advisories=[_adv()])])
    assert findings
    existing = {"bom-ref": findings[0].finding_id, "id": "UPSTREAM-ASSERTION"}
    source.document["vulnerabilities"] = [existing]
    output = build_bom(deps=source.dependencies, source_bom=source, vuln_findings=findings)
    assert output["vulnerabilities"][0] == existing
    new = output["vulnerabilities"][1]
    assert new["bom-ref"] != existing["bom-ref"]
    assert {item["ref"] for item in new["affects"]} == {"parent", "second-occurrence"}


@pytest.mark.parametrize("content", ["{broken", '{"bomFormat":"SPDX","components":[]}'])
def test_cli_rejects_failed_import_without_emitting_a_clean_empty_sbom(tmp_path, content):
    source = tmp_path / "bad.json"
    source.write_text(content)
    target = tmp_path / "empty"
    target.mkdir()
    output = tmp_path / "output"
    result = subprocess.run([sys.executable, "-m", "packages.sca.cli", str(target),
        "--sbom", str(source), "--offline", "--out", str(output)],
        cwd=Path(__file__).resolve().parents[3], capture_output=True, text=True, timeout=30)
    assert result.returncode == 3
    assert not (output / "sbom.cdx.json").exists()
    assert not (output / "findings.json").exists()


def test_missing_purl_version_uses_component_version_and_conflicts_fail(tmp_path):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "package", "version": "2", "purl": "pkg:pypi/package"}]}
    assert imported(tmp_path, doc).dependencies[0].version == "2"
    doc["components"][0]["purl"] = "pkg:pypi/package@3"
    with pytest.raises(ValueError, match="version conflicts"):
        imported(tmp_path, doc)


def test_sca_directness_property_survives_legacy_projection_roundtrip(tmp_path, document):
    dep = imported(tmp_path, document).dependencies[1]
    assert dep.direct is False
    plain = build_bom(deps=[dep])
    reparsed = imported(tmp_path, plain)
    assert reparsed.dependencies[0].direct is False
    document["components"][0]["properties"].append({"name": "raptor:direct", "value": "false"})
    with pytest.raises(ValueError, match="conflicts with its dependency graph"):
        imported(tmp_path, document)


def test_graph_depth_reaches_risk_inputs(tmp_path, document):
    from packages.sca.tests.test_sbom import _adv
    from packages.sca.findings import build_vuln_findings
    from packages.sca.osv import OsvResult
    deepest = {"type": "library", "name": "deep", "bom-ref": "deep", "purl": "pkg:pypi/deep@1"}
    document["components"].append(deepest)
    document["dependencies"][-1]["dependsOn"] = ["deep"]
    source = imported(tmp_path, document)
    dep = next(d for d in source.dependencies if d.name == "deep")
    finding = build_vuln_findings([dep], [OsvResult(dep_key=dep.key(), advisories=[_adv()])])[0]
    assert dep.direct is False
    assert finding.transitive_depth == 2


def test_cli_preserves_full_inventory_and_licence_gate_including_data(tmp_path, document):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(document))
    target = tmp_path / "target"
    target.mkdir()
    (target / ".raptor-sca-license-policy.yml").write_text("deny: [GPL-2.0-only, MPL-2.0]\non_unknown: allow\n")
    output = tmp_path / "output"
    result = subprocess.run([sys.executable, "-m", "packages.sca.cli", str(target),
        "--sbom", str(source), "--offline", "--trust-repo", "--out", str(output)],
        cwd=Path(__file__).resolve().parents[3], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr[-2000:]
    saved = json.loads((output / "sbom.cdx.json").read_text())
    assert saved["components"] == document["components"]
    assert saved["metadata"]["component"] == document["metadata"]["component"]
    rows = json.loads((output / "findings.json").read_text())
    reported = {r.get("sca", {}).get("spdx") for r in rows}
    assert {"GPL-2.0-only", "MPL-2.0"} <= reported
    assert (output / "analysis-gaps.jsonl").is_file()


def test_repeated_package_scan_context_uses_most_exposed_occurrence(tmp_path, document):
    from packages.sca.pipeline import select_canonical_for_osv
    child = document["components"][0]["components"][0]
    direct = deepcopy(child)
    direct["bom-ref"] = "direct-child"
    direct["scope"] = "required"
    document["components"].append(direct)
    document["dependencies"][0]["dependsOn"].append("direct-child")
    source = imported(tmp_path, document)
    canonical = select_canonical_for_osv(source.dependencies)
    selected = next(d for d in canonical if d.name == "child")
    assert selected.direct is True
    assert selected.scope == "main"
    assert selected.transitive_depth == 0
    assert build_bom(deps=canonical, source_bom=source)["components"] == document["components"]


@pytest.mark.parametrize("purl", [
    "pkg:pypi/thing@", "pkg:pypi/thing%GG@1", "pkg:pypi/thing%FF@1",
    "pkg:pypi/thing@1?distro=x&distro=y", "pkg:deb/debian/pkg@1?distro=ubuntu-22.04",
])
def test_ambiguous_or_invalid_package_urls_remain_inventory_with_a_matching_gap(tmp_path, purl):
    source = imported(tmp_path, {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "thing", "purl": purl}]})
    assert source.dependencies == []
    assert source.coverage_gaps
    assert source.document["components"][0]["purl"] == purl


def test_unpaired_surrogates_fail_before_evidence_export(tmp_path):
    path = tmp_path / "surrogate.json"
    path.write_text('{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"name":"\\ud800"}}')
    with pytest.raises(ValueError, match="Unicode scalar"):
        read_cyclonedx(path)


def test_repository_package_identity_keeps_owner(tmp_path):
    source = imported(tmp_path, {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "library", "purl": "pkg:github/owner/library@abcdef"}]})
    assert source.dependencies[0].name == "owner/library"


def test_reference_normalization_removes_only_affected_component_signatures(tmp_path):
    signature = {"algorithm": "HS256", "value": "example"}
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "parent", "bom-ref": "parent", "signature": signature,
         "components": [{"type": "library", "name": "child", "purl": "pkg:pypi/child@1", "signature": signature}]},
        {"type": "library", "name": "untouched", "bom-ref": "untouched", "signature": signature},
    ]}
    source = imported(tmp_path, doc)
    output = build_bom(deps=source.dependencies, source_bom=source)
    assert source.document == doc
    assert "signature" not in output["components"][0]
    assert "signature" not in output["components"][0]["components"][0]
    assert output["components"][1]["signature"] == signature
    assert any("component signatures" in warning for warning in source.notices)


def test_external_bom_links_are_preserved_and_unloaded_inventory_is_reported(tmp_path, document):
    link = "urn:cdx:00000000-0000-0000-0000-000000000001/1#external-component"
    document["dependencies"][0]["dependsOn"].append(link)
    source = imported(tmp_path, document)
    assert any("external BOM" in warning for warning in source.coverage_gaps)
    assert build_bom(deps=source.dependencies, source_bom=source)["dependencies"] == document["dependencies"]
    document["dependencies"][0]["dependsOn"][-1] = "urn:cdx:invalid"
    with pytest.raises(ValueError, match="dangling"):
        imported(tmp_path, document)


def test_registry_enrichment_never_overwrites_explicit_multiple_declarations(tmp_path, document):
    from packages.sca.license import enrich_licenses
    source = imported(tmp_path, document)
    multi = source.dependencies[0]
    registry = replace(multi, license_declarations=(), declared_license=None)

    class Http:
        def __init__(self):
            self.calls = []

        def get_json(self, url, **kwargs):
            self.calls.append(url)
            return {"info": {"license_expression": "MIT"}}

    http = Http()
    # Registry evidence may fill the unknown occurrence, but must not
    # replace the separately supplied multi-licence declaration.
    enrich_licenses([multi, registry], http=http, enabled=True)
    assert len(http.calls) == 1
    assert registry.declared_license == "MIT"
    assert multi.declared_license is None
    assert multi.license_declarations == ("BSD-2-Clause", "GPL-2.0-only")
