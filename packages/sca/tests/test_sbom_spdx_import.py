"""SPDX evidence preservation, matching boundaries and hostile-input cases."""
from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

from packages.sca.license import LicensePolicy, evaluate
from packages.sca.sbom import build_bom
from packages.sca.sbom_import import read_sbom
from packages.sca.sbom_spdx import render_sbom_spdx


def package(ref, name, purl=None, **fields):
    result = {
        "SPDXID": ref, "name": name, "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False, "licenseDeclared": "MIT",
        "licenseConcluded": "NOASSERTION", "copyrightText": "NOASSERTION",
    }
    if purl:
        result["externalRefs"] = [{"referenceCategory": "PACKAGE-MANAGER",
                                  "referenceType": "purl", "referenceLocator": purl}]
    return result | fields


@pytest.fixture
def document():
    return {
        "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0",
        "name": "image inventory", "documentNamespace": "https://example.org/sbom/image-1",
        "creationInfo": {"created": "2026-11-01T00:00:00Z", "creators": ["Tool: example-1"]},
        "documentDescribes": ["SPDXRef-image"],
        "packages": [
            package("SPDXRef-image", "example/image", checksums=[{"algorithm": "SHA256", "checksumValue": "a" * 64}]),
            package("SPDXRef-parent", "parent", "pkg:pypi/parent@1", versionInfo="1",
                    licenseDeclared="MIT OR GPL-2.0-only", licenseConcluded="GPL-2.0-only",
                    sourceInfo="https://example.org/parent-1.tar.gz"),
            package("SPDXRef-child", "child", "pkg:npm/child@2", versionInfo="2"),
            package("SPDXRef-data", "reference.dat", licenseDeclared="LicenseRef-example"),
        ],
        "relationships": [
            {"spdxElementId": "SPDXRef-image", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-parent"},
            {"spdxElementId": "SPDXRef-child", "relationshipType": "DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-parent"},
        ],
        "hasExtractedLicensingInfos": [{"licenseId": "LicenseRef-example", "name": "Example licence",
                                       "extractedText": "Original terms", "seeAlsos": ["https://example.org/LICENSE"]}],
        "files": [{"SPDXID": "SPDXRef-file", "fileName": "./LICENSE", "checksums": [{"algorithm": "SHA1", "checksumValue": "b" * 40}],
                   "licenseConcluded": "LicenseRef-example", "licenseInfoInFiles": ["LicenseRef-example"],
                   "copyrightText": "Copyright Example"}],
    }


def imported(tmp_path, document):
    path = tmp_path / "input.spdx.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return read_sbom(path)


def test_inventory_and_evidence_survive_independently_of_matching(tmp_path, document):
    source = imported(tmp_path, document)
    assert source.format == "SPDX"
    assert source.document == document
    assert [(d.name, d.direct, d.transitive_depth) for d in source.dependencies] == [
        ("parent", True, 0), ("child", False, 1)]
    assert [d.name for d in source.license_dependencies] == ["example/image", "reference.dat"]
    assert source.refs_by_key[source.dependencies[0].key()] == ["SPDXRef-parent"]
    assert any("files and snippets" in gap for gap in source.coverage_gaps)
    output = render_sbom_spdx(deps=source.dependencies, target_name="ignored", source_bom=source)
    assert output == document
    output["packages"][0]["name"] = "changed"
    assert source.document == document
    with pytest.raises(ValueError, match="CycloneDX source"):
        build_bom(deps=source.dependencies, source_bom=source)


def test_policy_uses_declared_expression_without_substituting_conclusion(tmp_path, document):
    source = imported(tmp_path, document)
    dep = source.dependencies[0]
    assert dep.declared_license == "MIT OR GPL-2.0-only"
    assert dep.source_extra["spdx_license_concluded"] == "GPL-2.0-only"
    policy = LicensePolicy(allow={"MIT"}, deny={"GPL-2.0-only", "LicenseRef-example"})
    findings = evaluate(source.dependencies + source.license_dependencies, policy)
    assert [f.spdx for f in findings] == ["LicenseRef-example"]
    assert any("concluded licence" in gap for gap in source.coverage_gaps)


@pytest.mark.parametrize("expression", [
    "MIT\nAND\tGPL-3.0-only", "(GPL-3.0-only)OR(GPL-2.0-only)",
])
def test_expression_formatting_cannot_bypass_licence_policy(tmp_path, document, expression):
    document["packages"][1]["licenseDeclared"] = expression
    source = imported(tmp_path, document)
    assert source.dependencies[0].source_extra["spdx_license_declared"] == expression
    assert evaluate([source.dependencies[0]], LicensePolicy(deny={"GPL-3.0-only", "GPL-2.0-only"}))
    assert render_sbom_spdx(deps=source.dependencies, target_name="x", source_bom=source) == document


@pytest.mark.parametrize("value", ["NONE", "NOASSERTION", None])
def test_unspecified_declared_licence_is_unknown_even_with_a_conclusion(tmp_path, document, value):
    parent = document["packages"][1]
    if value is None:
        parent.pop("licenseDeclared")
    else:
        parent["licenseDeclared"] = value
    dep = imported(tmp_path, document).dependencies[0]
    assert dep.declared_license is None
    assert dep.source_extra["spdx_license_declared"] == value
    assert evaluate([dep], LicensePolicy(on_unknown="deny"))


@pytest.mark.parametrize("change, message", [
    (lambda d: d.update(spdxVersion="SPDX-3.0"), "unsupported SPDX version"),
    (lambda d: d.update(bomFormat="CycloneDX"), "ambiguous"),
    (lambda d: d.update(dataLicense="MIT"), "CC0"),
    (lambda d: d.update(packages={}), "array"),
    (lambda d: d["packages"].append(deepcopy(d["packages"][1])), "duplicate SPDXID"),
    (lambda d: d["packages"][1].update(versionInfo="2"), "version conflicts"),
    (lambda d: d["packages"][1].update(filesAnalyzed="false"), "boolean"),
    (lambda d: d["packages"][1].update(externalRefs=None), "array"),
    (lambda d: d["packages"][1]["externalRefs"].append({"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/other@1"}), "multiple distinct purls"),
    (lambda d: d["relationships"][0].update(relatedSpdxElement="SPDXRef-missing"), "dangling"),
    (lambda d: d.update(documentDescribes=["SPDXRef-missing"]), "dangling"),
    (lambda d: d["packages"][0].update(hasFiles=["SPDXRef-missing"]), "hasFiles"),
    (lambda d: d["packages"][1].update(licenseDeclared="LicenseRef-missing"), "undefined"),
    (lambda d: d["packages"][1].update(licenseDeclared="DocumentRef-missing:LicenseRef-X"), "undeclared"),
    (lambda d: d["packages"][1].update(licenseDeclared="MIT OR"), "expression"),
    (lambda d: d["packages"][1].update(licenseDeclared="(MIT AND GPL-2.0-only"), "expression"),
    (lambda d: d["packages"][1].update(licenseDeclared="MIT WITH"), "expression"),
    (lambda d: d["packages"][1].update(licenseConcluded="GPL-2.0-only OR"), "expression"),
    (lambda d: d["creationInfo"].update(created="2026-02-30T00:00:00Z"), "timestamp"),
    (lambda d: d["creationInfo"].update(creators=[]), "creators"),
    (lambda d: d["hasExtractedLicensingInfos"].append(deepcopy(d["hasExtractedLicensingInfos"][0])), "duplicate SPDX LicenseRef"),
])
def test_invalid_input_fails_closed(tmp_path, document, change, message):
    change(document)
    with pytest.raises(ValueError, match=message):
        imported(tmp_path, document)


def test_external_references_are_retained_without_fetching(tmp_path, document, monkeypatch):
    import socket
    monkeypatch.setattr(socket, "create_connection", lambda *a, **kw: pytest.fail("network access during SBOM import"))
    document["externalDocumentRefs"] = [{"externalDocumentId": "DocumentRef-source",
        "spdxDocument": "https://example.org/source", "checksum": {"algorithm": "SHA1", "checksumValue": "c" * 40}}]
    document["packages"][1]["licenseDeclared"] = "DocumentRef-source:LicenseRef-upstream"
    document["relationships"].append({"spdxElementId": "SPDXRef-parent", "relationshipType": "GENERATED_FROM",
                                      "relatedSpdxElement": "DocumentRef-source:SPDXRef-source"})
    source = imported(tmp_path, document)
    assert source.document == document
    assert any("external SPDX" in gap for gap in source.coverage_gaps)


def test_contains_relationship_does_not_invent_dependency_depth(tmp_path, document):
    document["relationships"] = [{"spdxElementId": "SPDXRef-image", "relationshipType": "CONTAINS",
                                  "relatedSpdxElement": "SPDXRef-parent"}]
    source = imported(tmp_path, document)
    assert all(d.direct and d.transitive_depth is None for d in source.dependencies)
    assert all(d.source_extra["sbom_directness"] == "unknown" for d in source.dependencies)


def test_cycles_and_repeated_package_occurrences(tmp_path, document):
    document["packages"].append(package("SPDXRef-other", "parent", "pkg:pypi/parent@1", licenseDeclared="GPL-3.0-only"))
    document["relationships"].append({"spdxElementId": "SPDXRef-child", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-parent"})
    source = imported(tmp_path, document)
    assert len(source.dependencies) == 3
    assert source.refs_by_key[source.dependencies[0].key()] == ["SPDXRef-parent", "SPDXRef-other"]
    assert evaluate(source.dependencies, LicensePolicy(deny={"GPL-3.0-only"}))[0].spdx == "GPL-3.0-only"


def test_distro_context_is_preserved_without_claiming_source_correspondence(tmp_path, document):
    purl = "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1?arch=amd64&distro=ubuntu-22.04"
    document["packages"] = [package("SPDXRef-image", "libssl3", purl)]
    document["relationships"] = []
    source = imported(tmp_path, document)
    assert source.dependencies[0].ecosystem == "Ubuntu:22.04:LTS"
    assert source.dependencies[0].purl == purl
    assert any("binary-to-source" in gap for gap in source.coverage_gaps)
    assert render_sbom_spdx(deps=source.dependencies, target_name="x", source_bom=source) == document


@pytest.mark.parametrize("raw, message", [
    (b'{"spdxVersion":"SPDX-2.3","spdxVersion":"SPDX-2.2"}', "duplicate SBOM object key"),
    (b'{"spdxVersion":"SPDX-2.3","name":"\xff"}', "UTF-8"),
    (b'{"spdxVersion":"SPDX-2.3","name":"\\ud800"}', "Unicode scalar"),
    (b'{"spdxVersion":"SPDX-2.3","extra":NaN}', "non-finite"),
    (b'{"spdxVersion":"SPDX-2.3","extra":' + b'[' * 65 + b'0' + b']' * 65 + b'}', "nesting depth"),
])
def test_untrusted_json_preserves_the_shared_read_guards(tmp_path, raw, message):
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError, match=message):
        read_sbom(path)


def test_our_native_spdx_output_is_readable(tmp_path):
    from packages.sca.tests.test_sbom import _dep
    document = render_sbom_spdx(deps=[_dep(name="lodash", version="4.17.21", ecosystem="npm")], target_name="example")
    source = imported(tmp_path, document)
    assert [(d.ecosystem, d.name, d.version) for d in source.dependencies] == [("npm", "lodash", "4.17.21")]


def test_online_scan_keeps_explicit_unknown_licences_and_separate_conclusions(tmp_path, document):
    from core.json import JsonCache
    from packages.sca.pipeline import RunOptions, run_sca
    from packages.sca.tests.test_pipeline import StubHttp

    document["packages"] = [package("SPDXRef-image", "lodash", "pkg:npm/lodash@4.17.21",
                                    licenseDeclared="NOASSERTION", licenseConcluded="MIT")]
    document["relationships"] = []
    path = tmp_path / "input.json"
    path.write_text(json.dumps(document))
    target = tmp_path / "target"
    target.mkdir()
    http = StubHttp()
    output = tmp_path / "out"
    run_sca(target, output, RunOptions(sbom_input=path, enable_llm_review=False, enable_triage=False, enable_supply_chain=False),
            http=http, cache=JsonCache(root=tmp_path / "cache"))
    assert not any("registry.npmjs.org" in url or "pypi.org" in url for url in http.gets)
    findings = json.loads((output / "findings.json").read_text())
    unknown = next(row for row in findings if row["vuln_type"] == "sca:license:unknown")
    assert unknown["sca"]["confidence"]["reason"] == "SPDX package has no usable declared licence"
    assert json.loads((output / "sbom.spdx.json").read_text()) == document


def test_cli_preserves_spdx_and_reports_cross_format_projection(tmp_path, document):
    source = tmp_path / "input.json"
    source.write_text(json.dumps(document))
    target = tmp_path / "target"
    target.mkdir()
    (target / "requirements.txt").write_text("must-not-be-discovered==1\n")
    output = tmp_path / "out"
    result = subprocess.run([sys.executable, "-m", "packages.sca.cli", str(target),
                             "--sbom", str(source), "--offline", "--out", str(output)],
                            cwd=Path(__file__).resolve().parents[3], capture_output=True, text=True, timeout=60)
    assert result.returncode in {0, 1}, result.stderr
    assert json.loads((output / "sbom.spdx.json").read_text()) == document
    cdx = json.loads((output / "sbom.cdx.json").read_text())
    assert {c["name"] for c in cdx["components"]} == {"parent", "child"}
    gaps = [json.loads(line) for line in (output / "analysis-gaps.jsonl").read_text().splitlines()]
    assert any("scan projection" in str(gap) for gap in gaps)
    assert any("not vulnerability-matched" in str(gap) for gap in gaps)


def test_cli_rejects_invalid_spdx_without_emitting_a_clean_sbom(tmp_path, document):
    document["packages"][1]["licenseDeclared"] = "LicenseRef-missing"
    source = tmp_path / "input.json"
    source.write_text(json.dumps(document))
    output = tmp_path / "out"
    result = subprocess.run([sys.executable, "-m", "packages.sca.cli", str(tmp_path),
                             "--sbom", str(source), "--offline", "--out", str(output)],
                            cwd=Path(__file__).resolve().parents[3], capture_output=True, text=True, timeout=60)
    assert result.returncode == 3
    assert not (output / "sbom.cdx.json").exists()
    assert not (output / "sbom.spdx.json").exists()
