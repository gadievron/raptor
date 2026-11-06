from copy import deepcopy
from dataclasses import replace


from packages.sca.sbom_inventory.compare import compare
from packages.sca.sbom_inventory.model import Inventory, Notice, Record


def sample(*rows):
    return Inventory("CycloneDX-1.5", "a" * 64, records=list(rows))


def package(**kwargs):
    row = Record("one", "example", "1", "library", purl="pkg:npm/example@1", declarations=["MIT"])
    return replace(row, **kwargs)


def test_version_bumps_reuse_unique_identity_instead_of_add_remove():
    before = sample(package())
    after = sample(package(id="two", version="2", purl="pkg:npm/example@2"))
    result = compare(before, after)
    assert result["matched"] == 1
    assert result["counts"] == {"version_changed": 1}


def test_changed_license_and_new_gaps_are_explicit():
    old = package(notices=[Notice("a" * 64, "LICENSE", "source")], notice_status="captured")
    new = package(declarations=["NOASSERTION"], notice_status="missing")
    result = compare(sample(old), sample(new))
    assert result["counts"]["license_declaration_changed"] == 1
    assert result["counts"]["new_declaration_gap"] == 1
    assert result["counts"]["new_notice_gap"] == 1
    assert all(c["attention"] for c in result["changes"] if "gap" in c["kind"])


def test_spelling_year_and_notice_text_changes_are_only_informational():
    a = package(notices=[Notice("a" * 64, "LICENSE", "source")], notice_status="captured")
    b = package(notices=[Notice("b" * 64, "LICENSE", "source")], notice_status="captured")
    result = compare(sample(a), sample(b))
    assert result["counts"] == {"notice_text_changed": 1}
    assert not any(c["attention"] for c in result["changes"])


def test_flat_or_order_is_not_a_license_change_but_and_is():
    a = package(declarations=["MIT OR Apache-2.0"])
    b = package(declarations=["Apache-2.0 OR MIT"])
    assert compare(sample(a), sample(b))["counts"] == {}
    b.declarations = ["MIT AND Apache-2.0"]
    assert compare(sample(a), sample(b))["counts"] == {"license_declaration_changed": 1}


def test_reference_only_changes_do_not_claim_a_different_license():
    a = package(declarations=["LicenseRef-first"])
    b = package(declarations=["LicenseRef-second"])
    result = compare(sample(a), sample(b))
    assert result["counts"] == {"license_reference_changed": 1}
    assert not result["changes"][0]["attention"]


def test_parallel_occurrences_are_not_collapsed_or_arbitrarily_paired():
    before = sample(package(id="old-one"), package(id="old-two"))
    after = sample(package(id="new-one", version="2"))
    result = compare(before, after)
    assert result["matched"] == 0
    assert len(result["ambiguous"]) == 1
    assert result["counts"] == {}
    assert len(result["ambiguous"][0]["before"]) == 2


def test_missing_graph_or_evidence_is_not_a_new_notice_gap():
    a = package(notices=[Notice("a" * 64, "LICENSE", "source")], notice_status="captured")
    b = package()
    assert "new_notice_gap" not in compare(sample(a), sample(b))["counts"]


def test_distro_and_architecture_remain_distinct():
    a = package(purl="pkg:deb/debian/example@1?arch=amd64&distro=debian-12")
    b = package(purl="pkg:deb/debian/example@1?arch=arm64&distro=debian-12")
    assert compare(sample(a), sample(b))["counts"] == {"added": 1, "removed": 1}


def test_same_input_is_deterministic_and_unchanged():
    inventory = sample(package())
    before = deepcopy(inventory)
    assert compare(inventory, inventory)["counts"] == {}
    assert inventory == before


def test_source_candidates_from_different_tools_are_distinct():
    a = package(scope="source-candidates", purl="", evidence={"tool": "one"})
    b = package(scope="source-candidates", purl="", evidence={"tool": "two"})
    assert compare(sample(a), sample(b))["counts"] == {"added": 1, "removed": 1}
