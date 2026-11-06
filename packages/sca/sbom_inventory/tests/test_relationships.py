from dataclasses import replace

import pytest

from packages.sca.sbom_inventory.compare import compare
from packages.sca.sbom_inventory.model import Inventory, Record
from packages.sca.sbom_inventory.relationships import explain


def inventory(*rows, coverage=None):
    return Inventory("test", "a" * 64, records=list(rows), coverage=coverage)


def row(id, **kwargs):
    return Record(id, id, "1", "library", **kwargs)


def test_dependency_targets_follow_matched_version_identities():
    a = row("root", graph_supplied=True, children=["old"])
    b = row("old", purl="pkg:npm/dep@1")
    c = replace(b, id="new", version="2", purl="pkg:npm/dep@2")
    result = compare(inventory(a, b), inventory(replace(a, children=["new"]), c))
    assert result["format"] == "raptor-sbom-diff"
    assert result["dependencies"]["compared_records"] == 1
    assert result["dependencies"]["changes"] == []
    changed = compare(inventory(a, b), inventory(replace(a, children=[]), c))
    assert changed["dependencies"]["changes"][0]["kind"] == "dependency_removed"
    missing = compare(inventory(a), inventory(replace(a, graph_supplied=False)))
    assert not missing["dependencies"]["changes"]
    assert missing["dependencies"]["unavailable"]


def coverage(field, rows):
    return {"metrics": {"scanner_unidentified_executables": len(rows)}, field: rows}


def test_ownership_evidence_regression_and_resolution_are_separate_from_file_removal():
    known = {"path": "/bin/tool", "sha256": "a" * 64, "identity": {"name": "tool", "version": "1"}}
    unexplained = {"path": "/bin/tool", "sha256": "a" * 64}
    before = inventory(coverage=coverage("native_identity_matches", [known]))
    after = inventory(coverage=coverage("inventory_candidates", [unexplained]))
    result = compare(before, after)["ownership"]
    assert result["status"] == "compared"
    assert next(c for c in result["changes"] if c["attention"])["kind"] == "new_unexplained_executable"
    assert "resolved_executable_ownership" in {c["kind"] for c in compare(after, before)["ownership"]["changes"]}
    assert compare(before, inventory())["ownership"]["status"] == "not_compared"
    assert compare(before, inventory(coverage=coverage("inventory_candidates", [])))["ownership"]["changes"][0]["kind"] == "ownership_check_removed"


def test_multiple_layer_ownership_occurrences_remain_ambiguous():
    rows = [{"path": "/bin/tool", "layer_id": layer} for layer in ("one", "two")]
    source = inventory(coverage=coverage("inventory_candidates", rows))
    result = compare(source, source)["ownership"]
    assert len(result["ambiguous"]) == 1 and not result["changes"]


def test_why_keeps_occurrences_and_explicit_root_paths():
    source = inventory(row("app", children=["dep"]), row("dep", parents=["app"]), row("other"))
    result = explain(source, "dep", root="app")["results"][0]
    assert [n["name"] for n in result["paths"][0]["nodes"]] == ["app", "dep"]
    assert result["paths"][0]["requested_root_reached"]
    assert not result["outgoing_data_supplied"]
    with pytest.raises(ValueError, match="not found"):
        explain(source, "missing")


def test_why_cycles_and_depth_limits_are_explicit():
    source = inventory(row("a", parents=["b"]), row("b", parents=["a"]))
    assert explain(source, "a")["results"][0]["paths"][0]["cycle_boundary"]
    assert explain(source, "a", max_depth=1)["results"][0]["truncated"]
    with pytest.raises(ValueError, match="budgets"):
        explain(source, "a", max_paths=0)


def test_why_fanout_has_a_total_work_budget():
    source = inventory(row("target", parents=[f"p{i}" for i in range(10010)]),
                       *(row(f"p{i}") for i in range(10010)))
    result = explain(source, "target", max_paths=1)["results"][0]
    assert result["truncated"] and len(result["paths"]) == 1


def test_dependency_aliases_do_not_cross_inventory_scopes():
    root = row("root", graph_supplied=True, children=["old"])
    dep = row("old", purl="pkg:npm/dep@1")
    source = row("old", purl="pkg:npm/dep@1", scope="source-candidates")
    before = inventory(root, dep, source)
    after = inventory(replace(root, children=["new"]), replace(dep, id="new", purl="pkg:npm/dep@2"),
                      replace(source, id="source-new", purl="pkg:npm/dep@2"))
    assert compare(before, after)["dependencies"]["changes"] == []
