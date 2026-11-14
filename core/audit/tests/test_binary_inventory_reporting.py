"""Recorded binary inventory reaches reports without extraction authority."""
import pytest

from core.audit.report import generate_report
from core.audit.report_document import build_audit_document
from core.inventory import save_checklist
from core.inventory.binary_builder import build_binary_checklist
from core.reporting.renderers import get_renderer
from packages.ghidra.model import REDatabase, REFunction


def _checklist(tmp_path):
    # No binary exists at this owned path: only typed parsed records, no probe.
    db = REDatabase(source_tool="synthetic-records", binary_path=str(tmp_path / "absent-image"),
                    architecture="x86 64-bit", functions=[
                        REFunction(name="parsed", address=0x1000, size=32, decompilation="int parsed(void) { return 1; }"),
                        REFunction(name="name_only", address=0x2000, size=32),
                        REFunction(name="thunk", address=0x3000, size=8, is_thunk=True),
                    ])
    return build_binary_checklist(db)


def test_actual_binary_inventory_reports_separate_recorded_denominators(tmp_path):
    save_checklist(tmp_path, _checklist(tmp_path))
    report = generate_report(tmp_path)
    record = report["binary_inventory"]
    assert record["mode"] == "recorded" and record["authoritative"] is False
    assert record["parsed_functions"] == 3
    assert record["selected_functions"] == 2
    assert record["functions_outside_selection"] == 1
    assert record["pseudocode_recorded"] == 1
    assert record["pseudocode_not_recorded"] == 1
    assert all(value is None for value in record["unmeasured_dimensions"].values())
    assert report["coverage_delta"] == report["stats"]["reviewed"] == 0
    assert report["findings_count"] == 0
    _, document = build_audit_document(report, tmp_path)
    markdown = get_renderer("markdown").render(document).content.decode()
    assert "Recorded binary inventory" in markdown
    assert "Pseudocode presence is not completed review" in markdown
    assert "Decoded-byte coverage" in markdown and "unavailable" in markdown
    assert "%" not in markdown


def test_source_checklist_does_not_acquire_binary_coverage(tmp_path):
    save_checklist(tmp_path, {"target_kind": "source", "files": [], "total_items": 0})
    assert "binary_inventory" not in generate_report(tmp_path)


@pytest.mark.parametrize("change", ["wrong-total", "bool-total", "bad-representation"])
def test_inconsistent_binary_inventory_is_unavailable_not_zero_coverage(tmp_path, change):
    checklist = _checklist(tmp_path)
    if change == "wrong-total":
        checklist["total_items"] = 3
    elif change == "bool-total":
        checklist["binary_stats"]["total_functions"] = True
    else:
        checklist["files"][0]["items"][0]["has_decompilation"] = "yes"
    save_checklist(tmp_path, checklist)
    record = generate_report(tmp_path)["binary_inventory"]
    assert record["mode"] == "unavailable" and record["authoritative"] is False
    assert "pseudocode_recorded" not in record


@pytest.mark.parametrize("corrupt", [False, True])
def test_sharded_inventory_uses_integrity_checked_stream_not_partial_totals(tmp_path, monkeypatch, corrupt):
    import json

    import core.inventory as inventory

    monkeypatch.setattr(inventory, "_MAX_CHECKLIST_BYTES", 512)
    monkeypatch.setattr(inventory, "_CHECKLIST_SHARD_TARGET_BYTES", 1024)
    save_checklist(tmp_path, _checklist(tmp_path))
    index_path = tmp_path / "checklist" / "index.json"
    assert index_path.is_file()
    if corrupt:
        index = json.loads(index_path.read_text())
        shard = tmp_path / "checklist" / index["shards"][0]["path"]
        shard.write_bytes(b"tampered")
    record = generate_report(tmp_path)["binary_inventory"]
    if corrupt:
        assert record["mode"] == "unavailable"
        assert "pseudocode_recorded" not in record
    else:
        assert record["mode"] == "recorded"
        assert record["parsed_functions"] == 3 and record["selected_functions"] == 2
        assert record["pseudocode_recorded"] == 1


def test_zero_selected_rows_do_not_hide_corrupt_shard(tmp_path, monkeypatch):
    import json

    import core.inventory as inventory

    monkeypatch.setattr(inventory, "_MAX_CHECKLIST_BYTES", 512)
    monkeypatch.setattr(inventory, "_CHECKLIST_SHARD_TARGET_BYTES", 1024)
    checklist = _checklist(tmp_path)
    checklist["files"][0]["items"] = []
    checklist["total_items"] = checklist["total_functions"] = 0
    save_checklist(tmp_path, checklist)
    index_path = tmp_path / "checklist" / "index.json"
    index = json.loads(index_path.read_text())
    (tmp_path / "checklist" / index["shards"][0]["path"]).write_bytes(b"tampered")
    from core.audit.binary_inventory_reporting import load_binary_inventory
    record = load_binary_inventory(tmp_path)
    assert record["mode"] == "unavailable"
    assert "selected_functions" not in record
    # Existing best-effort callers retain their previous partial-walk API.
    assert list(inventory.iter_checklist_items(tmp_path)) == []


def test_optional_inventory_metadata_error_cannot_fail_final_report(tmp_path, monkeypatch):
    from core.audit import binary_inventory_reporting

    def unreadable(_path):
        raise OSError("owned metadata read seam")

    monkeypatch.setattr(binary_inventory_reporting, "read_checklist_meta", unreadable)
    report = generate_report(tmp_path)
    assert report["binary_inventory"]["mode"] == "unavailable"
    assert report["findings_count"] == 0
