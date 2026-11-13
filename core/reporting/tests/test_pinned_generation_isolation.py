"""Explicit historical reads do not depend on mutable compatibility views."""
import pytest

from core.reporting.adapters import native_findings
from core.reporting.builders import build_document
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.writer import load_committed_report, load_report_generation, publish_report


def _context(message):
    return ReportContext("fixture", "saved", target="owned", state="completed",
                         findings=native_findings([{"id": "F", "file": "a.c", "line": 1,
                                                    "message": message}],
                                                  run_id="saved", producer="fixture", triage=True))


def _tree(directory):
    return {path.relative_to(directory): None if path.is_dir() else path.read_bytes()
            for path in directory.rglob("*")}


@pytest.mark.parametrize("damage", ["mirrors", "current-pointer"])
def test_pinned_generation_survives_damage_to_mutable_views(tmp_path, damage):
    options = ReportOptions(formats=("json", "markdown"))
    first, second = _context("first retained observation"), _context("second selected observation")
    first_document, second_document = build_document(first), build_document(second)
    old = publish_report(first, first_document, tmp_path, options=options)
    current = publish_report(second, second_document, tmp_path, options=options)
    assert old.committed and current.committed and old.generation != current.generation
    assert load_committed_report(tmp_path)[0].to_dict() == second.to_dict()
    immutable = _tree(tmp_path / ".reporting")
    if damage == "mirrors":
        for name in ("report-context.json", "report-document.json", "report.json", "report.md"):
            (tmp_path / name).write_bytes(b"unreadable compatibility fixture")
        assert load_committed_report(tmp_path)[0].to_dict() == second.to_dict()
    else:
        (tmp_path / "reporting-manifest.json").write_bytes(b"not JSON")
        with pytest.raises(ValueError):
            load_committed_report(tmp_path)
    before_read = _tree(tmp_path)
    restored, document, manifest = load_report_generation(tmp_path, old.generation, first.snapshot_id)
    assert restored.to_dict() == first.to_dict()
    assert document.to_dict() == first_document.to_dict()
    assert manifest == {"generation": old.generation, "snapshot_id": first.snapshot_id}
    assert restored.findings[0]["status"] == "Unconfirmed"
    with pytest.raises(ValueError, match="digest mismatch"):
        load_report_generation(tmp_path, old.generation, second.snapshot_id)
    assert _tree(tmp_path) == before_read
    assert _tree(tmp_path / ".reporting") == immutable
