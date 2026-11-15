"""Saved syntax reaches optional reports without becoming checker evidence."""
from dataclasses import replace
import json

import pytest

from core.audit import source_observation_sidecar as sidecar
from core.audit.member_copy_observation import ObservationUnavailable, observe_member_copy
from core.audit.report import generate_report
from core.audit.report_document import build_audit_document
from core.audit.tests.test_analysis_observation_reporting import _publish
from core.audit.tests.test_member_copy_observation import FIXTURES
from core.reporting.renderers import get_renderer


@pytest.fixture
def observed(tmp_path):
    root = tmp_path / "target"
    for file, source in FIXTURES.items():
        path = root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source)
    result = observe_member_copy(root)
    assert result.status == "source_bound_conditional_observation", result
    return result


@pytest.fixture
def output(tmp_path):
    out = tmp_path / "run"
    out.mkdir()
    return out


def _save(out, data):
    (out / sidecar.FILENAME).write_text(json.dumps(data))


def _read(out):
    return json.loads((out / sidecar.FILENAME).read_text())


def _render(report, out):
    _, document = build_audit_document(report, out)
    return get_renderer("markdown").render(document).content.decode()


def test_real_observation_roundtrip_reaches_report_without_verdict_or_count_changes(observed, output):
    _publish(output)
    before = generate_report(output)
    assert "source_syntax_observations" not in before
    sidecar.write_source_syntax_observation(output, observed)
    saved = sidecar.load_saved_source_syntax(output)
    assert saved["mode"] == "saved"
    assert saved["authority"] is False and saved["source_verified"] is False
    assert saved["producer_authenticated"] is False and saved["history_complete"] is False
    assert saved["source_freshness"] == "unavailable"
    assert saved["unresolved"] == list(sidecar.REQUIRED_LIMITS)
    assert saved["recorded_files"] == 3 and saved["recorded_spans"] == 13
    after = generate_report(output)
    assert after["findings"] == before["findings"]
    assert after["analysis_observations"] == before["analysis_observations"]
    assert after["source_syntax_observations"] == saved
    markdown = _render(after, output)
    assert "Saved conditional source syntax" in markdown
    assert "not a verified defect" in markdown
    assert "does not change findings, verdicts, checker counts" in markdown
    for label in ("Preprocessing and system headers", "Fixed-width type definitions",
                  "ABI, size_t and header layout", "Allocator and copy-function bindings",
                  "External object validity and aliasing", "Successful allocation",
                  "A coherent build snapshot", "Claim-mechanism verification"):
        assert label in markdown


def test_absent_sidecar_is_omitted_and_never_invokes_observer(output, monkeypatch):
    import core.audit.member_copy_observation as producer
    monkeypatch.setattr(producer, "observe_member_copy", lambda *a, **k: pytest.fail("report must not invoke observer"))
    assert sidecar.load_saved_source_syntax(output) is None
    report = generate_report(output)
    assert "source_syntax_observations" not in report
    assert "Saved conditional source syntax" not in _render(report, output)
    assert "Saved source syntax unavailable" not in _render(report, output)


def test_refusal_roundtrip_remains_unavailable(output):
    sidecar.write_source_syntax_observation(output, ObservationUnavailable("parser-unavailable"))
    saved = sidecar.load_saved_source_syntax(output)
    assert saved["mode"] == "unavailable" and saved["saved_refusal"] is True
    markdown = _render(generate_report(output), output)
    assert "Saved source syntax unavailable" in markdown
    assert "does not establish that no analysis ran" in markdown


@pytest.mark.parametrize("change", [
    "top_true", "top_integer", "top_schema_bool", "top_schema_unknown", "top_contract", "top_role",
    "top_history", "top_extra", "row_true", "row_integer", "row_contract", "row_status", "row_extra",
    "role_file", "past_size", "duplicate_role", "outside_caller", "outside_callee", "order",
    "unit_order", "unit_size", "unit_version_bool", "unit_hash", "span_hash", "span_bool",
    "types", "argument_roles", "missing_limit", "duplicate_limit", "claim_cwe", "claim_ref",
])
def test_malformed_saved_data_is_unavailable(observed, output, change):
    sidecar.write_source_syntax_observation(output, observed)
    data = _read(output)
    row = data["record"]
    spans = {span["role"]: span for span in row["spans"]}
    if change == "top_true": data["authority"] = True
    elif change == "top_integer": data["source_verified"] = 0
    elif change == "top_schema_bool": data["schema_version"] = True
    elif change == "top_schema_unknown": data["schema_version"] = 2
    elif change == "top_contract": data["contract"] = "other"
    elif change == "top_role": data["role"] = "verified"
    elif change == "top_history": data["history_complete"] = True
    elif change == "top_extra": data["verified"] = True
    elif change == "row_true": row["authority"] = True
    elif change == "row_integer": row["source_verified"] = 0
    elif change == "row_contract": row["contract"] = "other"
    elif change == "row_status": row["status"] = "confirmed"
    elif change == "row_extra": row["verified"] = True
    elif change == "role_file": spans["copy"]["file"] = "protocol/parser.c"
    elif change == "past_size": spans["prototype"]["end_byte"] = row["source_units"][2][1]["version"][2] + 1
    elif change == "duplicate_role": row["spans"][-1] = dict(row["spans"][-2])
    elif change == "outside_caller": spans["member_assignment"]["start_byte"] = 0
    elif change == "outside_callee": spans["copy"]["end_byte"] = spans["callee"]["end_byte"] + 1
    elif change == "order":
        a, b = spans["allocation"], spans["copy"]
        a["start_byte"], b["start_byte"] = b["start_byte"], a["start_byte"]
        a["end_byte"], b["end_byte"] = b["end_byte"], a["end_byte"]
    elif change == "unit_order": row["source_units"].reverse()
    elif change == "unit_size": row["source_units"][0][1]["version"][2] = 32769
    elif change == "unit_version_bool": row["source_units"][0][1]["version"][0] = True
    elif change == "unit_hash": row["source_units"][0][1]["sha256"] = "x" * 64
    elif change == "span_hash": row["spans"][0]["sha256"] = "x" * 64
    elif change == "span_bool": row["spans"][0]["start_byte"] = False
    elif change == "types": row["member_type_spellings"] = ["uint32_t", "uint32_t"]
    elif change == "argument_roles": row["argument_roles"].reverse()
    elif change == "missing_limit": row["unresolved"].pop()
    elif change == "duplicate_limit": row["unresolved"][0] = row["unresolved"][1]
    elif change == "claim_cwe": row["declared_cwe"] = "CWE-190"
    elif change == "claim_ref": row["claim_reference"] = ["0" * 32, "1" * 32]
    _save(output, data)
    saved = sidecar.load_saved_source_syntax(output)
    assert saved["mode"] == "unavailable"
    assert "recorded_spans" not in saved
    assert "Saved conditional source syntax" not in _render(generate_report(output), output)


def test_no_clobber_and_final_symlink_do_not_change_other_files(output):
    other = output / "other.json"
    other.write_text("unchanged")
    destination = output / sidecar.FILENAME
    destination.symlink_to(other.name)
    with pytest.raises((OSError, ValueError)):
        sidecar.write_source_syntax_observation(output, ObservationUnavailable("parser-unavailable"))
    assert other.read_text() == "unchanged"
    assert destination.is_symlink()
    assert sidecar.load_saved_source_syntax(output)["mode"] == "unavailable"
    destination.unlink()
    sidecar.write_source_syntax_observation(output, ObservationUnavailable("parser-unavailable"))
    before = destination.read_bytes()
    with pytest.raises(FileExistsError):
        sidecar.write_source_syntax_observation(output, ObservationUnavailable("source-changed"))
    assert destination.read_bytes() == before


@pytest.mark.parametrize("raw", [
    '{"authority":false,"authority":true}', '{"value":NaN}', ' ' * 32769,
    '{', '[' * 1500 + ']' * 1500,
])
def test_invalid_json_is_unavailable(output, raw):
    (output / sidecar.FILENAME).write_text(raw)
    assert sidecar.load_saved_source_syntax(output)["mode"] == "unavailable"


def test_nonregular_sidecar_is_unavailable(output):
    (output / sidecar.FILENAME).mkdir()
    assert sidecar.load_saved_source_syntax(output)["mode"] == "unavailable"


def test_hostile_nested_descriptor_rejected_before_serialization(observed, output):
    class Hostile:
        def __deepcopy__(self, memo):
            pytest.fail("must not deepcopy arbitrary descriptor objects")
        def __str__(self):
            pytest.fail("must not stringify arbitrary descriptor objects")
        def __eq__(self, other):
            pytest.fail("must not compare arbitrary descriptor objects")
    forged = replace(observed, member_type_spellings=(Hostile(), "uint16_t"))
    with pytest.raises(ValueError):
        sidecar.write_source_syntax_observation(output, forged)
    forged = replace(observed)
    object.__setattr__(forged, "unresolved", (Hostile(), *observed.unresolved[1:]))
    with pytest.raises(ValueError):
        sidecar.write_source_syntax_observation(output, forged)
    with pytest.raises(TypeError):
        sidecar.write_source_syntax_observation(output, {"authority": False})
    assert not (output / sidecar.FILENAME).exists()


def test_ordinary_reader_failure_isolated_but_cancellation_propagates(observed, output, monkeypatch):
    _publish(output)
    sidecar.write_source_syntax_observation(output, observed)
    def fail(*a, **k):
        raise MemoryError("owned optional reader")
    monkeypatch.setattr(sidecar, "loads", fail)
    report = generate_report(output)
    assert report["source_syntax_observations"]["mode"] == "unavailable"
    assert report["findings"][0]["status"] == "suspicious"
    def cancel(*a, **k):
        raise KeyboardInterrupt("owned optional reader cancellation")
    monkeypatch.setattr(sidecar, "loads", cancel)
    with pytest.raises(KeyboardInterrupt):
        generate_report(output)


def test_ordinary_render_failure_isolated_but_cancellation_propagates(observed, output, monkeypatch):
    _publish(output)
    sidecar.write_source_syntax_observation(output, observed)
    report = generate_report(output)
    def fail(*a, **k):
        raise MemoryError("owned optional renderer")
    monkeypatch.setattr(sidecar, "source_syntax_blocks", fail)
    markdown = _render(report, output)
    assert "Saved source syntax unavailable" in markdown
    assert report["findings"][0]["status"] == "suspicious"
    def cancel(*a, **k):
        raise KeyboardInterrupt("owned optional renderer cancellation")
    monkeypatch.setattr(sidecar, "source_syntax_blocks", cancel)
    with pytest.raises(KeyboardInterrupt):
        _render(report, output)


def test_renderer_does_not_display_forged_saved_projection():
    blocks = sidecar.source_syntax_blocks({"source_syntax_observations": {
        "mode": "saved", "authority": True, "recorded_files": "<script>"
    }})
    assert len(blocks) == 1 and blocks[0].title == "Saved source syntax unavailable"
