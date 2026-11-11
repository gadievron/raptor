"""Bounded pass references describe recorded delivery, never assessment basis."""
import copy
import json

import pytest

from core.audit.knowledge_reporting import knowledge_processing_lines, load_knowledge_processing
from core.audit.tests.test_knowledge_reporting import _captured


def _record(out):
    path, payload = _captured(out)
    origin = {"file": "owned.c", "function": "f", "line_start": 1,
              "source_identity": None}
    payload["events"].insert(0, {"event": "continuation_reserved", "pass_id": "completed-pass",
                                 "origin": origin, "delta_ids": ["delivered", "context:late_joern:frozen"],
                                 "pending_ids": []})
    payload["events"].extend([
        {"event": "context_delta_offered", "origin": origin, "context_id": "context:late_joern:" + version,
         "kind": "late_joern", "version": version}
        for version in ("frozen", "later")
    ])
    payload["events"].append({"event": "review_prompt_context", "pass_id": "completed-pass", "records": [
        {"field": "source_study_delivery", "request_id": "delivered", "delivered": True},
        {"field": "external_context_delivery", "context_id": "context:late_joern:frozen",
         "kind": "late_joern", "version": "frozen", "delivered": True},
    ]})
    payload["events"][1]["delivered_request_ids"].append("context:late_joern:frozen")
    payload["units"][0]["cycle"]["delta_ids"].append("context:late_joern:later")
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path, payload


def test_completed_snapshot_index_excludes_late_pending_and_latest_answers(tmp_path):
    path, payload = _record(tmp_path)
    payload["requests"][0]["processing"]["latest_answer_version"] = "PRIVATE_NEW_ANSWER"
    path.write_text(json.dumps(payload), encoding="utf-8")
    before = path.read_bytes()
    result = load_knowledge_processing(tmp_path)
    row, = result["completed_passes"]
    assert row["pass_id"] == "completed-pass" and row["unit"] == ["owned.c", "f", 1]
    assert row["recorded_published_status"] == "clean"
    assert row["delivered_request_ids"] == ["delivered"]
    assert row["delivered_external_contexts"] == [{"context_id": "context:late_joern:frozen",
                                                 "kind": "late_joern", "version": "frozen"}]
    assert result["pending_delivery_context_updates"] == 1
    assert "PRIVATE_NEW_ANSWER" not in json.dumps(row)
    assert "assessment_basis" not in row and "assurance" not in row
    text = "\n".join(knowledge_processing_lines({"knowledge_processing": result}))
    assert "completed-pass" in text and "provenance only" in text
    assert "context:late_joern:later" not in text
    assert path.read_bytes() == before


@pytest.mark.parametrize("conflict", ["reservation", "completion"])
def test_conflicting_pass_snapshot_is_not_merged(tmp_path, conflict):
    path, payload = _record(tmp_path)
    event = copy.deepcopy(payload["events"][0 if conflict == "reservation" else 1])
    if conflict == "reservation":
        event["origin"]["source_identity"] = {"sha256": "different-snapshot"}
    else:
        event["published_status"] = "suspicious"
    payload["events"].append(event)
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = load_knowledge_processing(tmp_path)
    row, = result["completed_passes"]
    assert result["state"] == "recorded" and result["delivered_context_updates"] == 1
    assert row["state"] == "unavailable" and row["unit"] is None
    assert row["delivered_external_contexts"] is None


@pytest.mark.parametrize("missing", ["origin", "receipt", "fit_conflict", "offer_conflict", "wrong_request_fit"])
def test_missing_or_ambiguous_binding_is_unavailable(tmp_path, missing):
    path, payload = _record(tmp_path)
    if missing == "origin":
        payload["events"].pop(0)
        # Request-only completion keeps the existing aggregate reader valid.
        payload["events"][0]["delivered_request_ids"] = ["delivered"]
    elif missing == "receipt":
        payload["events"][-1]["records"] = []
        payload["events"][1]["delivered_request_ids"] = ["delivered"]
    elif missing == "fit_conflict":
        event = copy.deepcopy(payload["events"][-1])
        event["records"][1]["delivered"] = False
        payload["events"].append(event)
    elif missing == "offer_conflict":
        event = copy.deepcopy(payload["events"][2])
        event["origin"]["source_identity"] = {"sha256": "other-offered-snapshot"}
        payload["events"].append(event)
    else:
        payload["events"][-1]["records"][0].update(field="external_context_delivery", context_id="delivered")
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = load_knowledge_processing(tmp_path)
    row, = result["completed_passes"]
    assert row["state"] != "recorded" and row["limitations"]
    if missing in {"origin", "fit_conflict", "offer_conflict"}:
        assert row["delivered_external_contexts"] is None
    else:
        assert row["delivered_request_ids"] is None


def test_identical_repeated_records_are_not_new_passes(tmp_path):
    path, payload = _record(tmp_path)
    payload["events"].extend(copy.deepcopy(payload["events"]))
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = load_knowledge_processing(tmp_path)
    assert result["completed_pass_count"] == 1
    assert result["completed_passes"][0]["state"] == "recorded"


def test_unfinished_fitted_pass_is_not_a_completed_snapshot(tmp_path):
    path, payload = _record(tmp_path)
    payload["events"].pop(1)
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = load_knowledge_processing(tmp_path)
    assert result["completed_pass_count"] == 0 and result["completed_passes"] == []


def test_index_caps_and_rendered_id_escaping(tmp_path):
    path, payload = _record(tmp_path)
    hostile = "pass`|\n\x1b[31m<img src=x>"
    reserve, complete, receipt = payload["events"][0], payload["events"][1], payload["events"][-1]
    for event in (reserve, complete, receipt):
        event["pass_id"] = hostile
    for n in range(25):
        for event in (reserve, complete, receipt):
            clone = copy.deepcopy(event)
            clone["pass_id"] = f"pass-{n}"
            payload["events"].append(clone)
    path.write_text(json.dumps(payload), encoding="utf-8")
    result = load_knowledge_processing(tmp_path)
    assert len(result["completed_passes"]) == 20 and result["completed_passes_omitted"] == 6
    lines = knowledge_processing_lines({"knowledge_processing": result})
    assert all(len(line) <= 1700 and "\x1b" not in line and "\n" not in line for line in lines)
    assert hostile not in "\n".join(lines) and "<img" not in "\n".join(lines)
    assert any("6" in line and "omitted" in line for line in lines)


def test_identity_cap_and_legacy_completion_without_origin(tmp_path):
    path, payload = _captured(tmp_path)
    result = load_knowledge_processing(tmp_path)
    assert result["completed_passes"][0]["unit"] is None
    path, payload = _record(tmp_path)
    names = [f"request-{n}" for n in range(25)]
    request = payload["requests"][0]
    payload["requests"] += [{**copy.deepcopy(request), "request_id": name} for name in names]
    payload["events"][1]["delivered_request_ids"] += names
    payload["events"][-1]["records"] += [{"field": "source_study_delivery", "request_id": name,
                                          "delivered": True} for name in names]
    path.write_text(json.dumps(payload), encoding="utf-8")
    row, = load_knowledge_processing(tmp_path)["completed_passes"]
    assert len(row["delivered_request_ids"]) + len(row["delivered_external_contexts"]) == 20
    assert row["identities_omitted"] == 7
