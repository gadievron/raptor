"""Root-qualified review dependencies require current explicit root mappings."""

from copy import deepcopy
import hashlib
import json

import pytest

from core.audit import review_context_inputs as inputs


def _digest(text=b"source"):
    return hashlib.sha256(text).hexdigest()


def _v1(file="unit.c", text=b"source"):
    return {"version": 1, "role": "review-context-inputs", "complete": True,
            "sources": [{"file": file, "sha256": _digest(text)}]}


def _v2(label="study", file="unit.c", text=b"source", *, complete=True):
    return inputs.context_inputs_from_sources(((label, file, _digest(text)),), complete=complete)


def test_v1_encoding_and_digest_are_preserved():
    value = _v1()
    expected = hashlib.sha256(json.dumps(value, ensure_ascii=True,
        separators=(",", ":"), sort_keys=True).encode()).hexdigest()
    assert inputs.merge_context_inputs(value, None, value) == value
    assert inputs.context_inputs_digest(value) == expected
    assert inputs.context_inputs_record_digest(value) == expected
    assert inputs.merge_context_inputs(None, None) is None
    assert inputs.context_inputs_record_digest(None) is None


def test_pipeline_rooted_sources_do_not_recapture_source_identities(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("manifest construction must not refresh captured sources")

    monkeypatch.setattr(inputs, "capture_source_identity", forbidden)
    value = _v2()
    assert value == {"version": 2, "role": "review-context-inputs", "complete": True,
                     "sources": [{"root": "study", "file": "unit.c", "sha256": _digest()}]}
    assert inputs.context_inputs_digest(value)


def test_v1_merge_promotes_to_v2_without_collapsing_distinct_roots():
    left, right = _v1(), _v2(text=b"other source")
    merged = inputs.merge_context_inputs(left, right)
    assert merged == inputs.merge_context_inputs(right, left)
    assert merged["version"] == 2 and merged["complete"] is True
    assert {(row["root"], row["file"], row["sha256"]) for row in merged["sources"]} == {
        ("target", "unit.c", _digest()), ("study", "unit.c", _digest(b"other source"))}
    assert inputs.context_inputs_digest(_v1()) != inputs.context_inputs_digest(_v2("target"))
    assert inputs.merge_context_inputs(_v2("target"), _v1())["version"] == 2


def test_same_filename_in_separate_roots_retains_both_bindings(tmp_path):
    target, study = tmp_path / "target", tmp_path / "study"
    target.mkdir()
    study.mkdir()
    (target / "unit.c").write_bytes(b"source")
    (study / "unit.c").write_bytes(b"other source")
    snapshot = inputs.merge_context_inputs(_v1(), _v2(text=b"other source"))
    assert inputs.context_inputs_current(snapshot, target, source_roots={"study": study}) == (True, "")
    assert inputs.context_inputs_current(snapshot, target)[0] is False
    (study / "unit.c").write_bytes(b"changed")
    assert inputs.context_inputs_current(snapshot, target, source_roots={"study": study})[0] is False
    assert inputs.context_inputs_current(_v1(), target)[0] is True


def test_explicit_root_relocation_admits_identical_bytes(tmp_path):
    target, first, relocated = (tmp_path / label for label in ("target", "first", "relocated"))
    for root in (target, first, relocated):
        root.mkdir()
    for root in (first, relocated):
        (root / "unit.c").write_bytes(b"source")
    snapshot = _v2()
    assert inputs.context_inputs_current(snapshot, target, source_roots={"study": first})[0]
    assert inputs.context_inputs_current(snapshot, target, source_roots={"study": relocated})[0]
    assert not inputs.context_inputs_current(snapshot, target)[0]


def test_current_mapping_cannot_replace_target_argument(tmp_path):
    target, other = tmp_path / "target", tmp_path / "other"
    target.mkdir()
    other.mkdir()
    (target / "unit.c").write_bytes(b"changed")
    (other / "unit.c").write_bytes(b"source")
    assert not inputs.context_inputs_current(_v2("target"), target,
                                             source_roots={"target": other})[0]
    assert not inputs.context_inputs_current(_v1(), None, source_roots={"target": other})[0]
    (target / "unit.c").write_bytes(b"source")
    assert inputs.context_inputs_current(_v2("target"), target,
                                         source_roots={"target": other})[0]


def test_unregistered_label_never_falls_back_to_target(tmp_path):
    (tmp_path / "unit.c").write_bytes(b"source")
    snapshot = _v2("registered_elsewhere")
    assert not inputs.context_inputs_current(snapshot, tmp_path, source_roots={"study": tmp_path})[0]
    assert inputs.context_inputs_current(snapshot, tmp_path,
                                         source_roots={"registered_elsewhere": tmp_path})[0]


@pytest.mark.parametrize("label", ["", "../study", "/study", "study/path", "study\\path", "space root",
                                  "x" * 65, "study\n", 3, None])
def test_malformed_root_labels_are_incomplete_and_never_reusable(tmp_path, label):
    snapshot = _v2(label)
    assert snapshot["version"] == 2 and snapshot["complete"] is False
    assert snapshot["sources"] == []
    assert inputs.context_inputs_digest(snapshot) is None
    assert inputs.context_inputs_record_digest(snapshot)
    assert not inputs.context_inputs_current(snapshot, tmp_path)[0]


def test_root_names_cannot_escape_registered_containment(tmp_path):
    target, study = tmp_path / "target", tmp_path / "study"
    target.mkdir()
    study.mkdir()
    (tmp_path / "outside.c").write_bytes(b"source")
    (study / "unit.c").symlink_to(tmp_path / "outside.c")
    assert not inputs.context_inputs_current(_v2(), target, source_roots={"study": study})[0]


def test_rooted_interval_barrier_rechecks_earlier_root(tmp_path, monkeypatch):
    target, study = tmp_path / "target", tmp_path / "study"
    target.mkdir()
    study.mkdir()
    (target / "a.c").write_bytes(b"source")
    (study / "b.c").write_bytes(b"source")
    snapshot = inputs.context_inputs_from_sources((
        ("target", "a.c", _digest()), ("study", "b.c", _digest())))
    # Sorted source labels put study before target; mutate study after target's
    # first observation to exercise the final whole-set interval barrier.
    original = inputs.capture_source_identity
    changed = False

    def read_then_change(root, file):
        nonlocal changed
        identity = original(root, file)
        if file == "a.c" and not changed:
            changed = True
            (study / "b.c").write_bytes(b"changed")
        return identity

    monkeypatch.setattr(inputs, "capture_source_identity", read_then_change)
    assert not inputs.context_inputs_current(snapshot, target, source_roots={"study": study})[0]
    assert changed


def test_conflicts_caps_and_unknowns_survive_merges():
    good = _v2()
    conflict = _v2(text=b"different")
    merged = inputs.merge_context_inputs(good, conflict)
    assert merged == inputs.merge_context_inputs(conflict, good)
    assert merged["complete"] is False and len(merged["sources"]) == 2
    assert inputs.context_inputs_digest(merged) is None
    assert inputs.context_inputs_record_digest(merged)
    assert inputs.merge_context_inputs(None, merged, _v1())["complete"] is False
    malformed = {**good, "role": "evidence"}
    assert inputs.merge_context_inputs(good, malformed)["complete"] is False
    assert inputs.context_inputs_record_digest(malformed) is None
    many = inputs.context_inputs_from_sources(("study", f"{n:03}.c", _digest()) for n in range(40))
    assert many["complete"] is False and len(many["sources"]) == 32
    assert inputs.context_inputs_record_digest(many)
    assert inputs.context_inputs_digest(many) is None
    large = inputs.context_inputs_from_sources(("r" * 64, f"{n:03}" + "x" * 505, _digest())
                                               for n in range(32))
    assert large["complete"] is False
    assert len(json.dumps(large, ensure_ascii=True, separators=(",", ":")).encode()) <= 16384
    assert inputs.context_inputs_record_digest(large)


def test_record_digest_identifies_incomplete_state_without_granting_reuse():
    complete = inputs.merge_context_inputs(_v2(), _v2("target", "primary.c"))
    incomplete = {**complete, "complete": False}
    assert inputs.context_inputs_record_digest(complete) == inputs.context_inputs_digest(complete)
    assert inputs.context_inputs_record_digest(incomplete)
    assert inputs.context_inputs_record_digest(incomplete) != inputs.context_inputs_record_digest(complete)
    assert inputs.context_inputs_digest(incomplete) is None
    reordered = {**incomplete, "sources": list(reversed(incomplete["sources"]))}
    assert inputs.context_inputs_record_digest(reordered) == inputs.context_inputs_record_digest(incomplete)
    duplicate = {**incomplete, "sources": incomplete["sources"] * 2}
    assert inputs.context_inputs_record_digest(duplicate) != inputs.context_inputs_record_digest(incomplete)


@pytest.mark.parametrize("mutate", [
    lambda value: value.update(version=True),
    lambda value: value.update(version=3),
    lambda value: value.update(complete=1),
    lambda value: value.update(extra="unrecognised"),
    lambda value: value.update(sources={}),
    lambda value: value["sources"][0].update(root="../study"),
    lambda value: value["sources"][0].update(extra="unrecognised"),
], ids=["boolean-version", "unknown-version", "nonboolean-complete", "extra-field",
        "nonlist-sources", "invalid-root-label", "extra-source-field"])
def test_invalid_raw_records_have_no_record_or_reusable_digest(tmp_path, mutate):
    value = deepcopy(_v2())
    mutate(value)
    assert inputs.context_inputs_record_digest(value) is None
    assert inputs.context_inputs_digest(value) is None
    assert not inputs.context_inputs_current(value, tmp_path)[0]
