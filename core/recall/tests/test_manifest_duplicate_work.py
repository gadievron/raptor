"""Duplicate-id scans are bounded without a timing benchmark or large input."""
from copy import deepcopy
import json
import sys

import pytest

from core.recall import manifest as mod


def owned_manifest(ids):
    return {"schema_version": mod.SCHEMA_VERSION, "name": "owned labels",
            "target": {"repo_url": "https://example.invalid/owned", "pinned_sha": "a" * 40,
                       "local_path": "owned-tree"},
            "language": "c", "profile": "scan-codeql",
            "expected": [{"id": ident, "file": "owned.c", "cwe": "CWE-79",
                          "provenance": {"kind": "benchmark", "suite": "owned", "case": ident}}
                         for ident in ids]}


@pytest.fixture(autouse=True)
def no_file_load(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("parsed-object test attempted file load")
    monkeypatch.setattr(mod, "load_manifest", forbidden)


def test_unique_labels_do_not_repeat_full_id_scans():
    ids = [f"owned-{index:02d}" for index in range(32)]
    # Ensure real JSON-native objects, not comparison-counting string doubles.
    data = json.loads(json.dumps(owned_manifest(ids)))
    before = deepcopy(data)
    previous = sys.getprofile()
    if previous is not None:
        pytest.skip("profiling hook already owned")
    visited = 0

    def profile(frame, event, call):
        nonlocal visited
        if (event == "c_call" and frame.f_globals is vars(mod)
                and getattr(call, "__name__", None) == "count"
                and isinstance(getattr(call, "__self__", None), list)):
            # Native list.count scans every item, even for a unique ID.
            visited += len(call.__self__)
            if visited > 2 * len(ids):
                raise AssertionError("owned duplicate-id full-scan work budget exceeded")

    try:
        sys.setprofile(profile)
        result = mod.parse_manifest(data)
    finally:
        sys.setprofile(previous)
    assert sys.getprofile() is previous
    assert [entry.id for entry in result.expected] == ids
    assert visited <= 2 * len(ids)
    assert data == before


def test_duplicate_ids_keep_sorted_unique_diagnostic():
    data = owned_manifest(["owned-z", "owned-a", "owned-z", "owned-a", "owned-z"])
    before = deepcopy(data)
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert "duplicate expected ids: ['owned-a', 'owned-z']" in str(exc.value)
    assert data == before


def test_empty_ids_keep_missing_id_and_aggregate_errors():
    data = owned_manifest(["", ""])
    data["schema_version"] = 99
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert "schema_version" in str(exc.value)
    assert "expected[0]: missing id" in str(exc.value)
    assert "expected[1]: missing id" in str(exc.value)
    assert "duplicate expected ids" not in str(exc.value)
