"""Line labels are ordered intervals or retain the existing nullable forms."""
from copy import deepcopy

import pytest

from core.recall import manifest as mod


def owned_manifest():
    entry = {"id": "owned-label", "file": "owned.c", "cwe": "CWE-79",
             "provenance": {"kind": "benchmark", "suite": "owned", "case": "owned"}}
    return {"schema_version": mod.SCHEMA_VERSION, "name": "owned labels",
            "target": {"repo_url": "https://example.invalid/owned", "pinned_sha": "a" * 40,
                       "local_path": "owned-tree"},
            "language": "c", "profile": "scan-codeql", "expected": [entry],
            "clean_regions": [dict(deepcopy(entry), id="owned-clean")]}


@pytest.fixture(autouse=True)
def no_file_load(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("parsed-object test attempted file load")
    monkeypatch.setattr(mod, "load_manifest", forbidden)


@pytest.mark.parametrize("slot", ["expected", "clean_regions"], ids=["expected", "clean"])
@pytest.mark.parametrize("start,end", [(5, 4), (8, 1), (2, 1)], ids=["adjacent", "wide", "first-line"])
def test_reversed_positive_interval_is_refused(slot, start, end):
    data = owned_manifest()
    data[slot][0].update(line_start=start, line_end=end)
    before = deepcopy(data)
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert f"{slot}[0]: line_end must be greater than or equal to line_start" in str(exc.value)
    assert data == before


@pytest.mark.parametrize("slot", ["expected", "clean_regions"], ids=["expected", "clean"])
@pytest.mark.parametrize("start,end", [(1, 1), (1, 4), (None, None), (4, None)],
                         ids=["point", "span", "file-level", "implicit-end"])
def test_valid_interval_and_nullable_forms_are_preserved(slot, start, end):
    data = owned_manifest()
    data[slot][0].update(line_start=start, line_end=end)
    before = deepcopy(data)
    result = mod.parse_manifest(data)
    row = getattr(result, slot)[0]
    assert (row.line_start, row.line_end) == (start, end)
    assert data == before


@pytest.mark.parametrize("slot", ["expected", "clean_regions"], ids=["expected", "clean"])
@pytest.mark.parametrize("start,end", [("4", 1), (4, "1"), (True, 1), (4, True), (0, 1), (4, 0), (None, 3)],
                         ids=["start-text", "end-text", "start-bool", "end-bool", "zero-start", "zero-end", "end-only"])
def test_invalid_coordinate_keeps_manifest_diagnostic(slot, start, end):
    data = owned_manifest()
    data[slot][0].update(line_start=start, line_end=end)
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert f"{slot}[0]: line_" in str(exc.value)
