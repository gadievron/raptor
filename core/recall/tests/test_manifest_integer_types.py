"""Integer measurement fields refuse booleans at parsed-object admission."""
from copy import deepcopy

import pytest

from core.recall import manifest as mod


def owned_manifest():
    entry = {"id": "owned-label", "file": "owned.c", "cwe": "CWE-79",
             "line_start": 1, "line_end": 2,
             "provenance": {"kind": "synthetic", "generator": "owned-fixture",
                            "case": "owned-case", "seed": 0}}
    return {"schema_version": mod.SCHEMA_VERSION, "name": "owned fixture",
            "target": {"repo_url": "https://example.invalid/owned",
                       "pinned_sha": "a" * 40, "local_path": "owned-tree"},
            "language": "c", "profile": "scan-codeql",
            "tolerance": {"line_drift": 0, "cwe_family_match": False},
            "expected": [entry], "clean_regions": [dict(deepcopy(entry), id="owned-clean")]}


@pytest.fixture(autouse=True)
def no_manifest_file_load(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("parsed-object test attempted manifest file load")
    monkeypatch.setattr(mod, "load_manifest", forbidden)


@pytest.mark.parametrize("value", [True, False], ids=["true", "false"])
@pytest.mark.parametrize("path,diagnostic", [
    (("expected", 0, "line_start"), "expected[0]: line_start"),
    (("expected", 0, "line_end"), "expected[0]: line_end"),
    (("expected", 0, "provenance", "seed"), "expected[0]: synthetic provenance seed"),
    (("clean_regions", 0, "line_start"), "clean_regions[0]: line_start"),
    (("clean_regions", 0, "line_end"), "clean_regions[0]: line_end"),
    (("clean_regions", 0, "provenance", "seed"), "clean_regions[0]: synthetic provenance seed"),
    (("tolerance", "line_drift"), "tolerance.line_drift"),
], ids=["expected-start", "expected-end", "expected-seed", "clean-start", "clean-end", "clean-seed", "drift"])
def test_boolean_measurement_integer_is_refused(path, diagnostic, value):
    data = owned_manifest()
    holder = data
    for key in path[:-1]:
        holder = holder[key]
    holder[path[-1]] = value
    before = deepcopy(data)
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert diagnostic in str(exc.value)
    assert data == before


@pytest.mark.parametrize("seed,drift,start,end", [(-1, 0, 1, 2), (0, 5, None, None), (7, 2, 4, 8)],
                         ids=["negative-seed-zero-drift", "nullable-lines", "positive-values"])
def test_actual_integer_and_null_contract_is_preserved(seed, drift, start, end):
    data = owned_manifest()
    data["tolerance"]["line_drift"] = drift
    for row in [*data["expected"], *data["clean_regions"]]:
        row["line_start"], row["line_end"] = start, end
        row["provenance"]["seed"] = seed
    before = deepcopy(data)
    result = mod.parse_manifest(data)
    assert result.tolerance.line_drift == drift
    assert result.tolerance.cwe_family_match is False
    for row in [*result.expected, *result.clean_regions]:
        assert (row.line_start, row.line_end, row.provenance.seed) == (start, end, seed)
        assert type(row.provenance.seed) is int
    assert data == before
