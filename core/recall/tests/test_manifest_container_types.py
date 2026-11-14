"""Malformed manifest containers join aggregate validation diagnostics."""
from copy import deepcopy

import pytest

from core.recall import manifest as mod


def owned_manifest():
    return {"schema_version": mod.SCHEMA_VERSION, "name": "owned labels",
            "target": {"repo_url": "https://example.invalid/owned", "pinned_sha": "a" * 40,
                       "local_path": "owned-tree"},
            "language": "c", "profile": "scan-codeql",
            "expected": [{"id": "owned-label", "file": "owned.c", "cwe": "CWE-79",
                          "provenance": {"kind": "benchmark", "suite": "owned", "case": "owned"}}]}


@pytest.fixture(autouse=True)
def no_file_load(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("parsed-object test attempted file load")
    monkeypatch.setattr(mod, "load_manifest", forbidden)


@pytest.mark.parametrize("value", [[1], [], "invalid", "", 1, 0, True, False],
                         ids=["array", "empty-array", "text", "empty-text", "integer", "zero", "true", "false"])
def test_tolerance_requires_object(value):
    data = dict(owned_manifest(), tolerance=value)
    before = deepcopy(data)
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert "tolerance must be an object" in str(exc.value)
    assert data == before


@pytest.mark.parametrize("value", [{"wrong": "shape"}, {}, "invalid", "", 1, 0, True, False],
                         ids=["object", "empty-object", "text", "empty-text", "integer", "zero", "true", "false"])
def test_clean_regions_requires_list(value):
    data = dict(owned_manifest(), clean_regions=value)
    before = deepcopy(data)
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert "clean_regions must be a list" in str(exc.value)
    assert data == before


@pytest.mark.parametrize("mode", ["missing", "null", "empty"], ids=["missing", "null", "empty"])
def test_optional_container_defaults_are_preserved(mode):
    data = owned_manifest()
    if mode == "null":
        data.update(tolerance=None, clean_regions=None)
    elif mode == "empty":
        data.update(tolerance={}, clean_regions=[])
    before = deepcopy(data)
    result = mod.parse_manifest(data)
    assert result.tolerance.line_drift == mod.DEFAULT_LINE_DRIFT
    assert result.tolerance.cwe_family_match is True
    assert result.clean_regions == []
    assert data == before


def test_container_errors_are_aggregated_with_existing_errors():
    data = dict(owned_manifest(), schema_version=99, tolerance=[1], clean_regions=7)
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    message = str(exc.value)
    assert "schema_version" in message
    assert "tolerance must be an object" in message
    assert "clean_regions must be a list" in message
