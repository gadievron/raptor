"""JSON booleans are not numeric manifest schema versions."""
from copy import deepcopy

import pytest

from core.recall import manifest as mod


def owned_manifest(version):
    return {"schema_version": version, "name": "owned labels",
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


@pytest.mark.parametrize("version", [True, False], ids=["true", "false"])
def test_boolean_schema_version_is_refused(version):
    data = owned_manifest(version)
    before = deepcopy(data)
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert f"schema_version must be {mod.SCHEMA_VERSION}" in str(exc.value)
    assert data == before


@pytest.mark.parametrize("version", [mod.SCHEMA_VERSION, float(mod.SCHEMA_VERSION)], ids=["integer", "equivalent-number"])
def test_existing_numeric_version_equality_is_preserved(version):
    data = owned_manifest(version)
    before = deepcopy(data)
    assert mod.parse_manifest(data).name == "owned labels"
    assert data == before


def test_boolean_version_error_joins_other_diagnostics():
    data = owned_manifest(True)
    data["profile"] = "owned-invalid"
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert "schema_version" in str(exc.value)
    assert "profile" in str(exc.value)
