"""Family matching requires a real JSON boolean, without truthiness coercion."""
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


@pytest.mark.parametrize("value", [None, 0, 1, -1, 0.0, 1.0, "false", "true", "", [], [False], {}, {"value": False}],
                         ids=["null", "zero", "one", "negative", "float-zero", "float-one", "false-text", "true-text",
                              "empty-text", "empty-array", "array", "empty-object", "object"])
def test_nonboolean_family_flag_is_refused(value):
    data = dict(owned_manifest(), tolerance={"cwe_family_match": value})
    before = deepcopy(data)
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert "tolerance.cwe_family_match must be a bool" in str(exc.value)
    assert data == before


@pytest.mark.parametrize("mode,expected", [("missing", True), (True, True), (False, False)],
                         ids=["default", "enabled", "disabled"])
def test_boolean_family_flag_and_default_are_preserved(mode, expected):
    data = owned_manifest()
    if mode != "missing":
        data["tolerance"] = {"cwe_family_match": mode}
    before = deepcopy(data)
    flag = mod.parse_manifest(data).tolerance.cwe_family_match
    assert flag is expected
    assert type(flag) is bool
    assert data == before


def test_flag_error_joins_other_tolerance_diagnostics():
    data = dict(owned_manifest(), tolerance={"line_drift": -1, "cwe_family_match": "false"})
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert "tolerance.line_drift" in str(exc.value)
    assert "tolerance.cwe_family_match" in str(exc.value)
