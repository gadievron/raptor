"""Non-string JSON fields produce aggregate manifest diagnostics."""
from copy import deepcopy

import pytest

from core.recall import manifest as mod

BAD_VALUES = [pytest.param(["invalid"], id="array"), pytest.param({"invalid": "shape"}, id="object"),
              pytest.param(7, id="integer"), pytest.param(True, id="boolean")]


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


@pytest.mark.parametrize("value", BAD_VALUES)
@pytest.mark.parametrize("path,diagnostic", [
    (("name",), "name"), (("language",), "language"), (("profile",), "profile"),
    (("target", "repo_url"), "target.repo_url"),
    (("target", "pinned_sha"), "target.pinned_sha"),
    (("target", "local_path"), "target.local_path"),
    (("build_command",), "build_command"),
    (("expected", 0, "id"), "expected[0]: missing id"),
    (("expected", 0, "file"), "expected[0]: file"),
    (("expected", 0, "cwe"), "expected[0]: cwe"),
    (("clean_regions", 0, "id"), "clean_regions[0]: missing id"),
    (("clean_regions", 0, "file"), "clean_regions[0]: file"),
    (("clean_regions", 0, "cwe"), "clean_regions[0]: cwe"),
], ids=["name", "language", "profile", "repo-url", "sha", "local-path", "build-command",
        "expected-id", "expected-file", "expected-cwe", "clean-id", "clean-file", "clean-cwe"])
def test_nonstring_manifest_field_is_diagnosed(path, diagnostic, value):
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


@pytest.mark.parametrize("value", BAD_VALUES)
@pytest.mark.parametrize("kind,key,diagnostic", [
    ("benchmark", "suite", "benchmark provenance needs suite and case"),
    ("benchmark", "case", "benchmark provenance needs suite and case"),
    ("cve", "cve_id", "cve provenance needs a CVE id"),
    ("cve", "fix_commit", "cve provenance needs a fix commit"),
    ("synthetic", "generator", "synthetic provenance needs generator and case"),
    ("synthetic", "case", "synthetic provenance needs generator and case"),
], ids=["benchmark-suite", "benchmark-case", "cve-id", "fix-sha", "generator", "synthetic-case"])
def test_nonstring_provenance_field_is_diagnosed(kind, key, diagnostic, value):
    data = owned_manifest()
    provenance = {"kind": kind, "suite": "owned", "case": "owned", "cve_id": "CVE-2026-1234",
                  "fix_commit": "b" * 40, "generator": "owned"}
    provenance[key] = value
    data["expected"][0]["provenance"] = provenance
    before = deepcopy(data)
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert diagnostic in str(exc.value)
    assert data == before


@pytest.mark.parametrize("command", [None, "", "owned-command"], ids=["null", "empty", "text"])
def test_optional_string_build_command_is_preserved(command):
    data = dict(owned_manifest(), build_command=command)
    before = deepcopy(data)
    assert mod.parse_manifest(data).build_command == command
    assert data == before


def test_shape_errors_do_not_prevent_aggregate_diagnostics():
    data = owned_manifest()
    data["target"]["pinned_sha"] = ["invalid"]
    data["profile"] = {"invalid": "shape"}
    data["expected"][0].update(id=["invalid"], file=7, cwe=True)
    data["clean_regions"][0]["provenance"] = {"kind": "cve", "cve_id": 7, "fix_commit": []}
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    message = str(exc.value)
    for field in ("target.pinned_sha", "profile", "expected[0]: missing id", "expected[0]: file",
                  "expected[0]: cwe", "clean_regions[0]: cve provenance"):
        assert field in message
