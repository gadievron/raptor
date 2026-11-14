"""Manifest identifiers consume the entire supplied string."""
from copy import deepcopy

import pytest

from core.recall import manifest as mod


def owned_manifest():
    entry = {"id": "owned-label", "file": "owned.c", "cwe": "CWE-79",
             "provenance": {"kind": "cve", "cve_id": "CVE-2026-1234", "fix_commit": "a" * 40}}
    return {"schema_version": mod.SCHEMA_VERSION, "name": "owned labels",
            "target": {"repo_url": "https://example.invalid/owned", "pinned_sha": "b" * 40,
                       "local_path": "owned-tree"},
            "language": "c", "profile": "scan-codeql", "expected": [entry],
            "clean_regions": [dict(deepcopy(entry), id="owned-clean")]}


@pytest.fixture(autouse=True)
def no_file_load(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("parsed-object test attempted file load")
    monkeypatch.setattr(mod, "load_manifest", forbidden)


@pytest.mark.parametrize("suffix", ["\n", "\ntrailing", " "], ids=["newline", "newline-tail", "space"])
@pytest.mark.parametrize("path,diagnostic", [
    (("target", "pinned_sha"), "target.pinned_sha"),
    (("expected", 0, "cwe"), "expected[0]: cwe"),
    (("clean_regions", 0, "cwe"), "clean_regions[0]: cwe"),
    (("expected", 0, "provenance", "cve_id"), "expected[0]: cve provenance needs a CVE id"),
    (("expected", 0, "provenance", "fix_commit"), "expected[0]: cve provenance needs a fix commit"),
], ids=["pinned-sha", "expected-cwe", "clean-cwe", "cve-id", "fix-sha"])
def test_identifier_suffix_is_refused(path, diagnostic, suffix):
    data = owned_manifest()
    holder = data
    for key in path[:-1]:
        holder = holder[key]
    holder[path[-1]] += suffix
    before = deepcopy(data)
    with pytest.raises(mod.ManifestError) as exc:
        mod.parse_manifest(data)
    assert diagnostic in str(exc.value)
    assert data == before


@pytest.mark.parametrize("length", [7, 40, 64], ids=["short", "git-sha1", "long"])
def test_existing_sha_lengths_and_pinned_case_normalization_are_preserved(length):
    data = owned_manifest()
    data["target"]["pinned_sha"] = "A" * length
    for row in [*data["expected"], *data["clean_regions"]]:
        row["provenance"]["fix_commit"] = "b" * length
    before = deepcopy(data)
    result = mod.parse_manifest(data)
    assert result.pinned_sha == "a" * length
    assert result.expected[0].provenance.fix_commit == "b" * length
    assert result.expected[0].cwe == "CWE-79"
    assert result.expected[0].provenance.cve_id == "CVE-2026-1234"
    assert data == before
