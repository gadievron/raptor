"""Native identities require a validated source and actual same-layer bytes."""
from copy import deepcopy

import pytest

from core.oci.file_ownership import match_native_identities

SHA = "a" * 64
LAYER = "layer"


def entry(path, sha=SHA, layer=LAYER):
    return {"location": {"path": path, "layerID": layer}, "metadata": {"type": "RegularFile"},
            "digests": [{"algorithm": "sha256", "value": sha}]}


def fixture():
    native = {"files": [entry("/usr/local/bin/git"), entry("/different/location/alias")]}
    candidates = [{"path": "/different/location/alias", "layer_id": LAYER}]
    identities = [{"name": "git", "version": "2.56.0", "anchor_path": "/usr/local/bin/git",
                   "sha256": SHA, "layer_id": LAYER, "evidence_path": "/doc/NOTICE-PROVENANCE.json",
                   "evidence_sha256": "b" * 64}]
    return native, candidates, identities


def test_identical_alias_matches_by_bytes_independently_of_filename():
    native, candidates, identities = fixture()
    resolved, pending = match_native_identities(native, candidates, identities)
    assert not pending and len(resolved) == 1
    assert resolved[0]["identity"]["name"] == "git"
    assert resolved[0]["sha256"] == SHA
    assert resolved[0]["identity"]["evidence_sha256"] == "b" * 64


@pytest.mark.parametrize("change", ["changed_alias", "changed_anchor", "missing_anchor", "other_layer",
                                    "ambiguous_identity", "duplicate_anchor", "no_hash", "no_source_digest",
                                    "symlink_cycle", "missing_link_target", "non_regular_alias"])
def test_unverified_or_ambiguous_identity_never_hides_candidate(change):
    native, candidates, identities = fixture()
    if change == "changed_alias":
        native["files"][1]["digests"][0]["value"] = "c" * 64
    elif change == "changed_anchor":
        native["files"][0]["digests"][0]["value"] = "c" * 64
    elif change == "missing_anchor":
        del native["files"][0]
    elif change == "other_layer":
        candidates[0]["layer_id"] = "other"
        native["files"][1]["location"]["layerID"] = "other"
    elif change == "ambiguous_identity":
        other = deepcopy(identities[0])
        other["name"] = "different-project"
        identities.append(other)
    elif change == "duplicate_anchor":
        native["files"].append(deepcopy(native["files"][0]))
    elif change == "no_hash":
        del native["files"][1]["digests"]
    elif change == "no_source_digest":
        identities[0]["evidence_sha256"] = None
    elif change in {"symlink_cycle", "missing_link_target"}:
        native["files"][0]["metadata"] = {"type": "SymbolicLink", "linkDestination": "git" if change == "symlink_cycle" else "absent"}
    else:
        native["files"][1]["metadata"] = {"type": "SymbolicLink", "linkDestination": "/usr/local/bin/git"}
    resolved, pending = match_native_identities(native, candidates, identities)
    assert not resolved and len(pending) == 1


def test_primary_symlink_is_resolved_only_using_same_layer_catalogue():
    native, candidates, identities = fixture()
    native["files"].append(entry("/usr/local/bin/git-real"))
    native["files"][0]["metadata"] = {"type": "SymbolicLink", "linkDestination": "git-real"}
    resolved, pending = match_native_identities(native, candidates, identities)
    assert not pending
    assert resolved[0]["identity"]["resolved_anchor_path"] == "/usr/local/bin/git-real"
    native["files"][-1]["location"]["layerID"] = "different"
    assert not match_native_identities(native, candidates, identities)[0]


def declaration_fixture():
    native, candidates, identities = fixture()
    native["files"][1]["digests"][0]["value"] = "e" * 64
    native["files"].extend([entry("/usr/lib/python/Makefile", "c" * 64), entry("/usr/include/python/patchlevel.h", "d" * 64)])
    identities[0]["name"] = "cpython"
    identities[0]["installed_metadata"] = [{"image_path": "/usr/lib/python/Makefile", "sha256": "c" * 64},
                                            {"image_path": "/usr/include/python/patchlevel.h", "sha256": "d" * 64}]
    identities[0]["declared_files"] = [{"path": candidates[0]["path"], "sha256": "e" * 64,
                                         "basis": "cpython_installed_module_build_inventory", "metadata_sha256": ["c" * 64, "d" * 64]}]
    return native, candidates, identities


def test_build_declarations_are_separate_from_native_alias_proofs():
    from core.oci.file_ownership import match_native_declarations
    native, candidates, identities = declaration_fixture()
    assert not match_native_identities(native, candidates, identities)[0]
    resolved, pending = match_native_declarations(native, candidates, identities)
    assert not pending and resolved[0]["evidence_kind"] == "installed_build_declaration"


@pytest.mark.parametrize("change", ["payload", "metadata", "missing_metadata", "layer", "unknown_basis", "ambiguous"])
def test_build_claims_fail_closed_on_changed_or_incomplete_evidence(change):
    from core.oci.file_ownership import match_native_declarations
    native, candidates, identities = declaration_fixture()
    if change == "payload":
        native["files"][1]["digests"][0]["value"] = "f" * 64
    elif change == "metadata":
        native["files"][2]["digests"][0]["value"] = "f" * 64
    elif change == "missing_metadata":
        identities[0]["installed_metadata"] = []
    elif change == "layer":
        native["files"][2]["location"]["layerID"] = "different"
    elif change == "unknown_basis":
        identities[0]["declared_files"][0]["basis"] = "directory_name_guess"
    else:
        other = deepcopy(identities[0])
        other["name"] = "other"
        identities.append(other)
    resolved, pending = match_native_declarations(native, candidates, identities)
    assert not resolved and len(pending) == 1


def test_version_signatures_require_retained_release_target_definition():
    from core.oci.file_ownership import match_native_declarations
    native, candidates, identities = declaration_fixture()
    claim = identities[0]["declared_files"][0]
    claim.update(basis="git_release_target_and_elf_version", metadata_sha256=[])
    assert not match_native_declarations(native, candidates, identities)[0]
    claim["source_definition_sha256"] = ["f" * 64]
    identities[0]["source_definitions"] = ["f" * 64]
    resolved, pending = match_native_declarations(native, candidates, identities)
    assert not pending and resolved[0]["evidence_kind"] == "release_target_and_version"
