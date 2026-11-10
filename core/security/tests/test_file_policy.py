"""Explicit permission constraints remain distinct from file I/O failures."""

import os

import pytest

from core.security.file_policy import FilePermissionRefused, validate_file_permissions


@pytest.mark.parametrize("mode,mask,refused", [
    (0o600, 0o077, False), (0o640, 0o077, True),
    (0o604, 0o077, True), (0o644, 0o022, False),
    (0o620, 0o022, True), (0o602, 0o022, True),
    (0o700, 0o077, False), (0o666, 0, False),
])
def test_permission_masks_are_caller_policy(tmp_path, mode, mask, refused):
    path = tmp_path / "file"
    path.write_bytes(b"data")
    path.chmod(mode)
    metadata = path.stat()
    if refused:
        with pytest.raises(FilePermissionRefused) as error:
            validate_file_permissions(metadata, forbidden_mode_bits=mask)
        assert error.value.reason == "mode"
        assert error.value.metadata is metadata
        assert not isinstance(error.value, OSError)
    else:
        validate_file_permissions(metadata, forbidden_mode_bits=mask)


def test_owner_constraint_is_explicit(tmp_path):
    path = tmp_path / "file"
    path.touch()
    metadata = path.stat()
    validate_file_permissions(metadata)
    validate_file_permissions(metadata, owner_uid=metadata.st_uid)
    with pytest.raises(FilePermissionRefused) as error:
        validate_file_permissions(metadata, owner_uid=metadata.st_uid + 1)
    assert error.value.reason == "owner"
    assert error.value.metadata is metadata


def test_single_link_constraint_is_opt_in(tmp_path):
    path = tmp_path / "file"
    path.touch()
    validate_file_permissions(path.stat(), require_single_link=True)
    os.link(path, tmp_path / "alias")
    metadata = path.stat()
    assert metadata.st_nlink == 2
    validate_file_permissions(metadata)
    with pytest.raises(FilePermissionRefused) as error:
        validate_file_permissions(metadata, require_single_link=True)
    assert error.value.reason == "links"


@pytest.mark.parametrize("policy", [
    {"owner_uid": -1}, {"owner_uid": True}, {"owner_uid": "0"},
    {"forbidden_mode_bits": -1}, {"forbidden_mode_bits": True},
    {"forbidden_mode_bits": 0o10000}, {"require_single_link": 1},
])
def test_invalid_policy_is_not_silently_accepted(tmp_path, policy):
    path = tmp_path / "file"
    path.touch()
    with pytest.raises(ValueError) as error:
        validate_file_permissions(path.stat(), **policy)
    assert not isinstance(error.value, FilePermissionRefused)
