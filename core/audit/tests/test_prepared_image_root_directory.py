"""Inert basic-root declaration controls; no filesystem or kernel execution."""
import hashlib
from pathlib import Path
import struct

import pytest

from core.audit import prepared_image_backing as backing
from core.audit import prepared_image_root_directory as module
from core.audit import prepared_image_envelope as envelope
from core.audit.tests import test_prepared_image_backing as backing_helpers
from core.audit.tests import test_prepared_image_envelope as envelope_helpers

SyntheticKernel = backing_helpers.SyntheticKernel
header = envelope_helpers.header


@pytest.fixture
def case(monkeypatch):
    audit = Path(__file__).resolve().parents[1]
    tests = Path(__file__).resolve().parent
    assert Path(backing.__file__).resolve() == audit / 'prepared_image_backing.py'
    assert Path(module.__file__).resolve() == audit / 'prepared_image_root_directory.py'
    assert Path(envelope.__file__).resolve() == audit / 'prepared_image_envelope.py'
    assert Path(backing_helpers.__file__).resolve() == tests / 'test_prepared_image_backing.py'
    assert Path(envelope_helpers.__file__).resolve() == tests / 'test_prepared_image_envelope.py'
    assert module.probe_owned_header is envelope.probe_owned_header
    assert module.read_uncompressed_metadata is envelope.read_uncompressed_metadata
    clock = [0.0]
    monkeypatch.setattr(backing.time, 'monotonic', lambda: clock[0])
    owners = []
    def make(*, inode_changes=None, payload=None, root_offset=0, read_budget=130,
             header_changes=None, prefix=None, root_block=0, decoy_mode=None):
        values = dict(kind=1, mode=0o755, uid=0, gid=0, mtime=0, number=1,
                      start=0, nlink=2, size=3, offset=0, parent=1)
        values.update(inode_changes or {})
        body = struct.pack('<4H4I2HI', *values.values()) if payload is None else payload
        body = b'\0' * root_offset + body
        declarations = dict(root_inode=(root_block << 16) | root_offset)
        declarations.update(header_changes or {})
        artifact = bytearray(header(**declarations) + b'\0' * (512 - 96))
        frame = ((0x8000 | len(body)).to_bytes(2, 'little') if prefix is None else prefix) + body
        if decoy_mode is not None:
            decoy = dict(values, mode=decoy_mode)
            decoy_body = b'\0' * root_offset + struct.pack('<4H4I2HI', *decoy.values())
            decoy_frame = (0x8000 | len(decoy_body)).to_bytes(2, 'little') + decoy_body
            assert len(decoy_frame) <= root_block
            artifact[96:96 + len(decoy_frame)] = decoy_frame
        frame_start = 96 + root_block
        artifact[frame_start:frame_start + len(frame)] = frame
        kernel = SyntheticKernel(bytes(artifact))
        monkeypatch.setattr(backing, '_linux_api', lambda: (kernel, kernel))
        monkeypatch.setattr(backing, '_production_backing_backend', backing._LinuxSeals)
        owner = backing.ImageBackingOwner(max_images=1, max_artifact_bytes=len(artifact),
            max_retained_bytes=len(artifact), lifetime_seconds=30, max_read_bytes=read_budget)
        owners.append(owner)
        identity = backing.SuppliedArtifactIdentity(len(artifact), hashlib.sha256(artifact).hexdigest())
        ref = owner.acquire(9, identity)
        kernel.events.clear()
        return owner, ref, kernel, clock, identity
    yield make
    for owner in owners:
        owner.close()


def probe(owner, ref, **changes):
    budgets = dict(max_artifact_bytes=4096, max_inodes=16, max_ids=16,
                   max_directory_declared_bytes=65535)
    budgets.update(changes)
    return module.probe_basic_root_directory(owner, ref, **budgets)


def test_owned_root_declaration_uses_retained_bytes_and_no_authority(case):
    owner, ref, kernel, _, identity = case()
    kernel.data[9][96:130] = b'\0' * 34
    value = probe(owner, ref)
    assert type(value) is module.BasicRootDirectoryDeclaration
    assert value.artifact_sha256 == identity.sha256 and value.artifact_bytes == identity.byte_count
    assert (value.declared_mode, value.declared_inode_number, value.declared_parent_inode) == (0o755, 1, 1)
    assert value.declared_mtime == 0 and value.declared_nlink == 2
    assert not value.namespace_complete and not value.authenticated_build and not value.observed_child_context
    assert owner._read_bytes_remaining == 0
    assert [event[1:] for event in kernel.events if event[0] == 'read'] == [(100, 96, 0), (100, 2, 96), (100, 32, 98)]


def test_nonzero_root_offset_is_taken_from_owned_header(case):
    owner, ref, _, _, _ = case(root_offset=8, read_budget=138)
    assert type(probe(owner, ref)) is module.BasicRootDirectoryDeclaration
    assert owner._read_bytes_remaining == 0


@pytest.mark.parametrize('kind', [0, 2, 3, 4, 5, 6, 7, 8, 9, 65535])
def test_unsupported_inode_kinds_are_unavailable(case, kind):
    owner, ref, _, _, _ = case(inode_changes=dict(kind=kind))
    assert isinstance(probe(owner, ref), module.RootDirectoryUnavailable)


@pytest.mark.parametrize('changes', [dict(number=0), dict(number=2), dict(uid=1),
    dict(gid=1), dict(nlink=0), dict(offset=8192), dict(start=199)])
def test_root_declarations_must_fit_header_and_region_bounds(case, changes):
    owner, ref, _, _, _ = case(inode_changes=changes)
    assert isinstance(probe(owner, ref), module.RootDirectoryUnavailable)


def test_raw_directory_declaration_budget_is_explicit(case):
    owner, ref, _, _, _ = case(inode_changes=dict(size=10))
    assert isinstance(probe(owner, ref, max_directory_declared_bytes=9), module.RootDirectoryUnavailable)


@pytest.mark.parametrize('length', [0, 1, 16, 31])
def test_short_root_payload_is_unavailable(case, length):
    owner, ref, _, _, _ = case(payload=b'\0' * length, read_budget=130)
    assert isinstance(probe(owner, ref), module.RootDirectoryUnavailable)


@pytest.mark.parametrize('budget', [0, 95, 96, 97, 129])
def test_root_read_budget_never_returns_partial_declaration(case, budget):
    owner, ref, _, _, _ = case(read_budget=budget)
    assert isinstance(probe(owner, ref), module.RootDirectoryUnavailable)


def test_compressed_root_metadata_is_unavailable_without_decoder(case):
    owner, ref, _, _, _ = case(prefix=b'\x20\0')
    assert isinstance(probe(owner, ref), module.RootDirectoryUnavailable)
    assert owner._read_bytes_remaining == 32


def test_foreign_root_reference_cannot_alias_owned_handle(case):
    owner, ref, kernel, _, _ = case()
    class Foreign:
        def __hash__(self):
            return hash(ref)
        def __eq__(self, other):
            return True
    before = len(kernel.events)
    assert isinstance(probe(owner, Foreign()), module.RootDirectoryUnavailable)
    assert len(kernel.events) == before and owner._read_bytes_remaining == 130


def test_root_expiry_after_decode_withholds_result(case, monkeypatch):
    owner, ref, _, clock, _ = case()
    original = module.BasicRootDirectoryDeclaration
    def expire(*args, **kwargs):
        result = original(*args, **kwargs)
        clock[0] = 30
        return result
    monkeypatch.setattr(module, 'BasicRootDirectoryDeclaration', expire)
    assert isinstance(probe(owner, ref), module.RootDirectoryUnavailable)
    assert not owner._entries


def test_root_decode_allocation_failure_is_unavailable(case, monkeypatch):
    owner, ref, _, _, _ = case()
    def fail(*args, **kwargs):
        raise MemoryError()
    monkeypatch.setattr(module, 'BasicRootDirectoryDeclaration', fail)
    assert isinstance(probe(owner, ref), module.RootDirectoryUnavailable)
    assert ref in owner._entries


def test_root_decode_cancellation_propagates_without_stealing_ownership(case, monkeypatch):
    owner, ref, kernel, _, _ = case()
    def cancel(*args, **kwargs):
        raise KeyboardInterrupt()
    monkeypatch.setattr(module, 'BasicRootDirectoryDeclaration', cancel)
    with pytest.raises(KeyboardInterrupt):
        probe(owner, ref)
    assert ref in owner._entries and not any(event[0] == 'close' for event in kernel.events)
    owner.close()
    assert [event for event in kernel.events if event[0] == 'close'] == [('close', 100)]


@pytest.mark.parametrize('offset', [0, 96, 98])
def test_root_backend_cancellation_revokes_once(case, offset):
    owner, ref, kernel, _, _ = case()
    def cancel(name, *args):
        if name == 'read' and args[2] == offset:
            raise KeyboardInterrupt()
    kernel.fault = cancel
    with pytest.raises(KeyboardInterrupt):
        probe(owner, ref)
    kernel.fault = None
    assert not owner._entries and list(kernel.data) == [9]
    owner.close()
    assert [event for event in kernel.events if event[0] == 'close'] == [('close', 100)]


def test_root_block_and_offset_select_physically_displaced_owned_frame(case):
    owner, ref, kernel, _, _ = case(root_block=48, root_offset=4,
                                   decoy_mode=0o700, read_budget=134)
    value = probe(owner, ref)
    assert type(value) is module.BasicRootDirectoryDeclaration
    assert value.declared_mode == 0o755
    assert owner._read_bytes_remaining == 0
    assert [event[1:] for event in kernel.events if event[0] == 'read'] == [
        (100, 96, 0), (100, 2, 144), (100, 36, 146)]


def test_root_id_indices_use_actual_owned_header_count(case):
    owner, ref, _, _, _ = case(inode_changes=dict(uid=1, gid=2),
                               header_changes=dict(ids=3))
    value = probe(owner, ref)
    assert type(value) is module.BasicRootDirectoryDeclaration
    assert (value.declared_uid_index, value.declared_gid_index) == (1, 2)
