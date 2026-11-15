"""Synthetic structural bytes only, not a real filesystem/image or kernel test."""
import struct
from pathlib import Path

import pytest

from core.audit import prepared_image_envelope as module


def header(**changes):
    fields = dict(magic=0x73717368, inodes=1, mkfs_time=0, block_bytes=4096,
                  fragments=0, compression=1, block_log=12, flags=0, ids=1,
                  major=4, minor=0, root_inode=0, used=512, id_table=400,
                  xattr_table=(1 << 64) - 1, inode_table=96,
                  directory_table=200, fragment_table=(1 << 64) - 1,
                  lookup_table=(1 << 64) - 1)
    fields.update(changes)
    return struct.pack('<5I6H8Q', *fields.values())


def inspect(data, size=512):
    return module.inspect_header(data, size, max_artifact_bytes=4096, max_inodes=16, max_ids=16)


def test_synthetic_envelope_never_grants_filesystem_authority():
    value = inspect(header())
    assert isinstance(value, module.EnvelopeOnly)
    assert value.declared_bytes == 512 and value.trailing_bytes == 0
    assert value.table_offsets[:2] == (96, 200)
    assert not value.namespace_complete
    assert not value.authenticated_build and not value.observed_child_context


@pytest.mark.parametrize('changes', [dict(magic=0), dict(major=3), dict(minor=1),
    dict(inodes=0), dict(inodes=17), dict(ids=0), dict(ids=17), dict(fragments=17),
    dict(block_bytes=8193), dict(block_log=13), dict(compression=7), dict(flags=1 << 15),
    dict(used=513), dict(used=96), dict(inode_table=95), dict(directory_table=512),
    dict(id_table=200), dict(xattr_table=512), dict(fragments=1), dict(flags=1 << 7),
    dict(root_inode=8192), dict(root_inode=104 << 16)])
def test_malformed_declarations_are_refused(changes):
    assert isinstance(inspect(header(**changes)), module.EnvelopeRefusal)


@pytest.mark.parametrize('size', [False, -1, 95, 4097])
def test_artifact_size_refused_before_parsing(size):
    assert isinstance(inspect(header(), size), module.EnvelopeRefusal)


@pytest.mark.parametrize('data', [b'', b'x' * 95, b'x' * 97, 'x' * 96])
def test_exact_bytes_required(data):
    assert isinstance(inspect(data), module.EnvelopeRefusal)


@pytest.fixture
def backing_case(monkeypatch):
    import hashlib
    from core.audit import prepared_image_backing as backing
    from core.audit.tests.test_prepared_image_backing import SyntheticKernel
    assert Path(backing.__file__).resolve() == Path(__file__).resolve().parents[1] / 'prepared_image_backing.py'
    artifact = header() + b'\0' * (512 - 96)
    kernel = SyntheticKernel(artifact)
    clock = [0.0]
    monkeypatch.setattr(backing, '_linux_api', lambda: (kernel, kernel))
    monkeypatch.setattr(backing, '_production_backing_backend', backing._LinuxSeals)
    monkeypatch.setattr(backing.time, 'monotonic', lambda: clock[0])
    owners = []
    def make(read_budget=96, patch=None):
        kernel.data[9] = bytearray(artifact)
        if patch is not None:
            position, data = patch
            kernel.data[9][position:position + len(data)] = data
        owner = backing.ImageBackingOwner(max_images=1, max_artifact_bytes=512,
            max_retained_bytes=512, lifetime_seconds=30, max_read_bytes=read_budget)
        owners.append(owner)
        identity = backing.SuppliedArtifactIdentity(512, hashlib.sha256(kernel.data[9]).hexdigest())
        reference = owner.acquire(9, identity)
        kernel.events.clear()
        return owner, reference, kernel, clock, identity
    yield make
    for owner in owners:
        owner.close()


def test_owned_probe_reads_retained_bytes_not_mutated_borrowed_source(backing_case):
    owner, reference, kernel, _, identity = backing_case()
    kernel.data[9][:96] = b'\0' * 96
    result = module.probe_owned_header(owner, reference, max_artifact_bytes=512,
                                        max_inodes=16, max_ids=16)
    assert type(result) is module.BackingEnvelopeOnly
    assert result.artifact_sha256 == identity.sha256
    assert result.envelope.declared_bytes == 512
    assert not result.namespace_complete and not result.authenticated_build
    assert not result.observed_child_context
    assert owner._read_bytes_remaining == 0
    assert [event[1] for event in kernel.events if event[0] == 'read'] == [100]


@pytest.mark.parametrize('budget', [0, 95])
def test_owned_probe_insufficient_read_budget_never_publishes(backing_case, budget):
    owner, reference, kernel, _, _ = backing_case(budget)
    assert isinstance(module.probe_owned_header(owner, reference, max_artifact_bytes=512,
        max_inodes=16, max_ids=16), module.EnvelopeRefusal)
    assert not any(event[0] == 'read' for event in kernel.events)
    assert owner._read_bytes_remaining == budget and reference in owner._entries


def test_owned_probe_expiry_after_parse_withholds_result_and_retires(backing_case, monkeypatch):
    owner, reference, kernel, clock, _ = backing_case()
    original = module.inspect_header
    def expire(*args, **kwargs):
        value = original(*args, **kwargs)
        clock[0] = 30
        return value
    monkeypatch.setattr(module, 'inspect_header', expire)
    assert isinstance(module.probe_owned_header(owner, reference, max_artifact_bytes=512,
        max_inodes=16, max_ids=16), module.EnvelopeRefusal)
    assert owner._read_bytes_remaining == 0 and not owner._entries
    assert list(kernel.data) == [9]
    assert [event for event in kernel.events if event[0] == 'close'] == [('close', 100)]


def test_owned_probe_rejects_callback_shaped_source_without_calling_it():
    class ForeignOwner:
        def describe(self, *args):
            pytest.fail('foreign describe reached')
        def _read(self, *args):
            pytest.fail('foreign reader reached')
    assert isinstance(module.probe_owned_header(ForeignOwner(), object(),
        max_artifact_bytes=512, max_inodes=16, max_ids=16), module.EnvelopeRefusal)


def test_uncompressed_metadata_reads_owned_bytes_under_exact_budget(backing_case):
    owner, reference, kernel, _, _ = backing_case(7, (240, b'\x05\x80hello'))
    kernel.data[9][240:247] = b'\0' * 7
    value = module.read_uncompressed_metadata(owner, reference, 240,
                                              region_end=247, max_block_bytes=5)
    assert type(value) is module.MetadataBytesOnly
    assert value.payload == b'hello' and value.next_offset == 247
    assert not value.namespace_complete and not value.authenticated_build
    assert not value.observed_child_context and owner._read_bytes_remaining == 0
    assert [event[1:] for event in kernel.events if event[0] == 'read'] == [(100, 2, 240), (100, 5, 242)]
    assert 'hello' not in repr(value)


@pytest.mark.parametrize('encoded,end,budget', [(5, 247, 5), (0x8000, 247, 5),
    (0xffff, 512, 8192), (0x8005, 246, 5), (0x8005, 247, 4)])
def test_unsupported_metadata_never_reads_body(backing_case, encoded, end, budget):
    owner, reference, kernel, _, _ = backing_case(100, (240, encoded.to_bytes(2, 'little') + b'hello'))
    assert isinstance(module.read_uncompressed_metadata(owner, reference, 240,
        region_end=end, max_block_bytes=budget), module.EnvelopeRefusal)
    assert [event[1:] for event in kernel.events if event[0] == 'read'] == [(100, 2, 240)]
    assert owner._read_bytes_remaining == 98


def test_metadata_read_expiry_does_not_return_partial_bytes(backing_case):
    owner, reference, kernel, clock, _ = backing_case(7, (240, b'\x05\x80hello'))
    def expire(name, *args):
        if name == 'read' and args[2] == 242:
            clock[0] = 30
    kernel.fault = expire
    assert isinstance(module.read_uncompressed_metadata(owner, reference, 240,
        region_end=247, max_block_bytes=5), module.EnvelopeRefusal)
    kernel.fault = None
    assert not owner._entries and list(kernel.data) == [9]
    assert owner._read_bytes_remaining == 0


@pytest.mark.parametrize('changes', [dict(id_table=511), dict(id_table=505),
    dict(fragments=1, fragment_table=96), dict(fragments=1, fragment_table=396),
    dict(flags=128, lookup_table=200), dict(flags=128, lookup_table=396),
    dict(fragments=1, fragment_table=408), dict(flags=128, lookup_table=408),
    dict(xattr_table=500)])
def test_declared_index_spans_and_optional_regions_cannot_escape_or_alias(changes):
    assert isinstance(inspect(header(**changes)), module.EnvelopeRefusal)


@pytest.mark.parametrize('changes', [dict(id_table=504),
    dict(fragments=1, fragment_table=392), dict(flags=128, lookup_table=392),
    dict(fragments=1, fragment_table=384, flags=128, lookup_table=392)])
def test_complete_index_spans_may_meet_exact_region_boundary(changes):
    assert isinstance(inspect(header(**changes)), module.EnvelopeOnly)


@pytest.mark.parametrize('offset,end', [(-1, 247), (True, 247), (511, 512),
    (0, 1), (240, True), (240, 513), (240, None)])
def test_metadata_bad_region_refuses_before_byte_read(backing_case, offset, end):
    owner, reference, kernel, _, _ = backing_case(7, (240, b'\x05\x80hello'))
    assert isinstance(module.read_uncompressed_metadata(owner, reference, offset,
        region_end=end, max_block_bytes=5), module.EnvelopeRefusal)
    assert not any(event[0] == 'read' for event in kernel.events)
    assert owner._read_bytes_remaining == 7 and reference in owner._entries


@pytest.mark.parametrize('budget', [False, 0, -1, 8193, 1.5])
def test_metadata_bad_block_budget_rejects_configuration(backing_case, budget):
    owner, reference, kernel, _, _ = backing_case(7)
    with pytest.raises(ValueError):
        module.read_uncompressed_metadata(owner, reference, 240,
            region_end=247, max_block_bytes=budget)
    assert not kernel.events and owner._read_bytes_remaining == 7


def test_metadata_second_read_budget_exhaustion_withholds_body(backing_case):
    owner, reference, kernel, _, _ = backing_case(6, (240, b'\x05\x80hello'))
    assert isinstance(module.read_uncompressed_metadata(owner, reference, 240,
        region_end=247, max_block_bytes=5), module.EnvelopeRefusal)
    assert [event[1:] for event in kernel.events if event[0] == 'read'] == [(100, 2, 240)]
    assert owner._read_bytes_remaining == 4 and reference in owner._entries


@pytest.mark.parametrize('cancel_offset,remaining', [(240, 5), (242, 0)])
def test_metadata_cancellation_preserves_budget_and_close_ownership(backing_case, cancel_offset, remaining):
    owner, reference, kernel, _, _ = backing_case(7, (240, b'\x05\x80hello'))
    def cancel(name, *args):
        if name == 'read' and args[2] == cancel_offset:
            raise KeyboardInterrupt()
    kernel.fault = cancel
    with pytest.raises(KeyboardInterrupt):
        module.read_uncompressed_metadata(owner, reference, 240,
            region_end=247, max_block_bytes=5)
    kernel.fault = None
    assert owner._read_bytes_remaining == remaining and not owner._entries
    assert list(kernel.data) == [9]
    assert [event for event in kernel.events if event[0] == 'close'] == [('close', 100)]
