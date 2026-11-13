"""Bounded local PAX1.0 accounting and explicit override exclusions."""
import io
import tarfile

import pytest

from core.tar import extract
from core.testing.module_bindings import patch_module_attribute


def sparse_fields(logical):
    return {'GNU.sparse.major': '1', 'GNU.sparse.minor': '0',
            'GNU.sparse.name': 'hole', 'GNU.sparse.realsize': str(logical)}


def archive(*, stored=4096, logical=1, outer=(), maps=1, global_fields=None,
            local_size=None, tail=False):
    fields = {} if local_size is None else {'size': str(local_size)}
    fields.update(sparse_fields(logical))
    prefix = b''
    if global_fields is not None:
        prefix += tarfile.TarInfo._create_pax_generic_header(global_fields, tarfile.XGLTYPE, 'utf-8')
    for headers in (*outer, fields):
        prefix += tarfile.TarInfo._create_pax_generic_header(headers, tarfile.XHDTYPE, 'utf-8')
    member = tarfile.TarInfo('stored')
    member.size = stored
    data = b'1\n0\n1\n'.ljust(512, b'\0') * maps + b'x'
    assert len(data) <= stored
    raw = prefix + member.tobuf(format=tarfile.USTAR_FORMAT) + data.ljust(stored, b'\0')
    raw = raw.ljust((len(raw) + 511) // 512 * 512, b'\0')
    if tail:
        member = tarfile.TarInfo('tail')
        member.size = 1
        raw += member.tobuf(format=tarfile.USTAR_FORMAT) + b'y'.ljust(512, b'\0')
    raw += b'\0' * 1024
    assert len(raw) <= 8192
    return raw


def chunks(raw):
    counts = []
    for start in range(0, len(raw), 256):
        part = raw[start:start + 256]
        counts.append(len(part))
        assert len(counts) <= 32 and sum(counts) <= 8192
        yield part


def run(raw, budget, **kwargs):
    return extract.extract_files_from_tar(chunks(raw), mode='r|', max_total_bytes=budget,
                                          selector=kwargs.pop('selector', lambda m: m.name), **kwargs)


def native(raw):
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as tf:
        members = tf.getmembers()
        payload = {}
        for member in members:
            assert 0 <= member.size <= 8192
            with tf.extractfile(member) as source:
                payload[member.name] = source.read(8193)
        return members, payload, tf.offset


def refused_before_selector(raw, cap):
    selected = []
    with pytest.raises(extract.TarTotalBytesExceeded):
        run(raw, cap, selector=lambda member: selected.append(member.name))
    assert selected == []


def test_local_stored_span_exact_boundary():
    raw = archive(tail=True)
    members, payload, _ = native(raw)
    assert len(raw) == 7680 and members[0].size == 1 and members[1].offset == 5632
    assert payload == {'hole': b'x', 'tail': b'y'}
    refused_before_selector(raw, 1538)
    assert run(raw, 5121) == payload
    with pytest.raises(extract.TarTotalBytesExceeded):
        run(raw, 5120)


def test_valid_small_and_logical_hole_do_not_double_bill():
    raw = archive(stored=513)
    assert native(raw)[1] == {'hole': b'x'}
    assert run(raw, 1537) == {'hole': b'x'}
    refused_before_selector(raw, 1536)
    raw = archive(stored=513, logical=1024)
    expected = {'hole': b'x' + b'\0' * 1023}
    assert native(raw)[1] == expected and run(raw, 2560) == expected


def test_nested_late_logical_override_uses_final_size():
    raw = archive(outer=({'GNU.sparse.realsize': '4096'},))
    members, expected, _ = native(raw)
    assert members[0].size == 4096 and members[0].offset_data == 3072
    assert expected == {'hole': b'x' + b'\0' * 4095}
    assert run(raw, 6656) == expected
    refused_before_selector(raw, 6655)


def test_repeated_capture_is_sticky_unsafe():
    # Inner logical1, middle logical4096, then benign outer logical1:
    # the final hook would otherwise restore a misleading reliable capture.
    raw = archive(stored=2048, maps=3, outer=(sparse_fields(1), sparse_fields(4096)))
    members, expected, _ = native(raw)
    assert members[0].size == 1 and members[0].offset_data == 5120
    seen = []

    def select(member):
        seen.append((member._pax10_unsafe, member._pax10_storage[2]))
        return member.name

    assert run(raw, 4609, selector=select) == expected == {'hole': b'x'}
    assert seen == [(True, False)]
    refused_before_selector(raw, 4608)


def test_global_and_standard_size_exclusions_preserve_prior_policy():
    for inherited in (1, 4096):
        raw = archive(global_fields={'GNU.sparse.realsize': str(inherited)})
        members, expected, offset = native(raw)
        assert members[0].size == 1 and offset == 6656
        # Remaining global stored-span gap is intentionally NOT called fixed.
        assert run(raw, 2561) == expected == {'hole': b'x'}
    raw = archive(global_fields={'size': '4096', 'GNU.sparse.realsize': '1'})
    assert native(raw)[2] == 3584
    assert run(raw, 2561) == {'hole': b'x'}
    raw = archive(local_size=4096)
    assert native(raw)[2] == 2560
    assert run(raw, 1537) == {'hole': b'x'}


def test_ordinary_and_other_pax_sparse_formats_keep_old_charges():
    member = tarfile.TarInfo('ordinary')
    member.size = 1
    raw = member.tobuf(format=tarfile.USTAR_FORMAT) + b'x'.ljust(512, b'\0') + b'\0' * 1024
    assert run(raw, 1) == {'ordinary': b'x'}
    refused_before_selector(raw, 0)
    for fields in (
        {'GNU.sparse.map': '0,1', 'GNU.sparse.realsize': '1', 'GNU.sparse.name': 'hole'},
        {'GNU.sparse.size': '1', 'GNU.sparse.numblocks': '1',
         'GNU.sparse.offset': '0', 'GNU.sparse.numbytes': '1', 'GNU.sparse.name': 'hole'},
    ):
        prefix = tarfile.TarInfo._create_pax_generic_header(fields, tarfile.XHDTYPE, 'utf-8')
        data = prefix + raw
        assert native(data)[1] == {'hole': b'x'} and run(data, 1025) == {'hole': b'x'}
        refused_before_selector(data, 1024)

    legacy = tarfile.TarInfo('hole')
    legacy.type = tarfile.GNUTYPE_SPARSE
    header = bytearray(legacy.tobuf(format=tarfile.GNU_FORMAT))
    header[482] = 1
    header[483:495] = tarfile.itn(0, 12, tarfile.GNU_FORMAT)
    header[148:156] = b' ' * 8
    header[148:156] = f'{sum(header):06o}\0 '.encode('ascii')
    blocks = []
    for index in range(3):
        block = bytearray(512)
        block[504] = int(index < 2)
        blocks.append(bytes(block))
    raw = bytes(header) + b''.join(blocks) + b'\0' * 1024
    assert run(raw, 1536) == {'hole': b''}
    refused_before_selector(raw, 1535)


def test_optout_callbacks_and_source_restoration(monkeypatch):
    raw = archive(tail=True)
    assert run(raw, None) == {'hole': b'x', 'tail': b'y'}
    calls = []
    with pytest.raises(extract.TarTotalBytesExceeded):
        run(raw, 1538, selector=lambda m: None, sink=lambda *args: calls.append(args))
    assert calls == []
    native_factory = extract._budgeted_tarinfo
    restored = []

    def factory(budget, consumed):
        base = native_factory(budget, consumed)

        class Observed(base):
            def _proc_gnusparse_10(self, member, headers, tf):
                original = tf.fileobj
                try:
                    return super()._proc_gnusparse_10(member, headers, tf)
                finally:
                    restored.append((tf.fileobj is original, original.closed))

        return Observed

    monkeypatch.setattr(extract, '_budgeted_tarinfo', factory)
    failure = {'error': None}
    reads = []

    class Trace(io.BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= 8192 and len(reads) < 32
            data = super().read(size)
            reads.append(len(data))
            assert sum(reads) <= 8192
            if len(reads) == 4 and failure['error'] is not None:
                assert data.startswith(b'1\n0\n1\n')
                raise failure['error']
            return data

    patch_module_attribute(monkeypatch, extract, 'io', 'BytesIO', Trace)
    for error in (OSError('after map read'), KeyboardInterrupt('after map read')):
        failure['error'] = error
        reads.clear()
        with pytest.raises(extract.TarOpenError if isinstance(error, OSError) else KeyboardInterrupt) as caught:
            extract.extract_files_from_tar(raw, selector=lambda m: m.name, mode='r:', max_total_bytes=5121)
        assert (caught.value.__cause__ if isinstance(error, OSError) else caught.value) is error
    failure['error'] = None
    for cap in (1535, 1538):
        reads.clear()
        with pytest.raises(extract.TarTotalBytesExceeded):
            extract.extract_files_from_tar(raw, selector=lambda m: m.name, mode='r:', max_total_bytes=cap)
    reads.clear()
    assert extract.extract_files_from_tar(
        raw, selector=lambda m: m.name, mode='r:', max_total_bytes=5121,
    ) == {'hole': b'x', 'tail': b'y'}
    reads.clear()
    broken = archive(outer=({'GNU.sparse.realsize': 'bad'},))
    with pytest.raises(ValueError):
        extract.extract_files_from_tar(
            broken, selector=lambda m: m.name, mode='r:', max_total_bytes=8192,
        )
    assert restored == [(True, False)] * 6
    with pytest.raises(extract.TarTotalBytesExceeded):
        run(raw, 5120, selector=lambda m: None)
    directory = tarfile.TarInfo('directory')
    directory.type = tarfile.DIRTYPE
    nonregular = directory.tobuf(format=tarfile.GNU_FORMAT) + b'\0' * 1024
    observed = []
    assert run(nonregular, 0, on_nonregular=lambda m: observed.append(m.name)) == {}
    assert observed == ['directory']
    directory.size = -1
    negative = directory.tobuf(format=tarfile.GNU_FORMAT) + b'\0' * 1024
    with pytest.raises(extract.TarReadError):
        run(negative, 0)
