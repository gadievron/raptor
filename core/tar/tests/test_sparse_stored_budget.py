"""Sparse logical sizes cannot erase stored data from the byte budget."""
import gzip
import io
import tarfile

import pytest

from core.tar.extract import TarTotalBytesExceeded, extract_files_from_tar


def sparse_bytes(*, stored_size=4096, logical_size=0, extent=None):
    info = tarfile.TarInfo("hole")
    info.type = tarfile.GNUTYPE_SPARSE
    info.size = stored_size
    header = bytearray(info.tobuf(format=tarfile.GNU_FORMAT))
    if extent is not None:
        offset, length = extent
        header[386:398] = tarfile.itn(offset, 12, tarfile.GNU_FORMAT)
        header[398:410] = tarfile.itn(length, 12, tarfile.GNU_FORMAT)
    header[482] = 0
    header[483:495] = tarfile.itn(logical_size, 12, tarfile.GNU_FORMAT)
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
    return bytes(header) + b"x" * stored_size + b"\0" * 1024


def source_for(raw, mode):
    assert len(raw) <= 8192
    if mode == "r|gz":
        raw = gzip.compress(raw)
    if mode.startswith("r|"):
        def chunks():
            count = 0
            supplied = 0
            for offset in range(0, len(raw), 257):
                chunk = raw[offset:offset + 257]
                count += 1
                supplied += len(chunk)
                assert count <= 32 and supplied <= 8192
                yield chunk
        return chunks()
    return raw


@pytest.mark.parametrize("mode", ["r:", "r|", "r|gz"])
def test_stored_sparse_span_cannot_bypass_aggregate_budget(mode):
    raw = sparse_bytes()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as native:
        member, = native.getmembers()
        assert member.issparse() and member.size == 0 and native.offset >= 4608
    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(source_for(raw, mode), selector=lambda member: member.name,
                               mode=mode, max_total_bytes=1024)


def test_ordinary_stored_bytes_keep_existing_refusal():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        member = tarfile.TarInfo("ordinary")
        member.size = 4096
        archive.addfile(member, io.BytesIO(b"x" * 4096))
    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(output.getvalue()[:5632], selector=lambda member: member.name,
                               mode="r:", max_total_bytes=1024)


def test_sparse_stored_accounting_does_not_add_integrity_refusal():
    assert extract_files_from_tar(
        sparse_bytes(), selector=lambda member: member.name, mode="r:", max_total_bytes=4096,
    ) == {"hole": b""}


@pytest.mark.parametrize("mode", ["r:", "r|gz"])
def test_valid_sparse_holes_keep_logical_budget_and_bytes(mode):
    raw = sparse_bytes(stored_size=1024, logical_size=8192, extent=(4096, 1024))
    assert extract_files_from_tar(
        source_for(raw, mode), selector=lambda member: member.name, mode=mode,
        max_total_bytes=8192,
    ) == {"hole": b"\0" * 4096 + b"x" * 1024 + b"\0" * 3072}


def test_sparse_stored_budget_opt_out_is_unchanged():
    assert extract_files_from_tar(
        sparse_bytes(), selector=lambda member: member.name, mode="r:", max_total_bytes=None,
    ) == {"hole": b""}
