"""A tiny GNU sparse header chain must consume the metadata budget."""
import io
import tarfile

import pytest

from core.tar import extract
from core.testing.module_bindings import patch_module_attribute


def sparse_archive():
    info = tarfile.TarInfo("hole")
    info.type = tarfile.GNUTYPE_SPARSE
    info.size = 0
    header = bytearray(info.tobuf(format=tarfile.GNU_FORMAT))
    header[482] = 1
    header[483:495] = tarfile.itn(0, 12, tarfile.GNU_FORMAT)
    header[148:156] = b" " * 8
    header[148:156] = f"{sum(header):06o}\0 ".encode("ascii")
    blocks = []
    for index in range(3):
        block = bytearray(512)
        block[504] = int(index < 2)
        blocks.append(bytes(block))
    return bytes(header) + b"".join(blocks) + b"\0" * 1024


@pytest.fixture
def read_failure():
    return {"error": None}


@pytest.fixture
def reads(monkeypatch, read_failure):
    calls = []
    streams = []

    class BoundedTrace(io.BytesIO):
        def __init__(self, data):
            assert len(data) == 3072
            super().__init__(data)
            streams.append(self)

        def read(self, size=-1):
            assert size >= 0
            data = super().read(size)
            calls.append((size, len(data)))
            assert len(calls) <= 32 and sum(count for _, count in calls) <= 8192
            if len(calls) == 2 and read_failure["error"] is not None:
                raise read_failure["error"]
            return data

    patch_module_attribute(monkeypatch, extract, "io", "BytesIO", BoundedTrace)
    try:
        yield calls
    finally:
        for stream in streams:
            stream.close()


@pytest.fixture
def restored(monkeypatch):
    records = []
    native_factory = extract._budgeted_tarinfo

    def factory(budget, consumed):
        base = native_factory(budget, consumed)

        class Observed(base):
            def _proc_sparse(self, tarobj):
                original = tarobj.fileobj
                try:
                    return super()._proc_sparse(tarobj)
                finally:
                    records.append((original, tarobj.fileobj, original.closed))

        return Observed

    monkeypatch.setattr(extract, "_budgeted_tarinfo", factory)
    return records


def assert_restored(records):
    assert len(records) == 1
    original, restored_source, was_closed = records[0]
    assert original is restored_source and not was_closed and not original.closed


def test_sparse_extension_chain_is_charged_before_native_reads(reads, restored):
    raw = sparse_archive()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as native:
        member, = native.getmembers()
        assert member.issparse() and member.size == 0 and member.name == "hole"
        with native.extractfile(member) as source:
            assert source.read() == b""
    with pytest.raises(extract.TarTotalBytesExceeded):
        extract.extract_files_from_tar(
            raw, selector=lambda member: member.name, mode="r:", max_total_bytes=1024,
        )
    # The ordinary member header is separate; at most two 512-byte extension
    # blocks may be consumed before rejecting the third against this budget.
    assert sum(count for _, count in reads) <= 1536
    assert_restored(restored)


def test_exact_sparse_metadata_budget_keeps_native_member(reads, restored):
    assert extract.extract_files_from_tar(
        sparse_archive(), selector=lambda member: member.name,
        mode="r:", max_total_bytes=1536,
    ) == {"hole": b""}
    assert_restored(restored)


def test_sparse_metadata_opt_out_keeps_native_member(reads):
    assert extract.extract_files_from_tar(
        sparse_archive(), selector=lambda member: member.name,
        mode="r:", max_total_bytes=None,
    ) == {"hole": b""}


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_sparse_source_identity_restored_after_native_failure(reads, restored, read_failure, failure):
    read_failure["error"] = failure("after native sparse extension read")
    expected = extract.TarOpenError if failure is OSError else failure
    with pytest.raises(expected) as caught:
        extract.extract_files_from_tar(
            sparse_archive(), selector=lambda member: member.name,
            mode="r:", max_total_bytes=1536,
        )
    if failure is OSError:
        assert caught.value.__cause__ is read_failure["error"]
    else:
        assert caught.value is read_failure["error"]
    assert_restored(restored)


@pytest.mark.parametrize("archive_format", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT])
@pytest.mark.parametrize("budget", [512, 1024])
def test_existing_name_metadata_budget_keeps_boundary(archive_format, budget):
    output = io.BytesIO()
    name = "n" * 110
    with tarfile.open(fileobj=output, mode="w", format=archive_format) as archive:
        archive.addfile(tarfile.TarInfo(name))
    raw = output.getvalue()[:2560]
    if budget == 512:
        with pytest.raises(extract.TarTotalBytesExceeded):
            extract.extract_files_from_tar(
                raw, selector=lambda member: member.name, mode="r:", max_total_bytes=budget,
            )
    else:
        assert extract.extract_files_from_tar(
            raw, selector=lambda member: member.name, mode="r:", max_total_bytes=budget,
        ) == {name: b""}
