"""A non-regular tar member cannot subtract from the shared byte budget."""
import gzip
import io
import tarfile

import pytest

from core.tar.extract import TarReadError, TarTotalBytesExceeded, extract_files_from_tar


def archive_bytes(archive_format, *, negative=True, payload_size=4096):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=archive_format) as archive:
        first = tarfile.TarInfo("first")
        first.size = 4
        archive.addfile(first, io.BytesIO(b"safe"))
        directory = tarfile.TarInfo("directory")
        directory.type = tarfile.DIRTYPE
        directory.size = -8192 if negative else 0
        archive.addfile(directory)
        final = tarfile.TarInfo("payload")
        final.size = payload_size
        archive.addfile(final, io.BytesIO(b"x" * payload_size))
    return output.getvalue()


def source_for(raw, mode):
    if mode == "r|gz":
        raw = gzip.compress(raw)
    if mode.startswith("r|"):
        return (raw[offset:offset + 257] for offset in range(0, len(raw), 257))
    return raw


@pytest.mark.parametrize("archive_format", [tarfile.GNU_FORMAT, tarfile.PAX_FORMAT], ids=["gnu", "pax"])
@pytest.mark.parametrize("mode", ["r:", "r|", "r|gz"])
def test_negative_directory_cannot_credit_selected_payload(archive_format, mode):
    raw = archive_bytes(archive_format)
    with tarfile.open(fileobj=io.BytesIO(raw)) as reader:
        assert reader.getmembers()[1].size == -8192
    delivered = {}
    with pytest.raises(TarReadError, match="negative.*size"):
        extract_files_from_tar(
            source_for(raw, mode), selector=lambda member: member.name,
            mode=mode, max_total_bytes=2048,
            sink=lambda key, data: delivered.update({key: data}),
        )
    assert delivered == {"first": b"safe"}


def test_negative_size_is_corruption_even_without_byte_cap():
    raw = archive_bytes(tarfile.GNU_FORMAT)
    with pytest.raises(TarReadError, match="negative.*size"):
        extract_files_from_tar(raw, selector=lambda member: member.name,
                               mode="r:", max_total_bytes=None)


@pytest.mark.parametrize("mode", ["r:", "r|gz"])
def test_positive_size_still_exceeds_budget(mode):
    raw = archive_bytes(tarfile.GNU_FORMAT, negative=False)
    with pytest.raises(TarTotalBytesExceeded):
        extract_files_from_tar(source_for(raw, mode), selector=lambda member: member.name,
                               mode=mode, max_total_bytes=2048)


@pytest.mark.parametrize("mode", ["r:", "r|gz"])
def test_exact_positive_budget_keeps_selected_bytes(mode):
    raw = archive_bytes(tarfile.GNU_FORMAT, negative=False)
    assert extract_files_from_tar(
        source_for(raw, mode), selector=lambda member: member.name,
        mode=mode, max_total_bytes=4100,
    ) == {"first": b"safe", "payload": b"x" * 4096}
