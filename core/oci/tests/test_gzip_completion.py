"""Small owned gzip layers must finish their compression framing."""
import gzip
import io
import tarfile

import pytest

from core.oci.blob import extract_files_from_layer
from core.tar import TarOpenError


def test_public_layer_rejects_missing_gzip_trailer():
    output = io.BytesIO()
    info = tarfile.TarInfo("status")
    info.size = 1
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(info, io.BytesIO(b"x"))
    raw = output.getvalue()[:2048]
    complete = gzip.compress(raw, mtime=0)
    assert len(raw) == 2048 and len(complete) < 128
    assert gzip.decompress(complete) == raw
    truncated = complete[:-8]
    with pytest.raises(EOFError):
        gzip.decompress(truncated)
    calls = []

    def chunks():
        for index in range(0, len(truncated), 7):
            calls.append(index)
            assert len(calls) <= 32
            yield truncated[index:index + 7]

    with pytest.raises(TarOpenError):
        extract_files_from_layer(chunks(), {"status"}, compressed_size=len(truncated))


@pytest.mark.parametrize("split", [1, 7, 128])
@pytest.mark.parametrize("damage", ["healthy", "trailer", "crc"])
def test_layer_completion_preserves_payload_and_rejects_damage(split, damage):
    output = io.BytesIO()
    info = tarfile.TarInfo("status")
    info.size = 1
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(info, io.BytesIO(b"x"))
    data = gzip.compress(output.getvalue()[:2048], mtime=0)
    if damage == "trailer":
        data = data[:-8]
    elif damage == "crc":
        data = data[:-8] + bytes([data[-8] ^ 1]) + data[-7:]
    calls = []

    def chunks():
        for index in range(0, len(data), split):
            calls.append(index)
            assert len(calls) <= 128 and len(data) < 128
            yield data[index:index + split]

    if damage == "healthy":
        assert extract_files_from_layer(chunks(), {"status"}, compressed_size=len(data)) == {"status": b"x"}
    else:
        with pytest.raises(TarOpenError):
            extract_files_from_layer(chunks(), {"status"}, compressed_size=len(data))


def test_uncompressed_layer_keeps_payload():
    output = io.BytesIO()
    info = tarfile.TarInfo("status")
    info.size = 1
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(info, io.BytesIO(b"x"))
    assert extract_files_from_layer(
        iter([output.getvalue()[:2048]]), {"status"},
        media_type="application/vnd.oci.image.layer.v1.tar",
    ) == {"status": b"x"}
