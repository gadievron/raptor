"""Concatenated gzip layers must not depend on transport chunk boundaries."""
import gzip
import io
import tarfile

from core.oci.blob import extract_files_from_layer


def test_public_layer_reads_members_split_at_gzip_boundary():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in ("first", "second"):
            info = tarfile.TarInfo(name)
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
    raw = output.getvalue()[:3072]
    compressed = [gzip.compress(raw[:1024], mtime=0), gzip.compress(raw[1024:], mtime=0)]
    assert len(raw) == 3072 and sum(map(len, compressed)) < 256
    assert gzip.decompress(b"".join(compressed)) == raw
    expected = {"first": b"x", "second": b"x"}
    assert extract_files_from_layer(iter([b"".join(compressed)]), set(expected)) == expected
    calls = []

    def chunks():
        for chunk in compressed:
            calls.append(len(chunk))
            assert len(calls) <= 2 and sum(calls) < 256
            yield chunk

    assert extract_files_from_layer(chunks(), set(expected)) == expected


def _two_member_layer():
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in ("first", "second"):
            info = tarfile.TarInfo(name)
            info.size = 1
            archive.addfile(info, io.BytesIO(b"x"))
    raw = output.getvalue()[:3072]
    return gzip.compress(raw[:1024], mtime=0), gzip.compress(raw[1024:], mtime=0)


def test_empty_chunk_between_gzip_members_keeps_both_files():
    first, second = _two_member_layer()
    assert extract_files_from_layer(iter([first, b"", second]), {"first", "second"}) == {
        "first": b"x", "second": b"x",
    }


def test_truncated_second_gzip_member_is_refused():
    import pytest
    from core.tar import TarOpenError

    first, second = _two_member_layer()
    with pytest.raises(TarOpenError):
        extract_files_from_layer(iter([first, second[:-8]]), {"first", "second"})


def test_second_member_retains_cumulative_decompression_budget(monkeypatch):
    import pytest
    from core.oci import blob

    first, second = _two_member_layer()
    monkeypatch.setattr(blob, "DECOMPRESSION_BUDGET_FLOOR", 1500)
    monkeypatch.setattr(blob, "DECOMPRESSION_RATIO_BOUND", 1)
    with pytest.raises(blob.DecompressionBudgetExceeded):
        extract_files_from_layer(iter([first, second]), {"first", "second"})


def test_trailing_nul_padding_keeps_existing_acceptance():
    first, second = _two_member_layer()
    assert extract_files_from_layer(iter([first, second, b"\0" * 16]), {"first", "second"}) == {
        "first": b"x", "second": b"x",
    }
