"""Bound GNU sparse 1.0 map reads on a tiny native-readable archive."""
import io
import tarfile

import pytest

from core.tar import extract
from core.testing.module_bindings import patch_module_attribute


def pax10_archive():
    output = io.BytesIO()
    data = b"1\n0\n1\n".ljust(512, b"\0") + b"x"
    info = tarfile.TarInfo("stored")
    info.size = len(data)
    info.pax_headers = {
        "GNU.sparse.major": "1", "GNU.sparse.minor": "0",
        "GNU.sparse.name": "hole", "GNU.sparse.realsize": "1",
    }
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        archive.addfile(info, io.BytesIO(data))
    raw = output.getvalue()[:3584]
    assert len(raw) == 3584
    return raw


def test_pax10_map_consumes_aggregate_budget(monkeypatch):
    raw = pax10_archive()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as native:
        member, = native.getmembers()
        assert member.issparse() and member.name == "hole" and member.size == 1
        assert member.sparse == [(0, 1)] and member.offset_data == 2048
        with native.extractfile(member) as source:
            assert source.read() == b"x"
    calls = []

    class BoundedTrace(io.BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= 8192 and len(calls) < 32
            assert sum(count for _, count in calls) + size <= 8192
            data = super().read(size)
            calls.append((size, len(data)))
            return data

    patch_module_attribute(monkeypatch, extract, "io", "BytesIO", BoundedTrace)
    with pytest.raises(extract.TarTotalBytesExceeded):
        extract.extract_files_from_tar(
            raw, selector=lambda member: member.name, mode="r:", max_total_bytes=1025,
        )
    # PAX header/body plus ordinary header may be read, but the map may not.
    assert sum(count for _, count in calls) <= 1536


def test_ordinary_payload_exact_budget():
    output = io.BytesIO()
    info = tarfile.TarInfo("ordinary")
    info.size = 1
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        archive.addfile(info, io.BytesIO(b"x"))
    assert extract.extract_files_from_tar(
        output.getvalue()[:2048], selector=lambda member: member.name,
        mode="r:", max_total_bytes=1,
    ) == {"ordinary": b"x"}


@pytest.mark.parametrize("budget", [1025, 1537, None])
def test_pax10_source_restored_at_budget_boundary(monkeypatch, budget):
    records = []
    calls = []
    native_factory = extract._budgeted_tarinfo

    class Trace(io.BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= 8192 and len(calls) < 32
            assert sum(count for _, count in calls) + size <= 8192
            data = super().read(size)
            calls.append((size, len(data)))
            return data

    def factory(limit, consumed):
        base = native_factory(limit, consumed)

        class Observed(base):
            def _proc_gnusparse_10(self, member, headers, tarobj):
                original = tarobj.fileobj
                try:
                    return super()._proc_gnusparse_10(member, headers, tarobj)
                finally:
                    records.append((original is tarobj.fileobj, original.closed))

        return Observed

    raw = pax10_archive()
    patch_module_attribute(monkeypatch, extract, "io", "BytesIO", Trace)
    monkeypatch.setattr(extract, "_budgeted_tarinfo", factory)
    if budget == 1025:
        with pytest.raises(extract.TarTotalBytesExceeded):
            extract.extract_files_from_tar(raw, selector=lambda m: m.name, mode="r:", max_total_bytes=budget)
        assert calls == [(512, 512)] * 3
    else:
        assert extract.extract_files_from_tar(
            raw, selector=lambda m: m.name, mode="r:", max_total_bytes=budget,
        ) == {"hole": b"x"}
    assert records == ([] if budget is None else [(True, False)])


@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_pax10_restores_source_after_actual_map_read(monkeypatch, failure):
    raw = pax10_archive()
    calls = []
    records = []
    error = failure("after owned map read")
    native_factory = extract._budgeted_tarinfo

    class Trace(io.BytesIO):
        def read(self, size=-1):
            assert 0 <= size <= 8192 and len(calls) < 32
            assert sum(count for _, count in calls) + size <= 8192
            data = super().read(size)
            calls.append((size, len(data)))
            if len(calls) == 4:
                assert data.startswith(b"1\n0\n1\n")
                raise error
            return data

    def factory(limit, consumed):
        base = native_factory(limit, consumed)

        class Observed(base):
            def _proc_gnusparse_10(self, member, headers, tarobj):
                original = tarobj.fileobj
                try:
                    return super()._proc_gnusparse_10(member, headers, tarobj)
                finally:
                    records.append((original is tarobj.fileobj, original.closed))

        return Observed

    patch_module_attribute(monkeypatch, extract, "io", "BytesIO", Trace)
    monkeypatch.setattr(extract, "_budgeted_tarinfo", factory)
    expected = extract.TarOpenError if failure is OSError else failure
    with pytest.raises(expected) as caught:
        extract.extract_files_from_tar(raw, selector=lambda m: m.name, mode="r:", max_total_bytes=1537)
    assert (caught.value.__cause__ if failure is OSError else caught.value) is error
    assert len(calls) == 4 and records == [(True, False)]
