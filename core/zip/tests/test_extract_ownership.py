"""Archive cleanup preserves actual extraction refusals and caller streams."""
import io
from types import SimpleNamespace
import zipfile

import pytest

from core.zip import extract as consumer


@pytest.fixture
def archive_io(monkeypatch):
    source = io.BytesIO()
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("plain.txt", b"plain text")
    source.seek(0)
    state = {"source": source, "closes": 0, "cleanup": None}

    class Archive(zipfile.ZipFile):
        def close(self):
            active = self.fp is not None
            super().close()
            if active:
                state["closes"] += 1
                if state["cleanup"] is not None:
                    raise state["cleanup"]

    monkeypatch.setattr(consumer, "zipfile", SimpleNamespace(
        **{**vars(zipfile), "ZipFile": Archive}))
    try:
        yield state
    finally:
        source.close()


def test_total_byte_refusal_survives_archive_close(archive_io):
    archive_io["cleanup"] = OSError("after native archive close")
    with pytest.raises(consumer.ZipTotalBytesExceeded):
        consumer.extract_files_from_zip(
            archive_io["source"], selector=lambda item: item.filename,
            max_total_bytes=0)
    assert archive_io["closes"] == 1
    assert not archive_io["source"].closed


@pytest.mark.parametrize("primary_type", [ValueError, MemoryError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt])
def test_selector_primary_survives_archive_close(archive_io, primary_type, close_type):
    primary = primary_type("selector refused")
    archive_io["cleanup"] = close_type("after native archive close")

    def select(_item):
        raise primary

    with pytest.raises(primary_type) as raised:
        consumer.extract_files_from_zip(archive_io["source"], selector=select)
    assert raised.value is primary
    assert archive_io["closes"] == 1
    assert not archive_io["source"].closed


@pytest.mark.parametrize("close_type", [OSError, KeyboardInterrupt, SystemExit])
def test_fresh_archive_close_failure_stays_visible(archive_io, close_type):
    cleanup = close_type("after native archive close")
    archive_io["cleanup"] = cleanup
    with pytest.raises(close_type) as raised:
        consumer.extract_files_from_zip(
            archive_io["source"], selector=lambda item: item.filename)
    assert raised.value is cleanup
    assert archive_io["closes"] == 1
    assert not archive_io["source"].closed


def test_success_retires_archive_and_keeps_borrowed_source(archive_io):
    assert consumer.extract_files_from_zip(
        archive_io["source"], selector=lambda item: item.filename,
    ) == {"plain.txt": b"plain text"}
    assert archive_io["closes"] == 1
    assert not archive_io["source"].closed
