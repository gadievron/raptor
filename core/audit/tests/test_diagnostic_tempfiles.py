"""Heartbeat and disk-health diagnostics cannot strand partial temporary files."""

import json
import os
from pathlib import Path
import tempfile
import types

import pytest

from core.audit import environment, heartbeat
from core.run import scratch


@pytest.fixture
def files(monkeypatch):
    created = []
    original = tempfile.NamedTemporaryFile
    configure = [lambda stream: None]

    def allocate(**kwargs):
        stream = original(**kwargs)
        created.append((stream, stream.close, Path(stream.name)))
        configure[0](stream)
        return stream

    proxy = types.ModuleType("diagnostic_tempfile")
    proxy.__dict__.update(vars(tempfile))
    proxy.NamedTemporaryFile = allocate
    monkeypatch.setattr(scratch, "tempfile", proxy)
    try:
        yield created, configure
    finally:
        for stream, close, path in created:
            close()
            path.unlink(missing_ok=True)


def _probe(tmp_path):
    guard = environment.EnvironmentGuard(tmp_dir=tmp_path, drain_margin_s=0)
    guard._statvfs = None  # Exercise the canary, not filesystem floor arithmetic.
    return guard


@pytest.fixture(autouse=True)
def _fixed_floor(monkeypatch):
    monkeypatch.setenv("RAPTOR_ENV_FLOOR_MIB", "0")


@pytest.mark.parametrize("consumer", ["heartbeat", "probe"])
@pytest.mark.parametrize("stage", ["write", "close"])
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_write_or_close_failure_leaves_no_artifact(tmp_path, files, consumer, stage, error):
    created, configure = files

    def configure_stream(stream):
        write, close = stream.write, stream.close

        def fail_write(text):
            write(text[:2])
            raise error("diagnostic failure")

        def fail_close():
            close()
            raise error("diagnostic failure")

        setattr(stream, stage, fail_write if stage == "write" else fail_close)

    configure[0] = configure_stream
    if consumer == "heartbeat":
        writer = heartbeat.Heartbeat(tmp_path, "phase")
        if error is OSError:
            writer.beat(done=1)
            assert writer._failed
        else:
            with pytest.raises(error, match="diagnostic failure"):
                writer.beat(done=1)
    else:
        with pytest.raises(error, match="diagnostic failure"):
            _probe(tmp_path)._disk_ok(tmp_path)
    assert created
    assert all(stream.file.closed for stream, _, _ in created)
    assert not list(tmp_path.iterdir())


@pytest.mark.parametrize("consumer", ["heartbeat", "probe"])
@pytest.mark.parametrize("chunk", [1, 7])
def test_raw_short_writes_are_completed_before_use(tmp_path, files, consumer, chunk, monkeypatch):
    created, configure = files
    observed = []

    def configure_stream(stream):
        raw = stream.file.buffer.raw
        write, close = raw.write, stream.close
        monkeypatch.setattr(raw, "write", lambda data: write(data[:chunk]))

        def observe_closed_file():
            close()
            observed.append(Path(stream.name).read_bytes())

        stream.close = observe_closed_file

    configure[0] = configure_stream
    if consumer == "heartbeat":
        writer = heartbeat.Heartbeat(tmp_path, "phase")
        writer.beat(done=7)
        assert json.loads((tmp_path / heartbeat.HEARTBEAT_FILENAME).read_bytes())["done"] == 7
        assert json.loads(observed[0])["done"] == 7
    else:
        assert _probe(tmp_path)._disk_ok(tmp_path)
        assert observed == [b"\0" * 4096]
        assert not list(tmp_path.iterdir())
    assert created and all(stream.file.closed for stream, _, _ in created)
    assert all(path.parent == tmp_path and not path.exists() for _, _, path in created)


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt])
def test_failed_heartbeat_publication_preserves_previous_payload(tmp_path, monkeypatch, error):
    writer = heartbeat.Heartbeat(tmp_path, "phase", interval_s=0)
    writer.beat(done=1)
    target = tmp_path / heartbeat.HEARTBEAT_FILENAME
    before = target.read_bytes()
    proxy = types.ModuleType("heartbeat_os")
    proxy.__dict__.update(vars(os))

    def fail(*args, **kwargs):
        raise error("publication failure")

    proxy.replace = fail
    monkeypatch.setattr(heartbeat, "os", proxy)
    if error is OSError:
        writer.beat(done=2)
        assert writer._failed
    else:
        with pytest.raises(error, match="publication failure"):
            writer.beat(done=2)
    assert target.read_bytes() == before
    assert list(tmp_path.iterdir()) == [target]


@pytest.mark.parametrize("field", ["done", "total", "detail", "phase"])
def test_bad_diagnostic_payload_disables_once_without_allocating(tmp_path, files, field, caplog):
    created, _ = files
    writer = heartbeat.Heartbeat(tmp_path, "phase")
    kwargs = {field: object()}
    if field == "phase":
        writer.phase = kwargs.pop("phase")
    writer.beat(**kwargs)
    writer.beat(done=2)
    assert writer._failed
    assert not created
    assert not list(tmp_path.iterdir())
    assert sum("heartbeat write" in record.getMessage() for record in caplog.records) == 1


def test_removed_probe_directory_is_not_recreated(tmp_path):
    path = tmp_path / "removed"
    with pytest.raises(FileNotFoundError):
        _probe(tmp_path)._disk_ok(path)
    assert not path.exists()
