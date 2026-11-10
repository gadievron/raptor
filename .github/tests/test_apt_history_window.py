"""Owned-file controls for the nightly APT history capture boundary."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts/apt_history_window.py"
_PRIOR = b"Start-Date: prior\nInstall: sdk-font (1)\nEnd-Date: prior\n\n"
_NEW = (
    b"Start-Date: native\n"
    b"Install: radare2 (1), llvm-21 (1), fonts-needed-by-tool (1)\n"
    b"End-Date: native\n\n"
)


@pytest.fixture
def window():
    # This stdlib-only helper does not mutate sys.path or require sys.modules.
    spec = importlib.util.spec_from_file_location("apt_history_window_test", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def captured(window, tmp_path):
    history = tmp_path / "history.log"
    metadata = tmp_path / "snapshot.json"
    output = tmp_path / "window.log"
    history.write_bytes(_PRIOR)
    window.snapshot(history, metadata)
    history.write_bytes(_PRIOR + _NEW)
    return history, metadata, output


def test_complete_window_keeps_exact_new_transactions(window, captured):
    history, metadata, output = captured
    window.extract(history, metadata, output)
    assert output.read_bytes() == _NEW
    assert b"sdk-font" not in output.read_bytes()
    assert b"fonts-needed-by-tool" in output.read_bytes()
    assert history.read_bytes() == _PRIOR + _NEW


def test_empty_prior_history_can_capture_first_transaction(window, tmp_path):
    history = tmp_path / "history.log"
    metadata = tmp_path / "snapshot.json"
    output = tmp_path / "window.log"
    history.write_bytes(b"")
    assert window.main(["snapshot", str(history), str(metadata)]) == 0
    history.write_bytes(_NEW)
    assert window.main(["extract", str(history), str(metadata), str(output)]) == 0
    assert output.read_bytes() == _NEW


@pytest.mark.parametrize("change", ["prefix", "truncate", "rotate"])
def test_changed_history_identity_or_prefix_is_refused(window, captured, change):
    history, metadata, output = captured
    if change == "prefix":
        history.write_bytes((_PRIOR + _NEW).replace(b"sdk-font", b"bad-font"))
    elif change == "truncate":
        history.write_bytes(_PRIOR[:10])
    else:
        old = history.with_suffix(".retired")
        history.rename(old)
        history.write_bytes(old.read_bytes())
    with pytest.raises(ValueError, match="identity or prior prefix changed"):
        window.extract(history, metadata, output)
    assert not output.exists()


@pytest.mark.parametrize("suffix", [
    b"", b"Start-Date: native\nInstall: llvm-21 (1)\n",
    b"End-Date: native\n", b"outside transaction\n",
    b"Start-Date: first\nStart-Date: second\nEnd-Date: second\n",
    _NEW.rstrip(b"\n"),
], ids=["empty", "unfinished", "end-without-start", "outside", "nested", "no-final-newline"])
def test_incomplete_or_malformed_new_window_is_refused(window, captured, suffix):
    history, metadata, output = captured
    history.write_bytes(_PRIOR + suffix)
    with pytest.raises(ValueError):
        window.extract(history, metadata, output)
    assert not output.exists()


@pytest.mark.parametrize("data", [
    _PRIOR.rstrip(b"\n"), b"Start-Date: prior\nInstall: sdk-font (1)\n",
    b"orphan\n",
], ids=["line-boundary", "transaction-boundary", "outside"])
def test_invalid_snapshot_does_not_create_metadata(window, tmp_path, data):
    history = tmp_path / "history.log"
    metadata = tmp_path / "snapshot.json"
    history.write_bytes(data)
    with pytest.raises(ValueError):
        window.snapshot(history, metadata)
    assert not metadata.exists()


@pytest.mark.parametrize("key,value", [
    ("version", 2), ("version", True), ("device", -1), ("inode", "1"),
    ("size", True), ("size", -1), ("prefix_sha256", "not-a-digest"),
    ("prefix_sha256", 1),
])
def test_invalid_snapshot_fields_are_refused(window, captured, key, value):
    history, metadata, output = captured
    state = json.loads(metadata.read_text())
    state[key] = value
    metadata.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="invalid history snapshot"):
        window.extract(history, metadata, output)
    assert not output.exists()


@pytest.mark.parametrize("body", ["[]", "{}", '{"version":1,"version":1}', "{"])
def test_malformed_or_duplicate_metadata_is_refused(window, captured, body):
    history, metadata, output = captured
    metadata.write_text(body)
    with pytest.raises(ValueError):
        window.extract(history, metadata, output)
    assert not output.exists()


def test_snapshot_offset_inside_line_is_refused(window, captured):
    import hashlib

    history, metadata, output = captured
    state = json.loads(metadata.read_text())
    state["size"] = len(_PRIOR.rstrip(b"\n"))
    state["prefix_sha256"] = hashlib.sha256(history.read_bytes()[:state["size"]]).hexdigest()
    metadata.write_text(json.dumps(state))
    with pytest.raises(ValueError, match="inside a history line"):
        window.extract(history, metadata, output)
    assert not output.exists()


@pytest.mark.parametrize("operation", ["snapshot-history", "extract-history", "extract-metadata"])
def test_input_overwrite_is_refused(window, captured, operation):
    history, metadata, output = captured
    before = history.read_bytes(), metadata.read_bytes()
    with pytest.raises(ValueError, match="must not overwrite"):
        if operation == "snapshot-history":
            window.snapshot(history, history)
        else:
            window.extract(history, metadata, history if operation == "extract-history" else metadata)
    assert (history.read_bytes(), metadata.read_bytes()) == before
    assert not output.exists()


def test_read_time_mutation_is_refused_and_descriptor_closed(window, captured, monkeypatch):
    history, metadata, output = captured
    original_fstat = window.os.fstat
    descriptors = []

    def mutate_on_second_stat(fd):
        descriptors.append(fd)
        if len(descriptors) == 2:
            with history.open("ab") as stream:
                stream.write(_NEW)
        return original_fstat(fd)

    monkeypatch.setattr(window.os, "fstat", mutate_on_second_stat)
    with pytest.raises(ValueError, match="changed while reading"):
        window.extract(history, metadata, output)
    assert len(descriptors) == 2
    with pytest.raises(OSError):
        original_fstat(descriptors[0])
    assert not output.exists()


@pytest.mark.parametrize("failure", [OSError("owned read fault"), KeyboardInterrupt()])
def test_history_descriptor_closes_on_read_observation_failure(window, captured, monkeypatch, failure):
    history, metadata, output = captured
    original_fstat = window.os.fstat
    descriptors = []

    def fail_on_second_stat(fd):
        descriptors.append(fd)
        if len(descriptors) == 2:
            raise failure
        return original_fstat(fd)

    monkeypatch.setattr(window.os, "fstat", fail_on_second_stat)
    with pytest.raises(type(failure)) as error:
        window.extract(history, metadata, output)
    assert error.value is failure
    with pytest.raises(OSError):
        original_fstat(descriptors[0])
    assert not output.exists()


@pytest.mark.parametrize("command", ["snapshot", "extract"])
def test_partial_output_write_failure_returns_nonzero(window, captured, monkeypatch, capsys, command):
    history, metadata, output = captured
    destination = metadata if command == "snapshot" else output
    method = "write_text" if command == "snapshot" else "write_bytes"
    original = getattr(Path, method)

    def partial_then_fail(path, data, *args, **kwargs):
        if path == destination:
            original(path, data[:3], *args, **kwargs)
            raise OSError("owned output write fault")
        return original(path, data, *args, **kwargs)

    monkeypatch.setattr(Path, method, partial_then_fail)
    argv = [command, str(history), str(metadata)]
    if command == "extract":
        argv.append(str(output))
    assert window.main(argv) == 1
    assert "owned output write fault" in capsys.readouterr().err
    assert len(destination.read_bytes()) == 3
    assert history.read_bytes() == _PRIOR + _NEW


def test_missing_history_returns_nonzero_without_metadata(window, tmp_path, capsys):
    metadata = tmp_path / "snapshot.json"
    assert window.main(["snapshot", str(tmp_path / "absent"), str(metadata)]) == 1
    assert "[apt-history-window]" in capsys.readouterr().err
    assert not metadata.exists()


def test_successful_read_closes_owned_descriptor(window, captured, monkeypatch):
    history, metadata, output = captured
    original_fstat = window.os.fstat
    descriptors = []

    def record_stat(fd):
        descriptors.append(fd)
        return original_fstat(fd)

    monkeypatch.setattr(window.os, "fstat", record_stat)
    window.extract(history, metadata, output)
    assert output.read_bytes() == _NEW
    assert len(descriptors) == 2
    with pytest.raises(OSError):
        original_fstat(descriptors[0])
