"""Shared native captures retain private artifacts and the real exit status."""

from pathlib import Path

import pytest

from packages.frida.tests import test_e2e_live as native


@pytest.mark.parametrize("returncode", [0, 7], ids=["success", "failed-capture"])
def test_capture_snapshot_survives_consumer_mutation(
    tmp_path, tmp_path_factory, monkeypatch, returncode,
):
    calls = []
    expected = {
        Path("metadata.json"): b'{"ok":true}',
        Path("events.jsonl"): b'{"event":"owned"}\n',
        Path("nested/diagnostic.txt"): b"owned diagnostic",
    }

    def capture(binary, directory):
        calls.append((binary, directory))
        for relative, content in expected.items():
            path = directory / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        return returncode

    monkeypatch.setattr(native, "_run_frida_cli", capture)
    binary = tmp_path / "victim"
    snapshot = native.api_trace_capture.__wrapped__(binary, tmp_path_factory)
    assert len(calls) == 1 and calls[0][0] == binary
    assert isinstance(snapshot[1], tuple)
    assert dict(snapshot[1]) == expected

    first = tmp_path / "first"
    first.mkdir()
    assert native.api_trace_returncode.__wrapped__(snapshot, first) == returncode
    assert {path.relative_to(first): path.read_bytes()
            for path in first.rglob("*") if path.is_file()} == expected
    # A consumer can corrupt, remove or add files without changing the capture.
    (first / "metadata.json").write_bytes(b"changed")
    (first / "events.jsonl").unlink()
    (first / "extra.txt").write_text("consumer write")
    # The snapshot also owns its bytes independently of the native output tree.
    (calls[0][1] / "metadata.json").write_bytes(b"native file changed")

    second = tmp_path / "second"
    second.mkdir()
    assert native.api_trace_returncode.__wrapped__(snapshot, second) == returncode
    assert {path.relative_to(second): path.read_bytes()
            for path in second.rglob("*") if path.is_file()} == expected
    assert dict(snapshot[1]) == expected
    assert len(calls) == 1
