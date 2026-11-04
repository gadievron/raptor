"""A failed working-copy preparation may leave a large partial database."""

import pytest
from packages.ghidra import server


@pytest.mark.parametrize("error", [OSError("disk full"), KeyboardInterrupt()])
def test_copy_failure_cleans_server_and_allows_retry(tmp_path, monkeypatch, error):
    monkeypatch.setattr(server, "pyghidra_available", lambda: True)
    work = tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr(server.tempfile, "mkdtemp", lambda **kw: str(work))

    def copy(source, destination):
        (destination / "partial.rep").write_bytes(b"partial database")
        raise error

    monkeypatch.setattr(server, "prepare_working_copy", copy)
    instance = server.GhidraServer(tmp_path / "source.gpr")
    with pytest.raises(type(error)):
        instance.start()
    assert not work.exists()
    assert instance._work_dir is None
    assert instance._work_gpr is None
    work.mkdir()
    monkeypatch.setattr(
        server,
        "prepare_working_copy",
        lambda source, destination: destination / "ok.gpr",
    )
    monkeypatch.setattr(instance, "_boot", lambda: None)
    try:
        instance.start()
        assert instance._work_gpr == work / "ok.gpr"
    finally:
        instance.stop()
