"""Scratch allocations are owned before setup can fail."""

from pathlib import Path
import pytest
from core.run import scratch


from core.testing.module_bindings import patch_module_attribute

import core.run.scratch as _tempfile_owner


@pytest.fixture(autouse=True)
def _owned_tempfile_namespace(monkeypatch):
    """Share temporary-root faults only among this file's consumers."""
    from core.testing.tempdirs import private_tempfile_module
    import core.run.scratch as consumer_0

    private = private_tempfile_module(consumer_0.tempfile)
    monkeypatch.setattr(consumer_0, "tempfile", private)
    monkeypatch.setitem(globals(), "tempfile", private)


@pytest.mark.parametrize("keep", [False, True])
@pytest.mark.parametrize("stage", ["register", "advisory", "env"])
@pytest.mark.parametrize("error", [OSError("disk full"), KeyboardInterrupt()])
def test_setup_failure_removes_allocation(tmp_path, monkeypatch, stage, error, keep):
    allocated = tmp_path / "scratch"
    allocated.mkdir()
    patch_module_attribute(monkeypatch, scratch, 'tempfile', "mkdtemp", lambda **kw: str(allocated))
    live = set()

    def register(path):
        live.add(path)
        if stage == "register":
            raise error

    def advisory(path):
        if stage == "advisory":
            raise error

    class BadEnv(dict):
        def __setitem__(self, key, value):
            raise error

    monkeypatch.setattr(scratch, "keepalive_register", register)
    monkeypatch.setattr(scratch, "keepalive_unregister", live.discard)
    monkeypatch.setattr(scratch, "_inode_ceiling_advisory", advisory)
    with pytest.raises(type(error)):
        with scratch.scratch_dir(
            "raptor-test-", env=BadEnv() if stage == "env" else None, keep=keep
        ):
            pytest.fail("setup must fail before yielding")
    assert not allocated.exists()
    assert not live


@pytest.mark.parametrize("failure", ["write", "close"])
@pytest.mark.parametrize("error", [OSError("disk full"), KeyboardInterrupt()])
def test_temp_text_failure_removes_partial_file(tmp_path, monkeypatch, failure, error):
    original = scratch.tempfile.NamedTemporaryFile
    paths = []

    class Broken:
        def __init__(self, *args, **kw):
            kw["dir"] = tmp_path
            self.file = original(*args, **kw)
            self.name = self.file.name
            paths.append(Path(self.name))

        def __enter__(self):
            return self

        def write(self, text):
            self.file.write(text[:2])
            if failure == "write":
                raise error

        def close(self):
            self.file.close()
            if failure == "close":
                raise error

        def __exit__(self, *exc):
            self.close()

    patch_module_attribute(monkeypatch, scratch, 'tempfile', "NamedTemporaryFile", Broken)
    with pytest.raises(type(error)):
        scratch.write_temp_text("payload", prefix="rule-", suffix=".yaml")
    assert paths and all(not p.exists() for p in paths)


def test_temp_text_success_transfers_closed_utf8_file(tmp_path, monkeypatch):
    monkeypatch.setattr(_tempfile_owner.tempfile, 'tempdir', str(tmp_path))
    path = scratch.write_temp_text("café", prefix="rule-", suffix=".yaml")
    try:
        assert path.read_bytes() == "café".encode("utf-8")
        assert path.name.startswith("rule-") and path.suffix == ".yaml"
    finally:
        path.unlink(missing_ok=True)
