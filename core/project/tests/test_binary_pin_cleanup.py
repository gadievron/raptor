"""Binary-add pinning retains read errors while retiring its owned descriptor."""
import errno
import hashlib
import io
import os
import sys
from types import ModuleType, SimpleNamespace

import pytest

from core.project import cli
from core.project.project import ProjectManager
from core.testing.module_views import module_function_view
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture
def pin(tmp_path):
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path)
        target = tmp_path / "target"
        target.mkdir()
        manager = ProjectManager()
        project = manager.create("pin-owned", str(target), output_dir=str(tmp_path / "output"))
        path = target / "owned.bin"
        payload = b"owned inert binary witness\n"
        path.write_bytes(payload)
        record = manager.projects_dir / "pin-owned.json"
        original_record = record.read_bytes()
        state = SimpleNamespace(primary=None, cleanup=None, reads=[], closes=0,
                                streams=[], fd=None, path=path, payload=payload,
                                manager=manager, record=record, original_record=original_record)
        import core.source as source
        native_open = source.open_regular_gated

        class Reader(io.BufferedReader):
            def read(self, size=-1):
                data = super().read(size)
                state.reads.append(data)
                if state.primary is not None:
                    raise state.primary
                return data

            def close(self):
                if self.closed:
                    return super().close()
                super().close()
                state.closes += 1
                if state.cleanup is not None:
                    raise state.cleanup

        def owned_open(candidate, *, follow_symlinks):
            assert candidate == path.resolve() and follow_symlinks is False
            stream = native_open(candidate, follow_symlinks=follow_symlinks)
            state.fd = stream.fileno()
            info = os.fstat(state.fd)
            expected = path.stat()
            assert (info.st_dev, info.st_ino) == (expected.st_dev, expected.st_ino)
            reader = Reader(stream)
            state.streams.extend([stream, reader])
            return reader

        private_source = ModuleType(source.__name__)
        vars(private_source).update(vars(source))
        private_source.open_regular_gated = owned_open
        original_import = __import__

        def local_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name == "core.source" and level == 0:
                return private_source
            return original_import(name, globals, locals, fromlist, level)

        view = module_function_view(cli, import_hook=local_import)
        patch.setattr(sys, "argv", ["raptor project", "binary", "add", str(path), project.name])
        state.run = view.main
        try:
            yield state
        finally:
            for stream in reversed(state.streams):
                if not stream.closed:
                    io.BufferedReader.close(stream)
            assert path.read_bytes() == payload


def retired(pin):
    assert b"".join(pin.reads) == pin.payload
    assert pin.closes == 1 and all(stream.closed for stream in pin.streams)
    with pytest.raises(OSError) as caught:
        os.fstat(pin.fd)
    assert caught.value.errno == errno.EBADF


@pytest.mark.parametrize("primary", [KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("cleanup", [OSError, MemoryError])
def test_public_binary_add_preserves_read_cancellation(pin, primary, cleanup):
    pin.primary = primary("after actual owned read")
    pin.cleanup = cleanup("after consumed close")
    with pytest.raises(SystemExit) as caught:
        pin.run()
    if primary is KeyboardInterrupt:
        assert caught.value.code == 130
        assert caught.value.__context__ is pin.primary
    else:
        assert caught.value is pin.primary
    retired(pin)
    assert pin.record.read_bytes() == pin.original_record


@pytest.mark.parametrize("cleanup", [OSError, KeyboardInterrupt])
def test_public_binary_add_fresh_close_policy(pin, cleanup, capsys):
    pin.cleanup = cleanup("after consumed close")
    if cleanup is OSError:
        pin.run()
        assert "not added" in capsys.readouterr().out
    else:
        with pytest.raises(SystemExit) as caught:
            pin.run()
        assert caught.value.code == 130
        assert caught.value.__context__ is pin.cleanup
    retired(pin)
    assert pin.record.read_bytes() == pin.original_record


def test_public_binary_add_healthy_same_file_witness(pin):
    pin.run()
    retired(pin)
    project = pin.manager.load("pin-owned")
    assert project.binaries == [str(pin.path)]
    assert project.binary_witnesses == {str(pin.path): hashlib.sha256(pin.payload).hexdigest()}


def test_public_binary_add_read_oserror_refuses(pin, capsys):
    pin.primary = OSError("after owned read")
    pin.cleanup = KeyboardInterrupt("after consumed close")
    pin.run()
    retired(pin)
    assert "not added" in capsys.readouterr().out
    assert pin.record.read_bytes() == pin.original_record
