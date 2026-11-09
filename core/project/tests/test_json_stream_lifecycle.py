"""Project JSON uses the shared nonblocking, owned-file read boundary."""

import errno
import io
import os

import pytest

from core.project import cli
from core.source import gated
from core.testing.module_bindings import patch_module_attribute


@pytest.fixture
def document(tmp_path):
    path = tmp_path / "threat-model.json"
    path.write_bytes(b'{"owned": true}\n')
    return path, tmp_path


def test_project_json_open_is_nonblocking(document, monkeypatch, capsys):
    path, root = document
    real_open = os.open
    reached = []

    def opened(name, flags, *args, **kwargs):
        reached.append(flags)
        assert flags & os.O_NONBLOCK
        assert flags & os.O_NOFOLLOW
        return real_open(name, flags, *args, **kwargs)

    patch_module_attribute(monkeypatch, cli, "os", "open", opened)
    patch_module_attribute(monkeypatch, gated, "os", "open", opened)
    assert cli._stream_threat_model_json(path, root) == 0
    assert reached
    assert capsys.readouterr().out == path.read_text()


@pytest.mark.parametrize("error_type", [OSError, RuntimeError, KeyboardInterrupt, SystemExit])
def test_project_json_failed_wrapping_releases_descriptor(document, monkeypatch, capsys, error_type):
    path, root = document
    error = error_type("wrapping failed")
    retained = []

    def fail(fd, *args, **kwargs):
        info = os.fstat(fd)
        retained.append((fd, (info.st_dev, info.st_ino)))
        raise error

    patch_module_attribute(monkeypatch, cli, "os", "fdopen", fail)
    patch_module_attribute(monkeypatch, gated, "os", "fdopen", fail)
    try:
        if error_type is OSError:
            assert cli._stream_threat_model_json(path, root) == 1
            assert "wrapping failed" in capsys.readouterr().err
        else:
            with pytest.raises(error_type) as caught:
                cli._stream_threat_model_json(path, root)
            assert caught.value is error
        assert len(retained) == 1
        with pytest.raises(OSError) as closed:
            os.fstat(retained[0][0])
        assert closed.value.errno == errno.EBADF
    finally:
        for fd, identity in retained:
            try:
                info = os.fstat(fd)
            except OSError:
                continue
            if (info.st_dev, info.st_ino) == identity:
                os.close(fd)


def test_project_json_nonregular_refusal_stays_structured(document, monkeypatch, capsys):
    path, root = document
    reached = []

    def refuse(mode):
        reached.append(mode)
        return False

    patch_module_attribute(monkeypatch, gated, "_stat_mod", "S_ISREG", refuse)
    assert cli._stream_threat_model_json(path, root) == 1
    assert reached
    captured = capsys.readouterr()
    assert captured.out == "" and "not a regular file" in captured.err


def test_project_json_retains_byte_cap_and_truncation_disclosure(document, monkeypatch, capsys):
    path, root = document
    monkeypatch.setattr(cli, "_JSON_OUT_BYTE_CAP", 4)
    assert cli._stream_threat_model_json(path, root) == 0
    captured = capsys.readouterr()
    assert captured.out == path.read_bytes()[:4].decode()
    assert "output truncated" in captured.err


def test_project_json_keeps_outside_root_refusal(document, tmp_path, capsys):
    path, _ = document
    root = tmp_path / "other"
    root.mkdir()
    assert cli._stream_threat_model_json(path, root) == 1
    assert capsys.readouterr().out == ""


def test_output_error_survives_source_close_failure(document, monkeypatch):
    path, root = document
    primary = RuntimeError("output failed")
    real_fdopen = os.fdopen
    closed = []

    class Stream:
        def __init__(self, raw):
            self.raw = raw

        def __getattr__(self, name):
            return getattr(self.raw, name)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.raw.close()
            closed.append(self.raw.closed)
            raise OSError("source close failed")

    class BrokenOutput(io.BytesIO):
        def write(self, data):
            raise primary

    patch_module_attribute(monkeypatch, gated, "os", "fdopen",
                           lambda *a, **kw: Stream(real_fdopen(*a, **kw)))
    with io.TextIOWrapper(BrokenOutput(), encoding="utf-8") as output:
        patch_module_attribute(monkeypatch, cli, "sys", "stdout", output)
        with pytest.raises(RuntimeError) as caught:
            cli._stream_threat_model_json(path, root)
    assert caught.value is primary and closed == [True]
