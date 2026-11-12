"""Codec preparation on the inert namespace dispatcher, without a child."""

import fcntl
import os
import subprocess
import sys

import pytest

from core.sandbox import context
from core.sandbox.tests.test_context_decision_pins import _Driver
from core.sandbox.tests.test_setup_status_codec_precedence import _execute
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux dispatcher preparation")


@pytest.mark.parametrize("encoding", ["locale", "utf-8"])
def test_explicit_codec_decodes_successful_namespace_result(monkeypatch, tmp_path, encoding):
    result = _execute(monkeypatch, tmp_path, status=None,
                      stdout=b"owned\r\n", stderr=b"error\r\n", encoding=encoding)
    assert result.stdout == "owned\n"
    assert result.stderr == "error\n"


@pytest.mark.parametrize("encoding", ["locale", "utf-8"])
def test_explicit_codec_encodes_owned_readonly_input_spool(monkeypatch, tmp_path, encoding):
    streams = []

    def backend(cmd, **kwargs):
        assert kwargs["text"] is False
        stream = kwargs["stdin"]
        streams.append(stream)
        assert fcntl.fcntl(stream.fileno(), fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY
        assert stream.read() == b"owned input"
        result = subprocess.CompletedProcess(cmd, 0, None, None)
        result._setup_status = None
        return result

    def forbid_process(*args, **kwargs):
        pytest.fail("codec preparation must not launch a process")

    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    _Driver(monkeypatch, backend)
    monkeypatch.setattr(context, "_run_teardown_first_timeout", forbid_process)
    patch_module_attribute(monkeypatch, context, "subprocess", "Popen", forbid_process)
    with context.sandbox(profile="full", target=str(tmp_path)) as run:
        result = run(["/bin/true"], input="owned input", encoding=encoding,
                     capture_output=True, timeout=1)
        assert result.returncode == 0
    assert len(streams) == 1
    assert streams[0].closed
