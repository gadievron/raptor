"""An unreadable status channel must not promise that execution never began."""

import errno
import sys
from types import SimpleNamespace

import pytest

from core.sandbox import _spawn
from core.sandbox.errors import SandboxSetupError
from core.sandbox.tests.test_setup_status_codec_precedence import _execute
from core.testing.module_views import module_function_view

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux status dispatcher")


@pytest.mark.parametrize("prefix", [b"G:", b""])
def test_status_read_failure_reports_uncertain_execution(monkeypatch, tmp_path, prefix):
    chunks = [prefix] if prefix else []
    closed = []

    def read(fd, count):
        if chunks:
            return chunks.pop(0)
        raise OSError(errno.EIO, "owned status read error")

    private = module_function_view(_spawn, bindings={"os": SimpleNamespace(read=read, close=closed.append)})
    owned = {12345}
    status = private._drain_status_pipe(12345, owned)
    assert closed == [12345] and not owned
    with pytest.raises(SandboxSetupError) as caught:
        _execute(monkeypatch, tmp_path, status=status, stdout=b"", stderr=b"", encoding="utf-8")
    assert caught.value.setup_category == "!"
    assert "execution status is unknown" in caught.value.reason
    assert "could not be confirmed" in caught.value.reason
    assert "do not assume" in caught.value.instructions
    assert "the target never executed" not in caught.value.instructions


def test_missing_confirmation_remains_a_single_refusal(monkeypatch, tmp_path):
    status = _spawn._parse_setup_status(b"")
    with pytest.raises(SandboxSetupError) as caught:
        _execute(monkeypatch, tmp_path, status=status, stdout=b"", stderr=b"", encoding="utf-8")
    assert caught.value.setup_category == "!"
    assert "no exec confirmation" in caught.value.reason
    assert "could not be confirmed" in caught.value.reason
    assert "rc=99" in caught.value.reason
