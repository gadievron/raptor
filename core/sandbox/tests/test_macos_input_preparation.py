"""Darwin parent preparation controls; no native seatbelt enforcement claim."""

import errno
import os
import subprocess
import sys

import pytest

from core.sandbox import _macos_spawn as mac
from core.testing.module_views import module_function_view


@pytest.mark.parametrize("input_value,stdin_value", [
    (b"owned", subprocess.DEVNULL),
    (b"", subprocess.PIPE),
    ("", 0),
    ("owned", subprocess.DEVNULL),
], ids=["binary", "empty-binary", "empty-text-fd-zero", "text"])
def test_conflicting_input_is_refused_before_pipe_or_child_acquisition(
        input_value, stdin_value):
    real_pipe, real_close, real_stat = os.pipe, os.close, os.fstat
    owned = {}
    acquired = []

    def pipe():
        pair = real_pipe()
        for fd in pair:
            info = real_stat(fd)
            owned[fd] = (info.st_dev, info.st_ino)
        acquired.extend(pair)
        return pair

    def no_child(*args, **kwargs):
        pytest.fail("conflicting input must never start a child")

    private = module_function_view(mac, bindings={
        "os": module_function_view(os, bindings={"pipe": pipe}),
        "subprocess": module_function_view(subprocess, bindings={"Popen": no_child}),
    })
    try:
        with pytest.raises(ValueError, match="stdin and input"):
            private.run_sandboxed(
                [sys.executable, "-c", "pass"], env={}, nproc_limit=0,
                input=input_value, stdin=stdin_value)
        live = []
        for fd, identity in owned.items():
            try:
                info = real_stat(fd)
            except OSError as exc:
                assert exc.errno == errno.EBADF
            else:
                if (info.st_dev, info.st_ino) == identity:
                    live.append(fd)
        assert not live, f"caller-input refusal leaked {len(live)} owned pipe endpoints"
        assert acquired == [], "validate conflicting input before allocating pipes"
    finally:
        for fd, identity in owned.items():
            try:
                info = real_stat(fd)
            except OSError as exc:
                if exc.errno != errno.EBADF:
                    raise
            else:
                if (info.st_dev, info.st_ino) == identity:
                    real_close(fd)



def test_conflicting_input_is_refused_before_audit_evidence_preparation(tmp_path):
    def no_preparation(*args, **kwargs):
        pytest.fail("caller-input refusal must precede parent setup")

    private = module_function_view(mac, bindings={
        "_prepare_apple_tool": no_preparation,
    })
    with pytest.raises(ValueError, match="stdin and input"):
        private.run_sandboxed(
            [sys.executable, "-c", "pass"], env={}, nproc_limit=0,
            audit_mode=True, audit_run_dir=str(tmp_path),
            input=b"owned", stdin=subprocess.DEVNULL)
    assert not (tmp_path / ".audit").exists()
