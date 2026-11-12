"""Timeout snapshots encode text with the owned stream's resolved codec."""

import subprocess
import sys

import pytest

from core.sandbox.context import _timeout_snapshot


@pytest.mark.parametrize("encoding", ["locale", "utf-8"])
def test_completed_owned_pipe_text_extends_raw_timeout_snapshot(encoding):
    with subprocess.Popen(
        [sys.executable, "-I", "-c",
         "import os; os.write(1, b'alpha'); os.write(2, b'beta')"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        encoding=encoding,
    ) as proc:
        out, err = proc.communicate(timeout=5)
        assert proc.returncode == 0
        failure = subprocess.TimeoutExpired(proc.args, 1, output=b"a", stderr=b"b")
        _timeout_snapshot(failure, proc, out, err)
        assert failure.output == b"alpha"
        assert failure.stderr == b"beta"


def test_newline_translation_does_not_replace_incompatible_raw_prefix():
    with subprocess.Popen(
        [sys.executable, "-I", "-c", "import os; os.write(1, b'a\\r\\nb')"],
        stdout=subprocess.PIPE, encoding="locale",
    ) as proc:
        out, _ = proc.communicate(timeout=5)
        assert proc.returncode == 0
        failure = subprocess.TimeoutExpired(proc.args, 1, output=b"a\r\n")
        _timeout_snapshot(failure, proc, out)
        assert failure.output == b"a\r\n"
        assert failure.stderr is None


def test_raw_snapshots_do_not_require_text_stream_metadata():
    failure = subprocess.TimeoutExpired("owned", 1, output=b"a", stderr=b"b")
    _timeout_snapshot(failure, object(), b"alpha", b"beta")
    assert failure.output == b"alpha"
    assert failure.stderr == b"beta"
