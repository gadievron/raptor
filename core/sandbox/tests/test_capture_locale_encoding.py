"""Capped capture uses the codecs resolved by the owned pipe wrappers."""

import subprocess
import sys

import pytest

from core.sandbox.context import _run_teardown_first_timeout


@pytest.mark.parametrize("cap", [None, 64, 3], ids=["uncapped", "complete", "clipped"])
def test_locale_encoding_matches_owned_text_pipes(cap):
    result = _run_teardown_first_timeout(
        [sys.executable, "-I", "-c",
         "import os; os.write(1, b'first\\r\\n'); os.write(2, b'second\\r\\n')"],
        {"capture_output": True, "encoding": "locale", "timeout": 5},
        [None], start_new_session=True,
        max_capture_bytes=cap, teardown_first=False,
    )
    assert result.returncode == 0
    if cap == 3:
        assert result.stdout == "fir\n[sandbox: stdout capture truncated at 3 bytes]\n"
        assert result.stderr == "sec\n[sandbox: stderr capture truncated at 3 bytes]\n"
    else:
        assert result.stdout == "first\n"
        assert result.stderr == "second\n"


def test_locale_encoding_with_redirected_stdout(tmp_path):
    with (tmp_path / "owned-output").open("wb+") as output:
        result = _run_teardown_first_timeout(
            [sys.executable, "-I", "-c",
             "import os; os.write(1, b'file'); os.write(2, b'pipe')"],
            {"stdout": output, "stderr": subprocess.PIPE,
             "encoding": "locale", "errors": "replace", "timeout": 5},
            [None], start_new_session=True,
            max_capture_bytes=64, teardown_first=False,
        )
        assert result.returncode == 0
        assert result.stdout is None
        assert result.stderr == "pipe"
        assert not output.closed
        output.seek(0)
        assert output.read() == b"file"
