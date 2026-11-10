"""Raw ffuf request-file compatibility through the shared capped reader."""

import os
from pathlib import Path
import subprocess
import sys

import pytest

from core.testing.processes import run_in_process_group
from packages.web.ffuf import FfufConfig, FfufRunner


@pytest.mark.integration
def test_ffuf_fifo_request_file_refused_without_writer(tmp_path):
    fifo = tmp_path / "request.txt"
    os.mkfifo(fifo, 0o600)
    result = run_in_process_group([
        sys.executable, "-c", """
import sys
from pathlib import Path
from packages.web.ffuf import FfufConfig, FfufRunner
path = Path(sys.argv[1])
try:
    FfufRunner('https://example.test', path.parent)._read_scoped_request_file(
        FfufConfig(wordlist=path.parent / "words.txt", request_file=path))
except ValueError:
    print('refused')
else:
    raise AssertionError('FIFO accepted')
""", str(fifo)], cwd=Path(__file__).resolve().parents[3], timeout=8,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
    )
    assert result.stdout.strip() == "refused"


def test_ffuf_operator_symlink_and_crlf_are_preserved(tmp_path):
    path = tmp_path / "request.txt"
    path.write_bytes(b"GET /FUZZ HTTP/1.1\r\nHost: example.test\r\n\r\n")
    link = tmp_path / "selected-request"
    link.symlink_to(path)
    actual = FfufRunner("https://example.test", tmp_path)._read_scoped_request_file(
        FfufConfig(wordlist=tmp_path / "words.txt", request_file=link),
    )
    assert actual == path.read_text()
