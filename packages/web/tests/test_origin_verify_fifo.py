"""Verification-file admission is bounded and retires owned descriptors."""

import errno
import os
from pathlib import Path
import subprocess
import sys

import pytest

from core.source import gated
from core.testing.module_bindings import patch_module_attribute
from core.testing.processes import run_in_process_group
from packages.web.origin_verify import read_value


@pytest.mark.integration
def test_fifo_without_writer_is_rejected_without_blocking(tmp_path):
    path = tmp_path / "verification.fifo"
    os.mkfifo(path, 0o600)
    result = run_in_process_group(
        [sys.executable, "-c", """
import sys
from packages.web.origin_verify import read_value
try:
    read_value(sys.argv[1])
except ValueError as error:
    assert str(error) == 'origin verification file must be regular and owner-only'
    print('FIFO refused')
else:
    raise AssertionError('FIFO accepted')
""", str(path)],
        cwd=Path(__file__).resolve().parents[3], timeout=3,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
    )
    assert result.stdout.strip() == "FIFO refused"


@pytest.mark.parametrize("kind,message", [
    ("valid", None),
    ("public", "regular and owner-only"),
    ("directory", "regular and owner-only"),
    ("oversized", "too large"),
    ("invalid", "invalid content"),
    ("nonascii", "invalid content"),
])
def test_descriptor_closed_after_success_or_refusal(tmp_path, monkeypatch, kind, message):
    path = tmp_path / "verification"
    if kind == "directory":
        path.mkdir(mode=0o700)
    else:
        data = {"oversized": b"a" * 129, "invalid": b"x" * 64,
                "nonascii": b"\xff" * 64}.get(kind, b"a" * 64)
        path.write_bytes(data)
        path.chmod(0o644 if kind == "public" else 0o600)
    opened = []
    original_open = os.open

    def opening(*args, **kwargs):
        fd = original_open(*args, **kwargs)
        opened.append(fd)
        return fd

    patch_module_attribute(monkeypatch, gated, "os", "open", opening)
    if message is None:
        assert read_value(path) == "a" * 64
    else:
        with pytest.raises(ValueError, match=message):
            read_value(path)
    assert len(opened) == 1
    with pytest.raises(OSError) as retired:
        os.fstat(opened[0])
    assert retired.value.errno == errno.EBADF


def test_permissions_refused_before_body_adoption(tmp_path, monkeypatch):
    path = tmp_path / "verification"
    path.write_bytes(b"a" * 64)
    path.chmod(0o640)

    def unexpected_adoption(*args, **kwargs):
        pytest.fail("permission refusal must precede body adoption")

    monkeypatch.setattr(gated, "adopt_fd", unexpected_adoption)
    with pytest.raises(ValueError, match="regular and owner-only"):
        read_value(path)


def test_symlink_and_missing_path_keep_read_error(tmp_path):
    target = tmp_path / "verification"
    target.write_bytes(b"a" * 64)
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target)
    for path in (link, tmp_path / "missing"):
        with pytest.raises(ValueError, match="cannot read origin verification file"):
            read_value(path)


def test_private_file_whitespace_and_hardlink_remain_supported(tmp_path):
    path = tmp_path / "verification"
    path.write_bytes(b" \n" + b"A" * 64 + b"\n ")
    path.chmod(0o600)
    link = tmp_path / "hardlink"
    os.link(path, link)
    assert read_value(link) == "A" * 64
