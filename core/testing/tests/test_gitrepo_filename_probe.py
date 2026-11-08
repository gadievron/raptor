"""Filename integration probes distinguish encoding limits from I/O errors."""
import errno
import os

import pytest

from core.testing import gitrepo
from core.testing.module_bindings import patch_module_attribute


def test_filename_probe_removes_its_owned_files(tmp_path):
    assert isinstance(gitrepo.supports_non_utf8_filenames(tmp_path), bool)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX filename-byte probe")
@pytest.mark.parametrize("error", [OSError(errno.EILSEQ, "filename encoding"),
                                  UnicodeEncodeError("utf-8", "\udcff", 0, 1, "fixture")])
def test_filename_encoding_refusal_is_a_capability_result(tmp_path, monkeypatch, error):
    def fail(*args):
        raise error

    patch_module_attribute(monkeypatch, gitrepo, "os", "open", fail)
    assert not gitrepo.supports_non_utf8_filenames(tmp_path)
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX filename-byte probe")
@pytest.mark.parametrize("number", [errno.EIO, errno.ENOSPC, errno.EACCES])
def test_filename_probe_preserves_unrelated_failures(tmp_path, monkeypatch, number):
    error = OSError(number, "owned probe failure")

    def fail(*args):
        raise error

    patch_module_attribute(monkeypatch, gitrepo, "os", "open", fail)
    with pytest.raises(OSError) as caught:
        gitrepo.supports_non_utf8_filenames(tmp_path)
    assert caught.value is error
    assert list(tmp_path.iterdir()) == []
