"""Build creation faults leave unrelated tempfile allocations available."""
from contextlib import nullcontext
import builtins
import os
import tempfile

import pytest

from core.build.tests import test_build_artifact_lifecycle as native


@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_script_creation_fault_owns_only_its_detector(tmp_path, monkeypatch, error, outcome):
    detector = native.detector.__wrapped__(tmp_path, monkeypatch)
    method = native.bd.BuildDetector.synthesise_build_command
    original_mkstemp, importer = tempfile.mkstemp, builtins.__import__
    assert "synthesise_build_command" not in vars(detector)
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            native.test_creation_and_transfer_failures_leave_no_artifacts(
                detector, tmp_path, patch, error, "script_create")
            assert native.bd.BuildDetector.synthesise_build_command is method
            assert detector.synthesise_build_command.__func__.__code__ is method.__code__
            assert tempfile.mkstemp is original_mkstemp
            assert builtins.__import__ is importer
            fd, name = tempfile.mkstemp(dir=tmp_path, prefix="unrelated-")
            try:
                os.write(fd, b"independent allocation")
                assert os.fstat(fd).st_size == len(b"independent allocation")
            finally:
                os.close(fd)
                os.unlink(name)
            if outcome:
                raise outcome("owned body failure")
    assert "synthesise_build_command" not in vars(detector)
    assert native.bd.BuildDetector.synthesise_build_command is method
    assert tempfile.mkstemp is original_mkstemp
    assert builtins.__import__ is importer
    assert not list(tmp_path.glob(".raptor_build_*"))
    assert not list(tmp_path.glob("unrelated-*"))
