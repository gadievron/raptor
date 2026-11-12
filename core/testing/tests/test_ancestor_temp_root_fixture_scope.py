"""Ancestor policy fakes must not redirect unrelated temporary-file allocations."""
from contextlib import nullcontext
import builtins
from pathlib import Path
import tempfile

import pytest

from core.build import build_detector
from core.build.tests import test_ancestor_includes_tmp as native


@pytest.mark.parametrize("name", [
    "test_system_tempdir_include_not_adopted",
    "test_symlinked_include_resolving_into_tempdir_rejected",
], ids=["shared-root", "symlink-root"])
@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_ancestor_fixture_owns_lookup_and_restores_bindings(tmp_path, name, outcome):
    detector_class, namespace = native.BuildDetector, native.tempfile
    discovery = build_detector.BuildDetector._discover_ancestor_includes
    refusal = vars(build_detector.BuildDetector)["_ancestor_include_refusal"]
    lookup, importer = tempfile.gettempdir, builtins.__import__
    real_tmp = Path(tempfile.gettempdir())
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    with expected:
        with pytest.MonkeyPatch.context() as patch:
            native._owned_temp_root_lookup.__wrapped__(patch)
            getattr(native.TestTempRootAncestorBlocked(), name)(tmp_path, patch)
            assert tempfile.gettempdir is lookup
            assert builtins.__import__ is importer
            assert build_detector.BuildDetector is detector_class
            assert build_detector.BuildDetector._discover_ancestor_includes is discovery
            assert vars(build_detector.BuildDetector)["_ancestor_include_refusal"] is refusal
            assert native.BuildDetector._discover_ancestor_includes.__code__ is discovery.__code__
            assert native.BuildDetector._ancestor_include_refusal.__code__ is refusal.__func__.__code__
            with tempfile.NamedTemporaryFile(prefix="unrelated-") as allocated:
                assert Path(allocated.name).parent == real_tmp
                allocated.write(b"unrelated allocation")
                allocated.flush()
                assert Path(allocated.name).read_bytes() == b"unrelated allocation"
            if outcome:
                raise outcome("owned body failure")
    assert native.BuildDetector is detector_class
    assert native.tempfile is namespace
    assert tempfile.gettempdir is lookup
    assert builtins.__import__ is importer
    assert build_detector.BuildDetector._discover_ancestor_includes is discovery
    assert vars(build_detector.BuildDetector)["_ancestor_include_refusal"] is refusal
