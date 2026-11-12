"""Grant swap fixtures must preserve unrelated temporary allocations."""
from contextlib import nullcontext
import builtins
from pathlib import Path
import tempfile

import pytest

from core.build import build_detector
from core.build.artifacts import cleanup_build_paths
from core.build.tests import test_dry_run_ancestor_readable as native


@pytest.mark.parametrize("outcome", [None, RuntimeError, KeyboardInterrupt],
                         ids=["normal", "error", "interrupt"])
def test_actual_swap_fixture_preserves_global_lookup(tmp_path, outcome):
    original_class = native.BuildDetector
    discovery = build_detector.BuildDetector._discover_ancestor_includes
    refusal = vars(build_detector.BuildDetector)["_ancestor_include_refusal"]
    lookup, importer = tempfile.gettempdir, builtins.__import__
    real_tmp = Path(tempfile.gettempdir())
    expected = pytest.raises(outcome, match="owned body failure") if outcome else nullcontext()
    try:
        with expected:
            with pytest.MonkeyPatch.context() as patch:
                owned = native._owned_grant_temp_root.__wrapped__(patch)
                native.TestGrantReVetSharesDiscoveryPredicates().test_discovery_to_grant_swap_is_refused(
                    tmp_path, patch, owned)
                assert tempfile.gettempdir is lookup
                assert builtins.__import__ is importer
                assert build_detector.BuildDetector is original_class
                assert build_detector.BuildDetector._discover_ancestor_includes is discovery
                assert vars(build_detector.BuildDetector)["_ancestor_include_refusal"] is refusal
                assert native.BuildDetector._discover_ancestor_includes.__code__ is discovery.__code__
                assert native.BuildDetector._ancestor_include_refusal.__code__ is refusal.__func__.__code__
                with tempfile.NamedTemporaryFile(prefix="unrelated-") as allocated:
                    assert Path(allocated.name).parent == real_tmp
                    allocated.write(b"independent allocation")
                    allocated.flush()
                    assert Path(allocated.name).read_bytes() == b"independent allocation"
                if outcome:
                    raise outcome("owned body failure")
    finally:
        cleanup_build_paths(list(tmp_path.rglob(".raptor_build_*")))
    assert native.BuildDetector is original_class
    assert tempfile.gettempdir is lookup
    assert builtins.__import__ is importer
    assert build_detector.BuildDetector._discover_ancestor_includes is discovery
    assert vars(build_detector.BuildDetector)["_ancestor_include_refusal"] is refusal
    assert not list(tmp_path.rglob(".raptor_build_*"))
