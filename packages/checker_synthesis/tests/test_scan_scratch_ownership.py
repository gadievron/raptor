"""Scanner fixture cleanup restores borrowed parents and registrations."""

from pathlib import Path

import pytest

from core.run import scratch
from packages.semgrep import runner
from packages.checker_synthesis.tests.conftest import _owned_scan_scratch


@pytest.mark.parametrize("ending", ["normal", "throw", "close"])
@pytest.mark.parametrize("body_undo", [False, True])
def test_nested_scan_fixture_preserves_borrowed_parent(ending, body_undo):
    borrowed = runner._sandbox_scratch_parent()
    registrations = scratch._keepalive_paths
    assert borrowed in registrations
    with pytest.MonkeyPatch.context() as patch:
        fixture = _owned_scan_scratch.__wrapped__(patch)
        try:
            next(fixture)
            owned = runner._sandbox_scratch_parent()
            assert owned != borrowed
            if body_undo:
                patch.undo()
            if ending == "normal":
                with pytest.raises(StopIteration):
                    next(fixture)
            elif ending == "throw":
                with pytest.raises(RuntimeError, match="body failure"):
                    fixture.throw(RuntimeError("body failure"))
            else:
                fixture.close()
        finally:
            fixture.close()
    assert not Path(owned).exists()
    assert Path(borrowed).is_dir()
    assert runner._scratch_parent == borrowed
    assert scratch._keepalive_paths is registrations
    assert borrowed in registrations and owned not in registrations
