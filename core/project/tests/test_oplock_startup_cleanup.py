"""A lock-holder readiness failure must not outlive its owner."""
from unittest.mock import patch

import pytest

from core.project.tests.test_oplock import _Holder


@pytest.mark.slow
@pytest.mark.parametrize("failure", ["not-ready", "error", "interrupt"])
def test_holder_startup_failure_reaps_real_child(tmp_path, failure):
    holder = _Holder(tmp_path / "project")
    expected = {"not-ready": AssertionError, "error": RuntimeError,
                "interrupt": KeyboardInterrupt}[failure]
    try:
        # Process._args retains the real shared event constructed by _Holder.
        # Only the parent's observation fails; the child and lock are real.
        with patch.object(holder, "acquired", spec_set=holder.acquired) as readiness:
            if failure == "not-ready":
                readiness.wait.return_value = False
            else:
                readiness.wait.side_effect = expected("readiness failed")
            with pytest.raises(expected):
                with holder:
                    pytest.fail("a failed startup entered the holder body")
        assert not holder.proc.is_alive()
        assert holder.proc.exitcode is not None
    finally:
        # Also contain the original-code baseline, which leaves the child live.
        holder.release.set()
        if holder.proc.pid is not None:
            holder.proc.join(timeout=10)
            if holder.proc.is_alive():
                holder.proc.kill()
                holder.proc.join(timeout=5)
