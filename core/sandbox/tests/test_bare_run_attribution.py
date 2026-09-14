"""Bare-run posture advisory names the real caller.

The warning fires inside the ``sandbox()`` generator, so the frame
walk's first stop outside core/sandbox used to be the stdlib
contextlib machinery (``__enter__`` / ``enter_context``) — every
bare-run caller was attributed to ``contextlib.py`` instead of the
call site that omitted ``target=``/``output=``.
"""

import logging
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "darwin", reason="bare-run advisory is non-seatbelt",
)


def test_bare_run_warning_attributes_the_calling_module(
    caplog: pytest.LogCaptureFixture, tmp_path: Path,
) -> None:
    from core.sandbox import state
    from core.sandbox.context import check_net_available

    if not check_net_available():
        pytest.skip("no namespace backend — bare-run advisory inert")

    # The advisory is once-per-PROCESS by design (warn_once latch), so
    # any earlier bare-run consumer in the same process — a test from a
    # directory whose conftest doesn't snapshot this module's flags —
    # eats the once and the assertion below fails under shuffled
    # orders. Own the latch (reset_warn_once's documented contract);
    # this directory's autouse state guard restores the pre-test value.
    state.reset_warn_once("_bare_run_posture_warned")

    # The caller must live OUTSIDE core/sandbox (this test file is
    # inside the package dir the frame walk skips), matching the real
    # shape: an external module entering a bare sandbox() context.
    trigger = tmp_path / "bare_run_trigger.py"
    trigger.write_text(
        "def trigger():\n"
        "    from core.sandbox import sandbox\n"
        "    with sandbox(block_network=True):\n"
        "        pass\n",
    )
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "bare_run_trigger", trigger)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    with caplog.at_level(logging.WARNING, logger="core.sandbox"):
        mod.trigger()

    msgs = [r.getMessage() for r in caplog.records
            if "without target=/output=/rootfs=" in r.getMessage()]
    assert msgs, "bare-run advisory did not fire"
    assert "contextlib" not in msgs[0]
    assert "bare_run_trigger.py" in msgs[0]
