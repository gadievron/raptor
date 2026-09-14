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
from types import ModuleType

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "darwin", reason="bare-run advisory is non-seatbelt",
)


def _external_bare_run_module(tmp_path: Path) -> ModuleType:
    """Import a module OUTSIDE core/sandbox whose ``trigger()`` enters a
    bare ``sandbox()`` context (this test file lives inside the package
    dir the advisory's frame walk skips), matching the real shape: an
    external module entering a bare sandbox() context."""
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
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


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

    mod = _external_bare_run_module(tmp_path)

    with caplog.at_level(logging.WARNING, logger="core.sandbox"):
        mod.trigger()

    msgs = [r.getMessage() for r in caplog.records
            if "without target=/output=/rootfs=" in r.getMessage()]
    assert msgs, "bare-run advisory did not fire"
    assert "contextlib" not in msgs[0]
    assert "bare_run_trigger.py" in msgs[0]


def test_profile_none_call_neither_fires_nor_consumes_the_advisory(
    caplog: pytest.LogCaptureFixture, tmp_path: Path,
) -> None:
    """A call that declined filesystem confinement by profile contract
    ('none' — every run_trusted() call — or 'network-only') is not a
    forgotten-confinement bare run: the advisory must not fire for it,
    and must not be CONSUMED by it — the once-per-process attribution
    belongs to the first genuine bare-run caller."""
    from core.sandbox import state
    from core.sandbox.context import check_net_available, run_trusted

    if not check_net_available():
        pytest.skip("no namespace backend — bare-run advisory inert")

    state.reset_warn_once("_bare_run_posture_warned")

    with caplog.at_level(logging.WARNING, logger="core.sandbox"):
        run_trusted(["true"], capture_output=True, timeout=30)

    trusted_msgs = [r.getMessage() for r in caplog.records
                    if "without target=/output=/rootfs=" in r.getMessage()]
    assert not trusted_msgs, (
        "run_trusted (profile='none', which REJECTS target=/output=) "
        "must not trip the bare-run posture advisory")

    # The once is still unconsumed: a genuine bare run from an external
    # module fires the advisory and gets the attribution.
    mod = _external_bare_run_module(tmp_path)
    with caplog.at_level(logging.WARNING, logger="core.sandbox"):
        mod.trigger()

    msgs = [r.getMessage() for r in caplog.records
            if "without target=/output=/rootfs=" in r.getMessage()]
    assert msgs, "trusted call consumed the bare-run advisory"
    assert "bare_run_trigger.py" in msgs[0]
