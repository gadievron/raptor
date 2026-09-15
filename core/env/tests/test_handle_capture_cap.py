"""SandboxHandle.exec must bound its capture at the sandbox boundary.

Exec output is hostile workload output and the handle only ever
consumes bounded tails of it (kilobytes into ExecOutcome, a bounded
logs replay) — without a capture ceiling a gigabyte-spamming exec
transits the trusted parent's memory in full before the tail slice.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


def test_sandbox_handle_exec_bounds_capture(tmp_path) -> None:
    from core.env.handle import (
        _EXEC_CAPTURE_CAP_BYTES,
        SandboxHandle,
        sandbox_rootfs_supported,
    )

    if not sandbox_rootfs_supported():
        pytest.skip("sandbox image-rootfs mode unavailable on this tree")

    (tmp_path / "bin").mkdir()
    h = SandboxHandle(tmp_path)
    run_mock = MagicMock()
    run_mock.return_value = MagicMock(
        returncode=0, stdout="ok", stderr="", sandbox_info={},
    )
    with patch("core.sandbox.run", run_mock):
        outcome = h.exec("true")
    assert outcome.ok
    kwargs = run_mock.call_args.kwargs
    assert kwargs["capture_output"] is True
    assert kwargs["max_capture_bytes"] == _EXEC_CAPTURE_CAP_BYTES
    # The ceiling must comfortably cover everything the handle keeps
    # (8 KiB stdout + 4 KiB stderr tails) — shrinking it below that
    # would truncate legitimate ExecOutcome evidence.
    assert _EXEC_CAPTURE_CAP_BYTES >= 64 * 1024
