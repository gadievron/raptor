"""Capture accumulation must be linear in bytes received.

The spawn capture loop accumulated with ``bytes +=``: CPython bytes
has no in-place resize, so every append near the 64 MiB cap copies
the whole buffer — quadratic total cost, and the byte PACING is
attacker-chosen (the sandboxed target is attacker-derived by
contract). Filling fast to near-cap and then dribbling 1-byte writes
forced tens of milliseconds of TRUSTED-parent memcpy per wake,
starving concurrent runs; total copy work was bounded only by
cap²/chunk. The loop now list-accumulates and joins, like the audit
lane's drain.

CPU budget, not wall clock: a starved runner does not advance
process_time, while the complexity regression this pins still burns
it. The child's own CPU is invisible to process_time — only the
parent-side accumulation cost is measured.
"""

from __future__ import annotations

import sys

import pytest

from core.sandbox.tests.capability import requires_userns
from core.testing.wallclock import cpu_budget

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="spawn capture loop is Linux-only",
)

_MIB = 48  # below the 64 MiB cap — no truncation, pure accumulation


@requires_userns
def test_capture_accumulation_is_linear(tmp_path):
    from core.sandbox import run

    child = (
        "import sys\n"
        "buf = b'x' * 65536\n"
        f"for _ in range({_MIB} * 16):\n"
        "    sys.stdout.buffer.write(buf)\n"
    )
    # Quadratic bytes+= burned ~6s of parent CPU on this stream
    # (measured: ~2.7s at 32 MiB, super-linear); list+join costs
    # ~0.1s. Budget sits with wide separation from both.
    with cpu_budget(2.0, what=f"parent-side capture of {_MIB} MiB"):
        result = run(
            [sys.executable, "-c", child],
            target=str(tmp_path), output=str(tmp_path),
            capture_output=True, timeout=180,
        )
    assert result.returncode == 0
    assert len(result.stdout) == _MIB * 1024 * 1024
