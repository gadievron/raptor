"""Pid-ns quiescence attestation: channel decode and end-to-end verdicts.

The channel contract under test (core/sandbox/_attestation.py): only
the exact single byte ``b"A"`` ever decodes to the clean verdict — a
same-uid target can reopen the init's pipe fds via ``/proc/1/fd/N``
and inject, so every other stream shape must read as a refusal tier,
never as trust.
"""

import subprocess
import sys
import time

import pytest

from core.sandbox import (
    PIDNS_ATTEST_CLEAN,
    PIDNS_ATTEST_FOREIGN,
    PIDNS_ATTEST_UNATTESTED,
    context,
    pidns_attestation,
)
from core.sandbox._attestation import (
    decode_attestation_bytes,
    record_pidns_attestation,
)
from core.sandbox.tests.capability import (
    requires_landlock,
    requires_mount,
    requires_userns,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux", reason="Linux pid-namespace attestation")


class TestChannelDecode:
    """Fail-closed decode: exactly one clean byte, everything else refuses."""

    def test_clean_byte(self):
        assert decode_attestation_bytes(b"A") == PIDNS_ATTEST_CLEAN

    def test_foreign_byte(self):
        assert decode_attestation_bytes(b"F") == PIDNS_ATTEST_FOREIGN

    def test_empty_stream_is_unattested(self):
        assert decode_attestation_bytes(b"") == PIDNS_ATTEST_UNATTESTED

    @pytest.mark.parametrize("injected", [
        b"AA",          # duplicate clean byte (replayed injection)
        b"AF", b"FA",   # verdict plus injected byte, either order
        b"XA", b"A\x00",
        b"x" * 65536 + b"A",  # buffer-fill then the genuine verdict
        b"B", b"\x00", b"garbage",
    ])
    def test_any_injection_refuses(self, injected):
        # An injected stream may REFUSE (unattested) but never upgrade
        # to clean or flip foreign<->clean.
        assert decode_attestation_bytes(injected) == PIDNS_ATTEST_UNATTESTED

    def test_result_reader_round_trip(self):
        cp = subprocess.CompletedProcess(["x"], 0, "", "")
        assert pidns_attestation(cp) == PIDNS_ATTEST_UNATTESTED
        record_pidns_attestation(cp, PIDNS_ATTEST_CLEAN)
        assert pidns_attestation(cp) == PIDNS_ATTEST_CLEAN
        record_pidns_attestation(cp, PIDNS_ATTEST_FOREIGN)
        assert pidns_attestation(cp) == PIDNS_ATTEST_FOREIGN

    def test_absent_attribute_reads_unattested(self):
        # Lanes that never plumb the channel (fallback, macOS, daemon)
        # must read as not-attested, not clean.
        cp = subprocess.CompletedProcess(["x"], 0, "", "")
        assert pidns_attestation(cp) == PIDNS_ATTEST_UNATTESTED


@pytest.mark.slow
@pytest.mark.linux_native
@requires_landlock
@requires_mount
@requires_userns
class TestEndToEnd:
    """Verdicts from a real pid-ns spawn with the in-ns init sweeping."""

    @pytest.fixture()
    def run(self, tmp_path):
        target, output = tmp_path / "target", tmp_path / "output"
        target.mkdir()
        output.mkdir()
        with context.sandbox(profile="strict", target=str(target),
                             output=str(output)) as runner:
            yield runner

    def test_single_process_target_attests_clean(self, run):
        result = run(["/bin/sh", "-c", "exit 0"], capture_output=True,
                     timeout=30, pidns_attest=True)
        assert result.returncode == 0
        assert pidns_attestation(result) == PIDNS_ATTEST_CLEAN

    def test_short_lived_extra_process_still_clean(self, run):
        # A child the TARGET itself reaps never reaches the init: the
        # attestation is about processes outside the supervised tree
        # (orphans / sweep finds), not about the target forking at all.
        result = run(["/bin/sh", "-c", "/bin/true; exit 0"],
                     capture_output=True, timeout=30, pidns_attest=True)
        assert result.returncode == 0
        assert pidns_attestation(result) == PIDNS_ATTEST_CLEAN

    def test_orphan_survivor_reads_foreign_and_is_swept(self, run):
        # The CLONE_UNTRACED-survivor shape: a process that outlives the
        # supervised target. The init's census detects it (verdict:
        # foreign) and the init's exit SIGKILLs the namespace — the run
        # must return long before the orphan's own 300s sleep.
        start = time.monotonic()
        result = run(["/bin/sh", "-c", "sleep 300 & exit 0"],
                     capture_output=True, timeout=60, pidns_attest=True)
        elapsed = time.monotonic() - start
        assert result.returncode == 0
        assert pidns_attestation(result) == PIDNS_ATTEST_FOREIGN
        assert elapsed < 45, "init exit must kill the survivor, not wait it out"

    def test_without_opt_in_result_reads_unattested(self, run):
        result = run(["/bin/sh", "-c", "exit 0"], capture_output=True,
                     timeout=30)
        assert result.returncode == 0
        assert pidns_attestation(result) == PIDNS_ATTEST_UNATTESTED
