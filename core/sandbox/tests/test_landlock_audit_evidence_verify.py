"""Evidence-verify propagation on the Landlock-audit spawn path.

``EvidenceFile.close()`` returns the inode-verification verdict (did
the on-disk path still name the inode created at spawn?). The
Landlock-audit runner used to discard that return value in its
``finally`` block — the loud log warning fired, but no consumer could
act on the verdict programmatically. ``run_landlock_audit`` now
finalises the evidence file on the normal-return path and stamps the
result with ``evidence_verified`` so callers deciding whether to
trust the on-disk JSONL can check it.
"""

from __future__ import annotations

import sys

import pytest

from core.sandbox import _landlock_audit as mod
from core.sandbox import evidence as evidence_mod
from core.sandbox import tracer as tracer_mod

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="Landlock-audit spawn path is Linux-only",
)


def _ptrace_ready() -> bool:
    from core.sandbox.ptrace_probe import check_ptrace_available
    from core.sandbox.seccomp import check_seccomp_available
    return check_ptrace_available() and check_seccomp_available()


def test_clean_run_stamps_evidence_verified_true(tmp_path):
    if not _ptrace_ready():
        pytest.skip("ptrace/libseccomp unavailable")
    result = mod.run_landlock_audit(
        [sys.executable, "-c", "print('ok')"],
        audit_run_dir=str(tmp_path),
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert getattr(result, "evidence_verified", None) is True


def test_swapped_evidence_file_stamps_false(tmp_path):
    """A same-UID process (here: the audited child itself) renames the
    evidence JSONL mid-run. Appends through the held fd stay intact in
    the original inode, but the on-disk path no longer names it — the
    result must carry evidence_verified=False so consumers do not
    trust the file at that path."""
    if not _ptrace_ready():
        pytest.skip("ptrace/libseccomp unavailable")
    evidence = (evidence_mod.audit_dir_path(tmp_path)
                / tracer_mod._DENIALS_FILENAME)
    swap_code = (
        "import os, sys\n"
        f"src = {str(evidence)!r}\n"
        "os.rename(src, src + '.swapped')\n"
        "open(src, 'w').write('forged\\n')\n"
        "print('SWAPPED')\n"
    )
    result = mod.run_landlock_audit(
        [sys.executable, "-c", swap_code],
        audit_run_dir=str(tmp_path),
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True, text=True, timeout=60,
    )
    if "SWAPPED" not in (result.stdout or ""):
        pytest.skip(f"child could not swap the evidence file on this "
                    f"host: {result.stdout!r} {result.stderr!r}")
    assert getattr(result, "evidence_verified", None) is False, (
        "swapped evidence path must propagate evidence_verified=False"
    )
