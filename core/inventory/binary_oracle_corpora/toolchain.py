"""Toolchain-version probing for corpus drivers.

Adversarial review E P2-2: precision numbers depend on compiler/runtime
versions (clang inlining decisions vary across releases; rustc DCE shifts
between MSRV bumps; gcov format changes across binutils minor versions).
Without recording WHICH versions produced a given precision report,
reproducibility is implicit-host-state — the same commit yields
different numbers on a different box and we can't tell which is "right".

Two-layer approach instead of brittle version enforcement:

  1. ``record_toolchain(...)`` — probes each tool actually used by the
     driver and returns the version string. Drivers call this and store
     the result in the prepare() context so the harness can write it
     into report.json.

  2. ``check_compatible(...)`` — optional gate that drivers can call to
     bail out when the local toolchain is too far from what was used to
     calibrate the precision corpus (configurable per-driver). Defaults
     to warn-only — operators see the version skew but the run proceeds.

The point is visibility: when someone says "1952/1952 absent verdicts
correct," reproducing it needs to know what compiler emitted those
binaries. The toolchain block in the report gives them the answer.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from typing import Dict, Optional, Tuple

logger = logging.getLogger(__name__)


def _probe(cmd: list) -> Optional[str]:
    """Run ``cmd`` and return its first-line stdout/stderr (most tools
    print version on either stream). Returns ``None`` if the tool is
    absent or errors out — the corpus driver decides whether to fail."""
    if not shutil.which(cmd[0]):
        return None
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or proc.stderr or "").strip()
    if not text:
        return None
    return text.splitlines()[0].strip()


def record_toolchain(
    *,
    cc: Optional[str] = None,
    cxx: Optional[str] = None,
    rustc: Optional[str] = None,
    cargo: Optional[str] = None,
    gcov: Optional[str] = None,
    llvm_cov: Optional[str] = None,
    llvm_profdata: Optional[str] = None,
) -> Dict[str, str]:
    """Probe the toolchain components named (skip None). Returns a
    ``{tool: version_string}`` dict for inclusion in the report.

    Pass only the tools the driver actually uses — keeps the recorded
    set minimal and accurate. Example::

        ctx['toolchain'] = record_toolchain(
            cc='gcc', gcov='gcov',
        )
    """
    probes: Dict[str, list] = {}
    if cc:
        probes[f"cc({cc})"] = [cc, "--version"]
    if cxx:
        probes[f"cxx({cxx})"] = [cxx, "--version"]
    if rustc:
        probes[f"rustc({rustc})"] = [rustc, "--version"]
    if cargo:
        probes[f"cargo({cargo})"] = [cargo, "--version"]
    if gcov:
        probes[f"gcov({gcov})"] = [gcov, "--version"]
    if llvm_cov:
        probes[f"llvm-cov({llvm_cov})"] = [llvm_cov, "--version"]
    if llvm_profdata:
        probes[f"llvm-profdata({llvm_profdata})"] = [
            llvm_profdata, "--version"]
    out: Dict[str, str] = {}
    for label, cmd in probes.items():
        v = _probe(cmd)
        out[label] = v or "(not found)"
    return out


_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


def _major_minor(version_text: str) -> Optional[Tuple[int, int]]:
    """Extract the first ``MAJOR.MINOR`` pair from a version string."""
    m = _VERSION_RE.search(version_text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)))


def check_compatible(
    label: str, version_text: Optional[str], minimum: Tuple[int, int],
    *, fail: bool = False,
) -> bool:
    """Verify ``version_text`` parses to ``>= minimum`` MAJOR.MINOR.
    Warns or raises (``fail=True``) when below. Returns True on pass."""
    if not version_text:
        if fail:
            raise RuntimeError(
                f"{label}: tool not found; precision corpus requires "
                f">= {minimum[0]}.{minimum[1]}")
        logger.warning(
            "%s: tool not found; precision report will lack a"
            " calibrated baseline", label)
        return False
    ver = _major_minor(version_text)
    if ver is None or ver < minimum:
        msg = (f"{label}: version {version_text!r} below calibrated "
               f"minimum {minimum[0]}.{minimum[1]} — precision numbers "
               f"may differ from the reference (different DCE / inline "
               f"behaviour)")
        if fail:
            raise RuntimeError(msg)
        logger.warning(msg)
        return False
    return True


__all__ = ["record_toolchain", "check_compatible"]
