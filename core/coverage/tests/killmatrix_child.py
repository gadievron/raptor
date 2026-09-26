"""Kill-matrix child: run one journal checkpoint up to a named phase,
signal readiness, then hang until the parent SIGKILLs this process.

Phases (each hook sits at the exact seam it names):

* ``tmp-write``    — mid pass-2 rewrite (first spend-carrier build):
                     tmp file partially written, journal untouched;
* ``pre-rename``   — at the backup hardlink (``os.link``), before it
                     runs: tmp complete + floor-checked, no backup,
                     no swap;
* ``mid-archive``  — between the backup hardlink and the swap
                     (``os.rename``): backup exists, journal is the
                     old bytes;
* ``post-rename``  — after the swap, before cache invalidation and
                     the directory fsync: journal is the new bytes.

Run by ``test_journal_checkpoint_killmatrix.py``:
``python killmatrix_child.py <repo_root> <out_dir> <phase> <ready>``.
Test-support code — runs outside the launcher, so it locates the repo
via argv (the test passes its own ``Path(__file__)``-derived root).
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path


def main() -> int:
    repo_root, out_dir, phase, ready_path = sys.argv[1:5]
    sys.path.insert(0, repo_root)

    import core.coverage.journal as jm
    import core.coverage.journal_compact as jcmp
    from core.coverage.journal_checkpoint import checkpoint_journal

    out = Path(out_dir)

    def _hang() -> None:
        Path(ready_path).write_text("ready")
        time.sleep(600)   # parent SIGKILLs long before this returns

    def _hook(*_a, **_k):
        _hang()

    if phase == "tmp-write":
        jcmp._spend_carrier_line = _hook
    elif phase == "pre-rename":
        os.link = _hook
    elif phase == "mid-archive":
        os.rename = _hook
    elif phase == "post-rename":
        # journal_compact calls this through its ``_journal`` module
        # alias, so patching the journal module's attribute is seen.
        jm.invalidate_load_cache = _hook
    else:
        print(f"unknown phase: {phase}", file=sys.stderr)
        return 2

    # Arm the trigger exactly like the tests: budget 1.4x the current
    # journal so the 65% trigger fires.
    size = (out / jm.JOURNAL_FILENAME).stat().st_size
    jm._MAX_JOURNAL_BYTES = int(size * 1.4)

    checkpoint_journal(out, boundary="killmatrix")
    # Reaching here means the phase hook never fired — the parent
    # treats a clean exit as a harness failure.
    return 3


if __name__ == "__main__":
    sys.exit(main())
