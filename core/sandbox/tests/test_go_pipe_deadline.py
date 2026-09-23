"""Source pin: the setup child's step-7 go-pipe wait is deadline-bounded.

The child-side go-pipe read is the one handshake wait that had no
select+deadline (the parent's t_ready_r/pid_r/status_r waits all
carry one): p_go_w lives in the parent's fd table until step 8, so a
sibling spawn forked in the step-4..8 window inherits a transient
copy into its never-exec'ing setup child — after an orchestrator
hard-kill the dead run's setup child stayed blocked until the longest
concurrent sibling completed. A live-orphan reproduction needs an
orchestrator SIGKILL plus a concurrent sibling; the pin here is
structural, matching the module's other handshake-wait pins.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def test_go_pipe_read_is_deadline_bounded():
    src = (REPO / "core" / "sandbox" / "_spawn.py").read_text(
        encoding="utf-8")
    step7 = src.index("Step 7: wait for parent 'go'")
    block = src[step7:step7 + 3000]
    assert "_select_mod.select(" in block, (
        "step-7 go wait lost its select bound")
    assert "_go_deadline" in block
    assert "_P_READY_DEADLINE_S" in block
    # The bare blocking-read spelling must not come back.
    assert "if os.read(p_go_r, 1) != " not in block
