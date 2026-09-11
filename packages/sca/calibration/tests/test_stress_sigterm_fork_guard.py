"""The sweep's SIGTERM handler must never run its post-mortem in a
forked child.

Fork-context descendants (inventory extractor workers, mp helpers)
inherit the handler ``run_sweep_and_report`` installs. Running the
post-mortem there is doubly wrong: its lock-taking (``_in_flight``)
can block forever on a lock some sibling thread held at fork time —
a ``terminate()``d worker then never dies — and its output would
interleave a bogus "sweep interrupted" summary into the real log.
A signalled child must die like an unhandled SIGTERM, silently.
"""

from __future__ import annotations

import os
import signal
from pathlib import Path

import pytest

from packages.sca.calibration import stress as stress_mod

pytestmark = pytest.mark.skipif(
    not hasattr(os, "fork"), reason="fork required",
)


def test_sigterm_in_fork_child_dies_without_postmortem(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capfd,
) -> None:
    status: dict[str, int] = {}

    def fake_sweep(*, samples, git_clone_timeout, sca_timeout,
                   max_workers, results_sink):
        # The handler is installed by run_sweep_and_report before this
        # runs; the forked child inherits it. The child must die from
        # the SIGTERM itself — reaching os._exit(42) would mean the
        # handler returned instead of re-raising.
        pid = os.fork()
        if pid == 0:
            try:
                signal.raise_signal(signal.SIGTERM)
            finally:
                os._exit(42)
        _, st = os.waitpid(pid, 0)
        status["st"] = st
        return []

    monkeypatch.setattr(stress_mod, "run_stress_sweep", fake_sweep)
    # Default ``out=print`` deliberately: the handler's post-mortem
    # renders through the caller's sink, so a silent sink would hide
    # exactly the child-side output this test exists to forbid.
    rc, results = stress_mod.run_sweep_and_report(
        [], tmp_path / "baseline.json",
    )
    assert rc == 0 and results == []
    st = status["st"]
    assert os.WIFSIGNALED(st), (
        f"child exited normally (status={st:#x}) — handler returned "
        "instead of dying"
    )
    assert os.WTERMSIG(st) == signal.SIGTERM
    out, err = capfd.readouterr()
    assert "sweep interrupted" not in out + err
