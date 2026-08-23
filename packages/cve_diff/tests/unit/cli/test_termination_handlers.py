"""SIGTERM must unwind (and so clean the clone workdir), not leak it.

``run`` cleans its TemporaryDirectory in a ``finally`` block — which
never executes under SIGTERM's default terminate-without-unwinding
action. ``_install_termination_handlers`` converts SIGTERM/SIGINT into
exceptions so the ``finally`` fires; these tests exercise the handlers
in-process with ``os.kill``.
"""

from __future__ import annotations

import os
import signal
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("typer")

from cve_diff.cli.main import (  # noqa: E402
    _install_termination_handlers,
    _restore_termination_handlers,
)


@pytest.fixture()
def _handlers():
    restore = _install_termination_handlers()
    try:
        yield restore
    finally:
        _restore_termination_handlers(restore)


def test_sigterm_raises_systemexit(_handlers):
    with pytest.raises(SystemExit) as excinfo:
        os.kill(os.getpid(), signal.SIGTERM)
    assert excinfo.value.code == 128 + signal.SIGTERM


def test_sigint_raises_keyboardinterrupt(_handlers):
    with pytest.raises(KeyboardInterrupt):
        os.kill(os.getpid(), signal.SIGINT)


def test_sigterm_lets_finally_clean_the_workdir(_handlers):
    tmp_ctx = tempfile.TemporaryDirectory(prefix="cve-diff-")
    workdir = Path(tmp_ctx.name)
    (workdir / "clone-marker").write_text("2GB of clone lives here")
    try:
        with pytest.raises(SystemExit):
            os.kill(os.getpid(), signal.SIGTERM)
    finally:
        tmp_ctx.cleanup()
    assert not workdir.exists()


def test_restore_puts_previous_handlers_back():
    before_term = signal.getsignal(signal.SIGTERM)
    before_int = signal.getsignal(signal.SIGINT)
    restore = _install_termination_handlers()
    assert signal.getsignal(signal.SIGTERM) is not before_term
    _restore_termination_handlers(restore)
    assert signal.getsignal(signal.SIGTERM) is before_term
    assert signal.getsignal(signal.SIGINT) is before_int
