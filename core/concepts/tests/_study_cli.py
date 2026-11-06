"""Invoke study-prep's real main without repeating interpreter startup."""

import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest


def run_prep_main(load_prep, script, args) -> CompletedProcess[str]:
    """Load fresh script globals and own argv, path, trust and output scopes.

    Other exceptions propagate so implementation failures cannot become
    successful command results. Filesystem work and subprocesses in main
    remain real; dedicated tests retain the interpreter boundary.
    """
    command = [sys.executable, str(script), *args]
    with (
        io.StringIO() as stdout,
        io.StringIO() as stderr,
        patch.object(sys, "argv", command[1:]),
        patch.object(sys, "path", sys.path.copy()),
        pytest.MonkeyPatch.context() as monkeypatch,
        redirect_stdout(stdout),
        redirect_stderr(stderr),
    ):
        monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
        module = load_prep()
        status = 0
        try:
            module.main()
        except SystemExit as exc:
            if exc.code is not None:
                if isinstance(exc.code, int):
                    status = exc.code
                else:
                    print(exc.code, file=sys.stderr)
                    status = 1
        return CompletedProcess(command, status, stdout.getvalue(), stderr.getvalue())
