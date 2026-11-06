"""Invoke study entrypoints without repeating interpreter startup."""

import importlib.machinery
import importlib.util
import io
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

import pytest


def run_study_main(load_script, script, args) -> CompletedProcess[str]:
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
        module = load_script()
        try:
            status = module.main()
        except SystemExit as exc:
            status = exc.code
        if status is None:
            status = 0
        elif not isinstance(status, int):
            print(status, file=sys.stderr)
            status = 1
        return CompletedProcess(command, status, stdout.getvalue(), stderr.getvalue())


def run_loop_with_prep(load_loop, script, args) -> CompletedProcess[str]:
    """Run empty-study features through real loop and prep entrypoints.

    The consumer's _run binding is the only replaced seam. Only prep is
    allowed: unexpected study/compile stages fail before starting work.
    Dedicated interpreter cases cover transport environment and startup.
    """
    prep_path = Path(script).with_name("raptor-study-prep")

    def load_prep():
        name = "raptor_study_prep_for_loop_test"
        loader = importlib.machinery.SourceFileLoader(name, str(prep_path))
        spec = importlib.util.spec_from_file_location(name, prep_path, loader=loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        return module

    def run_prep(command, *, verbose=False):
        assert command[:2] == [sys.executable, str(prep_path)], (
            "empty-study test attempted an unexpected helper", command)
        result = run_study_main(load_prep, prep_path, command[2:])
        if verbose:
            sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        return result.returncode

    def load():
        module = load_loop()
        module._run = run_prep
        return module

    return run_study_main(load, script, args)
