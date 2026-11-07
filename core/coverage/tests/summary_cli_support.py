"""Harness for driving ``libexec/raptor-coverage-summary``.

Two invocation contexts, matching the CLI's operator-tier rule for
review-grade marks:

* ``run_cli(...)`` — subprocess with every fd piped: the CLI sees a
  non-interactive (agent) context, so a plain ``--mark`` demotes to
  map-grade. This is the production agent shape, exercised for real.
* ``run_cli(..., operator=True)`` — IN-PROCESS invocation with an
  operator context injected at the check boundary
  (``detect_invocation_context``). This is the DOCUMENTED test seam
  (see ``live_context_grants_operator``): no production subprocess
  can reach a granting context — the dispatch gate requires an
  environment marker and every marker demotes on the mark path — so
  the review-grade path is testable only by injection here, and the
  harness deliberately shares NO code path with a
  production-forgeable recipe (no pty, no env-var knob).
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.testing.standalone_cli import run_standalone_cli

# parents[3] = core/coverage/tests -> core/coverage -> core -> repo root.
REPO_ROOT = Path(__file__).resolve().parents[3]
CLI = REPO_ROOT / "libexec" / "raptor-coverage-summary"

#: The injected operator context: interactive fds, inherited session,
#: NO dispatch environment marker, shell-rooted ancestry ending at a
#: live non-shell parent — the full set live_context_grants_operator
#: requires.
OPERATOR_CONTEXT = {
    "tty": "stdin,stdout,stderr",
    "provenance": "interactive-tty",
    "sid": "inherited",
    "envm": "none",
    "parents": "bash,sshd",
}

_cli_module = None


def _load_cli_module():
    global _cli_module
    if _cli_module is None:
        loader = SourceFileLoader("raptor_coverage_summary_harness", str(CLI))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        mod = importlib.util.module_from_spec(spec)
        with pytest.MonkeyPatch.context() as mp, patch.object(sys, "path", sys.path.copy()):
            mp.setenv("_RAPTOR_TRUSTED", "1")
            loader.exec_module(mod)
        _cli_module = mod
    return _cli_module


def _run_inprocess_operator(*args: str) -> SimpleNamespace:
    import core.annotations.provenance as prov

    mod = _load_cli_module()
    out, err = io.StringIO(), io.StringIO()
    code = 0
    orig_detect = prov.detect_invocation_context
    orig_argv = sys.argv
    prov.detect_invocation_context = lambda: dict(OPERATOR_CONTEXT)
    try:
        sys.argv = ["raptor-coverage-summary", *args]
        with redirect_stdout(out), redirect_stderr(err):
            try:
                mod.main()
            except SystemExit as exc:  # the CLI exits on errors
                code = int(exc.code or 0)
    finally:
        prov.detect_invocation_context = orig_detect
        sys.argv = orig_argv
    return SimpleNamespace(
        returncode=code, stdout=out.getvalue(), stderr=err.getvalue(),
    )


def run_cli(*args: str, operator: bool = False, trusted: bool = True):
    if operator:
        return _run_inprocess_operator(*args)
    env = dict(os.environ)
    if trusted:
        env["_RAPTOR_TRUSTED"] = "1"
    else:
        env.pop("_RAPTOR_TRUSTED", None)
        env.pop("CLAUDECODE", None)
    env["RAPTOR_DIR"] = str(REPO_ROOT)
    return run_standalone_cli(
        [sys.executable, str(CLI), *args],
        # The coverage autouse fixture owns this key directory. Share it
        # across CLI calls and the in-process operator/reader paths.
        env=env, data_home=os.environ["XDG_DATA_HOME"],
        capture_output=True, text=True, timeout=60,
    )
