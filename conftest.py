"""Root-level pytest config.

libexec/ scripts now refuse to run without one of CLAUDECODE,
_RAPTOR_TRUSTED, or RAPTOR_DIR set in the environment (see the
trust-marker block at the top of each script). Several test suites
subprocess-invoke libexec scripts and inherit env from this test
runner — set the marker once here so every test is treated as a
trusted caller by default.

Tests that exercise the refusal path explicitly pop the marker from
the subprocess env when they spawn the wrapper.

`RAPTOR_DIR` is also set here. Modules that follow the project's
"hard lookup, no fallbacks" path-safety rule (CLAUDE.md, e.g.
packages/recon/agent.py) read `os.environ["RAPTOR_DIR"]` at
import time and KeyError if unset. CI runners and developer
shells that don't pre-export RAPTOR_DIR would otherwise fail
test collection. Set it here to the project root (the directory
this conftest.py lives in) so the import-time lookup succeeds
in every test invocation, while production code paths still
require operators to set it explicitly per the launcher rule.
"""

import os
import sys
from pathlib import Path

os.environ.setdefault("_RAPTOR_TRUSTED", "1")

# Force RAPTOR_DIR to point at THIS worktree, not whatever the
# developer's login shell exports. ``setdefault`` is a no-op when the
# env var is already set, so a developer with multiple checkouts who
# exports ``RAPTOR_DIR=/home/me/other-raptor`` in their profile would
# silently run the test SUBPROCESS bootstrap (e.g.
# core/sandbox/tests/test_fork_safe_warn*.py) against the wrong tree
# — failing with "No module named core.sandbox._fork_safe_warn" when
# the module is new on this branch but missing from the other tree.
#
# CI environments that pre-export RAPTOR_DIR correctly are unaffected
# (the path already matches). Mismatch surfaces as a one-line warning
# on stderr so the developer notices the divergence.
_conftest_dir = str(Path(__file__).resolve().parent)
_existing = os.environ.get("RAPTOR_DIR")
if _existing and _existing != _conftest_dir:
    print(
        f"conftest: overriding RAPTOR_DIR ({_existing!r} → {_conftest_dir!r}) "
        f"to match the worktree this test run lives in",
        file=sys.stderr,
    )
os.environ["RAPTOR_DIR"] = _conftest_dir
