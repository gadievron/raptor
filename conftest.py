"""Root-level pytest config.

libexec/ scripts now refuse to run without one of CLAUDECODE,
_RAPTOR_TRUSTED, or RAPTOR_DIR set in the environment (see the
trust-marker block at the top of each script). Several test suites
subprocess-invoke libexec scripts and inherit env from this test
runner — set the marker once here so every test is treated as a
trusted caller by default.

Tests that exercise the refusal path explicitly pop the marker from
the subprocess env (see libexec/tests/test_raptor_sca_run.py in the
SCA branch for the pattern).

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
from pathlib import Path

os.environ.setdefault("_RAPTOR_TRUSTED", "1")
os.environ.setdefault("RAPTOR_DIR", str(Path(__file__).resolve().parent))
