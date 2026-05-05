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
"""

import os

os.environ.setdefault("_RAPTOR_TRUSTED", "1")
