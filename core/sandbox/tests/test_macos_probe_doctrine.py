"""Parent-side ps/sysctl probes follow the binary-resolution doctrine.

These helpers run in the UNSANDBOXED parent: a bare-name PATH
fallback would execute a planted stub with the operator's ambient
authority, and the full inherited env steers even an
absolute-path binary (DYLD_INSERT_LIBRARIES-class variables). The
Linux probe helpers carry both defences; the darwin arm skipped
them. Source + behaviour pins (darwin execution is
environment-blocked on Linux CI; the properties pinned here are
platform-independent code shape).
"""

from __future__ import annotations

import os

from core.sandbox import _macos_spawn as mod


def test_no_bare_name_candidates():
    for cand in mod._PS_CANDIDATES:
        assert os.path.isabs(cand), cand
    src = open(mod.__file__, encoding="utf-8").read()
    assert '"sysctl")' not in src, (
        "bare-name sysctl fallback reintroduced")


def test_probe_env_is_scrubbed_allowlist():
    env = mod._safe_probe_env()
    assert "PATH" in env
    # A canary outside the allowlist must not survive.
    os.environ["RAPTOR_TEST_MACOS_PROBE_CANARY"] = "x"
    try:
        assert "RAPTOR_TEST_MACOS_PROBE_CANARY" not in (
            mod._safe_probe_env())
    finally:
        os.environ.pop("RAPTOR_TEST_MACOS_PROBE_CANARY", None)


def test_probe_invocations_pass_the_scrubbed_env():
    src = open(mod.__file__, encoding="utf-8").read()
    assert src.count("env=_safe_probe_env()") >= 3
