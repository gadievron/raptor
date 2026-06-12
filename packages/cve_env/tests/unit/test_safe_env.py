"""Tests for utils/safe_env.py — strip hostile env vars from subprocess calls.

Two test layers per F-5 lesson (every "X disables Y" claim needs both
kwarg-assertion AND behavioral test simulating the failure mode):

1. Marker tests: assert the dangerous-vars set + return-shape contract.
2. Behavioral tests: spawn an actual subprocess with hostile env vars
   set in the parent process, verify the child does NOT see them.

Source: peer REC-2 from Phase O cross-project analysis (2026-05-06),
ported from raptor's get_safe_env pattern.
"""

from __future__ import annotations

import os
import subprocess
import sys
from unittest.mock import patch


from cve_env.utils.safe_env import _DANGEROUS_ENV_VARS, safe_subprocess_env


# ─── Marker tests ────────────────────────────────────────────────────────


def test_dangerous_vars_set_includes_canonical_threats() -> None:
    """The blocklist must cover the four threat shapes documented in
    safe_env.py: Python loader, native loader, git command channel,
    network proxy. Catches future refactors that drop a category."""
    must_include = {
        # Python loader
        "PYTHONPATH",
        # Native loader (linux + macOS)
        "LD_PRELOAD",
        "DYLD_INSERT_LIBRARIES",
        # Git channel
        "GIT_SSH_COMMAND",
        # Proxy redirect (uppercase + lowercase)
        "HTTPS_PROXY",
        "https_proxy",
    }
    missing = must_include - _DANGEROUS_ENV_VARS
    assert not missing, (
        f"_DANGEROUS_ENV_VARS missing canonical threat vars: {missing}"
    )


def test_safe_subprocess_env_strips_dangerous_vars() -> None:
    """Result dict must NOT contain any var in _DANGEROUS_ENV_VARS."""
    fake_env = {var: "hostile" for var in _DANGEROUS_ENV_VARS}
    fake_env["PATH"] = "/usr/bin"
    fake_env["HOME"] = "/Users/test"
    with patch.dict(os.environ, fake_env, clear=True):
        env = safe_subprocess_env()
    leaked = _DANGEROUS_ENV_VARS & env.keys()
    assert not leaked, f"safe_subprocess_env did not strip: {leaked}"
    assert env["PATH"] == "/usr/bin", "PATH must be preserved"
    assert env["HOME"] == "/Users/test", "HOME must be preserved"


def test_safe_subprocess_env_keep_param_retains_specified_vars() -> None:
    """If a caller opts back in via ``keep``, those vars survive the strip."""
    fake_env = {
        "HTTPS_PROXY": "http://attacker:9999",
        "LD_PRELOAD": "/tmp/evil.so",
        "PATH": "/usr/bin",
    }
    with patch.dict(os.environ, fake_env, clear=True):
        env = safe_subprocess_env(keep=frozenset({"HTTPS_PROXY"}))
    assert env["HTTPS_PROXY"] == "http://attacker:9999", (
        "HTTPS_PROXY in keep set must be preserved"
    )
    assert "LD_PRELOAD" not in env, (
        "LD_PRELOAD not in keep set must still be stripped"
    )


def test_safe_subprocess_env_does_not_mutate_os_environ() -> None:
    """Side-effect-free: reading the result must not have stripped anything
    from the real os.environ."""
    fake_env = {"HTTPS_PROXY": "http://attacker", "PATH": "/usr/bin"}
    with patch.dict(os.environ, fake_env, clear=True):
        _ = safe_subprocess_env()
        # os.environ still has HTTPS_PROXY (we got our own dict).
        assert os.environ.get("HTTPS_PROXY") == "http://attacker", (
            "safe_subprocess_env mutated os.environ — must return a copy"
        )


# ─── Behavioral test (F-5 lesson) ────────────────────────────────────────


def test_safe_subprocess_env_behaviorally_blocks_proxy_in_child() -> None:
    """F-5 lesson — kwarg assertion alone is insufficient. Spawn a real
    subprocess with HTTPS_PROXY set in the parent, pass safe_subprocess_env()
    as env, and verify the child does NOT see HTTPS_PROXY in its environment.

    This is the same shape as BUG-004b's behavioral test for proxies={"http":
    "", "https": ""} — proves the SECURITY GOAL, not just the kwarg shape.
    """
    parent_env_with_proxy = dict(os.environ)
    parent_env_with_proxy["HTTPS_PROXY"] = "http://attacker:9999"
    parent_env_with_proxy["LD_PRELOAD"] = "/tmp/evil.so"

    with patch.dict(os.environ, parent_env_with_proxy, clear=True):
        # Child: print HTTPS_PROXY + LD_PRELOAD from its own environment.
        # If safe_subprocess_env stripped them, child sees empty strings.
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import os;"
                    "print('HTTPS_PROXY=' + os.environ.get('HTTPS_PROXY', ''));"
                    "print('LD_PRELOAD=' + os.environ.get('LD_PRELOAD', ''))"
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
            env=safe_subprocess_env(),
        )

    assert result.returncode == 0, f"child failed: {result.stderr}"
    assert "HTTPS_PROXY=\n" in result.stdout or result.stdout.startswith(
        "HTTPS_PROXY=\n"
    ), (
        f"child saw HTTPS_PROXY despite safe_subprocess_env(): "
        f"stdout={result.stdout!r}"
    )
    assert "LD_PRELOAD=\n" in result.stdout or "LD_PRELOAD=" in result.stdout, (
        f"child saw LD_PRELOAD despite safe_subprocess_env(): "
        f"stdout={result.stdout!r}"
    )
    # Stronger: explicit empty-value check
    assert "HTTPS_PROXY=http" not in result.stdout, (
        f"BEHAVIORAL FAIL: HTTPS_PROXY leaked to child: {result.stdout!r}"
    )
    assert "LD_PRELOAD=/tmp/evil" not in result.stdout, (
        f"BEHAVIORAL FAIL: LD_PRELOAD leaked to child: {result.stdout!r}"
    )


def test_safe_subprocess_env_baseline_proxy_leaks_without_safe_env() -> None:
    """Inverse-baseline: confirm that WITHOUT safe_subprocess_env (the
    default behavior), the child DOES inherit HTTPS_PROXY. Proves the
    behavioral test above isn't trivially true."""
    parent_env_with_proxy = dict(os.environ)
    parent_env_with_proxy["HTTPS_PROXY"] = "http://attacker:9999"

    with patch.dict(os.environ, parent_env_with_proxy, clear=True):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import os;"
                    "print(os.environ.get('HTTPS_PROXY', '<unset>'))"
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
            # NO env=safe_subprocess_env() — default subprocess inherits.
        )

    assert result.returncode == 0, f"baseline child failed: {result.stderr}"
    assert "http://attacker:9999" in result.stdout, (
        f"baseline expected HTTPS_PROXY to leak; got {result.stdout!r}. "
        f"If this fails, the behavioral test above proves nothing."
    )
