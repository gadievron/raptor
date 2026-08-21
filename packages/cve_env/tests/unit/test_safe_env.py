"""Tests for utils/safe_env.py — allowlisted child env via core's
``RaptorConfig.get_safe_env`` plus the docker-CLI vars.

Two test layers per the F-5 lesson (every "X disables Y" claim needs
both a shape assertion AND a behavioral test simulating the failure
mode):

1. Shape tests: canonical threat vars are absent from the returned
   dict; docker vars and ``keep`` opt-ins are present; allowlist
   property (unknown secrets dropped by construction).
2. Behavioral tests: spawn a real subprocess with hostile env vars set
   in the parent, verify the child does NOT see them.
"""

from __future__ import annotations

import os
import subprocess
import sys
from unittest.mock import patch

from cve_env.utils.safe_env import _DOCKER_CHILD_VARS, safe_subprocess_env

# The four documented threat shapes: Python loader, native loader, git
# command channel, network proxy — plus the allowlist's raison d'être,
# an unknown future secret no denylist would have named.
_CANONICAL_THREATS = {
    "PYTHONPATH": "/tmp/evil",
    "LD_PRELOAD": "/tmp/evil.so",
    "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib",
    "GIT_SSH_COMMAND": "attacker-cmd",
    "HTTPS_PROXY": "http://attacker:9999",
    "https_proxy": "http://attacker:9999",
    "SOME_FUTURE_PROVIDER_API_KEY": "s3cret",
    "BASH_FUNC_ls%%": "() { evil; }",
}


# ─── Shape tests ─────────────────────────────────────────────────────────


def test_strips_canonical_threats_and_unknown_secrets() -> None:
    fake_env = dict(_CANONICAL_THREATS)
    fake_env["PATH"] = "/usr/bin"
    fake_env["HOME"] = "/home/test"
    with patch.dict(os.environ, fake_env, clear=True):
        env = safe_subprocess_env()
    leaked = set(_CANONICAL_THREATS) & env.keys()
    assert not leaked, f"safe_subprocess_env did not strip: {leaked}"
    assert env["PATH"] == "/usr/bin", "PATH must be preserved"
    assert env["HOME"] == "/home/test", "HOME must be preserved"


def test_docker_cli_vars_are_preserved() -> None:
    """The one cve-env-specific addition over core's allowlist: docker
    children must reach the right daemon and auth config."""
    fake_env = {v: f"val-{v}" for v in _DOCKER_CHILD_VARS}
    fake_env["PATH"] = "/usr/bin"
    with patch.dict(os.environ, fake_env, clear=True):
        env = safe_subprocess_env()
    for v in _DOCKER_CHILD_VARS:
        assert env.get(v) == f"val-{v}", f"{v} must survive for docker CLI"


def test_keep_param_retains_specified_vars() -> None:
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
    assert "LD_PRELOAD" not in env, "LD_PRELOAD not in keep set must be stripped"


def test_does_not_mutate_os_environ() -> None:
    fake_env = {"HTTPS_PROXY": "http://attacker", "PATH": "/usr/bin"}
    with patch.dict(os.environ, fake_env, clear=True):
        _ = safe_subprocess_env()
        assert os.environ.get("HTTPS_PROXY") == "http://attacker", (
            "safe_subprocess_env mutated os.environ — must return a copy"
        )


def test_delegates_to_core_get_safe_env() -> None:
    """The core allowlist IS the mechanism — no parallel list here. Any
    var core admits (beyond the docker/keep additions) is admitted, and
    nothing else."""
    from core.config import RaptorConfig

    fake_env = {"PATH": "/usr/bin", "LANG": "C.UTF-8", "RANDOM_VAR": "x"}
    with patch.dict(os.environ, fake_env, clear=True):
        ours = safe_subprocess_env()
        core = dict(RaptorConfig.get_safe_env())
    assert ours == core, "with no docker/keep vars set, output must be core's"
    assert "RANDOM_VAR" not in ours


# ─── Behavioral tests (F-5 lesson) ───────────────────────────────────────


def test_behaviorally_blocks_hostile_vars_in_child() -> None:
    """Spawn a real subprocess with hostile vars in the parent; verify
    the child sees none of them but keeps PATH."""
    parent_env = dict(os.environ)
    parent_env["HTTPS_PROXY"] = "http://attacker:9999"
    parent_env["LD_PRELOAD"] = "/tmp/evil.so"
    parent_env["SOME_FUTURE_PROVIDER_API_KEY"] = "s3cret"

    with patch.dict(os.environ, parent_env, clear=True):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import os;"
                    "print('HTTPS_PROXY=' + os.environ.get('HTTPS_PROXY', ''));"
                    "print('LD_PRELOAD=' + os.environ.get('LD_PRELOAD', ''));"
                    "print('KEY=' + os.environ.get("
                    "'SOME_FUTURE_PROVIDER_API_KEY', ''))"
                ),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
            env=safe_subprocess_env(),
        )

    assert result.returncode == 0, f"child failed: {result.stderr}"
    assert "HTTPS_PROXY=http" not in result.stdout, (
        f"BEHAVIORAL FAIL: HTTPS_PROXY leaked to child: {result.stdout!r}"
    )
    assert "LD_PRELOAD=/tmp/evil" not in result.stdout, (
        f"BEHAVIORAL FAIL: LD_PRELOAD leaked to child: {result.stdout!r}"
    )
    assert "KEY=s3cret" not in result.stdout, (
        f"BEHAVIORAL FAIL: unknown secret leaked to child: {result.stdout!r}"
    )


def test_baseline_proxy_leaks_without_safe_env() -> None:
    """Inverse-baseline: WITHOUT safe_subprocess_env the child DOES
    inherit HTTPS_PROXY — proves the behavioral test isn't vacuous."""
    parent_env = dict(os.environ)
    parent_env["HTTPS_PROXY"] = "http://attacker:9999"

    with patch.dict(os.environ, parent_env, clear=True):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import os;print(os.environ.get('HTTPS_PROXY', '<unset>'))",
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
            # NO env= — default subprocess inherits.
        )

    assert result.returncode == 0, f"baseline child failed: {result.stderr}"
    assert "http://attacker:9999" in result.stdout, (
        f"baseline expected HTTPS_PROXY to leak; got {result.stdout!r}. "
        f"If this fails, the behavioral test above proves nothing."
    )
