"""Tests for core.config.RaptorConfig."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch

# Pre-fix this file did:
#
#   import sys
#   sys.path.insert(0, str(Path(__file__).parent.parent.parent))
#
# in order to make the bare `from core.config import RaptorConfig`
# import below work when pytest is run from a deep cwd.
#
# Two problems with that:
#
#   1. Project rule (CLAUDE.md "Python path safety"): NEVER add
#      anything to sys.path except `os.environ["RAPTOR_DIR"]`. The
#      `parent.parent.parent` walk hard-codes the test's distance
#      from the repo root, so moving the file (e.g. into
#      `core/tests/unit/`) would silently start importing from
#      whatever stray directory happened to be three levels up.
#   2. Mutating sys.path at MODULE-import time leaks the entry
#      into every other test that imports later in the same
#      session — a global side-effect from a single test file.
#
# pytest's top-level `conftest.py` already adds the repo root
# to sys.path before any test module imports. The bare
# `from core.config import RaptorConfig` works without the
# manual insert. Drop the mutation.
from core.config import RaptorConfig


class TestGetSafeEnv:
    """Tests for RaptorConfig.get_safe_env()."""

    def test_strips_dangerous_env_vars(self):
        """TERMINAL, BROWSER, PAGER, VISUAL, EDITOR must be removed."""
        injected = {var: f"malicious_{var}" for var in RaptorConfig.DANGEROUS_ENV_VARS}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_safe_env()
            for var in RaptorConfig.DANGEROUS_ENV_VARS:
                assert var not in env, f"{var} should be stripped from safe env"

    def test_strips_proxy_env_vars(self):
        """HTTP_PROXY and friends must be removed."""
        injected = {var: "http://proxy.evil.com" for var in RaptorConfig.PROXY_ENV_VARS}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_safe_env()
            for var in RaptorConfig.PROXY_ENV_VARS:
                assert var not in env, f"{var} should be stripped from safe env"

    def test_sets_pythonunbuffered(self):
        env = RaptorConfig.get_safe_env()
        assert env.get("PYTHONUNBUFFERED") == "1"

    def test_does_not_strip_term(self):
        """TERM is read as a string (terminfo lookup), not shell-evaluated — must not be stripped."""
        with patch.dict(os.environ, {"TERM": "xterm-256color"}):
            env = RaptorConfig.get_safe_env()
            assert "TERM" in env

    def test_missing_dangerous_vars_handled_gracefully(self):
        """Should not raise if dangerous vars are absent."""
        cleaned = {var: None for var in RaptorConfig.DANGEROUS_ENV_VARS}
        env_without = {k: v for k, v in os.environ.items() if k not in cleaned}
        with patch.dict(os.environ, env_without, clear=True):
            env = RaptorConfig.get_safe_env()  # must not raise
            assert isinstance(env, dict)

    def test_mutations_do_not_leak_to_os_environ(self):
        """Mutating the returned dict must NOT propagate to os.environ.

        Pre-fix this test was named ``test_returns_copy_not_
        original``. The name implies an identity check
        (``env is not os.environ``) — but the body asserts a
        BEHAVIOURAL property: that mutations don't leak. The two
        are not equivalent: a defensive shallow copy passes
        ``is not`` but a deep nested mutation could still alias
        through. Renaming clarifies what the test actually
        guarantees, so future readers don't add a redundant
        identity check or weaken the leak check thinking the
        original name covers both.
        """
        env = RaptorConfig.get_safe_env()
        env["RAPTOR_TEST_SENTINEL"] = "should_not_leak"
        assert "RAPTOR_TEST_SENTINEL" not in os.environ


class TestGetGitEnv:
    """Tests for RaptorConfig.get_git_env()."""

    def test_disables_terminal_prompt(self):
        env = RaptorConfig.get_git_env()
        assert env.get("GIT_TERMINAL_PROMPT") == "0"

    def test_sets_askpass(self):
        env = RaptorConfig.get_git_env()
        assert env.get("GIT_ASKPASS") == "true"

    def test_also_strips_dangerous_vars(self):
        injected = {var: "bad" for var in RaptorConfig.DANGEROUS_ENV_VARS}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_git_env()
            # GIT_CONFIG_GLOBAL/SYSTEM are deliberately re-set by GIT_ENV_VARS
            # to a safe sentinel (/dev/null) so git ignores ~/.gitconfig and
            # /etc/gitconfig regardless of $HOME — verify the override took
            # effect rather than asserting absence.
            git_overrides = set(RaptorConfig.GIT_ENV_VARS)
            for var in RaptorConfig.DANGEROUS_ENV_VARS:
                if var in git_overrides:
                    assert env[var] == RaptorConfig.GIT_ENV_VARS[var]
                else:
                    assert var not in env

    def test_also_strips_proxy_vars(self):
        injected = {var: "http://proxy.evil.com" for var in RaptorConfig.PROXY_ENV_VARS}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_git_env()
            for var in RaptorConfig.PROXY_ENV_VARS:
                assert var not in env


class TestGetOutDir:
    """Tests for RaptorConfig.get_out_dir()."""

    def test_uses_raptor_out_dir_env(self, tmp_path):
        with patch.dict(os.environ, {"RAPTOR_OUT_DIR": str(tmp_path)}):
            result = RaptorConfig.get_out_dir()
            assert result == tmp_path.resolve()

    def test_falls_back_to_base_out_dir(self):
        env_without = {k: v for k, v in os.environ.items() if k != "RAPTOR_OUT_DIR"}
        with patch.dict(os.environ, env_without, clear=True):
            result = RaptorConfig.get_out_dir()
            assert result == RaptorConfig.BASE_OUT_DIR

    def test_empty_raptor_out_dir_falls_back(self):
        """Empty string for RAPTOR_OUT_DIR should fall back to base.

        Pre-fix this branch was uncovered: the implementation
        does ``if not base: return BASE_OUT_DIR``, which catches
        BOTH unset (None) and empty (``""``) — but only the
        unset case had a test. An accidental
        ``RAPTOR_OUT_DIR=`` (e.g. shell-expansion of an
        unset var with ``$RAPTOR_OUT_DIR``) used to surface as
        a ``Path("").resolve()`` returning cwd, which the
        forbidden-prefix check then rejected randomly depending
        on cwd. Confirm the empty-string fallback explicitly.
        """
        with patch.dict(os.environ, {"RAPTOR_OUT_DIR": ""}):
            result = RaptorConfig.get_out_dir()
            assert result == RaptorConfig.BASE_OUT_DIR

    @pytest.mark.parametrize("system_path", [
        "/etc", "/etc/foo",
        "/usr", "/usr/local/bin",
        "/bin", "/sbin",
        "/boot", "/dev", "/proc", "/sys",
    ])
    def test_rejects_system_paths(self, system_path):
        """RAPTOR_OUT_DIR pointing at a system prefix raises ValueError.

        Pre-fix the system-path warning branch was uncovered.
        The branch existed (refusing /etc, /usr, etc.) but no
        test verified it actually rejected. A regression that
        accidentally downgraded the raise to a warning would
        have shipped silently and caused operator output to
        land under /etc on the next misconfigured run.

        Test both the bare prefix (``/usr``) and a sub-path
        (``/usr/local/bin``) — the implementation matches on
        the path-component boundary specifically to allow
        ``/usr-local-foo`` while still catching ``/usr/x``.
        """
        with patch.dict(os.environ, {"RAPTOR_OUT_DIR": system_path}):
            with pytest.raises(ValueError, match="resolves under system path"):
                RaptorConfig.get_out_dir()

    def test_accepts_usr_local_lookalike(self):
        """`/usr-local-foo` must NOT match the `/usr` rule.

        The forbidden-prefix check uses component-boundary
        matching specifically to avoid this false positive.
        Pre-fix this case was uncovered, leaving the
        component-boundary logic vulnerable to a "naive
        startswith refactor for simplicity" that would have
        broken legitimate operator paths.
        """
        with patch.dict(os.environ, {"RAPTOR_OUT_DIR": "/tmp/usr-local-foo"}):
            # Resolved → /tmp/usr-local-foo, parent /tmp exists,
            # so no ValueError on the system-path check; should
            # return the resolved path.
            try:
                result = RaptorConfig.get_out_dir()
                assert "/usr-local-foo" in str(result)
            except ValueError as e:
                if "system path" in str(e):
                    pytest.fail(
                        f"/usr-local-foo wrongly matched /usr rule: {e}"
                    )
                raise


class TestEnsureDirectories:
    """Tests for RaptorConfig.ensure_directories()."""

    def test_creates_required_directories(self, tmp_path):
        """Patch REPO_ROOT so dirs are created under tmp_path."""
        with patch.object(RaptorConfig, "BASE_OUT_DIR", tmp_path / "out"), \
             patch.object(RaptorConfig, "MCP_JOB_DIR", tmp_path / "out" / "jobs"), \
             patch.object(RaptorConfig, "LOG_DIR", tmp_path / "out" / "logs"), \
             patch.object(RaptorConfig, "SCHEMAS_DIR", tmp_path / "schemas"), \
             patch.object(RaptorConfig, "CODEQL_DB_DIR", tmp_path / "codeql_dbs"), \
             patch.object(RaptorConfig, "CODEQL_SUITES_DIR", tmp_path / "codeql" / "suites"):
            RaptorConfig.ensure_directories()
            assert (tmp_path / "out").exists()
            assert (tmp_path / "out" / "jobs").exists()
            assert (tmp_path / "out" / "logs").exists()

    def test_idempotent(self, tmp_path):
        """Calling twice must not raise."""
        with patch.object(RaptorConfig, "BASE_OUT_DIR", tmp_path / "out"), \
             patch.object(RaptorConfig, "MCP_JOB_DIR", tmp_path / "out" / "jobs"), \
             patch.object(RaptorConfig, "LOG_DIR", tmp_path / "out" / "logs"), \
             patch.object(RaptorConfig, "SCHEMAS_DIR", tmp_path / "schemas"), \
             patch.object(RaptorConfig, "CODEQL_DB_DIR", tmp_path / "codeql_dbs"), \
             patch.object(RaptorConfig, "CODEQL_SUITES_DIR", tmp_path / "codeql" / "suites"):
            RaptorConfig.ensure_directories()
            RaptorConfig.ensure_directories()  # must not raise


class TestGetSafeEnvIncludePythonUserBase:
    """F102 — opt-in restoration of PYTHONUSERBASE for scanners that
    depend on ``pip install --user`` tools (semgrep, etc.).

    Default behaviour: PYTHONUSERBASE is in DANGEROUS_ENV_VARS and
    must remain stripped (it's a real RCE vector via .pth files —
    see core/config/__init__.py line 396-400).

    With ``include_python_user_base=True``, scanner sites that
    legitimately invoke a pip-installed user tool can re-admit the
    variable so the tool finds its site-packages. The same kwarg
    pattern as ``preserve_proxy``.

    Without this opt-in, an operator who installed semgrep with
    ``pip install --user`` and set ``PYTHONUSERBASE`` outside the
    default sees ``ModuleNotFoundError: No module named 'semgrep'``
    when RAPTOR spawns the scanner subprocess — verified in
    W6/W9 PoC.
    """

    def test_default_strips_pythonuserbase(self):
        """Backward-compat regression guard: default behaviour
        unchanged. PYTHONUSERBASE still removed."""
        with patch.dict(os.environ, {"PYTHONUSERBASE": "/home/user/.local"}):
            env = RaptorConfig.get_safe_env()
            assert "PYTHONUSERBASE" not in env

    def test_include_python_user_base_keeps_pythonuserbase(self):
        """Opt-in: when caller passes
        ``include_python_user_base=True``, the var flows through."""
        with patch.dict(os.environ, {"PYTHONUSERBASE": "/home/user/.local"}):
            env = RaptorConfig.get_safe_env(include_python_user_base=True)
            assert env.get("PYTHONUSERBASE") == "/home/user/.local"

    def test_include_python_user_base_no_op_when_not_set(self):
        """If the original env has no PYTHONUSERBASE, opt-in must
        not invent one."""
        # Build an env without PYTHONUSERBASE
        scrubbed = {k: v for k, v in os.environ.items() if k != "PYTHONUSERBASE"}
        with patch.dict(os.environ, scrubbed, clear=True):
            env = RaptorConfig.get_safe_env(include_python_user_base=True)
            assert "PYTHONUSERBASE" not in env

    def test_include_python_user_base_does_not_re_admit_other_dangerous_vars(self):
        """Opt-in is targeted — every OTHER dangerous var must still
        be stripped. Regression guard against an over-broad opt-in
        that accidentally lifts the whole blocklist."""
        injected = {var: f"malicious_{var}" for var in RaptorConfig.DANGEROUS_ENV_VARS}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_safe_env(include_python_user_base=True)
            # PYTHONUSERBASE is the ONLY var the opt-in re-admits.
            for var in RaptorConfig.DANGEROUS_ENV_VARS:
                if var == "PYTHONUSERBASE":
                    assert env.get(var) == "malicious_PYTHONUSERBASE"
                else:
                    assert var not in env, f"{var} should still be stripped"

    def test_include_python_user_base_combines_with_preserve_proxy(self):
        """Combining both kwargs is legal — neither flag rejects
        the other. (Whether ``preserve_proxy`` actually re-admits
        proxy vars depends on the allowlist; out of scope here.
        This test only guards against an accidental kwarg-collision
        regression in the function signature.)"""
        injected = {"PYTHONUSERBASE": "/home/user/.local"}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_safe_env(
                preserve_proxy=True, include_python_user_base=True,
            )
            assert env.get("PYTHONUSERBASE") == "/home/user/.local"


class TestGetLlmEnvIncludePythonUserBase:
    """F102b — ``get_llm_env()`` must forward
    ``include_python_user_base`` to ``get_safe_env()``.

    Without this forwarding, ``python raptor.py agentic`` (the
    canonical operator entry point at ``raptor.py:313,317``) calls
    ``get_llm_env()`` which strips PYTHONUSERBASE before the
    ``raptor_agentic.py:757`` opt-in can restore it for the semgrep
    spawn — the F102 fix is orphaned on this path.

    Default (False) must keep the existing strip behaviour;
    opt-in (True) must preserve the var. Mirrors the existing
    ``preserve_proxy`` opt-in pattern on the underlying
    ``get_safe_env``. Sibling test class:
    ``TestGetSafeEnvIncludePythonUserBase``.
    """

    def test_default_strips_pythonuserbase(self):
        """Backward-compat regression guard: default ``get_llm_env()``
        still strips PYTHONUSERBASE (security contract unchanged)."""
        with patch.dict(os.environ, {"PYTHONUSERBASE": "/home/user/.local"}):
            env = RaptorConfig.get_llm_env()
            assert "PYTHONUSERBASE" not in env

    def test_include_python_user_base_keeps_pythonuserbase(self):
        """F102b: when caller passes
        ``include_python_user_base=True``, the var flows through to
        the returned env so the canonical operator path
        (``raptor.py:313,317``) can preserve it for the agentic
        subprocess that wires it into the semgrep spawn."""
        with patch.dict(os.environ, {"PYTHONUSERBASE": "/home/user/.local"}):
            env = RaptorConfig.get_llm_env(include_python_user_base=True)
            assert env.get("PYTHONUSERBASE") == "/home/user/.local"

    def test_include_python_user_base_no_op_when_not_set(self):
        """If the original env has no PYTHONUSERBASE, opt-in must
        not invent one."""
        scrubbed = {k: v for k, v in os.environ.items() if k != "PYTHONUSERBASE"}
        with patch.dict(os.environ, scrubbed, clear=True):
            env = RaptorConfig.get_llm_env(include_python_user_base=True)
            assert "PYTHONUSERBASE" not in env

    def test_include_python_user_base_does_not_re_admit_other_dangerous_vars(self):
        """Opt-in is targeted — the LLM-env opt-in must not lift the
        wider DANGEROUS_ENV_VARS blocklist (regression guard against
        an over-broad forwarding implementation)."""
        injected = {var: f"malicious_{var}" for var in RaptorConfig.DANGEROUS_ENV_VARS}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_llm_env(include_python_user_base=True)
            for var in RaptorConfig.DANGEROUS_ENV_VARS:
                if var == "PYTHONUSERBASE":
                    assert env.get(var) == "malicious_PYTHONUSERBASE"
                else:
                    assert var not in env, f"{var} should still be stripped"

    def test_include_python_user_base_preserves_llm_api_key_passthrough(self):
        """Combining the opt-in with the LLM-key passthrough must
        not break either contract: API keys still flow, PYTHONUSERBASE
        is preserved."""
        injected = {
            "PYTHONUSERBASE": "/home/user/.local",
            "ANTHROPIC_API_KEY": "sk-ant-test-f102b",
        }
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_llm_env(include_python_user_base=True)
            assert env.get("PYTHONUSERBASE") == "/home/user/.local"
            assert env.get("ANTHROPIC_API_KEY") == "sk-ant-test-f102b"


