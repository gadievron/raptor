"""Tests for core.config.RaptorConfig."""

import os
from unittest.mock import patch

import pytest

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


class TestEffectiveVersion:
    """Tests for RaptorConfig.effective_version()."""

    def test_falls_back_to_VERSION_on_git_error(self):
        """Any git failure (binary absent, not a repo) → baked VERSION."""
        import subprocess
        with patch.object(subprocess, "run", side_effect=OSError("no git")):
            assert RaptorConfig.effective_version() == RaptorConfig.VERSION

    def test_falls_back_to_VERSION_on_nonzero_exit(self):
        import subprocess
        from types import SimpleNamespace
        fake = SimpleNamespace(returncode=128, stdout="", stderr="fatal")
        with patch.object(subprocess, "run", return_value=fake):
            assert RaptorConfig.effective_version() == RaptorConfig.VERSION

    def test_uses_git_describe_and_strips_leading_v(self):
        """In a checkout, derive from describe (leading 'v' stripped)."""
        import subprocess
        from pathlib import Path
        from types import SimpleNamespace

        repo = Path(__file__).resolve().parents[3]
        if not (repo / ".git").exists():
            pytest.skip("not a git checkout")
        fake = SimpleNamespace(returncode=0, stdout="v3.0.0-5-gabc1234\n",
                               stderr="")
        with patch.object(subprocess, "run", return_value=fake):
            assert RaptorConfig.effective_version() == "3.0.0-5-gabc1234"


class TestGetSafeEnv:
    """Tests for RaptorConfig.get_safe_env()."""

    def test_strips_dangerous_env_vars(self):
        """TERMINAL, BROWSER, PAGER, VISUAL, EDITOR must be removed."""
        injected = {var: f"malicious_{var}" for var in RaptorConfig.DANGEROUS_ENV_VARS}
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_safe_env()
            for var in RaptorConfig.DANGEROUS_ENV_VARS:
                if var in RaptorConfig.GIT_ENV_VARS:
                    # Git config vars are REPLACED with our pinned safe
                    # values rather than merely stripped — the malicious
                    # operator value must never survive either way.
                    assert env.get(var) == RaptorConfig.GIT_ENV_VARS[var]
                else:
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

    def test_ef_benign_knobs_survive_scrub(self):
        """Numeric/boolean feasibility knobs must reach scrub-spawned
        children (the loader runs inside them); the exec-path class
        (tool paths, config path, cache dir) must NOT — env-supplied
        executable paths are the EDITOR/PAGER threat this scrub
        strips."""
        with patch.dict(os.environ, {
            "RAPTOR_EF_TIMEOUT_FAST": "7",
            "RAPTOR_EF_VERBOSE": "yes",
            "RAPTOR_EF_CHECKSEC_PATH": "/tmp/evil-checksec",
            "RAPTOR_EF_ONE_GADGET_PATH": "/tmp/evil-og",
            "RAPTOR_EF_CONFIG": "/tmp/evil.json",
            "RAPTOR_EF_CACHE_DIR": "/tmp/ef",
        }):
            env = RaptorConfig.get_safe_env()
            assert env.get("RAPTOR_EF_TIMEOUT_FAST") == "7"
            assert env.get("RAPTOR_EF_VERBOSE") == "yes"
            for blocked in ("RAPTOR_EF_CHECKSEC_PATH",
                            "RAPTOR_EF_ONE_GADGET_PATH",
                            "RAPTOR_EF_CONFIG", "RAPTOR_EF_CACHE_DIR"):
                assert blocked not in env, blocked

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

    def test_is_a_pure_alias_of_get_safe_env(self):
        """get_safe_env() already applies GIT_ENV_VARS for every
        subprocess; get_git_env must not re-overlay anything on top —
        one source of truth, so the two can never diverge."""
        assert RaptorConfig.get_git_env() == RaptorConfig.get_safe_env()


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
        with patch.dict(os.environ, {"RAPTOR_OUT_DIR": system_path}), \
                pytest.raises(ValueError, match="resolves under system path"):
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
        with patch.dict(os.environ, {"RAPTOR_OUT_DIR": "./usr-local-foo"}):
            # Resolved → ./usr-local-foo (cwd-relative; parent exists),
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
                elif var in RaptorConfig.GIT_ENV_VARS:
                    # Replaced with our pinned safe value, not stripped.
                    assert env.get(var) == RaptorConfig.GIT_ENV_VARS[var]
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
                elif var in RaptorConfig.GIT_ENV_VARS:
                    # Replaced with our pinned safe value, not stripped.
                    assert env.get(var) == RaptorConfig.GIT_ENV_VARS[var]
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




class TestGetSafeEnvNormalisesProxyUrls:
    """URL-shaped proxy values are normalised at ingestion (trailing
    slash breaks strict parsers like the JVM's HttpHost — observed in
    CodeQL's pack downloader); NO_PROXY is a host list and must pass
    through byte-for-byte."""

    def test_trailing_slash_stripped(self):
        injected = {
            "HTTPS_PROXY": "http://proxy.corp:3128/",
            "HTTP_PROXY": "http://proxy.corp:3128/",
            "NO_PROXY": "localhost,127.0.0.1/8,169.254.169.254",
        }
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_safe_env(preserve_proxy=True)
            assert env["HTTPS_PROXY"] == "http://proxy.corp:3128"
            assert env["HTTP_PROXY"] == "http://proxy.corp:3128"
            assert env["NO_PROXY"] == injected["NO_PROXY"]


class TestGetLlmEnvPreservesProxy:
    """``get_llm_env()`` must carry the operator's launch-time proxy
    vars through to RAPTOR's own analysis children.

    This env is exclusively for trusted RAPTOR scripts, and every
    downstream proxy mechanism (sandbox egress upstream autodetect,
    ``egress.operator_proxy_env()``, ``get_safe_env(preserve_proxy=
    True)``) reads the *current process* env — so stripping proxy vars
    at this seam starves all of them one level down and breaks every
    outbound call on mandatory-egress-proxy hosts.
    """

    def test_proxy_vars_preserved(self):
        injected = {
            "HTTPS_PROXY": "http://proxy.corp:3128",
            "https_proxy": "http://proxy.corp:3128",
            "NO_PROXY": "169.254.169.254",
        }
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_llm_env()
            for var, val in injected.items():
                assert env.get(var) == val

    def test_no_proxy_vars_invented(self):
        scrubbed = {
            k: v for k, v in os.environ.items()
            if k not in RaptorConfig.PROXY_ENV_VARS
        }
        with patch.dict(os.environ, scrubbed, clear=True):
            env = RaptorConfig.get_llm_env()
            for var in RaptorConfig.PROXY_ENV_VARS:
                assert var not in env

    def test_get_safe_env_default_still_strips(self):
        """Regression guard: the untrusted-child default is unchanged —
        only the LLM/trusted seam preserves proxy vars."""
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://proxy.corp:3128"}):
            env = RaptorConfig.get_safe_env()
            assert "HTTPS_PROXY" not in env

    def test_get_safe_env_isolates_git_config(self):
        """Every subprocess env must carry the git config isolation —
        an operator ~/.gitconfig with commit.gpgsign=true otherwise
        routes sandboxed git commits through gpg-agent's unix-socket
        IPC (blocked under network-denied sandboxes), and
        log.showSignature / core.fsmonitor / credential.helper leak
        operator behaviour into internal git invocations."""
        env = RaptorConfig.get_safe_env()
        for key, expected in RaptorConfig.GIT_ENV_VARS.items():
            assert env.get(key) == expected, (
                f"{key} missing/mismatched in get_safe_env(): "
                f"{env.get(key)!r} != {expected!r}")

    def test_get_safe_env_git_isolation_beats_operator_env(self):
        """Operator-exported GIT_CONFIG_GLOBAL must not survive — the
        dangerous-var strip removes it and our /dev/null wins."""
        with patch.dict(os.environ,
                        {"GIT_CONFIG_GLOBAL": "/home/op/.evil-gitconfig"}):
            env = RaptorConfig.get_safe_env()
            assert env["GIT_CONFIG_GLOBAL"] == "/dev/null"


class TestGetLlmEnvRoutingFamily:
    """LLM transport-routing family carried by ``get_llm_env()``.

    Pre-fix, ``get_llm_env()`` stripped ``CLAUDE_CODE_USE_BEDROCK``,
    ``CLAUDE_CODE_USE_MANTLE``, ``ANTHROPIC_MODEL``, ``AWS_PROFILE``
    and ``AWS_REGION`` (none were in SAFE_ENV_ALLOWLIST or
    LLM_API_KEY_VARS), so every spawned LLM child lost the operator's
    backend selection: minimal ``{"provider": "bedrock"}`` entries
    could not backfill from the Claude Code install, the SigV4 chain
    lost its profile/region pins, and claudecode-fallback ``claude -p``
    grandchildren silently flipped from the operator's Bedrock backend
    to the direct API — HTTP 400 on Bedrock-shaped model ids.
    """

    _FAMILY = {
        "CLAUDE_CODE_USE_BEDROCK": "1",
        "CLAUDE_CODE_USE_MANTLE": "1",
        "ANTHROPIC_MODEL": "us.anthropic.claude-opus-4-8-v1:0",
        "AWS_PROFILE": "llm-signing",
        "AWS_REGION": "us-east-1",
        "AWS_DEFAULT_REGION": "us-west-2",
        "AWS_SHARED_CREDENTIALS_FILE": "/home/op/.aws/alt-credentials",
        "AWS_CONFIG_FILE": "/home/op/.aws/alt-config",
        "CLAUDE_CODE_USE_VERTEX": "1",
        "CLAUDE_CODE_USE_FOUNDRY": "1",
        "ANTHROPIC_SMALL_FAST_MODEL": "anthropic.claude-haiku-4-5",
        "ANTHROPIC_BASE_URL": "https://proxy.example/v1",
    }

    def test_family_carried_junk_stripped(self):
        """Ambient containing the family + junk: family present, junk
        stripped, allowlist discipline intact."""
        injected = {
            **self._FAMILY,
            # Junk that must NOT flow: unrelated var, AWS-prefixed
            # var outside the explicit list (proves no blanket AWS_
            # prefix), and a shell-eval vector.
            "TOTALLY_UNRELATED_VAR": "junk",
            "AWS_VAULT": "some-vault-profile",
            "BASH_ENV": "/tmp/evil.sh",
        }
        with patch.dict(os.environ, injected):
            env = RaptorConfig.get_llm_env()
            for var, val in self._FAMILY.items():
                assert env.get(var) == val, f"{var} missing from get_llm_env()"
            assert "TOTALLY_UNRELATED_VAR" not in env
            assert "AWS_VAULT" not in env
            assert "BASH_ENV" not in env

    def test_raptor_prefix_families_carried(self):
        """RAPTOR_BEDROCK_* / RAPTOR_CC_* operator knobs flow; the
        dispatcher route vars are NOT blanket-inherited (a socket
        path without its token FD is a broken route — only
        spawn_worker may set the pair)."""
        injected = {
            "RAPTOR_BEDROCK_MODEL": "anthropic.claude-opus-4-8",
            "RAPTOR_BEDROCK_PROFILE": "bedrock-signing",
            "RAPTOR_BEDROCK_REGION": "us-east-1",
            "RAPTOR_BEDROCK_API": "mantle",
            "RAPTOR_CC_MODEL": "opus",
            "RAPTOR_CC_EFFORT": "high",
        }
        with patch.dict(os.environ, {**injected,
                                     "RAPTOR_LLM_SOCKET": "/tmp/d.sock",
                                     "RAPTOR_LLM_TOKEN_FD": "7"}):
            env = RaptorConfig.get_llm_env()
            for var, val in injected.items():
                assert env.get(var) == val, f"{var} missing from get_llm_env()"
            assert "RAPTOR_LLM_SOCKET" not in env
            assert "RAPTOR_LLM_TOKEN_FD" not in env

    def test_no_family_vars_invented(self):
        scrubbed = {
            k: v for k, v in os.environ.items()
            if k not in RaptorConfig.LLM_ROUTING_ENV_VARS
            and not k.startswith(RaptorConfig.LLM_ROUTING_ENV_PREFIXES)
        }
        with patch.dict(os.environ, scrubbed, clear=True):
            env = RaptorConfig.get_llm_env()
            for var in RaptorConfig.LLM_ROUTING_ENV_VARS:
                assert var not in env

    def test_bedrock_bearer_flows_in_llm_env_only(self):
        """AWS_BEARER_TOKEN_BEDROCK is a credential: LLM children get
        it (selection signal + auth), untrusted-code envs never do."""
        with patch.dict(os.environ,
                        {"AWS_BEARER_TOKEN_BEDROCK": "bearer-test-value"}):
            assert RaptorConfig.get_llm_env().get(
                "AWS_BEARER_TOKEN_BEDROCK") == "bearer-test-value"
            assert "AWS_BEARER_TOKEN_BEDROCK" not in RaptorConfig.get_safe_env()

    def test_get_safe_env_posture_unchanged(self):
        """The general sanitisation posture is intact: none of the
        routing family leaks into get_safe_env() (untrusted-code
        subprocesses must not learn the operator's LLM topology)."""
        with patch.dict(os.environ, self._FAMILY):
            env = RaptorConfig.get_safe_env()
            for var in self._FAMILY:
                assert var not in env, f"{var} leaked into get_safe_env()"

    def test_family_disjoint_from_dangerous_vars(self):
        """strict_env paths re-strip DANGEROUS_ENV_VARS — the routing
        family must stay disjoint so the two mechanisms never fight
        (guards future drift in either list)."""
        overlap = set(RaptorConfig.LLM_ROUTING_ENV_VARS) & set(
            RaptorConfig.DANGEROUS_ENV_VARS)
        assert not overlap
        for var in RaptorConfig.DANGEROUS_ENV_VARS:
            assert not var.startswith(RaptorConfig.LLM_ROUTING_ENV_PREFIXES)

    def test_raptor_dir_pin_unaffected(self):
        """RAPTOR_DIR pinning at the same chokepoint survives the
        family overlay (no name collision; SET value wins)."""
        with patch.dict(os.environ, self._FAMILY):
            env = RaptorConfig.get_llm_env()
            assert env.get("RAPTOR_DIR") == str(RaptorConfig.REPO_ROOT)


class TestEnvFlag:
    """Shared boolean-toggle parser (``core.config.env_flag``)."""

    _VAR = "RAPTOR_TEST_ENV_FLAG"

    def _flag(self, value, default):
        from core.config import env_flag
        with patch.dict(os.environ, {self._VAR: value}):
            return env_flag(self._VAR, default=default)

    @pytest.mark.parametrize("value", ["1", "true", "yes", "on"])
    def test_truthy_spellings(self, value):
        assert self._flag(value, default=False) is True
        assert self._flag(value, default=True) is True

    @pytest.mark.parametrize("value", ["0", "false", "no", "off"])
    def test_falsy_spellings(self, value):
        assert self._flag(value, default=True) is False
        assert self._flag(value, default=False) is False

    @pytest.mark.parametrize("value", ["TRUE", " On ", "YES", "\ttrue\n"])
    def test_case_and_whitespace_insensitive_truthy(self, value):
        assert self._flag(value, default=False) is True

    @pytest.mark.parametrize("value", ["FALSE", " Off ", "NO", "\t0\n"])
    def test_case_and_whitespace_insensitive_falsy(self, value):
        assert self._flag(value, default=True) is False

    def test_unset_returns_default(self):
        from core.config import env_flag
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(self._VAR, None)
            assert env_flag(self._VAR, default=True) is True
            assert env_flag(self._VAR, default=False) is False

    def test_empty_and_blank_return_default(self):
        assert self._flag("", default=True) is True
        assert self._flag("   ", default=False) is False

    def test_unrecognised_warns_and_returns_default(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="core.config"):
            assert self._flag("enabled", default=True) is True
            assert self._flag("ture", default=False) is False
        warnings = [r for r in caplog.records
                    if "not a recognised boolean toggle" in r.getMessage()]
        assert len(warnings) == 2
        assert self._VAR in warnings[0].getMessage()

    def test_recognised_values_do_not_warn(self, caplog):
        import logging
        with caplog.at_level(logging.WARNING, logger="core.config"):
            self._flag("on", default=False)
            self._flag("off", default=True)
        assert not [r for r in caplog.records
                    if "boolean toggle" in r.getMessage()]


class TestPolicyGroupRuleFiles:
    """Single-file policy groups must point at real in-repo rule files."""

    def test_entries_exist_on_disk(self):
        from core.config import RaptorConfig
        for group, path in RaptorConfig.POLICY_GROUP_RULE_FILES.items():
            assert path.is_file(), f"group {group!r} points at missing {path}"

    def test_keys_do_not_shadow_rule_directories(self):
        from core.config import RaptorConfig
        for group in RaptorConfig.POLICY_GROUP_RULE_FILES:
            assert not (RaptorConfig.SEMGREP_RULES_DIR / group).is_dir(), (
                f"group {group!r} also has a rule directory — the dir "
                "wins in scanner group resolution; remove the alias"
            )

    def test_ssrf_group_present(self):
        from core.config import RaptorConfig
        assert "ssrf" in RaptorConfig.POLICY_GROUP_RULE_FILES
