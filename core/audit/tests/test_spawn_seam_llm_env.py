"""LLM-env discipline at the spawn seams (post-sweep contract).

Two directions, one family:

* LLM-calling children (study-prep, agentic phase-3 agent,
  validation-helper, sca/binary/frida surfaces, fuzz crash analysis)
  must receive the operator's backend selection — the transport-
  routing family (and, where their design allows, the API keys).
* Non-LLM children spawned from full-environ copies (SMT/Z3 probes:
  they must mirror the parent's interpreter env to unpickle RAPTOR
  verbs) must NOT carry credentials, backend selection, or a broken
  half-route.
"""

from __future__ import annotations

import pytest


_LLM_AMBIENT = {
    "ANTHROPIC_API_KEY": "sk-ant-seam-test",
    "AWS_BEARER_TOKEN_BEDROCK": "bearer-seam-test",
    "CLAUDE_CODE_USE_BEDROCK": "1",
    "CLAUDE_CODE_USE_MANTLE": "1",
    "ANTHROPIC_MODEL": "us.anthropic.claude-opus-4-8-v1:0",
    "AWS_PROFILE": "seam-profile",
    "AWS_REGION": "us-east-1",
    "RAPTOR_BEDROCK_MODEL": "anthropic.claude-opus-4-8",
    "RAPTOR_CC_EFFORT": "high",
}


@pytest.fixture
def llm_ambient(monkeypatch):
    for k, v in _LLM_AMBIENT.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("RAPTOR_LLM_SOCKET", "/tmp/seam.sock")
    monkeypatch.setenv("RAPTOR_LLM_TOKEN_FD", "9")
    return dict(_LLM_AMBIENT)


class TestStripLlmEnvVars:

    def test_strips_keys_family_and_route(self, llm_ambient):
        import os

        from core.config import RaptorConfig

        env = RaptorConfig.strip_llm_env_vars(dict(os.environ))
        for var in (*_LLM_AMBIENT, "RAPTOR_LLM_SOCKET",
                    "RAPTOR_LLM_TOKEN_FD"):
            assert var not in env, f"{var} survived the strip"
        # Interpreter environment is otherwise untouched.
        assert "PATH" in env


class TestSmtChildrenCarryNoLlmEnv:
    """SMT/Z3 probe children make no LLM calls — full-environ copy
    minus the LLM surface."""

    def test_smt_child_env(self, llm_ambient):
        from core.audit.sweep import smt_child_env

        env = smt_child_env()
        for var in (*_LLM_AMBIENT, "RAPTOR_LLM_SOCKET"):
            assert var not in env
        # The chokepoint's original job is preserved.
        from core.config import RaptorConfig
        assert env["RAPTOR_DIR"] == str(RaptorConfig.REPO_ROOT)
        assert "PATH" in env

    def test_z3_child_env(self, llm_ambient):
        from core.audit.condition_smt import _z3_child_env

        env = _z3_child_env()
        for var in (*_LLM_AMBIENT, "RAPTOR_LLM_SOCKET"):
            assert var not in env
        from core.config import RaptorConfig
        assert env["RAPTOR_DIR"] == str(RaptorConfig.REPO_ROOT)


class TestBinaryActivePhaseEnv:
    """raptor_fuzzing children (LLM crash analysis) get get_llm_env();
    frida trace phases stay on the safe baseline."""

    def _capture(self, monkeypatch, tmp_path, *, llm: bool):
        import packages.binary_analysis.cli as cli

        captured: dict = {}

        def fake_run(cmd, **kwargs):
            captured.update(kwargs.get("env") or {})

            class R:
                returncode = 0
                stdout = ""
                stderr = ""
            return R()

        monkeypatch.setattr(cli.subprocess, "run", fake_run)
        cli._run_active_phase(
            kind="test", cmd=["/bin/true"], output_dir=tmp_path / "p",
            trusted=True, llm=llm,
        )
        return captured

    def test_llm_child_receives_keys_and_family(
        self, llm_ambient, monkeypatch, tmp_path,
    ):
        env = self._capture(monkeypatch, tmp_path, llm=True)
        assert env.get("ANTHROPIC_API_KEY") == "sk-ant-seam-test"
        assert env.get("CLAUDE_CODE_USE_BEDROCK") == "1"
        assert env.get("AWS_PROFILE") == "seam-profile"
        assert env.get("RAPTOR_CC_EFFORT") == "high"
        assert env.get("_RAPTOR_TRUSTED") == "1"

    def test_non_llm_child_stays_on_safe_env(
        self, llm_ambient, monkeypatch, tmp_path,
    ):
        env = self._capture(monkeypatch, tmp_path, llm=False)
        assert "ANTHROPIC_API_KEY" not in env
        assert "CLAUDE_CODE_USE_BEDROCK" not in env


class TestAgenticPhase3Overlay:
    """run_command_streaming children get the routing family overlay
    (names only — credentials stay relay-based by design)."""

    def test_family_overlaid_keys_absent(
        self, llm_ambient, monkeypatch,
    ):
        import raptor_agentic

        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
        monkeypatch.delenv("RAPTOR_LLM_TOKEN_FD", raising=False)

        captured: dict = {}

        class FakeProc:
            returncode = 0
            stdout = None
            stderr = None

            def __init__(self, cmd, **kwargs):
                captured.update(kwargs.get("env") or {})
                import io
                self.stdout = io.StringIO("")
                self.stderr = io.StringIO("")

            def wait(self, timeout=None):
                return 0

        monkeypatch.setattr(
            raptor_agentic.subprocess, "Popen", FakeProc,
        )
        rc, _out, _err = raptor_agentic.run_command_streaming(
            ["/bin/true"], "seam test",
        )
        assert rc == 0
        assert captured.get("CLAUDE_CODE_USE_BEDROCK") == "1"
        assert captured.get("ANTHROPIC_MODEL") == (
            "us.anthropic.claude-opus-4-8-v1:0")
        assert captured.get("AWS_PROFILE") == "seam-profile"
        assert captured.get("RAPTOR_BEDROCK_MODEL") == (
            "anthropic.claude-opus-4-8")
        # Phase B/C isolation intact: no credentials in the child env.
        assert "ANTHROPIC_API_KEY" not in captured
        assert "AWS_BEARER_TOKEN_BEDROCK" not in captured


class TestCcSubprocessEnvRaptorKnobs:
    """Skill-pass `claude` children drive libexec helpers that read
    RAPTOR's own LLM knobs — the prefix families must carry them."""

    def test_raptor_knobs_carried(self, llm_ambient):
        from core.llm.cc_adapter import cc_subprocess_env

        env = cc_subprocess_env()
        assert env.get("RAPTOR_BEDROCK_MODEL") == "anthropic.claude-opus-4-8"
        assert env.get("RAPTOR_CC_EFFORT") == "high"
        # Pre-existing families unchanged.
        assert env.get("CLAUDE_CODE_USE_BEDROCK") == "1"
        assert env.get("AWS_PROFILE") == "seam-profile"
