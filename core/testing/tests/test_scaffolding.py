"""Self-tests for core.testing — the shared test scaffolding.

Pin the consolidated behaviours, including the drift fixes: the
fake provider's ``**kwargs`` signature, the egress fixture's FULL
proxy-var family + ``OLLAMA_HOST`` pin, and the git helpers'
hermeticity (operator config scrubbed, identity pinned, deterministic
branch).
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from core.testing import (
    DEFAULT_OLLAMA_HOST,
    PROXY_ENV_VARS,
    FakeStructuredProvider,
    git_run,
    init_scratch_repo,
    install_provider,
    make_test_client,
    reset_llm_egress_state,
)

HAVE_GIT = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not HAVE_GIT, reason="git not installed")


class TestFakeStructuredProvider:
    def test_returns_canned_pair_and_counts(self):
        fake = FakeStructuredProvider({"verdict": "safe"}, raw="RAW")
        out = fake.generate_structured("p", {"type": "object"})
        assert out == ({"verdict": "safe"}, "RAW")
        assert fake.calls == 1
        assert fake.total_cost > 0
        assert fake.total_tokens > 0

    def test_accepts_per_call_kwargs(self):
        # Drift fix pin: copies without **kwargs TypeError'd when the
        # client forwarded per-call options like temperature.
        fake = FakeStructuredProvider({})
        fake.generate_structured(
            "p", {}, system_prompt="s", temperature=0.2, task_type="x",
        )
        assert fake.last_kwargs == {"temperature": 0.2, "task_type": "x"}

    def test_client_integration_end_to_end(self, tmp_path):
        client = make_test_client(tmp_path)
        fake = FakeStructuredProvider({"k": "v"})
        install_provider(client, fake)
        resp = client.generate_structured("prompt", {
            "type": "object", "properties": {"k": {"type": "string"}},
        })
        assert resp.result == {"k": "v"}
        assert fake.calls == 1


class TestEgressFixtureBody:
    def test_scrubs_full_proxy_family_and_pins_ollama(self, monkeypatch):
        # Drift fix pin: one conftest copy scrubbed only 4 of the 8
        # conventional proxy vars; another lost the OLLAMA_HOST pin.
        assert len(PROXY_ENV_VARS) == 8
        monkeypatch.setenv("HTTP_PROXY", "http://corp:3128")
        monkeypatch.setenv("ALL_PROXY", "http://corp:3128")
        monkeypatch.setenv("OLLAMA_HOST", "10.0.0.9:11434")
        gen = reset_llm_egress_state(monkeypatch)
        next(gen)
        for var in PROXY_ENV_VARS:
            assert var not in os.environ
        assert os.environ["OLLAMA_HOST"] == DEFAULT_OLLAMA_HOST
        with pytest.raises(StopIteration):
            next(gen)

    def test_resets_egress_module_state(self, monkeypatch):
        from core.llm import egress
        gen = reset_llm_egress_state(monkeypatch)
        next(gen)
        egress._enabled = True
        with pytest.raises(StopIteration):
            next(gen)
        assert egress._enabled is False


@needs_git
class TestGitScaffolding:
    def test_init_scratch_repo_pins_branch(self, tmp_path):
        repo = init_scratch_repo(tmp_path)
        (repo / "f.txt").write_text("x\n")
        git_run(repo, "add", "f.txt")
        git_run(repo, "commit", "-q", "-m", "first")
        assert git_run(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"

    def test_hermetic_against_operator_gitconfig(self, tmp_path, monkeypatch):
        # A hostile/flaky global config (signing on, odd default
        # branch) must not leak into fixture repos.
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        gitconfig = fake_home / ".gitconfig"
        gitconfig.write_text(
            "[init]\n\tdefaultBranch = trunk\n"
            "[commit]\n\tgpgsign = true\n"
            "[user]\n\tname = Operator\n\temail = op@example.com\n"
        )
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(gitconfig))
        repo = init_scratch_repo(tmp_path)
        (repo / "f.txt").write_text("x\n")
        git_run(repo, "add", "f.txt")
        git_run(repo, "commit", "-q", "-m", "first")
        assert git_run(repo, "rev-parse", "--abbrev-ref", "HEAD") == "main"
        author = git_run(repo, "log", "-1", "--format=%an <%ae>")
        assert author == "fixture <fixture@example.invalid>"

    def test_git_run_raises_on_failure(self, tmp_path):
        repo = init_scratch_repo(tmp_path)
        with pytest.raises(subprocess.CalledProcessError):
            git_run(repo, "not-a-subcommand")
