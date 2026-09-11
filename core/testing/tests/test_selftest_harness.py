"""Hermeticity contracts of the ``libexec/raptor-self-test`` harness.

The self-test promises that tier-0 children can never resolve a paid
external LLM and that its cases exercise real outcomes (no vacuous
assertions). These tests import the script as a module and pin:

* the tier-0 env scrub covers every env signal
  ``core.llm.detection`` treats as an available external LLM, and the
  models-config discovery path is redirected to an empty stub;
* ``case_project_lifecycle`` actually fails when the project manager
  breaks, and keeps all state under the scratch tree;
* the tool-matrix classifies an unexercised (build-failed) AFL entry
  as a visible skip, never a clean pass;
* the no-secret-leakage sweep sees both the outputs and the logs
  trees, in both directions.

Everything runs against scratch/tmp state: fake HOME, scrubbed env,
no network, no LLM calls.
"""

from __future__ import annotations

import argparse
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:
    from types import ModuleType

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-self-test"


@pytest.fixture(scope="module")
def selftest() -> Any:
    """Import the raptor-self-test script as a module (trust marker set)."""
    prior = os.environ.get("_RAPTOR_TRUSTED")
    os.environ["_RAPTOR_TRUSTED"] = "1"
    try:
        loader = importlib.machinery.SourceFileLoader(
            "raptor_self_test", str(SCRIPT),
        )
        spec = importlib.util.spec_from_loader("raptor_self_test", loader)
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        sys.modules["raptor_self_test"] = mod
        spec.loader.exec_module(mod)
        yield mod
    finally:
        sys.modules.pop("raptor_self_test", None)
        if prior is None:
            os.environ.pop("_RAPTOR_TRUSTED", None)
        else:
            os.environ["_RAPTOR_TRUSTED"] = prior


def _make_ctx(selftest: "ModuleType", scratch: Path) -> Any:
    args = argparse.Namespace(
        timeout=120, keep=False, model=None, max_llm_cost=2.0,
        only=[], with_llm=False, deep=False, json=None, case_workers=1,
    )
    return selftest.Ctx(scratch, args)


def _poison_llm_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Set every LLM env signal plus a keyed models.json in a fake HOME
    and via RAPTOR_CONFIG — the worst-case operator environment a
    tier-0 child must never see."""
    keyed = {"models": [{"provider": "openai", "model": "gpt-fixture",
                         "api_key": "unit-test-inline-key"}]}
    home = tmp_path / "poison-home"
    cfg_dir = home / ".config" / "raptor"
    cfg_dir.mkdir(parents=True)
    (cfg_dir / "models.json").write_text(json.dumps(keyed))
    explicit = tmp_path / "keyed-models.json"
    explicit.write_text(json.dumps(keyed))
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("RAPTOR_CONFIG", str(explicit))
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
                "MISTRAL_API_KEY", "AWS_BEARER_TOKEN_BEDROCK",
                "RAPTOR_BEDROCK_MODEL", "RAPTOR_BEDROCK_PROFILE",
                "RAPTOR_LLM_SOCKET"):
        monkeypatch.setenv(var, "unit-test-poison")
    return home


class TestTier0LlmScrub:
    def test_scrub_covers_every_detection_signal(self, selftest) -> None:
        # Every env var core.llm.detection counts toward external-LLM
        # availability (cloud keys, the Bedrock opt-in signals, the
        # dispatcher socket) plus the Claude Code marker must be in
        # the scrub set — one omission makes tier-0 children able to
        # dispatch paid calls.
        required = {
            "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY",
            "MISTRAL_API_KEY", "AWS_BEARER_TOKEN_BEDROCK",
            "RAPTOR_BEDROCK_MODEL", "RAPTOR_BEDROCK_PROFILE",
            "RAPTOR_LLM_SOCKET", "CLAUDECODE",
        }
        missing = required - set(selftest._LLM_ENV_VARS)
        assert not missing, f"tier-0 scrub misses LLM signals: {missing}"

    def test_env_t0_strips_signals_and_neutralises_config(
        self, selftest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        _poison_llm_env(monkeypatch, tmp_path)
        ctx = _make_ctx(selftest, tmp_path / "scratch")
        env = ctx.env_t0()
        for var in selftest._LLM_ENV_VARS:
            assert var not in env, f"{var} survived the tier-0 scrub"
        # Config discovery must resolve to the empty stub, defeating
        # both $RAPTOR_CONFIG and the HOME-path fallback.
        assert env["RAPTOR_CONFIG"] == str(ctx.empty_models_config)
        assert json.loads(ctx.empty_models_config.read_text()) == {
            "models": [],
        }

    def test_env_t0_child_resolves_no_external_llm(
        self, selftest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Functional: with the worst-case poisoned operator env, a
        # child running the real detection must report no external
        # LLM (the paid-call gate for every tier-0 case).
        _poison_llm_env(monkeypatch, tmp_path)
        ctx = _make_ctx(selftest, tmp_path / "scratch")
        env = ctx.env_t0()
        env.setdefault("RAPTOR_DIR", str(REPO_ROOT))
        probe = (
            "import os, sys\n"
            "sys.path.insert(0, os.environ['RAPTOR_DIR'])\n"
            "from core.llm.detection import detect_llm_availability\n"
            "print('EXTERNAL', detect_llm_availability().external_llm)\n"
        )
        proc = subprocess.run(
            [sys.executable, "-c", probe], env=env, cwd=str(REPO_ROOT),
            capture_output=True, text=True, timeout=120, check=False,
        )
        assert proc.returncode == 0, proc.stderr[-500:]
        assert "EXTERNAL False" in proc.stdout, (
            f"tier-0 child still resolves an external LLM:\n"
            f"{proc.stdout}{proc.stderr[-300:]}"
        )

    def test_env_llm_keeps_operator_env(
        self, selftest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # Tier 1 is the other direction: the operator's keys and
        # config must stay visible.
        monkeypatch.setenv("ANTHROPIC_API_KEY", "unit-test-value")
        ctx = _make_ctx(selftest, tmp_path / "scratch")
        env = ctx.env_llm()
        assert env["ANTHROPIC_API_KEY"] == "unit-test-value"
        assert env.get("RAPTOR_CONFIG") != str(ctx.empty_models_config)


class TestProjectLifecycleCase:
    def test_broken_project_manager_fails_the_case(
        self, selftest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A project manager that exits nonzero on every subcommand
        # must fail the case (it used to pass unconditionally).
        fake_repo = tmp_path / "fake-repo"
        (fake_repo / "libexec").mkdir(parents=True)
        stub = fake_repo / "libexec" / "raptor-project-manager"
        stub.write_text("#!/bin/sh\nexit 1\n")
        stub.chmod(0o755)
        monkeypatch.setattr(selftest, "_RAPTOR_DIR", fake_repo)
        ctx = _make_ctx(selftest, tmp_path / "scratch")
        ctx.fixture.mkdir(parents=True, exist_ok=True)
        with pytest.raises(AssertionError):
            selftest.case_project_lifecycle(ctx)

    @pytest.mark.slow
    def test_lifecycle_passes_and_stays_in_scratch(
        self, selftest, tmp_path: Path,
    ) -> None:
        # Good direction: against the real project manager the whole
        # step list succeeds, and no state leaks outside the scratch
        # tree (isolated HOME registry + RAPTOR_OUT_DIR data dirs).
        ctx = _make_ctx(selftest, tmp_path / "scratch")
        ctx.fixture.mkdir(parents=True, exist_ok=True)
        (ctx.fixture / "app.py").write_text("x = 1\n")
        repo_projects = REPO_ROOT / "out" / "projects"
        before = (set(os.listdir(repo_projects))
                  if repo_projects.is_dir() else set())
        selftest.case_project_lifecycle(ctx)
        after = (set(os.listdir(repo_projects))
                 if repo_projects.is_dir() else set())
        assert after == before, (
            f"project state leaked into the checkout: {after - before}"
        )
        # The case's own end-state check: scratch registry left empty.
        registry = ctx.home / ".raptor" / "projects"
        assert not list(registry.glob("*.json"))


class TestRunLifecycleCase:
    def test_fail_leg_asserted_end_to_end(
        self, selftest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # start → complete → start → fail, with the fail leg now
        # checked (exit 0 + status=failed recorded in run2's dir).
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("XDG_DATA_HOME", str(home / ".local" / "share"))
        monkeypatch.setenv("XDG_CACHE_HOME", str(home / ".cache"))
        ctx = _make_ctx(selftest, tmp_path / "scratch")
        ctx.fixture.mkdir(parents=True, exist_ok=True)
        (ctx.fixture / "app.py").write_text("x = 1\n")
        selftest.case_run_lifecycle(ctx)
        status = json.loads(
            (ctx.outs / "lifecycle" / "run2" / ".raptor-run.json")
            .read_text()
        )
        assert status.get("status") == "failed"


class TestToolMatrixSkip:
    def test_failed_afl_build_returns_skip_verdict(
        self, selftest, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        stub = tmp_path / "afl-clang-fast"
        stub.write_text("#!/bin/sh\necho 'no such target' >&2\nexit 1\n")
        stub.chmod(0o755)
        monkeypatch.setattr(
            selftest.shutil, "which",
            lambda name, *a, **k: (
                str(stub) if name in ("afl-clang-fast", "afl-gcc") else None
            ),
        )
        ctx = _make_ctx(selftest, tmp_path / "scratch")
        native = ctx.fixture / "native"
        native.mkdir(parents=True)
        (native / "main.c").write_text("int main(void){return 0;}\n")
        verdict = selftest._run_afl_matrix(ctx, dict(os.environ))
        assert verdict.get("skip"), "build failure must yield a skip verdict"
        # The old shape returned rc=0, which sat inside afl-showmap's
        # expected set and read as a clean pass forever.
        assert verdict.get("rc") != 0
        assert selftest._matrix_entry_status(verdict, [0, 2], False) == "skip"

    def test_matrix_entry_status_directions(self, selftest) -> None:
        st = selftest._matrix_entry_status
        assert st({"rc": 0}, [0, 2], False) == "pass"
        assert st({"rc": 2}, [0, 2], False) == "pass"
        assert st({"rc": 7}, [0, 2], False) == "fail"
        assert st({"rc": 0, "fallback": True}, [0], False) == "degraded"
        assert st({"rc": 0, "fallback": True}, [0], True) == "fail"
        # skip wins over everything — it must never read as pass.
        assert st({"rc": 0, "skip": "x"}, [0], False) == "skip"


class TestNoSecretLeakageSweep:
    def test_clean_trees_pass(self, selftest, tmp_path: Path) -> None:
        ctx = _make_ctx(selftest, tmp_path / "scratch")
        (ctx.outs / "report.md").write_text("all clean\n")
        (ctx.logs / "scan.log").write_text("$ scan\nok\n")
        selftest.case_no_secret_leakage(ctx)

    def test_marker_in_outputs_fails(self, selftest, tmp_path: Path) -> None:
        ctx = _make_ctx(selftest, tmp_path / "scratch")
        (ctx.outs / "combined.sarif").write_text("token sk-FAKE-leak\n")
        with pytest.raises(AssertionError, match="leaked"):
            selftest.case_no_secret_leakage(ctx)

    def test_marker_in_logs_fails(self, selftest, tmp_path: Path) -> None:
        # The logs tree is where the hostile fixture's consumers write
        # their captured stdout — a masking regression lands here.
        ctx = _make_ctx(selftest, tmp_path / "scratch")
        (ctx.logs / "trust-mask-hostile.log").write_text(
            "report: key sk-FAKE-leak\n"
        )
        with pytest.raises(AssertionError, match="leaked"):
            selftest.case_no_secret_leakage(ctx)

    def test_oversize_files_reported_not_silent(
        self, selftest, tmp_path: Path, capsys: pytest.CaptureFixture[str],
    ) -> None:
        ctx = _make_ctx(selftest, tmp_path / "scratch")
        big = ctx.outs / "huge.sarif"
        with open(big, "wb") as fh:
            fh.write(b"sk-FAKE-hidden")
            fh.truncate(50_000_001)  # sparse: st_size counts, no disk cost
        selftest.case_no_secret_leakage(ctx)
        assert "not swept" in capsys.readouterr().out


class TestHelpTextTruthful:
    def test_max_llm_cost_documented_per_case(self) -> None:
        env = dict(os.environ)
        env["_RAPTOR_TRUSTED"] = "1"
        proc = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"], env=env,
            cwd=str(REPO_ROOT), capture_output=True, text=True,
            timeout=120, check=False,
        )
        assert proc.returncode == 0
        # The cap is enforced per case (audit 0.50, agentic 1.00), so
        # the help must not promise a single total ceiling.
        assert "per-case USD ceiling" in proc.stdout
        assert "total USD ceiling" not in proc.stdout
