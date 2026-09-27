"""The standalone LLM-calling libexec CLIs must self-serve the
in-process dispatcher route on every client path, not just the
--model-pinned one."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

RAPTOR_DIR = Path(__file__).resolve().parents[3]


def _load_script(path: Path, name: str) -> ModuleType:
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_file_location(
        name, str(path), loader=loader,
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# ------------------------------------------------------------------
# raptor-study-run
# ------------------------------------------------------------------


@pytest.fixture
def study_run_mod() -> ModuleType:
    return _load_script(
        RAPTOR_DIR / "libexec" / "raptor-study-run",
        "raptor_study_run_bootstrap",
    )


def _fake_llm_module(client) -> ModuleType:
    mod = ModuleType("packages.llm_analysis")
    mod.get_client = lambda config=None: client
    return mod


def _fake_study_model() -> SimpleNamespace:
    return SimpleNamespace(concepts=[], invariants=[], contracts=[])


class TestStudyRunDispatcherBootstrap:
    def _prepare(self, tmp_path, monkeypatch, study_run_mod, argv):
        (tmp_path / "study-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8")
        client = SimpleNamespace()
        monkeypatch.setitem(
            sys.modules, "packages.llm_analysis", _fake_llm_module(client))
        calls: list[tuple] = []
        monkeypatch.setattr(
            study_run_mod, "_ensure_llm_dispatcher",
            lambda c, label: calls.append((c, label)),
        )
        monkeypatch.setattr(
            study_run_mod, "run_study",
            lambda *a, **k: _fake_study_model(),
        )
        monkeypatch.setattr(sys, "argv", ["raptor-study-run"] + argv)
        return client, calls

    def test_default_client_path_bootstraps_dispatcher(
        self, tmp_path, monkeypatch, study_run_mod,
    ) -> None:
        """No --model: the default get_client() branch still needs the
        route — the default primary can be dispatcher-only."""
        client, calls = self._prepare(
            tmp_path, monkeypatch, study_run_mod, [str(tmp_path)])
        assert study_run_mod.main() == 0
        assert calls == [(client, "raptor-study-run")]

    def test_pinned_model_path_bootstraps_dispatcher(
        self, tmp_path, monkeypatch, study_run_mod,
    ) -> None:
        client, calls = self._prepare(
            tmp_path, monkeypatch, study_run_mod,
            [str(tmp_path), "--model", "some-model"])

        class _FakeLLMConfig:
            def __init__(self, primary_model=None, fallback_models=None):
                self.primary_model = primary_model
                self.fallback_models = fallback_models or []

            def config_for_model(self, name):
                return SimpleNamespace(api_key="k", provider="test")

        import core.llm.config as llm_config
        monkeypatch.setattr(llm_config, "LLMConfig", _FakeLLMConfig)

        assert study_run_mod.main() == 0
        assert calls == [(client, "raptor-study-run")]


# ------------------------------------------------------------------
# raptor-synthesise-checker
# ------------------------------------------------------------------


class TestSynthesiseCheckerDispatcherBootstrap:
    def test_bootstraps_dispatcher_before_synthesis(
        self, tmp_path, monkeypatch,
    ) -> None:
        pytest.importorskip("packages.checker_synthesis")
        mod = _load_script(
            RAPTOR_DIR / "libexec" / "raptor-synthesise-checker",
            "raptor_synthesise_checker_bootstrap",
        )

        repo = tmp_path / "repo"
        (repo / "src").mkdir(parents=True)
        (repo / "src" / "a.c").write_text(
            "int f(void) {\n    return system(\"x\");\n}\n",
            encoding="utf-8",
        )

        fake_client = SimpleNamespace(
            config=SimpleNamespace(
                primary_model="primary-cfg", fallback_models=[]),
        )
        import core.llm.client as llm_client
        monkeypatch.setattr(llm_client, "LLMClient", lambda: fake_client)

        import core.llm.dispatcher.lifecycle as lifecycle
        route_calls: list[tuple] = []
        monkeypatch.setattr(
            lifecycle, "ensure_route_for_model_configs",
            lambda configs, label=None, run_dir=None: route_calls.append(
                (list(configs), label)),
        )

        import packages.checker_synthesis as checker_synthesis
        fake_result = SimpleNamespace(to_dict=lambda: {"rule": None})
        monkeypatch.setattr(
            checker_synthesis, "synthesise_and_run",
            lambda *a, **k: fake_result,
        )

        monkeypatch.setattr(sys, "argv", [
            "raptor-synthesise-checker",
            "--file", "src/a.c",
            "--function", "f",
            "--lines", "1-3",
            "--repo", str(repo),
            "--out", str(tmp_path / "out"),
            "--no-refine",
            "--json",
        ])
        assert mod.main() == 0
        assert len(route_calls) == 1
        configs, label = route_calls[0]
        assert label == "raptor-synthesise-checker"
        assert "primary-cfg" in configs


class TestMinConfidenceValidation:
    """A mistyped --min-confidence must be a usage error — the old
    `except ValueError: floor = 0` silently disabled the confidence
    floor and still forwarded the raw invalid string to
    compile_model."""

    def test_invalid_grade_rejected(self):
        import os
        import subprocess
        env = dict(os.environ, _RAPTOR_TRUSTED="1")
        res = subprocess.run(
            [sys.executable,
             str(RAPTOR_DIR / "libexec" / "raptor-compile-invariants"),
             "/nonexistent", "--min-confidence", "bogus"],
            env=env, capture_output=True, text=True, timeout=60,
            check=False,
        )
        assert res.returncode == 2
        assert "invalid choice" in res.stderr


# ------------------------------------------------------------------
# raptor-study-prep concept seeding
# ------------------------------------------------------------------


class TestStudyPrepSeedingClient:
    """Concept seeding must honour a keyless --model pin (Bedrock /
    claudecode / ollama are keyless BY DESIGN — study-run's gate
    documents the set) and bootstrap the dispatcher route like its
    siblings; pre-fix a pinned Bedrock run seeded concepts with a
    DIFFERENT model than it studied with, and standalone prep on a
    Bedrock default silently degraded to unseeded extraction."""

    @pytest.fixture
    def prep_mod(self) -> ModuleType:
        return _load_script(
            RAPTOR_DIR / "libexec" / "raptor-study-prep",
            "raptor_study_prep_bootstrap",
        )

    def _seed(self, monkeypatch, prep_mod, *, api_key, provider,
              model="pinned-model"):
        seen: dict = {}

        class _Client:
            config = SimpleNamespace(primary_model=None,
                                     fallback_models=[])

            def generate(self, prompt, max_tokens=0):
                return SimpleNamespace(content="[]")

        client = _Client()

        def fake_get_client(config=None):
            seen["config"] = config
            return client

        mod = ModuleType("packages.llm_analysis")
        mod.get_client = fake_get_client
        monkeypatch.setitem(sys.modules, "packages.llm_analysis", mod)

        class _FakeLLMConfig:
            def __init__(self, primary_model=None, fallback_models=None):
                self.primary_model = primary_model
                self.fallback_models = fallback_models or []

            def config_for_model(self, name):
                return SimpleNamespace(api_key=api_key,
                                       provider=provider, name=name)

        import core.llm.config as llm_config
        monkeypatch.setattr(llm_config, "LLMConfig", _FakeLLMConfig)

        routes: list = []
        import core.llm.dispatcher.lifecycle as lifecycle
        monkeypatch.setattr(
            lifecycle, "ensure_route_for_model_configs",
            lambda configs, **kw: routes.append(list(configs)),
        )
        prep_mod._llm_seed_concepts_from_names(
            ["ownership"], ["a_fn", "b_fn"], model=model)
        return seen, routes

    def test_keyless_pin_reaches_get_client(self, monkeypatch, prep_mod):
        seen, routes = self._seed(
            monkeypatch, prep_mod, api_key=None, provider="bedrock")
        assert seen["config"] is not None, (
            "keyless --model pin was silently dropped"
        )
        assert seen["config"].primary_model.provider == "bedrock"
        assert routes, "dispatcher route bootstrap never ran"

    def test_keyed_pin_still_reaches_get_client(self, monkeypatch,
                                                prep_mod):
        seen, _ = self._seed(
            monkeypatch, prep_mod, api_key="k", provider="test")
        assert seen["config"] is not None
        assert seen["config"].primary_model.api_key == "k"

    def test_unknown_keyless_provider_falls_back(self, monkeypatch,
                                                 prep_mod):
        seen, _ = self._seed(
            monkeypatch, prep_mod, api_key=None, provider="mystery")
        assert seen["config"] is None
