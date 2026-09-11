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
            lambda configs, label=None: route_calls.append(
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
