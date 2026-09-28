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
            lambda c, label, run_dir=None: calls.append((c, label, run_dir)),
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
        assert calls == [(client, "raptor-study-run", tmp_path.resolve())]

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
        assert calls == [(client, "raptor-study-run", tmp_path.resolve())]


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
                (list(configs), label, run_dir)),
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
        configs, label, run_dir = route_calls[0]
        assert label == "raptor-synthesise-checker"
        assert "primary-cfg" in configs
        # The L5 audit log follows run_dir into this run's output dir.
        assert run_dir == tmp_path / "out"


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
              model="pinned-model", run_dir=None):
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
            lambda configs, **kw: routes.append((list(configs), kw)),
        )
        prep_mod._llm_seed_concepts_from_names(
            ["ownership"], ["a_fn", "b_fn"], model=model, run_dir=run_dir)
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


# ------------------------------------------------------------------
# run_dir threading: the L5 audit log must land in the run directory
# ------------------------------------------------------------------


class TestStudyRunAuditLogPlacement:
    """The dispatcher's L5 audit JSONL follows ``run_dir`` into the
    run's output directory. Pre-fix the CLI called the shared gate
    without one, so on a dispatcher-only (Bedrock-routed) primary the
    audit log fell back to the gate's in-memory default instead of
    the run directory the operator can inspect."""

    def test_gate_receives_the_run_output_dir(
        self, tmp_path, monkeypatch, study_run_mod,
    ) -> None:
        (tmp_path / "study-list.json").write_text(
            json.dumps({"items": []}), encoding="utf-8")
        client = SimpleNamespace(
            config=SimpleNamespace(
                primary_model=SimpleNamespace(provider="bedrock"),
                fallback_models=[],
            ),
        )
        monkeypatch.setitem(
            sys.modules, "packages.llm_analysis", _fake_llm_module(client))
        monkeypatch.setattr(
            study_run_mod, "run_study", lambda *a, **k: _fake_study_model())
        monkeypatch.setattr(sys, "argv", ["raptor-study-run", str(tmp_path)])
        monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)

        # Real route gates run; only the placement owner is stubbed —
        # the run_dir it receives IS where the audit log would land.
        import core.llm.dispatcher.lifecycle as lifecycle
        placements: list = []

        def fake_env(label="inprocess", run_dir=None):
            placements.append((label, run_dir))
            return None

        monkeypatch.setattr(
            lifecycle, "ensure_inprocess_dispatcher_env", fake_env)

        assert study_run_mod.main() == 0
        assert placements == [("raptor-study-run", tmp_path.resolve())]


class TestStudyLoopRunDirThreading:
    @pytest.fixture
    def study_loop_mod(self) -> ModuleType:
        return _load_script(
            RAPTOR_DIR / "libexec" / "raptor-study-loop",
            "raptor_study_loop_bootstrap",
        )

    def _gate_recorder(self, monkeypatch) -> list:
        import core.llm.dispatcher.lifecycle as lifecycle
        calls: list = []
        monkeypatch.setattr(
            lifecycle, "ensure_route_for_client",
            lambda client, label, run_dir=None: calls.append(
                (label, run_dir)),
        )
        return calls

    def test_wrapper_forwards_run_dir_to_shared_gate(
        self, tmp_path, monkeypatch, study_loop_mod,
    ) -> None:
        calls = self._gate_recorder(monkeypatch)
        client = SimpleNamespace()
        study_loop_mod._ensure_llm_dispatcher(
            client, "raptor-study-loop", run_dir=tmp_path)
        assert calls == [("raptor-study-loop", tmp_path)]

    def test_wrapper_defaults_to_no_placement(
        self, monkeypatch, study_loop_mod,
    ) -> None:
        # Two-direction: without a run_dir the gate keeps its
        # documented in-memory fallback (run_dir=None), unchanged.
        calls = self._gate_recorder(monkeypatch)
        study_loop_mod._ensure_llm_dispatcher(
            SimpleNamespace(), "raptor-study-loop")
        assert calls == [("raptor-study-loop", None)]

    def _broken_client_module(self) -> tuple[SimpleNamespace, ModuleType]:
        def _boom(*a, **k):
            raise RuntimeError("no LLM in tests")

        client = SimpleNamespace(generate_structured=_boom)
        return client, _fake_llm_module(client)

    def test_overview_threads_run_dir(
        self, tmp_path, monkeypatch, study_loop_mod,
    ) -> None:
        client, llm_mod = self._broken_client_module()
        monkeypatch.setitem(sys.modules, "packages.llm_analysis", llm_mod)
        calls: list = []
        monkeypatch.setattr(
            study_loop_mod, "_ensure_llm_dispatcher",
            lambda c, label, run_dir=None: calls.append((c, label, run_dir)),
        )
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f(void){return 0;}\n",
                                    encoding="utf-8")
        run_dir = tmp_path / "out"
        result = study_loop_mod._overview_from_directory(
            target, model=None, run_dir=run_dir)
        assert result == ([], [], "", "")  # LLM stub fails; best-effort
        assert calls == [(client, "raptor-study-loop", run_dir)]

    def test_synthesis_threads_run_dir(
        self, tmp_path, monkeypatch, study_loop_mod,
    ) -> None:
        client, llm_mod = self._broken_client_module()
        monkeypatch.setitem(sys.modules, "packages.llm_analysis", llm_mod)
        calls: list = []
        monkeypatch.setattr(
            study_loop_mod, "_ensure_llm_dispatcher",
            lambda c, label, run_dir=None: calls.append((c, label, run_dir)),
        )
        dm_data = {"concepts": [{"id": "c1", "description": "d"}],
                   "invariants": [], "contracts": []}
        result = study_loop_mod._synthesise_overview(
            dm_data, None, run_dir=tmp_path)
        assert result == ("", "", "", None)  # LLM stub fails; best-effort
        assert calls == [(client, "raptor-study-loop", tmp_path)]


class TestStudyPrepRunDirThreading:
    @pytest.fixture
    def prep_mod(self) -> ModuleType:
        return _load_script(
            RAPTOR_DIR / "libexec" / "raptor-study-prep",
            "raptor_study_prep_bootstrap",
        )

    def test_seeding_threads_run_dir_to_gate(
        self, tmp_path, monkeypatch, prep_mod,
    ) -> None:
        seeding = TestStudyPrepSeedingClient()
        seen, routes = seeding._seed(
            monkeypatch, prep_mod, api_key=None, provider="bedrock",
            run_dir=tmp_path)
        assert routes, "dispatcher route bootstrap never ran"
        _configs, kwargs = routes[0]
        assert kwargs["run_dir"] == tmp_path

    def test_seeding_without_run_dir_keeps_fallback(
        self, monkeypatch, prep_mod,
    ) -> None:
        # Two-direction: the default stays the gate's in-memory
        # fallback (run_dir=None), unchanged for run-dir-less callers.
        seeding = TestStudyPrepSeedingClient()
        _seen, routes = seeding._seed(
            monkeypatch, prep_mod, api_key=None, provider="bedrock")
        assert routes
        assert routes[0][1]["run_dir"] is None


class TestCompileInvariantsRunDir:
    def test_gate_receives_the_run_output_dir(
        self, tmp_path, monkeypatch,
    ) -> None:
        mod = _load_script(
            RAPTOR_DIR / "libexec" / "raptor-compile-invariants",
            "raptor_compile_invariants_bootstrap",
        )
        out_dir = tmp_path / "run"
        out_dir.mkdir()
        (out_dir / "domain-model.json").write_text("{}", encoding="utf-8")

        invariant = SimpleNamespace(
            id="inv-1", statement="s", negation="n",
            mechanical_rule=None, confidence="traced",
        )
        fake_model = SimpleNamespace(invariants=[invariant],
                                     save=lambda p: None)
        import core.concepts.model as concepts_model
        monkeypatch.setattr(
            concepts_model, "DomainModel",
            SimpleNamespace(load=lambda p: fake_model),
        )

        client = SimpleNamespace(config=SimpleNamespace())
        import core.llm.client as llm_client
        monkeypatch.setattr(llm_client, "LLMClient", lambda **kw: client)

        import core.llm.dispatcher.lifecycle as lifecycle
        calls: list = []
        monkeypatch.setattr(
            lifecycle, "ensure_route_for_client",
            lambda c, label, run_dir=None: calls.append(
                (c, label, run_dir)),
        )

        import core.concepts.compiler as compiler
        monkeypatch.setattr(compiler, "compile_model",
                            lambda *a, **k: [])

        monkeypatch.setattr(
            sys, "argv", ["raptor-compile-invariants", str(out_dir)])
        assert mod.main() == 0
        assert calls == [(client, "raptor-compile-invariants",
                          out_dir.resolve())]
