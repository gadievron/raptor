"""Fresh-process contracts for lightweight metadata imports and public APIs."""

import os
from pathlib import Path
import subprocess
import sys
import textwrap


# Make subprocess-only dependencies visible to CI's static import graph.
import core.project  # noqa: F401
import core.run  # noqa: F401


ROOT = Path(__file__).resolve().parents[3]


def _python(program, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = dict(os.environ, HOME=str(home), XDG_DATA_HOME=str(home / "data"),
               XDG_CACHE_HOME=str(home / "cache"))
    result = subprocess.run(
        [sys.executable, "-I", "-c",
         f"import sys\nsys.path.insert(0, {str(ROOT)!r})\n" + textwrap.dedent(program)],
        cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr


def test_metadata_imports_do_not_initialize_project_configuration(tmp_path):
    _python("""
        import core.project
        import core.run
        from core.project import registry_home, sessions
        from core.run import metadata

        assert set(core.project.__all__) <= set(dir(core.project))
        assert set(core.run.__all__) <= set(dir(core.run))
        for package in (core.project, core.run):
            try:
                getattr(package, "not_a_public_export")
            except AttributeError:
                pass
            else:
                raise AssertionError("unknown export did not raise AttributeError")
        for name in (
            "core.project.project", "core.project.clean", "core.project.report",
            "core.run.output", "core.config", "core.llm.model_brokers",
        ):
            assert name not in sys.modules, name
    """, tmp_path)


def test_public_exports_resolve_to_original_objects_and_are_cached(tmp_path):
    _python("""
        from importlib import import_module

        contracts = {
            "core.project": {
                "core.project.project": ("Project", "ProjectManager", "is_project_output_dir"),
                "core.project.clean": ("clean_project", "execute_clean", "plan_clean"),
                "core.project.report": ("generate_project_report",),
            },
            "core.run": {
                "core.run.metadata": (
                    "RUN_METADATA_FILE", "RunOwnershipError", "cancel_run", "complete_run",
                    "ensure_run_command", "fail_run", "generate_run_metadata", "infer_command_type",
                    "interrupt_run", "is_run_directory", "load_run_metadata",
                    "parse_timestamp_from_name", "resume_run", "start_run", "tracked_run",
                ),
                "core.run.output": ("TargetMismatchError", "get_output_dir"),
            },
        }
        for package_name, providers in contracts.items():
            package = import_module(package_name)
            expected = {name for names in providers.values() for name in names}
            assert set(package.__all__) == expected
            for module_name, names in providers.items():
                for name in names:
                    value = getattr(package, name)
                    assert value is getattr(import_module(module_name), name)
                    assert vars(package)[name] is value
            namespace = {}
            exec(f"from {package_name} import *", namespace)
            assert all(namespace[name] is getattr(package, name) for name in expected)
        # Project/output exports load configuration, but credential registry
        # initialization remains deferred until credential access.
        assert "core.config" in sys.modules
        assert "core.llm.model_brokers" not in sys.modules
        from core.config import RaptorConfig
        broker_keys = RaptorConfig._LLM_AGGREGATOR_KEYS
        assert "core.llm.model_brokers" in sys.modules
        from core.llm.model_brokers import MODEL_BROKERS
        assert broker_keys == tuple(broker.api_key_env for broker in MODEL_BROKERS)
    """, tmp_path)


def test_historical_submodule_attributes_remain_available(tmp_path):
    _python("""
        from importlib import import_module
        import core.project
        import core.run

        for package, names in (
            (core.project, ("project", "clean", "report")),
            (core.run, ("output",)),
        ):
            for name in names:
                module = getattr(package, name)
                assert module is import_module(package.__name__ + "." + name)
                assert vars(package)[name] is module
    """, tmp_path)


def test_reload_refreshes_cached_public_exports(tmp_path):
    _python("""
        from importlib import import_module, reload

        for package_name, provider_name, name in (
            ("core.project", "core.project.project", "Project"),
            ("core.run", "core.run.output", "get_output_dir"),
        ):
            package = import_module(package_name)
            original = getattr(package, name)
            provider = import_module(provider_name)
            replacement = object()
            setattr(provider, name, replacement)
            try:
                reload(package)
                assert getattr(package, name) is replacement
            finally:
                setattr(provider, name, original)
                reload(package)
                assert getattr(package, name) is original
    """, tmp_path)
