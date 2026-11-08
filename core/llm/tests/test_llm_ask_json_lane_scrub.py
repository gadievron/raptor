"""raptor-llm-ask --json-schema lane: JSON escapes C0 but passes C1
terminal controls (U+0080-U+009F, incl. single-byte CSI 0x9B and OSC
0x9D) through raw when ensure_ascii is off. A model induced to echo
hostile --file content must not drive the operator terminal through
the structured lane either."""

from __future__ import annotations

from contextlib import ExitStack
import importlib.util
import logging
import json
import os
import sys
import types
from pathlib import Path
from unittest.mock import patch

import pytest

from core.testing.logging_state import isolated_cli_logging
from core.testing.module_views import scoped_function_imports
from core.testing.standalone_cli import run_standalone_cli

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-llm-ask"


@pytest.fixture(autouse=True)
def _isolate_scorecard(tmp_path):
    """Only fake clients run here; own the path without importing real SDKs."""
    with pytest.MonkeyPatch.context() as state:
        state.setenv("RAPTOR_SCORECARD_PATH", str(tmp_path / "scorecard.json"))
        yield


@pytest.fixture(autouse=True)
def _hermetic_process_state():
    """Own direct CLI environment writes independently of body undo."""
    with pytest.MonkeyPatch.context() as state:
        state.setenv("_RAPTOR_TRUSTED", "1")
        for key in ("RAPTOR_DIR", "RAPTOR_LLM_QUIET"):
            # Register absent keys before the CLI can write them directly.
            present = key in os.environ
            state.setenv(key, os.environ.get(key, ""))
            if not present:
                state.delenv(key)
        yield

HOSTILE = "evil\x9b2J\x9d0;pwn\x07‮end"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "raptor_llm_ask_under_test", SCRIPT,
        submodule_search_locations=[])
    if spec is None or spec.loader is None:
        mod = types.ModuleType("raptor_llm_ask_under_test")
        mod.__file__ = str(SCRIPT)
        code = compile(SCRIPT.read_text(), str(SCRIPT), "exec")
        with patch.object(sys, "path", sys.path.copy()):
            exec(code, mod.__dict__)  # noqa: S102 — our own libexec script
        return mod
    mod = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        spec.loader.exec_module(mod)
    return mod


class _StubResponse:
    result = {"answer": HOSTILE}
    content = HOSTILE
    model = "stub-model"
    provider = "stub"
    cost = 0.0


class _StubConfig:
    def config_for_model(self, name):
        return types.SimpleNamespace(provider="stub", model_name=name)

    primary_model = None
    fallback_models = ()


class _StubClient:
    def __init__(self, *a, **k):
        self.config = _StubConfig()

    def generate_structured(self, prompt, schema, **kwargs):
        return _StubResponse()

    def generate(self, prompt, **kwargs):
        return _StubResponse()


def _run_main(mod, argv, monkeypatch, tmp_path):
    client_mod = types.ModuleType("core.llm.client")
    client_mod.LLMClient = _StubClient
    lifecycle_mod = types.ModuleType("core.llm.dispatcher.lifecycle")
    lifecycle_mod.ensure_route_for_model_configs = lambda *a, **k: None
    monkeypatch.setattr(sys, "argv", ["raptor-llm-ask", *argv])
    names = ("raptor", "httpx", "httpcore")
    with ExitStack() as cleanup:
        cleanup.enter_context(isolated_cli_logging(logger_names=names))
        # The CLI also adjusts handlers attached directly to named loggers.
        for name in names:
            for handler in logging.getLogger(name).handlers:
                cleanup.callback(handler.setLevel, handler.level)
        cleanup.enter_context(scoped_function_imports(mod, ("main",), {
            "core.llm.client": client_mod,
            "core.llm.dispatcher.lifecycle": lifecycle_mod,
        }))
        return mod.main()


def test_json_schema_lane_escapes_c1(monkeypatch, tmp_path, capsys):
    mod = _load_module()
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(json.dumps(
        {"type": "object", "properties": {"answer": {"type": "string"}}}))
    rc = _run_main(
        mod,
        ["--model", "stub-model", "--json-schema", str(schema_path), "hi"],
        monkeypatch, tmp_path,
    )
    out = capsys.readouterr().out
    assert rc == 0
    for raw in ("\x9b", "\x9d", "\x07", "‮"):
        assert raw not in out
    assert "answer" in out
    # Still valid JSON after ASCII-encoding.
    assert json.loads(out)["answer"].startswith("evil")


def test_free_text_lane_still_escaped(monkeypatch, tmp_path, capsys):
    mod = _load_module()
    rc = _run_main(mod, ["--model", "stub-model", "hi"],
                   monkeypatch, tmp_path)
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("evil") and out.endswith("end\n")
    for raw in ("\x9b", "\x9d", "\x07", "‮"):
        assert raw not in out


def test_output_lanes_do_not_load_real_sdk_clients(tmp_path):
    program = '''
import io, json, sys
from types import SimpleNamespace
from contextlib import closing, redirect_stdout
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import pytest
from core.llm.tests import test_llm_ask_json_lane_scrub as cases
target = Path(sys.argv[2])
schema = target / "schema.json"
schema.write_text(json.dumps({"type": "object"}))
with closing(cases._hermetic_process_state.__wrapped__()) as state:
    next(state)
    script = cases._load_module()
    for extra in ([], ["--json-schema", str(schema)], ["--json-schema", str(schema), "--raw"]):
        with pytest.MonkeyPatch.context() as scope, redirect_stdout(io.StringIO()) as output:
            scope.setattr(cases._StubConfig, "primary_model", SimpleNamespace(provider="stub", model_name="stub-model"))
            assert cases._run_main(script, [*extra, "hi"], scope, target) == 0
        assert "evil" in output.getvalue()
        for name in ("core.llm.client", "core.llm.providers", "core.llm.dispatcher.lifecycle", "openai", "anthropic", "google.genai"):
            assert name not in sys.modules, "unexpected SDK/dispatcher startup: " + name
'''
    result = run_standalone_cli(
        [sys.executable, "-I", "-c", program, str(REPO_ROOT), str(tmp_path)],
        cwd=tmp_path, capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stdout + result.stderr
