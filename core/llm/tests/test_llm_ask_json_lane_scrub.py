"""raptor-llm-ask --json-schema lane: JSON escapes C0 but passes C1
terminal controls (U+0080-U+009F, incl. single-byte CSI 0x9B and OSC
0x9D) through raw when ensure_ascii is off. A model induced to echo
hostile --file content must not drive the operator terminal through
the structured lane either."""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import types
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-llm-ask"


@pytest.fixture(autouse=True)
def _hermetic_process_state(monkeypatch):
    """The script mutates process-global state at import (RAPTOR_DIR
    env pin) and in main() (quiet mode drops the root/raptor/httpx
    logger levels to CRITICAL). Snapshot and restore both so later
    tests keep their logging and env expectations."""
    import logging

    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    # main() exports RAPTOR_LLM_QUIET=1 (quiet mode) and the script's
    # import pins RAPTOR_DIR — both outlive the call unless restored.
    saved_env = {k: os.environ.get(k)
                 for k in ("RAPTOR_DIR", "RAPTOR_LLM_QUIET")}
    names = ("", "raptor", "httpx", "httpcore")
    saved_levels = []
    for n in names:
        lg = logging.getLogger(n)
        saved_levels.append((lg, lg.level,
                             [(h, h.level) for h in lg.handlers]))
    yield
    for k, v in saved_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    for lg, lvl, handlers in saved_levels:
        lg.setLevel(lvl)
        for h, hl in handlers:
            h.setLevel(hl)

HOSTILE = "evil\x9b2J\x9d0;pwn\x07‮end"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "raptor_llm_ask_under_test", SCRIPT,
        submodule_search_locations=[])
    if spec is None or spec.loader is None:
        mod = types.ModuleType("raptor_llm_ask_under_test")
        mod.__file__ = str(SCRIPT)
        code = compile(SCRIPT.read_text(), str(SCRIPT), "exec")
        exec(code, mod.__dict__)  # noqa: S102 — our own libexec script
        return mod
    mod = importlib.util.module_from_spec(spec)
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
    import core.llm.client as client_mod
    import core.llm.dispatcher.lifecycle as lifecycle_mod
    monkeypatch.setattr(client_mod, "LLMClient", _StubClient)
    monkeypatch.setattr(
        lifecycle_mod, "ensure_route_for_model_configs",
        lambda *a, **k: None,
    )
    monkeypatch.setattr(sys, "argv", ["raptor-llm-ask", *argv])
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
    for raw in ("\x9b", "\x9d", "\x07", "‮"):
        assert raw not in out
