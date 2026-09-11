"""CC dispatch transport contract tests.

Covers two invoke_cc_simple properties:

* the ``--json-schema`` payload handed to the CC transport is real
  JSON Schema — the task layer produces descriptive dicts
  ({"field": "type — description"}) that a JSON-Schema validator
  treats as annotation-only, so they must be normalised exactly like
  the native provider lanes normalise them before use;
* per-invocation debug artifacts never clobber each other under
  parallel dispatch — each failure gets a unique file and each failed
  result's ``cc_debug_file`` points at its own dump.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from packages.llm_analysis import cc_dispatch  # noqa: E402


@pytest.fixture(autouse=True)
def _transport_enabled(monkeypatch):
    monkeypatch.delenv("RAPTOR_CC_TRANSPORT_DISABLED", raising=False)


class _ConfigRecorder:
    """Wraps CCDispatchConfig, recording every constructed config."""

    def __init__(self):
        self.configs: list = []
        self._real = cc_dispatch.CCDispatchConfig

    def __call__(self, *args, **kwargs):
        config = self._real(*args, **kwargs)
        self.configs.append(config)
        return config


class TestSchemaNormalisedForCCTransport:
    def _invoke(self, monkeypatch, schema):
        recorder = _ConfigRecorder()
        monkeypatch.setattr(cc_dispatch, "CCDispatchConfig", recorder)

        # Abort the invocation right after config construction — the
        # sandbox-launch failure path returns a graceful error result,
        # so the test never spawns anything.
        def _raise(config):
            raise FileNotFoundError("stop after config capture")

        monkeypatch.setattr(cc_dispatch, "system_prompt_file_for", _raise)
        result = cc_dispatch.invoke_cc_simple(
            "prompt", schema, "/tmp/repo", "claude", "/tmp/out",
        )
        assert "error" in result.result  # graceful abort, as arranged
        assert len(recorder.configs) == 1
        return recorder.configs[0].json_schema

    def test_descriptive_schema_converted_to_json_schema(self, monkeypatch):
        descriptive = {
            "reasoning": "string",
            "path_conditions": "list of strings or null - branch conditions",
            "is_exploitable": "bool",
        }
        sent = self._invoke(monkeypatch, descriptive)
        # Real JSON Schema shape: properties with typed entries, not
        # bare descriptive strings the CLI validator would ignore.
        assert "properties" in sent
        props = sent["properties"]
        assert props["reasoning"]["type"] == "string"
        assert props["is_exploitable"]["type"] == "boolean"
        # Nullable "or null" descriptive fields become union types.
        assert "null" in props["path_conditions"]["type"]
        # No raw descriptive string survives as a property value.
        assert all(isinstance(v, dict) for v in props.values())

    def test_proper_json_schema_passes_through(self, monkeypatch):
        proper = {
            "properties": {"verdict": {"type": "string"}},
            "required": ["verdict"],
        }
        sent = self._invoke(monkeypatch, proper)
        assert sent == proper

    def test_none_schema_stays_freeform(self, monkeypatch):
        assert self._invoke(monkeypatch, None) is None

    def test_analysis_schema_normalises(self, monkeypatch):
        # The real task-layer schema (descriptive strings) must come
        # out as a closed, typed JSON Schema.
        from packages.llm_analysis.prompts import build_analysis_schema
        sent = self._invoke(monkeypatch, build_analysis_schema())
        assert "properties" in sent
        assert all(isinstance(v, dict) for v in sent["properties"].values())


class TestDebugFilesUniquePerInvocation:
    def _invoke_failing(self, monkeypatch, out_dir):
        @contextlib.contextmanager
        def _no_prompt_file(config):
            yield None

        monkeypatch.setattr(cc_dispatch, "system_prompt_file_for",
                            _no_prompt_file)
        monkeypatch.setattr(cc_dispatch, "build_cc_command",
                            lambda config, system_prompt_file=None: ["true"])

        import core.llm.cc_proxy_hosts as proxy_hosts
        monkeypatch.setattr(proxy_hosts, "proxy_hosts_for_cc_dispatch",
                            lambda claude_bin: [])
        monkeypatch.setattr(proxy_hosts, "readable_paths_for_cc_dispatch",
                            lambda claude_bin: [])

        import core.sandbox as sandbox
        monkeypatch.setattr(
            sandbox, "run_untrusted_networked",
            lambda *a, **kw: SimpleNamespace(
                returncode=1, stdout="child stdout", stderr="child stderr",
            ),
        )
        return cc_dispatch.invoke_cc_simple(
            "prompt", None, "/tmp/repo", "claude", str(out_dir),
        )

    def test_two_failures_write_distinct_debug_files(self, monkeypatch, tmp_path):
        r1 = self._invoke_failing(monkeypatch, tmp_path)
        r2 = self._invoke_failing(monkeypatch, tmp_path)
        f1 = r1.result.get("cc_debug_file")
        f2 = r2.result.get("cc_debug_file")
        assert f1 and f2
        # Each failure keeps its own artifact — a constant name meant
        # parallel failures truncate-wrote the same file and operators
        # debugging finding A read finding B's output.
        assert f1 != f2
        assert (tmp_path / f1).is_file()
        assert (tmp_path / f2).is_file()
