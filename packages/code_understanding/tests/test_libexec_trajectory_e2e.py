"""End-to-end test for trajectory persistence through the
``libexec/raptor-understand`` shim.

These tests load the shim as a module (via the same ``_load_module``
pattern test_libexec_understand.py uses for its in-process NUL test)
and drive ``main()`` with patched LLM internals. The goal is to prove
that:

  1. The shim sets ``RAPTOR_TRAJECTORY_DIR`` to the resolved output
     directory before dispatch runs.
  2. The dispatch reads that env var (via ``core.trajectories.auto``)
     and writes a ``trajectory.json`` file at the documented path.

Without these tests, a future refactor could rename the env var or
move the assignment to a code path the dispatch doesn't reach, and
the dispatch-unit tests would still pass — operators just wouldn't
get trajectories.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
LIBEXEC = REPO_ROOT / "libexec" / "raptor-understand"


def _load_shim():
    """Import libexec/raptor-understand as a module. The session-wide
    ``_RAPTOR_TRUSTED=1`` env var (set by the root conftest) lets the
    script's trust-marker check pass during module load."""
    loader = SourceFileLoader("raptor_understand_e2e", str(LIBEXEC))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture
def repo(tmp_path):
    """Minimal source tree the dispatch can point at."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "x.c").write_text("void f(char *p) { strcpy(buf, p); }\n")
    return tmp_path


def _fake_provider_responding_with_empty_variants():
    """Build a fake LLMProvider whose single turn submits empty variants
    so the hunt loop terminates cleanly without needing tool dispatch."""
    from dataclasses import dataclass
    from typing import Iterator

    from core.llm.tool_use.types import (
        StopReason,
        ToolCall,
        TurnResponse,
    )

    @dataclass
    class _FakeTurn:
        tool_calls: list

    class _FakeProvider:
        def __init__(self):
            self._iter: Iterator[_FakeTurn] = iter([
                _FakeTurn(tool_calls=[("submit_variants", {"variants": []})]),
            ])

        def turn(self, *_a, **_kw):
            try:
                t = next(self._iter)
            except StopIteration:
                raise AssertionError("fake provider exhausted")
            content = [
                ToolCall(id=f"c{i}", name=name, input=inp)
                for i, (name, inp) in enumerate(t.tool_calls)
            ]
            return TurnResponse(
                content=content,
                stop_reason=StopReason.NEEDS_TOOL_CALL,
                input_tokens=10, output_tokens=5,
            )

        def supports_tool_use(self): return True
        def supports_prompt_caching(self): return True
        def supports_parallel_tools(self): return True
        def context_window(self): return 200_000
        def estimate_tokens(self, text): return max(len(text) // 4, 1)
        def price_per_million(self): return (3.0, 15.0)

        def compute_cost(self, response):
            return ((response.input_tokens * 3.0
                     + response.output_tokens * 15.0) / 1_000_000)

    return _FakeProvider()


def _patch_shim_for_fake_model(mod, monkeypatch, model_name):
    """Replace _resolve_models so the fake model name passes the
    API-key gate without configuring a real key — and create_provider
    so no real LLM call happens."""
    from core.llm.config import ModelConfig

    fake_cfg = ModelConfig(
        provider="anthropic",
        model_name=model_name,
        api_key="fake-key-for-test",
    )
    monkeypatch.setattr(
        mod, "_resolve_models", lambda _names: ([fake_cfg], []),
    )
    monkeypatch.setattr(
        "packages.code_understanding.dispatch.hunt_dispatch.create_provider",
        lambda _cfg: _fake_provider_responding_with_empty_variants(),
    )


def test_understand_hunt_writes_trajectory_at_resolved_out_dir(
    repo, tmp_path, monkeypatch,
):
    """Drive libexec/raptor-understand's main() through the hunt path
    with a fake provider. Assert that
    ``<out_dir>/trajectories/hunt-<model>/trajectory.json`` lands.

    This exercises the chain that no unit test could:
      shim.main() → sets RAPTOR_TRAJECTORY_DIR → calls hunt() →
      calls default_hunt_dispatch() → ToolUseLoop runs → calls
      persist_from_loop_result() → reads env var → writes JSON.

    If ANY link in that chain is broken (env var renamed, env var set
    AFTER dispatch, dispatch not calling the auto helper, etc.) this
    test fails.
    """
    out_dir = tmp_path / "out"
    # Defensive: the shim sets RAPTOR_TRAJECTORY_DIR via os.environ
    # which persists across the test session unless monkeypatch knows
    # about it. Stage it as "absent" so monkeypatch restores it after
    # the test instead of letting the shim's mutation leak into other
    # tests in the same pytest session.
    monkeypatch.delenv("RAPTOR_TRAJECTORY_DIR", raising=False)

    mod = _load_shim()
    _patch_shim_for_fake_model(mod, monkeypatch, "fake-haiku-x")

    argv = [
        "raptor-understand",
        "--hunt", "strcpy misuse",
        "--hunt-tool", "llm",
        "--target", str(repo),
        "--model", "fake-haiku-x",
        "--out", str(out_dir),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    rc = mod.main()
    assert rc == 0, f"shim main() returned {rc}"

    expected = (
        out_dir / "trajectories" / "hunt-fake-haiku-x" / "trajectory.json"
    )
    assert expected.exists(), (
        f"trajectory not at {expected}\n"
        f"out tree: {sorted(out_dir.rglob('*'))}"
    )
    payload = json.loads(expected.read_text())
    assert payload["model_name"] == "fake-haiku-x"
    assert payload["run_id"] == "hunt-fake-haiku-x"
    assert payload["terminated_by"] == "terminal_tool"


def test_understand_does_not_clobber_existing_trajectory_env_var(
    repo, tmp_path, monkeypatch,
):
    """If the operator already set RAPTOR_TRAJECTORY_DIR in their
    environment, the shim overrides it to the resolved --out so the
    trajectory ends up co-located with the run's other artefacts.

    Pin this behaviour so a future refactor doesn't accidentally
    "respect" the inherited env var and scatter trajectories outside
    the run dir.
    """
    out_dir = tmp_path / "out"
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    monkeypatch.setenv("RAPTOR_TRAJECTORY_DIR", str(foreign))

    mod = _load_shim()
    _patch_shim_for_fake_model(mod, monkeypatch, "fake-haiku-x")

    argv = [
        "raptor-understand",
        "--hunt", "x",
        "--hunt-tool", "llm",
        "--target", str(repo),
        "--model", "fake-haiku-x",
        "--out", str(out_dir),
    ]
    monkeypatch.setattr(sys, "argv", argv)
    rc = mod.main()
    assert rc == 0, f"shim main() returned {rc}"

    # Trajectory lands under --out, not the foreign pre-set dir.
    assert (out_dir / "trajectories" / "hunt-fake-haiku-x"
            / "trajectory.json").exists()
    assert not (foreign / "trajectories").exists()
