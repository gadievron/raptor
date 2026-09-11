"""Pre-flight budget gate tests for libexec/raptor-run-lifecycle start.

``--max-cost-usd`` is an operator-declared cap: when no target path is
given on the command line the gate must still resolve the run's default
target (active project / caller dir) and run the estimate — and when no
target can be resolved at all, it must say so loudly rather than drop
the cap silently.
"""

import importlib.util
import os
import sys
import types
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_script():
    os.environ.setdefault("_RAPTOR_TRUSTED", "1")
    script = str(REPO_ROOT / "libexec" / "raptor-run-lifecycle")
    loader = SourceFileLoader("raptor_run_lifecycle", script)
    spec = importlib.util.spec_from_loader("raptor_run_lifecycle", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@pytest.fixture
def env(tmp_path: Path, monkeypatch) -> dict:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("RAPTOR_CALLER_DIR", raising=False)
    # Stub the heavyweight raptor CLI module: the script imports only
    # _preflight_cost_gate from it, and recording the call is the point.
    calls: list = []
    fake_raptor = types.ModuleType("raptor")

    def fake_gate(target, max_cost_usd, out_dir, *, estimate_stream=None):
        calls.append((target, max_cost_usd))
        return False

    fake_raptor._preflight_cost_gate = fake_gate
    monkeypatch.setitem(sys.modules, "raptor", fake_raptor)
    return {
        "mod": _load_script(),
        "out": tmp_path / "out",
        "calls": calls,
    }


def _start(env, monkeypatch, *extra: str) -> None:
    argv = ["raptor-run-lifecycle", "start", "scan",
            "--out", str(env["out"]), "--max-cost-usd", "5", *extra]
    monkeypatch.setattr(sys, "argv", argv)
    env["mod"].main()


def test_gate_runs_with_explicit_target(env, monkeypatch, tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    _start(env, monkeypatch, "--target", str(target))
    assert env["calls"] == [(str(target), 5.0)]
    assert "WARNING" not in capsys.readouterr().err


def test_gate_resolves_default_target_when_none_given(env, monkeypatch,
                                                      tmp_path, capsys):
    # No --target on the command line: the run's target comes from the
    # session default (active project / caller dir) — the cap must
    # follow it instead of being skipped.
    resolved = tmp_path / "project-target"
    resolved.mkdir()
    import core.run.output as run_output
    monkeypatch.setattr(run_output, "resolve_default_target",
                        lambda: str(resolved))
    _start(env, monkeypatch)
    assert env["calls"] == [(str(resolved), 5.0)]
    assert "WARNING" not in capsys.readouterr().err


def test_unresolvable_target_warns_loudly(env, monkeypatch, capsys):
    import core.run.output as run_output
    monkeypatch.setattr(run_output, "resolve_default_target", lambda: None)
    _start(env, monkeypatch)
    assert env["calls"] == []
    captured = capsys.readouterr()
    assert "pre-flight cost estimate skipped" in captured.err
    assert "WARNING" in captured.err
    # The run itself still starts — only the estimate is skipped.
    assert "OUTPUT_DIR=" in captured.out
