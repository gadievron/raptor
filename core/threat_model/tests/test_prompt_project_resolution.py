"""Prompt-local project reuse must not outlive its owner or bypass pinning."""

from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from pathlib import Path
from types import SimpleNamespace
import threading

import pytest

import core.threat_model as tm


@pytest.fixture
def setup(tmp_path, monkeypatch):
    import core.project.project as projects
    import core.project.trust as trust
    import core.run.pin as pin
    import core.understand_graph as graph

    state = SimpleNamespace(by_target={}, by_name={}, models={}, graphs={}, pin=None,
                            finds=[], loads=[], graph_hook=None)

    def create(name, target=None):
        target = target or tmp_path / f"{name}-target"
        target.mkdir(exist_ok=True)
        output = tmp_path / f"{name}-output"
        (output / "graph").mkdir(parents=True, exist_ok=True)
        (output / "graph/raptor.graph.sqlite").touch()
        project = SimpleNamespace(name=name, target=str(target), output_dir=str(output),
                                  threat_model_path="model.json")
        state.by_target[str(target.resolve())] = project
        state.by_name[name] = project
        state.models[str(output)] = tm.ThreatModel(
            project_name=name, target=str(target), source="operator", summary=f"model-{name}")
        state.graphs[str(output)] = f"graph-{name}"
        return project

    class Manager:
        def find_project_for_target(self, target):
            state.finds.append(str(Path(target).resolve()))
            return state.by_target.get(str(Path(target).resolve()))

        def get_active(self):
            return None

        def load(self, name):
            state.loads.append(name)
            return state.by_name.get(name)

    def graph_context(path, target, **kwargs):
        if state.graph_hook is not None:
            state.graph_hook(path, target)
        return state.graphs[str(Path(path).parent.parent)]

    monkeypatch.setattr(projects, "ProjectManager", Manager)
    monkeypatch.setattr(pin, "get_process_project", lambda: state.pin)
    monkeypatch.setattr(trust, "_context_project_name", lambda: state.pin)
    monkeypatch.setattr(tm, "load_model", lambda p: state.models[str(Path(p).parent)])
    monkeypatch.setattr(graph, "threat_model_graph_context", graph_context)
    project = create("a")
    return state, create, project


def test_exact_prompt_parity_and_one_lookup(setup):
    state, _, project = setup
    target = Path(project.target)
    old = tm._render_threat_model_prompt_block(target)
    assert len(state.finds) == 2
    state.finds.clear()
    assert tm.threat_model_prompt_block(target) == old
    assert len(state.finds) == 1
    assert tm._prompt_project_resolution.get() is None


def test_updates_and_absence_are_fresh_between_prompts(setup):
    state, _, project = setup
    target = Path(project.target)
    state.by_target.clear()
    assert tm.threat_model_prompt_block(target) == ""
    assert len(state.finds) == 1
    state.by_target[str(target)] = project
    first = tm.threat_model_prompt_block(target)
    assert "model-a" in first and "graph-a" in first
    state.models[project.output_dir].summary = "new-model"
    state.graphs[project.output_dir] = "new-graph"
    second = tm.threat_model_prompt_block(target)
    assert "new-model" in second and "new-graph" in second
    assert len(state.finds) == 3


def test_direct_loaders_remain_uncached(setup):
    state, _, project = setup
    assert tm.load_for_target(Path(project.target))
    assert tm.load_for_target(Path(project.target))
    assert len(state.finds) == 2


def test_resolution_exception_is_retried_in_the_other_lane(setup, monkeypatch):
    import core.project.project as projects

    state, _, project = setup
    original = projects.ProjectManager.find_project_for_target
    attempts = []

    def fail_once(self, target):
        attempts.append(1)
        if len(attempts) == 1:
            raise OSError("transient registry failure")
        return original(self, target)

    monkeypatch.setattr(projects.ProjectManager, "find_project_for_target", fail_once)
    output = tm.threat_model_prompt_block(Path(project.target))
    assert "model-a" in output and "graph-a" not in output
    assert len(attempts) == 2
    assert tm._prompt_project_resolution.get() is None


def test_failed_governance_resolution_does_not_cache_fallback(setup, monkeypatch):
    import core.project.trust as trust

    state, create, legacy = setup
    pinned = create("pinned", Path(legacy.target))
    state.by_target[legacy.target] = legacy
    state.pin = "pinned"
    attempts = []

    def owner():
        attempts.append(1)
        if len(attempts) == 1:
            raise OSError("transient pin validation failure")
        return "pinned"

    monkeypatch.setattr(trust, "_context_project_name", owner)
    output = tm.threat_model_prompt_block(Path(pinned.target))
    assert "graph-a" in output and "model-pinned" in output
    assert len(attempts) == 2 and state.loads == ["pinned"]


def test_pin_changes_are_not_hidden_by_prompt_reuse(setup):
    state, create, first = setup
    second = create("b", Path(first.target))
    state.pin = "a"
    state.graph_hook = lambda *a: setattr(state, "pin", "b")
    output = tm.threat_model_prompt_block(Path(second.target))
    assert "graph-a" in output and "model-b" in output
    assert state.loads == ["a", "b"] and not state.finds


def test_cache_failure_never_relaxes_owner_rule(setup):
    state, _, project = setup

    class UnhashablePath(type(Path(project.target))):
        __hash__ = None

    state.pin = "a"
    assert "model-a" in tm.threat_model_prompt_block(UnhashablePath(project.target))
    assert state.loads == ["a", "a"] and not state.finds


def test_inherited_context_cannot_reuse_after_prompt_returns(setup):
    state, create, project = setup
    captured = []
    state.graph_hook = lambda *a: captured.append(copy_context())
    tm.threat_model_prompt_block(Path(project.target))
    replacement = create("b", Path(project.target))
    selected = captured[0].run(tm._project_for_target, Path(project.target))
    assert selected is replacement
    assert len(state.finds) == 2


def test_nested_and_overlapping_renders_are_isolated(setup):
    state, create, first = setup
    second = create("b")
    nested = []

    def recurse(path, target):
        if target == str(Path(first.target)) and not nested:
            nested.append(tm.threat_model_prompt_block(Path(second.target)))

    state.graph_hook = recurse
    assert "model-a" in tm.threat_model_prompt_block(Path(first.target))
    assert "model-b" in nested[0]
    assert len(state.finds) == 2
    state.finds.clear()
    barrier = threading.Barrier(2)
    state.graph_hook = lambda *a: barrier.wait(timeout=5)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(tm.threat_model_prompt_block, Path(p.target)) for p in (first, second)]
        outputs = [f.result(timeout=10) for f in futures]
    assert "model-a" in outputs[0] and "model-b" in outputs[1]
    assert len(state.finds) == 2


def test_renderer_exception_restores_scope(setup, monkeypatch):
    _, _, project = setup

    def fail(*a, **kw):
        raise ValueError("render failed")

    monkeypatch.setattr(tm, "prompt_context", fail)
    with pytest.raises(ValueError, match="render failed"):
        tm.threat_model_prompt_block(Path(project.target))
    assert tm._prompt_project_resolution.get() is None


def test_relative_target_cwd_changes_are_not_hidden(setup, tmp_path, monkeypatch):
    import os

    state, create, first = setup
    other = tmp_path / "other-cwd"
    other.mkdir()
    create("b", other / Path(first.target).name)
    monkeypatch.chdir(tmp_path)
    state.graph_hook = lambda *a: os.chdir(other)
    output = tm.threat_model_prompt_block(Path(first.target).relative_to(tmp_path))
    assert "graph-a" in output and "model-b" in output
    assert len(state.finds) == 2


def test_replaced_project_is_resolved_on_the_next_render(setup):
    state, create, first = setup
    target = Path(first.target)
    assert "model-a" in tm.threat_model_prompt_block(target)
    create("replacement", target)
    updated = tm.threat_model_prompt_block(target)
    assert "model-replacement" in updated and "graph-replacement" in updated
    assert len(state.finds) == 2
