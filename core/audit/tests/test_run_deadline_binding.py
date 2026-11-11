"""Actual caller seams forward the analysis clock; SDK enforcement is separate."""
import builtins
from types import SimpleNamespace

import pytest

from core.audit import orchestrator
from core.testing.module_views import module_function_view


class _BeforePreparation(BaseException):
    pass


class _Client:
    _run_deadline_protocol = 1

    def __init__(self, events):
        self.deadlines = []
        self.events = events

    def bind_run_deadline(self, deadline):
        self.deadlines.append(deadline)
        self.events.append(("bind", self))


def _global_snapshot():
    return {name: (id(getattr(orchestrator, name)), len(getattr(orchestrator, name)))
            for name in ("_sink_guard_cache", "_parse_wrapper_cache", "_line_end_cache",
                         "_sigterm_flush_hooks")}


def _entry(tmp_path, budget, review, events, *, maximum=17):
    config = orchestrator.OrchestratorConfig(
        target_path=tmp_path, out_dir=None, max_seconds=maximum,
        llm_budget_client=budget, llm_client=review,
    )
    guards = []

    class Router:
        def __init__(self, _paths):
            self.paths = []
            self.primary = None

    def guard(**kwargs):
        events.append(("guard", kwargs["deadline_monotonic"]))
        guards.append(kwargs)
        raise _BeforePreparation

    environment = SimpleNamespace(
        EnvironmentGuard=guard, effective_tmp_dir=lambda: tmp_path,
        preflight_environment=lambda _paths: None,
    )

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "environment":
            return environment
        if level == 1 and name == "codeql_dbs":
            return SimpleNamespace(CodeqlDbRouter=Router)
        if level == 0 and name == "core.llm.concurrency":
            return SimpleNamespace(warm_claudecode_probe=lambda: None)
        return builtins.__import__(name, globals, locals, fromlist, level)

    view = module_function_view(orchestrator, import_hook=imports, bindings={
        "time": SimpleNamespace(monotonic=lambda: 100.0),
        "_apply_profile_gates": lambda _config: None,
        "_reset_shutdown_state": lambda: None,
        "install_sigterm_grace": lambda: None,
        "_clear_file_lines_cache": lambda: None,
        "_sink_guard_cache": {}, "_parse_wrapper_cache": {}, "_line_end_cache": {},
        "_sigterm_flush_hooks": [],
    })

    def no_review(*_args, **_kwargs):
        raise AssertionError("review must not execute before the guard sentinel")

    def invoke():
        before = _global_snapshot()
        try:
            return view.run_orchestrator(config, no_review)
        finally:
            assert _global_snapshot() == before

    return invoke, config, guards


def test_shared_client_binds_exact_stamped_deadline_once_before_preparation(tmp_path):
    events = []
    client = _Client(events)
    invoke, config, guards = _entry(tmp_path, client, client, events)
    with pytest.raises(_BeforePreparation):
        invoke()
    assert config.run_deadline_monotonic == 117.0
    assert client.deadlines == [117.0]
    assert events == [("bind", client), ("guard", 117.0)]
    assert len(guards) == 1 and guards[0]["deadline_monotonic"] == 117.0


def test_distinct_clients_both_receive_same_analysis_deadline(tmp_path):
    events = []
    budget, review = _Client(events), _Client(events)
    invoke, config, guards = _entry(tmp_path, budget, review, events)
    with pytest.raises(_BeforePreparation):
        invoke()
    assert budget.deadlines == review.deadlines == [117.0]
    assert events == [("bind", budget), ("bind", review), ("guard", 117.0)]
    assert guards[0]["deadline_monotonic"] == config.run_deadline_monotonic


@pytest.mark.parametrize("protocol", [None, 0, True, "1"], ids=["absent", "zero", "bool", "text"])
def test_legacy_client_without_literal_protocol_is_not_bound(tmp_path, protocol):
    events, bindings = [], []
    client = SimpleNamespace(bind_run_deadline=bindings.append)
    if protocol is not None:
        client._run_deadline_protocol = protocol
    invoke, config, guards = _entry(tmp_path, client, client, events)
    with pytest.raises(_BeforePreparation):
        invoke()
    assert config.run_deadline_monotonic == 117.0 and not bindings
    assert guards[0]["deadline_monotonic"] == 117.0


@pytest.mark.parametrize("maximum", [None, 0, float("inf")], ids=["unset", "zero", "infinite"])
def test_unlimited_run_does_not_create_an_external_deadline(tmp_path, maximum):
    events = []
    client = _Client(events)
    invoke, config, guards = _entry(tmp_path, client, client, events, maximum=maximum)
    with pytest.raises(_BeforePreparation):
        invoke()
    expected = float("inf") if maximum == float("inf") else None
    assert config.run_deadline_monotonic == expected and client.deadlines == []
    assert guards[0]["deadline_monotonic"] == expected


def test_declared_missing_binder_refuses_before_preparation(tmp_path):
    client = SimpleNamespace(_run_deadline_protocol=1)
    invoke, _, guards = _entry(tmp_path, client, client, [])
    with pytest.raises(TypeError, match="bind_run_deadline"):
        invoke()
    assert guards == []


def test_declared_binder_error_keeps_identity_and_prevents_preparation(tmp_path):
    failure = RuntimeError("owned deadline binder failed")

    def fail(_deadline):
        raise failure

    client = SimpleNamespace(_run_deadline_protocol=1, bind_run_deadline=fail)
    invoke, _, guards = _entry(tmp_path, client, client, [])
    with pytest.raises(RuntimeError) as caught:
        invoke()
    assert caught.value is failure and guards == []


@pytest.mark.parametrize("fresh", [False, True], ids=["shared", "fresh-fallback"])
def test_run_client_accessor_binds_before_observer(tmp_path, fresh):
    events = []
    client = _Client(events)
    config = orchestrator.OrchestratorConfig(
        target_path=tmp_path, out_dir=None, models=["owned-model"],
        llm_budget_client=None if fresh else client, run_deadline_monotonic=117.0,
    )
    marker, builds = object(), []

    def build(**kwargs):
        builds.append(kwargs)
        return client

    def observed(actual, *, purpose):
        assert actual is client and actual.deadlines == [117.0]
        assert purpose == "auxiliary"
        events.append(("observe", actual))
        return marker

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "knowledge_calls":
            return SimpleNamespace(observed_client=observed)
        if level == 0 and name == "core.llm.transcript":
            return SimpleNamespace(build_llm_client=build)
        return builtins.__import__(name, globals, locals, fromlist, level)

    view = module_function_view(orchestrator, import_hook=imports)
    assert view._run_llm_client(config) is marker
    assert events == [("bind", client), ("observe", client)]
    assert builds == ([{"pinned_model": "owned-model"}] if fresh else [])


def test_legacy_structural_config_without_deadline_remains_valid():
    client = object()
    config = SimpleNamespace(llm_budget_client=client)

    def imports(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 1 and name == "knowledge_calls":
            return SimpleNamespace(observed_client=lambda actual, **kwargs: actual)
        return builtins.__import__(name, globals, locals, fromlist, level)

    view = module_function_view(orchestrator, import_hook=imports)
    assert view._run_llm_client(config) is client
