"""The existing executor owner can wake while an unrelated review is waiting."""

import threading

import pytest

from core.audit import orchestrator as orch
from core.audit.executor import ExecutorConfig, run_executor_sync
from core.audit.shared_state import SharedState
from core.audit.task_graph import TaskGraph
from core.testing.audit_shutdown import isolated_audit_shutdown


def test_owner_runs_while_an_unrelated_review_is_still_waiting(tmp_path):
    started = threading.Event()
    released = threading.Event()
    owner_thread = threading.get_ident()
    seen = []
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", max_workers=2)
    result = orch.OrchestratorResult()
    graph = TaskGraph.from_workqueue([
        {"file": "owned.c", "name": "unrelated", "line_start": 1, "priority_score": 1.0},
    ], [])

    def work(gap, shared, cfg, reviewer, result, **kwargs):
        started.set()
        assert released.wait(5), "owner did not process ready information during the wait"
        return orch.ReviewOutcome("owned.c", "unrelated", "clean", "scripted review")

    def idle():
        assert threading.get_ident() == owner_thread
        if started.is_set():
            seen.append(not released.is_set())
            released.set()
            return None
        return 0.05

    with isolated_audit_shutdown(orch):
        try:
            stats = run_executor_sync(
                graph, lambda *args: None, SharedState(), config, result,
                ExecutorConfig(max_workers=2), review_one_fn=work, on_idle=idle,
            )
        finally:
            released.set()
    assert seen == [True]
    assert stats.completed == 1


def test_idle_owner_dispatches_new_ready_work_without_waiting_for_unrelated_review(tmp_path):
    from core.testing.wallclock import wall_deadline

    started = threading.Event()
    released = threading.Event()
    finished = threading.Event()
    continuation_started = threading.Event()
    owner_thread = threading.get_ident()
    injected = []
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", max_workers=2)
    result = orch.OrchestratorResult()
    graph = TaskGraph.from_workqueue([
        {"file": "owned.c", "name": "unrelated", "line_start": 1, "priority_score": 1.0},
    ], [])

    def work(gap, shared, cfg, reviewer, result, **kwargs):
        if gap["name"] == "continuation":
            assert threading.get_ident() != owner_thread
            assert not finished.is_set(), "continuation waited for the unrelated review"
            continuation_started.set()
            released.set()
        else:
            started.set()
            try:
                assert released.wait(5), "idle-injected work was not dispatched into the free slot"
            finally:
                finished.set()
        return orch.ReviewOutcome("owned.c", gap["name"], "clean", "scripted review")

    def idle():
        assert threading.get_ident() == owner_thread
        if started.is_set() and not injected:
            injected.append(graph.inject_task("knowledge-continuation", {
                "file": "owned.c", "name": "continuation", "line_start": 2,
            }, priority=2.0))
        return 0.05 if not continuation_started.is_set() else None

    with isolated_audit_shutdown(orch), wall_deadline(10, code_bound_s=float("inf"), what="idle graph dispatch"):
        try:
            stats = run_executor_sync(
                graph, lambda *args: None, SharedState(), config, result,
                ExecutorConfig(max_workers=2), review_one_fn=work, on_idle=idle,
            )
        finally:
            released.set()
    assert injected == [True]
    assert continuation_started.is_set()
    assert stats.completed == 2 and stats.failed == 0


def test_serial_dispatch_holds_the_shared_study_throttle_once(tmp_path):
    from contextlib import contextmanager
    held = []
    calls = []

    class Throttle:
        @contextmanager
        def acquire_sync(self):
            assert not held, "nested acquisition deadlocks a one-slot throttle"
            held.append(True)
            try:
                yield
            finally:
                held.pop()

    def work(gap, *args, **kwargs):
        assert held == [True]
        calls.append(gap["name"])
        return orch.ReviewOutcome("owned.c", gap["name"], "clean", "scripted")

    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    graph = TaskGraph.from_workqueue([{"file": "owned.c", "name": "f", "line_start": 1}], [])
    with isolated_audit_shutdown(orch):
        stats = run_executor_sync(graph, lambda *a: None, SharedState(), config,
            orch.OrchestratorResult(), ExecutorConfig(max_workers=1),
            review_one_fn=work, throttle=Throttle())
    assert calls == ["f"] and stats.completed == 1 and not held


@pytest.mark.slow
def test_actual_audit_interleaves_initial_and_knowledge_review_opportunities(tmp_path, monkeypatch):
    import json
    from core.audit import capabilities
    from core.audit.llm_review import make_review_fn
    from core.llm.providers import StructuredResponse
    from core.testing.wallclock import wall_deadline

    target, out = tmp_path / 'target', tmp_path / 'out'
    target.mkdir()
    out.mkdir()
    (target / 'units.py').write_text(''.join(f'def f{i}(n):\n    return n + 1\n' for i in range(10)))
    (target / 'caller.py').write_text('def caller(n):\n    return f0(n)\n')
    items = [{'name': f'f{i}', 'kind': 'function', 'line_start': 2 * i + 1, 'line_end': 2 * i + 2}
             for i in range(10)]
    checklist = {'files': [{'path': 'units.py', 'items': items}]}
    (out / 'checklist.json').write_text(json.dumps(checklist))
    inventory = {'files': checklist['files'] + [{'path': 'caller.py', 'items': [
        {'name': 'caller', 'kind': 'function', 'line_start': 1, 'line_end': 2}]}]}
    monkeypatch.setattr(orch, '_run_mechanical_detectors', lambda *args, **kwargs: ({}, set()))
    monkeypatch.setattr(orch, '_proactive_validate', lambda outcome, *args, **kwargs: outcome)
    monkeypatch.setattr(capabilities, 'probe_capabilities', lambda *args, **kwargs: capabilities.AuditCapabilities())
    admissions = []

    class Client:
        def is_budget_exhausted(self):
            return False

        def generate_structured(self, prompt, schema, **kwargs):
            return StructuredResponse(result={'status': 'suspicious', 'body': 'Unresolved scripted concern',
                'hypothesis': 'The caller-dependent condition needs review',
                'caller_context_requests': [{'file': 'caller.py', 'function': 'caller', 'line_start': 1,
                                             'reason': 'Inspect this supplied related code'}]},
                raw='', cost=0, model='scripted')

    client = Client()
    monkeypatch.setattr(orch, '_run_llm_client', lambda cfg: client)
    rendered = make_review_fn(client, escalate_clean=False)

    def review(context, config):
        admissions.append('C' if context.get('caller_context_answers') else 'I')
        return rendered(context, config)

    review._knowledge_observed_client_contract = True
    config = orch.OrchestratorConfig(target_path=target, out_dir=out, inventory=inventory,
        max_workers=1, resume=False, prefilter=False, validate=False, immediate_verify=False,
        sweep_validate_findings=False, max_refinements=0, deepen_suspicious=False,
        open_discovery=False, sage_recall=False, iris=False, adversarial=False,
        joern_overrides={'enabled': False}, llm_budget_client=client)
    with isolated_audit_shutdown(orch), wall_deadline(30, code_bound_s=float('inf'), what='fair review admission'):
        result = orch.run_orchestrator(config, review)
    assert ''.join(admissions[:12]) == 'IIICIIICIIIC'
    assert admissions.count('I') == 10 and admissions.count('C') == 10
    assert len(result.outcomes) == 10
    trace = json.loads((out / 'review-admission.json').read_text())
    assert trace['scope'] == 'main_review_graph' and trace['global_review_ownership'] is False
    assert trace['policy']['initial_admissions'] == 10
    assert trace['policy']['continuation_admissions'] == 10


def test_fair_parallel_executor_uses_free_slots_without_global_study_hold(tmp_path):
    from core.testing.wallclock import wall_deadline

    graph = TaskGraph.from_workqueue([
        {'file': 'units.py', 'name': f'f{i}', 'line_start': i + 1} for i in range(10)
    ], [], review_fairness=True)
    for i in range(5):
        assert graph.inject_task(f'continuation-{i}',
            {'file': 'units.py', 'name': f'c{i}', 'line_start': 20 + i},
            priority=1000, continuation=True)
    released = threading.Event()
    seen = []
    lock = threading.Lock()

    class PendingStudy(orch.StudyQueue):
        consumer_done = False
        checks = 0

        def pending_concepts(self):
            self.checks += 1
            return frozenset({'unrelated-inflight-study'})

    class Concepts:
        def concepts_for(self, file, name):
            return frozenset({'unrelated-inflight-study'})

    queue = PendingStudy()
    config = orch.OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / 'out', max_workers=2)
    result = orch.OrchestratorResult()

    def work(gap, *args, **kwargs):
        if gap['name'] == 'f1':
            assert released.wait(5), 'another ready unit did not get a free worker'
        elif gap['name'] != 'f0':
            released.set()
        with graph._lock:
            assert len(graph._issued) <= 2, 'ready work was pre-admitted behind occupied workers'
        with lock:
            seen.append(gap['name'])
        return orch.ReviewOutcome('units.py', gap['name'], 'clean', 'Scripted review')

    with isolated_audit_shutdown(orch), wall_deadline(10, code_bound_s=float('inf'), what='free-slot fairness'):
        try:
            stats = run_executor_sync(graph, lambda *args: None, SharedState(), config, result,
                ExecutorConfig(max_workers=2), review_one_fn=work, study_queue=queue,
                concept_index_ref=[Concepts()])
        finally:
            released.set()
    assert stats.completed == 15 and stats.failed == 0
    assert len(seen) == len(set(seen)) == 15
    assert queue.checks == 0, 'global pending study must not hold governed first reviews'
    assert graph.admission_state()['initial_admissions'] == 10
    assert graph.admission_state()['continuation_admissions'] == 5
