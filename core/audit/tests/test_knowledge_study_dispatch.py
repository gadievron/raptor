"""Concrete source resolution keeps audited origins and dependency roots distinct."""

from types import SimpleNamespace

from core.audit.knowledge_requests import KnowledgeOrigin, KnowledgeRequest
from core.audit.knowledge_study import _prepare
from core.audit.refutation_source import capture_source_identity
from core.audit.study_inputs import StudyInputBindings
from core.concepts.study import run_phase2
from core.concepts.subject_study import StudySubject, StudySubjects


def test_separate_study_root_supplies_declaration_and_current_target_origin(tmp_path):
    target, study = tmp_path / "target", tmp_path / "dependency"
    target.mkdir()
    study.mkdir()
    (target / "same.py").write_text("def audit_target():\n    return external_type()\n")
    (study / "same.py").write_text("class external_type:\n    pass\n")
    origin = KnowledgeOrigin("p", "same.py", "audit_target", 1, 2,
                             capture_source_identity(target, "same.py"))
    request = KnowledgeRequest("r", origin, "target_study", "external_type", "construction", "normal", "identifier")
    bindings = StudyInputBindings(target)
    plan = _prepare((request,), SimpleNamespace(bindings=bindings),
                    SimpleNamespace(target_path=target, study_root=study))
    assert not plan.unavailable
    subjects = StudySubjects((StudySubject("r", "external_type", "construction", "identifier", "same.py"),),
        bind_packet=lambda packet: bindings.bind(packet, expected=plan.expected),
        request_items=plan.request_items, material_roots=plan.material_roots, request_context=plan.request_context)
    calls = []

    class Client:
        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            packet = subjects.current_packet()
            assert {m.source_root for m in packet.materials} == {"target", "study"}
            assert {m.file for m in packet.materials} == {"same.py"}
            return {"subject_answers": [{"request_id": "r", "status": "partial",
                "explanation": "A class; construction behavior is not shown.", "reason": "limited source",
                "material_ids": [m.material_id for m in packet.materials]}]}

    run_phase2(plan.items, str(study), Client(), subjects=subjects)
    assert len(calls) == 1
    assert "def audit_target" in calls[0] and "class external_type" in calls[0]
    answer = subjects.snapshot()[0]
    assert bindings.admit(answer)[0]
    (target / "same.py").write_text("def audit_target():\n    return other_type()\n")
    assert not bindings.admit(answer)[0]


def test_late_source_change_refuses_actual_attempt_and_finishes_job(tmp_path, monkeypatch):
    from contextlib import contextmanager
    from threading import Lock
    from core.audit.knowledge_study import study_batch
    from core.audit import orchestrator

    path = tmp_path / "unit.py"
    path.write_text("class foo_t:\n    pass\ndef use():\n    return foo_t()\n")
    origin = KnowledgeOrigin("p", "unit.py", "use", 3, 4, capture_source_identity(tmp_path, "unit.py"))
    request = KnowledgeRequest("r", origin, "target_study", "foo_t", "construction", "normal", "identifier")
    calls, attempts, answers, finished = [], [], [], []
    bindings = StudyInputBindings(tmp_path)

    class Client:
        _call_cost_history = {}

        def generate_structured(self, *args, **kwargs):
            calls.append(args)
            raise AssertionError("stale input must not reach provider")

    class Runtime:
        def track_source_job(self, job):
            self.job = job

        def finish_source_job(self, job):
            answers.extend(job.drain_updates())
            finished.append(job)

        def admit_source_attempt(self, submitted):
            attempts.extend(submitted)
            return True

        def record_source_answers(self, updates):
            answers.extend(updates)

    runtime = Runtime()
    runtime.bindings = bindings

    class Throttle:
        @contextmanager
        def acquire_sync(self, **kwargs):
            path.write_text(path.read_text() + "# edit while queued\n")
            yield

    monkeypatch.setattr(orchestrator, "_run_llm_client", lambda config: Client())
    result = SimpleNamespace(_lock=Lock(), total_cost_usd=0,
                             cost_tracker=SimpleNamespace(record_call=lambda *a, **k: None))
    study_batch((request,), runtime, SimpleNamespace(target_path=tmp_path, study_root=None, llm_budget_client=Client()), result,
                checklist={}, should_stop=lambda: False, throttle=Throttle())
    assert not calls and not attempts
    assert len(finished) == 1
    assert len(answers) == 1 and answers[0].producer == "pipeline"
    assert answers[0].reason == "study_material_changed"
    assert result.total_cost_usd == 0


def test_qualified_identifier_does_not_fall_back_to_unrelated_method(tmp_path):
    (tmp_path / "unit.py").write_text("class Other:\n    def run(self):\n        pass\ndef caller():\n    pass\n")
    origin = KnowledgeOrigin("p", "unit.py", "caller", 4, 5, capture_source_identity(tmp_path, "unit.py"))
    request = KnowledgeRequest("r", origin, "target_study", "Missing.run", "dispatch", "normal", "identifier")
    plan = _prepare((request,), SimpleNamespace(bindings=StudyInputBindings(tmp_path)),
                    SimpleNamespace(target_path=tmp_path, study_root=None))
    assert not plan.items
    assert plan.unavailable == {"r": "source_subject_unresolved_in_bounded_scope"}


def test_two_current_declarations_are_explicitly_ambiguous(tmp_path):
    (tmp_path / "unit.py").write_text("def caller():\n    pass\n")
    for name in ("one.py", "two.py"):
        (tmp_path / name).write_text("class foo_t:\n    pass\n")
    origin = KnowledgeOrigin("p", "unit.py", "caller", 1, 2, capture_source_identity(tmp_path, "unit.py"))
    request = KnowledgeRequest("r", origin, "target_study", "foo_t", "construction", "normal", "identifier")
    plan = _prepare((request,), SimpleNamespace(bindings=StudyInputBindings(tmp_path)),
                    SimpleNamespace(target_path=tmp_path, study_root=None))
    assert not plan.items
    assert plan.unavailable == {"r": "ambiguous_identifier_material"}


def test_real_phase_failure_books_existing_ledger_and_actual_waiters(tmp_path, monkeypatch):
    from threading import Lock
    from core.audit import orchestrator
    from core.audit.knowledge_study import study_batch

    (tmp_path / "unit.py").write_text("class foo_t:\n    pass\ndef first():\n    return foo_t()\ndef second():\n    return foo_t()\n")
    identity = capture_source_identity(tmp_path, "unit.py")
    requests = tuple(KnowledgeRequest(name, KnowledgeOrigin("p", "unit.py", name, start, start + 1, identity),
        "target_study", "foo_t", name + " construction", "normal", "identifier")
        for name, start in (("first", 3), ("second", 5)))
    attempts, answers, booked, calls = [], [], [], []

    class Runtime:
        bindings = StudyInputBindings(tmp_path)

        def track_source_job(self, job):
            self.job = job

        def finish_source_job(self, job):
            answers.extend(job.drain_updates())
            self.job = None

        def admit_source_attempt(self, submitted):
            attempts.append(tuple(r.request_id for r in submitted))
            return True

        def record_source_answers(self, updates):
            answers.extend(updates)

    class Client:
        def __init__(self):
            self._call_cost_history = {}

        def generate_structured(self, prompt, schema, **kwargs):
            calls.append(prompt)
            self._call_cost_history["study"] = (1, 0.25)
            raise RuntimeError("scripted provider failure")

    runtime, client = Runtime(), Client()
    monkeypatch.setattr(orchestrator, "_run_llm_client", lambda config: client)
    result = SimpleNamespace(_lock=Lock(), total_cost_usd=0,
        cost_tracker=SimpleNamespace(record_call=lambda *a, **k: booked.append((a, k))))
    study_batch(requests, runtime, SimpleNamespace(target_path=tmp_path, study_root=None, llm_budget_client=client), result,
                checklist={}, should_stop=lambda: False)
    assert attempts == [("first", "second")]
    assert len(calls) == 1
    assert "def first" in calls[0] and "def second" in calls[0]
    assert {a.request_id for a in answers} == {"first", "second"}
    assert all(a.status == "unavailable" for a in answers)
    assert result.total_cost_usd == 0.25 and booked == [(("study",), {"cost_usd": 0.25})]
    assert runtime.job is None
