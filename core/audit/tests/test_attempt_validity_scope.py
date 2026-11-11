"""Owned first-attempt credit still requires a current runtime lifetime."""

import pytest

from core.audit.knowledge_calls import KnowledgeCallRefused, observed_client
from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.orchestrator import StudyQueue


def test_runtime_deadline_expiring_before_first_attempt_refuses_without_extra_credit(tmp_path, monkeypatch):
    clock = [1.0]
    monkeypatch.setattr("core.audit.knowledge_runtime.monotonic", lambda: clock[0])
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=10.0)
    attempts = []

    class DelayedClient:
        _attempt_admission_protocol = 1

        def generate(self, **kwargs):
            clock[0] = 10.0
            kwargs["accounting_attempt_admission"]()
            attempts.append("generation")

    @runtime.wrap_unit
    def review(gap):
        observed_client(DelayedClient(), purpose="review").generate()

    try:
        with pytest.raises(KnowledgeCallRefused, match="unit_validity"):
            review({"file": "unit.c", "name": "f", "line_start": 1})
        assert attempts == []
        assert runtime._calls[("unit.c", "f", 1)] == 1
        assert len([e for e in runtime.events() if e["event"] == "client_call_attempt"]) == 1
    finally:
        runtime.close()


def test_runtime_lifetime_check_is_pure_at_deadline_and_after_close(tmp_path, monkeypatch):
    clock = [1.0]
    monkeypatch.setattr("core.audit.knowledge_runtime.monotonic", lambda: clock[0])
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=10.0)
    try:
        before = (dict(runtime._calls), runtime.events(), runtime._wakeup.is_set())
        assert all(runtime.client_lifetime_valid() is True for _ in range(20))
        clock[0] = 10.0
        assert all(runtime.client_lifetime_valid() is False for _ in range(20))
        assert (dict(runtime._calls), runtime.events(), runtime._wakeup.is_set()) == before
        runtime.close()
        after_close = (dict(runtime._calls), runtime.events(), runtime._wakeup.is_set())
        assert runtime.client_lifetime_valid() is False
        assert (dict(runtime._calls), runtime.events(), runtime._wakeup.is_set()) == after_close
    finally:
        runtime.close()


@pytest.mark.parametrize("value", [False, None, 1, "true", [], object()])
def test_scope_requires_true_before_consuming_admission(value):
    from core.audit.knowledge_calls import owned_call_scope
    from core.llm.budget_errors import is_budget_exceeded_error
    admitted, generated = [], []

    class Client:
        def generate(self):
            generated.append(True)

    with owned_call_scope(lambda *a: admitted.append(a) or True, validity=lambda: value):
        with pytest.raises(KnowledgeCallRefused, match="unit_validity") as caught:
            observed_client(Client()).generate()
    assert not is_budget_exceeded_error(caught.value)
    assert admitted == generated == []


def test_scope_rejects_noncallable_before_entering():
    from core.audit.knowledge_calls import owned_call_scope
    entered = []
    with pytest.raises(TypeError, match="validity must be callable"):
        with owned_call_scope(lambda *a: True, validity=True):
            entered.append(True)
    assert not entered


def test_pure_callback_preserves_first_credit_and_rechecks_captured_close():
    from core.audit.knowledge_calls import owned_call_scope
    admitted, kwargs_seen = [], []

    class Client:
        _attempt_admission_protocol = 1
        _attempt_validity_protocol = 1

        def generate(self, **kwargs):
            kwargs_seen.append(kwargs)
            pure, consume = kwargs["accounting_attempt_validity"], kwargs["accounting_attempt_admission"]
            assert all(pure() is True for _ in range(20))
            assert len(admitted) == 1
            assert consume() is True
            assert len(admitted) == 1
            assert consume() is True
            assert len(admitted) == 2

    with owned_call_scope(lambda *a: admitted.append(a) or True):
        observed_client(Client()).generate()
    assert len(admitted) == 2
    for name in ("accounting_attempt_validity", "accounting_attempt_admission"):
        with pytest.raises(KnowledgeCallRefused, match="scope_closed"):
            kwargs_seen[0][name]()
    assert len(admitted) == 2


@pytest.mark.parametrize("protocol", [None, False, True, 0, 2, "1"])
def test_validity_keyword_requires_literal_protocol_one(protocol):
    from core.audit.knowledge_calls import owned_call_scope
    received = []

    class Client:
        _attempt_validity_protocol = protocol

        def generate(self, **kwargs):
            received.append(kwargs)

    with owned_call_scope(lambda *a: True, validity=lambda: True):
        observed_client(Client()).generate()
    assert received == [{}]


def test_validity_exception_identity_is_preserved_without_admission():
    from core.audit.knowledge_calls import owned_call_scope
    failure = KeyboardInterrupt("owned validity interrupt")
    admitted = []

    def validity():
        raise failure

    with owned_call_scope(lambda *a: admitted.append(a) or True, validity=validity):
        with pytest.raises(KeyboardInterrupt) as caught:
            observed_client(object()).generate()
    assert caught.value is failure and admitted == []


def test_review_owner_forwards_runtime_lifetime_to_late_client_check(tmp_path, monkeypatch):
    clock = [1.0]
    monkeypatch.setattr("core.audit.knowledge_runtime.monotonic", lambda: clock[0])
    (tmp_path / "unit.c").write_text("int f(void) { return 0; }\n")
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=10.0)
    reached = []

    class Client:
        _attempt_validity_protocol = 1

        def generate(self, **kwargs):
            clock[0] = 10.0
            kwargs["accounting_attempt_validity"]()
            reached.append(True)

    initial_counts = []

    def review(ctx, config):
        # Unknown scripted reviewers already retain one conservative credit.
        # A pure check must preserve that existing debit plus the observed call.
        initial_counts.append(runtime._calls[("unit.c", "f", 1)])
        observed_client(Client()).generate()
        raise AssertionError("expired review must not complete")

    try:
        with pytest.raises(KnowledgeCallRefused, match="unit_validity"):
            runtime.wrap_review(review)({"file": "unit.c", "function": "f", "line_start": 1,
                                         "source": "int f(void) { return 0; }", "language": "c"}, None)
        assert reached == []
        assert initial_counts == [1]
        assert runtime._calls[("unit.c", "f", 1)] == 2
        assert len([e for e in runtime.events() if e["event"] == "client_call_attempt"]) == 1
    finally:
        runtime.close()
