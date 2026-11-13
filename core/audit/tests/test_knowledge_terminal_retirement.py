"""Actual terminal cycle transitions retire Runtime ownership on interruption."""
import pytest

from core.audit.knowledge_runtime import AuditKnowledgeRuntime
from core.audit.llm_review import make_review_fn
from core.audit.orchestrator import OrchestratorConfig, StudyQueue
from core.llm.providers import StructuredResponse


def _reference_runtime(tmp_path):
    source = "unsigned f(unsigned n) { return n + 1; }\n"
    (tmp_path / "unit.c").write_text(source)
    runtime = AuditKnowledgeRuntime(tmp_path, StudyQueue(), deadline=float("inf"), window=0)
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    calls = []

    class Client:
        _attempt_admission_protocol = 1
        entry_id = "c.integer-shift"
        topic = "integer shifts"

        def generate_structured(self, prompt, schema, **kwargs):
            assert kwargs.pop("accounting_attempt_admission")() is True
            calls.append(prompt)
            return StructuredResponse(result={"status": "suspicious", "body": "Owned concern",
                "language_reference_requests": [{"topic": self.topic, "entry_id": self.entry_id}]},
                raw="", cost=.125, model="scripted")

    ctx = {"file": "unit.c", "function": "f", "line_start": 1, "line_end": 1,
           "source": source.rstrip(), "language": "c"}
    return runtime, config, Client(), ctx, calls


@pytest.mark.parametrize("terminal", ["complete", "fail"])
@pytest.mark.parametrize("interrupt", ["healthy", "before", "after", "rejected"])
def test_terminal_transition_releases_original_runtime_owner(tmp_path, monkeypatch, terminal, interrupt):
    runtime, config, client, ctx, calls = _reference_runtime(tmp_path)
    try:
        runtime.wrap_review(make_review_fn(client, escalate_clean=False))(ctx, config)
        reservation, = runtime.ready_continuations(admission=lambda: True, required_calls=1)
        key = runtime._key(reservation.origin)
        cycle = runtime._cycles[key]
        assert runtime._active_units[key] is reservation
        original = cycle.complete if terminal == "complete" else cycle.failed
        transitions = []

        def terminal_then_interrupt(*args, **kwargs):
            if interrupt == "before":
                raise KeyboardInterrupt("owned interruption before actual cycle terminal transition")
            if interrupt == "rejected":
                return False
            transitioned = original(*args, **kwargs)
            assert transitioned is True
            transitions.append(cycle.state_record())
            assert transitions[-1]["active_pass_id"] is None
            if interrupt == "after":
                raise KeyboardInterrupt("owned interruption after actual cycle terminal transition")
            return transitioned

        with monkeypatch.context() as patch:
            patch.setattr(cycle, "complete" if terminal == "complete" else "failed", terminal_then_interrupt)
            if interrupt in {"before", "after"}:
                with pytest.raises(KeyboardInterrupt, match="actual cycle terminal"):
                    if terminal == "complete":
                        runtime.complete(reservation, {})
                    else:
                        runtime.fail(reservation, "owned_failure")
            elif interrupt == "rejected":
                if terminal == "complete":
                    assert runtime.complete(reservation, {}) is False
                else:
                    assert runtime.fail(reservation, "owned_failure") is False
            elif terminal == "complete":
                assert runtime.complete(reservation, {}) is True
            else:
                assert runtime.fail(reservation, "owned_failure") is True
        if interrupt in {"before", "rejected"}:
            assert runtime._active_units[key] is reservation
            assert cycle.state_record()["active_pass_id"] == reservation.packet.pass_id
        # Mirror the outer continuation owner's best-effort failure cleanup.
        runtime.fail(reservation, "continuation_failed")
        runtime.close("owned_close")
        assert len(transitions) == (0 if interrupt in {"before", "rejected"} else 1)
        assert len(calls) == cycle.started == 1
        assert sum(runtime._calls.values()) == 1
        assert cycle.state_record()["active_pass_id"] is None
        assert not runtime._active and not runtime._active_units
        assert not runtime._knowledge_deliveries and not runtime._caller_deliveries
        assert not runtime.ready_continuations(admission=lambda: True)
    finally:
        runtime.close("test_complete")


def test_stale_release_preserves_actual_newer_reservation(tmp_path):
    runtime, config, client, ctx, calls = _reference_runtime(tmp_path)
    review = runtime.wrap_review(make_review_fn(client, escalate_clean=False))
    try:
        review(dict(ctx), config)
        first, = runtime.ready_continuations(admission=lambda: True)
        assert runtime.complete(first, {})
        client.entry_id = "c.integer-division"
        client.topic = "integer division"
        review(dict(ctx), config)
        second, = runtime.ready_continuations(admission=lambda: True)
        assert first.packet.pass_id != second.packet.pass_id
        key = runtime._key(second.origin)
        runtime._release(first)
        assert runtime._active[second.packet.pass_id] is second
        assert runtime._active_units[key] is second
        assert runtime._cycles[key].state_record()["active_pass_id"] == second.packet.pass_id
        assert len(calls) == sum(runtime._calls.values()) == runtime._cycles[key].started == 2
        assert runtime.fail(second, "owned_cleanup")
        assert not runtime._active and not runtime._active_units
    finally:
        runtime.close("test_complete")
