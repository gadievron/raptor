"""Run-wrapper cleanup precedence controls against the installed modules."""
from __future__ import annotations

import builtins
from types import FunctionType

import pytest

from core.analysis import reach_audit
from core.audit import orchestrator as orch
from core.audit.tests.test_postloop_environment_gate import _binding_run, _SiteRecordingGuard
from core.audit.tests.test_study_claim_retention import _owned_review_caches as _owned_review_caches
from core.llm import telemetry
from core.testing.audit_shutdown import isolated_audit_shutdown


def _install(monkeypatch):
    from core.audit import review_resources

    return review_resources


def _own_state(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    install = tmp_path / "owned-install"
    install.mkdir()
    monkeypatch.setenv("RAPTOR_DIR", str(install))
    monkeypatch.setattr(telemetry, "_sink", None)
    monkeypatch.setattr(_SiteRecordingGuard, "last", None)


@pytest.mark.slow
@pytest.mark.parametrize("body_cancel", [False, True], ids=["retirement-cancel", "body-cancel"])
def test_run_wrapper_cancellation_survives_existing_cleanup_error(tmp_path, monkeypatch, body_cancel):
    _install(monkeypatch)
    _own_state(tmp_path, monkeypatch)
    events = []
    body_error = KeyboardInterrupt("owned body cancellation")
    retirement_error = KeyboardInterrupt("owned resource cancellation")
    reset_error = OSError("owned reach-reset failure")
    reset = reach_audit.reset_joern_server

    def failed_reset(token):
        events.append("existing-reset")
        reset(token)
        raise reset_error

    def observed_stop(server):
        assert server is None, "this control must not own or stop a native server"
        events.append("existing-stop")

    def body(*args, **kwargs):
        resources = kwargs["review_resources"]
        resources.register(lambda: events.append("other-resource"))

        def cancelled_close():
            events.append("resource-cancel")
            raise retirement_error

        resources.register(cancelled_close)
        if body_cancel:
            raise body_error
        return kwargs["result"]

    monkeypatch.setattr(reach_audit, "reset_joern_server", failed_reset)
    monkeypatch.setattr(orch, "_stop_joern_server", observed_stop)
    monkeypatch.setattr(orch, "_run_audit_body", body)
    with isolated_audit_shutdown(orch):
        with pytest.raises(KeyboardInterrupt) as caught:
            _binding_run(tmp_path, monkeypatch)
    assert caught.value is (body_error if body_cancel else retirement_error)
    assert events == ["resource-cancel", "other-resource", "existing-reset", "existing-stop"]
    notes = getattr(caught.value, "__notes__", ())
    assert any("OSError" in note for note in notes)
    if body_cancel:
        assert any("KeyboardInterrupt" in note for note in notes)


@pytest.mark.slow
def test_normal_review_boundary_does_not_hide_fresh_final_cleanup_cancellation(tmp_path, monkeypatch):
    _install(monkeypatch)
    _own_state(tmp_path, monkeypatch)
    events = []
    fresh = KeyboardInterrupt("owned final cleanup cancellation")
    reset = reach_audit.reset_joern_server

    def cancelled_reset(token):
        events.append("existing-reset")
        reset(token)
        raise fresh

    def observed_stop(server):
        assert server is None
        events.append("existing-stop")

    def body(*args, **kwargs):
        resources = kwargs["review_resources"]
        resources.register(lambda: events.append("resource-close"))
        resources.retire()
        # The final wrapper still owns its existing cleanup, even though the
        # normal review boundary already retired the resource callbacks.
        return kwargs["result"]

    monkeypatch.setattr(reach_audit, "reset_joern_server", cancelled_reset)
    monkeypatch.setattr(orch, "_stop_joern_server", observed_stop)
    monkeypatch.setattr(orch, "_run_audit_body", body)
    with isolated_audit_shutdown(orch):
        with pytest.raises(KeyboardInterrupt) as caught:
            _binding_run(tmp_path, monkeypatch)
    assert caught.value is fresh
    assert events == ["resource-close", "existing-reset", "existing-stop"]


@pytest.mark.slow
@pytest.mark.parametrize("later_kind", ["ordinary", "cancellation"])
def test_run_wrapper_selects_cleanup_error_without_losing_later_cancellation(tmp_path, monkeypatch, later_kind):
    _install(monkeypatch)
    _own_state(tmp_path, monkeypatch)
    events = []
    first = OSError("owned earlier cleanup error")
    later = OSError("owned later cleanup error") if later_kind == "ordinary" else KeyboardInterrupt("owned later cancellation")
    reset = reach_audit.reset_joern_server

    def observed_reset(token):
        events.append("existing-reset")
        return reset(token)

    def observed_stop(server):
        assert server is None
        events.append("existing-stop")

    def body(*args, **kwargs):
        resources = kwargs["review_resources"]

        def later_close():
            events.append("later-error")
            raise later

        def first_close():
            events.append("ordinary-first")
            raise first

        resources.register(later_close)
        resources.register(first_close)
        return kwargs["result"]

    monkeypatch.setattr(reach_audit, "reset_joern_server", observed_reset)
    monkeypatch.setattr(orch, "_stop_joern_server", observed_stop)
    monkeypatch.setattr(orch, "_run_audit_body", body)
    selected = first if later_kind == "ordinary" else later
    with isolated_audit_shutdown(orch):
        with pytest.raises(type(selected)) as caught:
            _binding_run(tmp_path, monkeypatch)
    assert caught.value is selected
    assert events == ["ordinary-first", "later-error", "existing-reset", "existing-stop"]
    assert any("OSError" in note for note in selected.__notes__)


@pytest.mark.slow
@pytest.mark.parametrize("failure", ["import", "constructor"])
def test_resource_owner_setup_failure_precedes_run_resource_acquisition(tmp_path, monkeypatch, failure):
    helper = _install(monkeypatch)
    _own_state(tmp_path, monkeypatch)
    attempts = []
    error = ImportError("owned owner import failure") if failure == "import" else OSError("owned owner setup failure")

    def forbidden(*args, **kwargs):
        attempts.append((args, kwargs))
        raise AssertionError("owner setup must precede run resource acquisition")

    monkeypatch.setattr(reach_audit, "set_joern_server", forbidden)
    monkeypatch.setattr(telemetry, "set_sink", forbidden)
    monkeypatch.setattr(orch, "_start_joern_server_raw", forbidden)
    if failure == "constructor":
        class FailedOwner:
            def __init__(self):
                raise error
        monkeypatch.setattr(helper, "RunReviewResources", FailedOwner)
    else:
        # Bind the import fault to this consumer's private builtins, not the
        # process-wide import function used by pytest and fixture cleanup.
        original = orch.run_orchestrator
        namespace = dict(original.__globals__)
        private_builtins = dict(builtins.__dict__)
        real_import = private_builtins["__import__"]

        def failed_owner_import(name, globals=None, locals=None, fromlist=(), level=0):
            if name in {"review_resources", "core.audit.review_resources"}:
                raise error
            return real_import(name, globals, locals, fromlist, level)

        private_builtins["__import__"] = failed_owner_import
        namespace["__builtins__"] = private_builtins
        private_run = FunctionType(original.__code__, namespace, original.__name__, original.__defaults__)
        private_run.__kwdefaults__ = original.__kwdefaults__
        monkeypatch.setattr(orch, "run_orchestrator", private_run)
    with isolated_audit_shutdown(orch):
        with pytest.raises(type(error)) as caught:
            _binding_run(tmp_path, monkeypatch)
    assert caught.value is error
    assert attempts == []
