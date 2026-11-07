"""Singleton activation, rollback and replacement retain real loop ownership."""

import threading
import asyncio
import signal
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from core.sandbox import proxy as proxy_mod
from core.testing.module_bindings import patch_module_attribute
from core.testing.proxy_scope import isolated_proxy_scope


@pytest.fixture
def activation():
    with isolated_proxy_scope():
        with pytest.MonkeyPatch.context() as setup:
            for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy",
                         "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy"):
                setup.delenv(name, raising=False)
            parser = Mock(return_value=Mock(landlocked=True))
            patch_module_attribute(setup, proxy_mod, "parser_jail", "get_parser_jail", parser)
            original = proxy_mod.EgressProxy
            created = []
            def create(*args, **kwargs):
                instance = original(*args, **kwargs)
                created.append(instance)
                return instance
            setup.setattr(proxy_mod, "EgressProxy", create)
            yield SimpleNamespace(created=created, parser=parser)


@pytest.fixture
def monkeypatch(activation):
    # Undo body faults before the owning proxy scope retires its resources.
    with pytest.MonkeyPatch.context() as patch:
        yield patch


INVALID_TIMEOUTS = [pytest.param(value, id=name) for value, name in [
    (0, "zero"), (-1, "negative"), (float("nan"), "nan"),
    (float("inf"), "inf"), (-float("inf"), "negative-inf"),
    (True, "boolean"), ("1", "text"), (None, "none"),
    (10 ** 1000, "huge-int"),
]]


@pytest.mark.parametrize("field", ["idle_timeout", "total_timeout"])
@pytest.mark.parametrize("value", INVALID_TIMEOUTS)
def test_constructor_rejects_invalid_timeouts_before_worker_acquisition(activation, field, value):
    with pytest.raises(ValueError, match=field):
        proxy_mod.EgressProxy(set(), **{field: value})
    activation.parser.assert_not_called()
    assert not activation.created


@pytest.mark.parametrize("field,value", [
    pytest.param("buffer_size", 0, id="empty-buffer"),
    pytest.param("buffer_size", -1, id="unbounded-read"),
    pytest.param("buffer_size", 1.5, id="fractional-buffer"),
    pytest.param("buffer_size", True, id="boolean-buffer"),
    pytest.param("max_tunnels", -1, id="negative-cap"),
    pytest.param("max_tunnels", 1.5, id="fractional-cap"),
    pytest.param("max_tunnels", False, id="boolean-cap"),
])
def test_constructor_rejects_invalid_resource_counts_before_workers(activation, field, value):
    with pytest.raises(ValueError, match=field):
        proxy_mod.EgressProxy(set(), **{field: value})
    activation.parser.assert_not_called()
    assert not activation.created


def test_zero_capacity_remains_a_valid_refuse_all_configuration(activation):
    instance = proxy_mod.EgressProxy(set(), max_tunnels=0)
    assert instance._max_tunnels == 0 and instance.is_alive()


def test_first_acquisition_honors_an_idle_override_below_the_default(activation):
    instance = proxy_mod.get_proxy({"owned.invalid"}, idle_timeout=0.5)
    assert instance._idle_timeout == 0.5
    assert instance is proxy_mod._instance and instance.is_alive()


def test_reuse_preserves_host_union_and_timeout_max_semantics(activation):
    first = proxy_mod.get_proxy({"One.Invalid"}, idle_timeout=600)
    assert proxy_mod.get_proxy({"Two.Invalid"}, idle_timeout=900) is first
    assert proxy_mod.get_proxy(set(), idle_timeout=800) is first
    assert first._idle_timeout == 900
    assert first._allowed_hosts == {"one.invalid", "two.invalid"}
    assert len(activation.created) == 1


@pytest.mark.parametrize("value", [item for item in INVALID_TIMEOUTS if item.id != "none"])
def test_bad_reuse_budget_cannot_mutate_existing_configuration(activation, value):
    instance = proxy_mod.get_proxy({"old.invalid"}, idle_timeout=600)
    with pytest.raises(ValueError, match="idle_timeout"):
        proxy_mod.get_proxy({"new.invalid"}, idle_timeout=value)
    assert instance._allowed_hosts == {"old.invalid"}
    assert instance._idle_timeout == 600 and instance.is_alive()
    assert proxy_mod._instance is instance and len(activation.created) == 1


def test_failed_host_iterator_cannot_partially_reconfigure_live_proxy(activation):
    instance = proxy_mod.get_proxy({"old.invalid"}, idle_timeout=600)
    def broken():
        yield "new.invalid"
        raise RuntimeError("owned iterator failure")
    with pytest.raises(RuntimeError, match="owned iterator"):
        proxy_mod.get_proxy(broken(), idle_timeout=900)
    assert instance._allowed_hosts == {"old.invalid"} and instance._idle_timeout == 600
    assert proxy_mod._instance is instance


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
@pytest.mark.parametrize("partial", [False, True], ids=["before-register", "after-register"])
def test_exit_registration_failure_rolls_back_the_created_loop(activation, monkeypatch, failure_type, partial):
    failure = failure_type("owned exit registration failure")
    register = proxy_mod.atexit.register
    observed = []
    def failed(callback):
        observed.append(proxy_mod._instance)
        if partial:
            register(callback)
        raise failure
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, proxy_mod, "atexit", "register", failed)
        with pytest.raises(failure_type) as raised:
            proxy_mod.get_proxy({"owned.invalid"})
    assert raised.value is failure
    assert observed == [None]
    assert proxy_mod._instance is None
    assert len(activation.created) == 1
    assert not activation.created[0].is_alive()
    assert activation.created[0]._loop.is_closed()
    assert proxy_mod.get_proxy({"retry.invalid"}).is_alive()


@pytest.mark.parametrize("failure_type", [RuntimeError, KeyboardInterrupt])
def test_post_registration_setup_failure_releases_singleton_and_hook(activation, monkeypatch, failure_type):
    failure = failure_type("owned signal setup failure")
    unregistered = []
    unregister = proxy_mod.atexit.unregister
    def track(callback):
        unregistered.append(callback)
        unregister(callback)
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, proxy_mod, "atexit", "unregister", track)
        fault.setattr(proxy_mod, "_install_sigterm_cleanup", Mock(side_effect=failure))
        with pytest.raises(failure_type) as raised:
            proxy_mod.get_proxy({"owned.invalid"})
    assert raised.value is failure and proxy_mod._instance is None
    owner = activation.created[0]
    assert not owner.is_alive() and owner._loop.is_closed()
    assert len(unregistered) == 1 and unregistered[0].__self__ is owner


def test_incomplete_rollback_stays_owned_and_detaches_the_exact_hook_on_retry(activation, monkeypatch):
    create = proxy_mod.EgressProxy
    failure = RuntimeError("owned activation failure")
    stored = []
    def unable_to_stop(*, drain_timeout=5.0):
        raise RuntimeError("owned stop pending")
    def blocked_create(*args, **kwargs):
        owner = create(*args, **kwargs)
        fault.setattr(owner, "stop", unable_to_stop)
        stored.append(owner)
        return owner
    with monkeypatch.context() as fault:
        fault.setattr(proxy_mod, "EgressProxy", blocked_create)
        fault.setattr(proxy_mod, "_install_sigterm_cleanup", Mock(side_effect=failure))
        with pytest.raises(RuntimeError) as raised:
            proxy_mod.get_proxy({"owned.invalid"})
        assert raised.value is failure
        owner = stored[0]
        assert proxy_mod._instance is owner and owner._stopping
        with pytest.raises(RuntimeError, match="cleanup is incomplete"):
            proxy_mod.get_proxy({"second.invalid"})
        assert len(activation.created) == 1
    removed = []
    unregister = proxy_mod.atexit.unregister
    def track(callback):
        removed.append(callback)
        unregister(callback)
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, proxy_mod, "atexit", "unregister", track)
        replacement = proxy_mod.get_proxy({"retry.invalid"})
    assert replacement is not owner and replacement.is_alive()
    assert removed == [unable_to_stop]
    assert not owner.is_alive() and owner._loop.is_closed()


def test_stopping_proxy_cannot_be_returned_or_replaced_while_its_loop_is_live(activation, monkeypatch):
    owner = proxy_mod.get_proxy({"first.invalid"})
    entered, release = threading.Event(), threading.Event()
    def block():
        entered.set()
        assert release.wait(5)
    owner._loop.call_soon_threadsafe(block)
    assert entered.wait(5)
    join = owner._thread.join
    try:
        with monkeypatch.context() as fault:
            # Model the bounded join expiring; keep real thread/loop liveness.
            fault.setattr(owner._thread, "join", lambda timeout: None)
            owner.stop(drain_timeout=0)
            with pytest.raises(RuntimeError, match="cleanup is incomplete"):
                proxy_mod.get_proxy({"second.invalid"})
            assert proxy_mod._instance is owner and len(activation.created) == 1
    finally:
        release.set()
        join(5)
    replacement = proxy_mod.get_proxy({"second.invalid"})
    assert replacement is not owner and replacement.is_alive()


def test_dead_thread_with_unclosed_loop_remains_owned_for_cleanup(activation, monkeypatch):
    owner = proxy_mod.get_proxy({"owned.invalid"})
    close = owner._loop.close
    try:
        with monkeypatch.context() as fault:
            fault.setattr(owner._loop, "close", lambda: None)
            owner.stop(drain_timeout=0)
            assert not owner.is_alive() and not owner._loop.is_closed()
            with pytest.raises(RuntimeError, match="cleanup is incomplete"):
                proxy_mod.get_proxy({"replacement.invalid"})
            assert proxy_mod._instance is owner and len(activation.created) == 1
    finally:
        close()
    assert proxy_mod.get_proxy({"replacement.invalid"}) is not owner


def test_stopped_replacement_unregisters_old_callback(activation, monkeypatch):
    removed = []
    unregister = proxy_mod.atexit.unregister
    owner = proxy_mod.get_proxy({"first.invalid"})
    # Capture the registered callable without requiring the new storage field
    # in baseline reproduction against the original consumer.
    registered = owner.stop
    owner.stop(drain_timeout=0)
    def track(callback):
        removed.append(callback)
        unregister(callback)
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, proxy_mod, "atexit", "unregister", track)
        replacement = proxy_mod.get_proxy({"second.invalid"})
    assert replacement is not owner and removed == [registered]


def test_worker_first_acquisition_retries_signal_setup_on_main_thread(activation, monkeypatch):
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    calls = []
    install = proxy_mod._install_sigterm_cleanup
    def track():
        calls.append(threading.current_thread() is threading.main_thread())
        install()
    monkeypatch.setattr(proxy_mod, "_install_sigterm_cleanup", track)
    result, errors = [], []
    def acquire():
        try:
            result.append(proxy_mod.get_proxy({"first.invalid"}))
        except BaseException as failure:
            errors.append(failure)
    worker = threading.Thread(target=acquire)
    worker.start()
    worker.join(5)
    assert not worker.is_alive() and not errors
    assert proxy_mod.get_proxy({"second.invalid"}) is result[0]
    assert calls == [False, True] and proxy_mod._sigterm_hook_installed


@pytest.mark.parametrize("value", INVALID_TIMEOUTS)
def test_direct_timeout_update_rejects_invalid_values_without_mutation(activation, value):
    owner = proxy_mod.EgressProxy(set(), idle_timeout=600)
    with pytest.raises(ValueError, match="idle_timeout"):
        owner.update_idle_timeout(value)
    assert owner._idle_timeout == 600 and owner.is_alive()


@pytest.mark.parametrize("failure_type", [OSError, ValueError])
def test_allowlist_diagnostics_cannot_prevent_valid_activation_or_reuse(activation, monkeypatch, failure_type):
    def failed(*args):
        raise failure_type("owned diagnostic stream failure")
    monkeypatch.setattr(proxy_mod, "_warn_doh_hosts", failed)
    owner = proxy_mod.get_proxy({"first.invalid"})
    assert proxy_mod.get_proxy({"second.invalid"}) is owner
    assert owner._allowed_hosts == {"first.invalid", "second.invalid"}
    assert owner.is_alive()


@pytest.mark.parametrize("failure_type", [OSError, ValueError])
def test_timeout_diagnostic_cannot_abort_a_valid_update(activation, monkeypatch, failure_type):
    original = proxy_mod.logger
    class LoggerView:
        def __getattr__(self, name):
            return getattr(original, name)
        def info(self, *args, **kwargs):
            raise failure_type("owned diagnostic stream failure")
    monkeypatch.setattr(proxy_mod, "logger", LoggerView())
    owner = proxy_mod.get_proxy({"first.invalid"}, idle_timeout=600)
    assert proxy_mod.get_proxy({"second.invalid"}, idle_timeout=900) is owner
    assert owner._idle_timeout == 900 and owner.is_alive()


def test_reset_retires_resources_and_unregisters_owned_exit_hook(activation, monkeypatch):
    owner = proxy_mod.get_proxy({"owned.invalid"})
    registered = owner.stop
    removed = []
    unregister = proxy_mod.atexit.unregister
    def track(callback):
        removed.append(callback)
        unregister(callback)
    with monkeypatch.context() as fault:
        patch_module_attribute(fault, proxy_mod, "atexit", "unregister", track)
        proxy_mod._reset_for_tests()
    assert removed == [registered] and proxy_mod._instance is None
    assert not owner.is_alive() and owner._loop.is_closed()


@pytest.mark.parametrize("phase", ["exit-registration", "signal-setup"])
def test_candidate_stopping_during_startup_is_rolled_back_before_return(activation, monkeypatch, phase):
    register = proxy_mod.atexit.register
    def register_then_stop(callback):
        result = register(callback)
        activation.created[-1].stop(drain_timeout=0)
        return result
    def stop_during_setup():
        proxy_mod._instance.stop(drain_timeout=0)
    with monkeypatch.context() as fault:
        if phase == "exit-registration":
            patch_module_attribute(fault, proxy_mod, "atexit", "register", register_then_stop)
        else:
            fault.setattr(proxy_mod, "_install_sigterm_cleanup", stop_during_setup)
        with pytest.raises(RuntimeError, match="stopped during activation"):
            proxy_mod.get_proxy({"owned.invalid"})
    assert proxy_mod._instance is None
    assert len(activation.created) == 1 and not activation.created[0].is_alive()
    assert proxy_mod.get_proxy({"retry.invalid"}).is_alive()


def test_reuse_stopping_during_signal_retry_cannot_return_a_dead_proxy(activation, monkeypatch):
    owner = proxy_mod.get_proxy({"old.invalid"})
    def stop_during_setup():
        owner.stop(drain_timeout=0)
    with monkeypatch.context() as fault:
        fault.setattr(proxy_mod, "_install_sigterm_cleanup", stop_during_setup)
        with pytest.raises(RuntimeError, match="stopped during acquisition"):
            proxy_mod.get_proxy({"new.invalid"})
    assert proxy_mod._instance is owner and not owner.is_alive()
    assert proxy_mod.get_proxy({"retry.invalid"}) is not owner



def test_readiness_is_not_published_before_the_loop_starts_serving(activation, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    observed, errors = [], []
    make_loop = asyncio.new_event_loop
    def delayed_loop():
        loop = make_loop()
        run_forever = loop.run_forever
        calls = []
        def held():
            calls.append(True)
            if len(calls) == 2:
                owner = threading.current_thread()._target.__self__
                observed.append((owner._ready.is_set(), loop.is_running()))
                entered.set()
                assert release.wait(5)
            return run_forever()
        loop.run_forever = held
        return loop
    patch_module_attribute(monkeypatch, proxy_mod, "asyncio", "new_event_loop", delayed_loop)
    def acquire():
        try:
            proxy_mod.get_proxy({"owned.invalid"})
        except BaseException as failure:
            errors.append(failure)
    caller = threading.Thread(target=acquire)
    caller.start()
    try:
        assert entered.wait(5), "proxy never reached the permanent-loop boundary"
        assert observed == [(False, False)]
    finally:
        release.set()
        caller.join(5)
    assert not caller.is_alive() and not errors
    assert proxy_mod._instance.is_alive() and proxy_mod._instance._loop.is_running()
