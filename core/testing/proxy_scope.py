"""Own proxy-test workers without stopping inherited process singletons."""

from contextlib import ExitStack, contextmanager
import atexit
import signal
from types import ModuleType

from core.testing.module_state import isolated_module_state


@contextmanager
def isolated_proxy_scope():
    """Finish owned listeners and parser workers before restoring caller state.

    The proxy subclass retains the real listener, parser and policy behavior.
    Recording construction before initialization also covers setup failures.
    Exit registrations use a consumer-local module view; other users of atexit
    keep the real module. Signal installation and delivery remain native.
    """
    from core.sandbox import parser_jail, proxy

    previous_signal = signal.getsignal(signal.SIGTERM)
    if previous_signal is None:
        raise RuntimeError("proxy test cannot restore an opaque C SIGTERM handler")
    proxies, jails, callbacks = [], [], []
    real_proxy = proxy.EgressProxy
    real_stop = real_proxy.stop
    real_parser = parser_jail.ParserJail
    real_parser_stop = real_parser.stop
    exits = ModuleType("atexit")
    vars(exits).update(vars(atexit))

    def register(callback, *args, **kwargs):
        callbacks.append(callback)
        return atexit.register(callback, *args, **kwargs)

    exits.register = register

    class OwnedProxy(real_proxy):
        def __init__(self, *args, **kwargs):
            proxies.append(self)
            super().__init__(*args, **kwargs)

    def stop_proxy(owner):
        if getattr(owner, "_loop", None) is not None:
            try:
                owner.stop(drain_timeout=0)
            except BaseException:
                real_stop(owner, drain_timeout=0)
                raise
        thread = getattr(owner, "_thread", None)
        if thread is not None and thread.ident is not None:
            thread.join(timeout=5)
            assert not thread.is_alive(), "test-owned proxy thread survived cleanup"

    def stop_proxies():
        with ExitStack() as cleanup:
            for owner in proxies:
                cleanup.callback(stop_proxy, owner)

    class OwnedParser(real_parser):
        def __init__(self, *args, **kwargs):
            jails.append(self)
            super().__init__(*args, **kwargs)

    def stop_parser(owner):
        try:
            owner.stop()
        except BaseException:
            real_parser_stop(owner)
            raise

    def stop_parsers():
        # get_parser_jail registers its exit hook before publishing _jail.
        # Track construction so a failed registration cannot strand that worker.
        with ExitStack() as cleanup:
            for owner in jails:
                cleanup.callback(stop_parser, owner)

    def unregister():
        for callback in callbacks:
            atexit.unregister(callback)

    with ExitStack() as scope:
        scope.enter_context(isolated_module_state(proxy, {
            "_instance": None, "_sigterm_hook_installed": False,
            "EgressProxy": OwnedProxy, "atexit": exits,
        }, lock=proxy._lock))
        scope.enter_context(isolated_module_state(
            parser_jail, {"_jail": None, "atexit": exits, "ParserJail": OwnedParser},
            lock=parser_jail._jail_lock))
        scope.callback(signal.signal, signal.SIGTERM, previous_signal)
        scope.callback(unregister)
        scope.callback(stop_parsers)
        scope.callback(stop_proxies)
        yield
