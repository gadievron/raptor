"""Private shutdown state and consumer bindings for audit unit tests."""

from contextlib import contextmanager, ExitStack
import threading
from types import ModuleType

import pytest


@contextmanager
def isolated_audit_shutdown(orchestrator):
    """Preserve borrowed events, bookkeeping, hooks, and module bindings.

    Copies of the OS/threading bindings keep incidental mocks local to the
    orchestrator. Real threads started through the private binding finish
    before the state they can observe is restored.
    """
    workers = []
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(orchestrator, "_sigterm_event", threading.Event())
        patch.setattr(orchestrator, "_shutdown_event", threading.Event())
        state = dict(orchestrator._sigterm_state)
        state["count"] = 0
        patch.setattr(orchestrator, "_sigterm_state", state)
        patch.setattr(orchestrator, "_sigterm_flush_hooks", [])
        for name in ("os", "_threading"):
            original = getattr(orchestrator, name)
            private = ModuleType(original.__name__)
            private.__dict__.update(vars(original))
            patch.setattr(orchestrator, name, private)
        real_thread = orchestrator._threading.Thread

        def owned_thread(*args, **kwargs):
            worker = real_thread(*args, **kwargs)
            workers.append(worker)
            return worker

        orchestrator._threading.Thread = owned_thread
        def finish_worker(worker):
            if worker.ident is not None:
                worker.join(5)
                if worker.is_alive():
                    raise AssertionError(
                        f"audit test worker survived cleanup: {worker.name}")

        try:
            yield
        finally:
            with ExitStack() as cleanup:
                for worker in reversed(workers):
                    cleanup.callback(finish_worker, worker)
