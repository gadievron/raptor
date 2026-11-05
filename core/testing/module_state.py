"""Fixture-owned module state, with optional locking around publication."""

from contextlib import contextmanager, nullcontext

import pytest


@contextmanager
def isolated_module_state(module, replacements, *, lock=None):
    """Install fresh state and restore borrowed attributes under the same lock.

    Pass newly owned values in ``replacements``. The lock guards publication
    and restoration, not the test body, so cache consumers can acquire it.
    """
    patch = pytest.MonkeyPatch()
    try:
        with lock if lock is not None else nullcontext():
            for name, value in replacements.items():
                patch.setattr(module, name, value)
        yield
    finally:
        with lock if lock is not None else nullcontext():
            patch.undo()
