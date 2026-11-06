"""Fixture-owned module state, with optional locking around publication."""

from contextlib import ExitStack, contextmanager, nullcontext
import inspect
from types import ModuleType

import pytest


_ABSENT = object()


def _restore_attribute(owner, name, original):
    if original is _ABSENT:
        if name in vars(owner):
            delattr(owner, name)
    else:
        setattr(owner, name, original)


@contextmanager
def isolated_module_state(module, replacements, *, lock=None):
    """Install fresh state and restore borrowed attributes under the same lock.

    Pass newly owned values in ``replacements``. The lock guards publication
    and restoration, not the test body, so cache consumers can acquire it.
    Register restoration before publication: a module setter can raise after
    changing its namespace. Run every restoration even if another one fails.
    """
    restore = ExitStack()
    patch = pytest.MonkeyPatch()
    published = False
    needs_raw_restore = False
    try:
        with lock if lock is not None else nullcontext():
            for name, value in replacements.items():
                original = getattr(module, name)
                if isinstance(module, ModuleType) or inspect.isclass(module):
                    raw = vars(module).get(name, _ABSENT)
                    needs_raw_restore |= raw is not original
                    original = raw
                restore.callback(_restore_attribute, module, name, original)
                patch.setattr(module, name, value)
            published = True
        yield
    finally:
        with lock if lock is not None else nullcontext():
            try:
                patch.undo()
            except BaseException:
                # Finish every registered restoration even if one undo fails.
                restore.close()
                raise
            else:
                if not published or needs_raw_restore:
                    restore.close()
                else:
                    # Ordinary undo already restored these bindings. Discard
                    # the backups rather than invoking module setters twice.
                    restore.pop_all()
