"""Own selected module-cache bindings without rewinding unrelated imports."""

from contextlib import ExitStack, contextmanager
import sys

_ABSENT = object()


def _restore(table, name, previous):
    if previous is _ABSENT:
        table.pop(name, None)
    else:
        table[name] = previous


@contextmanager
def module_registry_scope(*names):
    """Yield the module table, restoring only the selected slots on exit.

    Register before creating or executing a helper module. Missing slots and
    negative-cache entries (None) are distinct. Keep the scope active while
    consumers need the published modules, including dataclass resolution.
    Normal dependency imports and other module-cache writers remain intact.
    """
    table = sys.modules
    with ExitStack() as cleanup:
        for name in names:
            cleanup.callback(_restore, table, name, table.get(name, _ABSENT))
        yield table
