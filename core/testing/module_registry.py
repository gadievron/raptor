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


@contextmanager
def mock_module_registry(replacements):
    """Publish selected fake or missing dependencies without rewinding imports.

    Unlike a whole-table snapshot, this leaves unrelated module-cache writes
    intact. Yield the live table for tests that configure their fake after
    publication. Register every selected slot before publishing the first.
    """
    with module_registry_scope(*replacements) as modules:
        for name, module in replacements.items():
            modules[name] = module
        yield modules


def _in_module_tree(key, root):
    return isinstance(key, str) and (key == root or key.startswith(root + "."))


def _restore_module_tree(table, root, saved):
    with ExitStack() as restore:
        for name, previous in saved.items():
            restore.callback(_restore, table, name, previous)
        for name in tuple(table):
            if _in_module_tree(name, root) and name not in saved:
                restore.callback(_restore, table, name, _ABSENT)


@contextmanager
def fresh_module_tree(root):
    """Temporarily remove one import namespace, preserving its borrowed state.

    Restore original entries, including None, and remove newly imported
    descendants. Own the raw child attribute on an already-loaded parent
    independently of its sys.modules entry: those bindings need not agree.
    Other namespaces and their concurrent imports remain untouched.
    """
    table = sys.modules
    saved = {name: table[name] for name in tuple(table) if _in_module_tree(name, root)}
    parent_name, _, child = root.rpartition(".")
    parent = table.get(parent_name) if parent_name else None
    with ExitStack() as restore:
        if parent is not None:
            namespace = vars(parent)
            restore.callback(_restore, namespace, child, namespace.get(child, _ABSENT))
        restore.callback(_restore_module_tree, table, root, saved)
        for name in saved:
            table.pop(name, None)
        yield table
