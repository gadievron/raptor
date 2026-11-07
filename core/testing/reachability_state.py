"""Private inventory indexes for tests exercising reachability resolution."""

from collections import OrderedDict
from contextlib import ExitStack, contextmanager

from core.testing.module_state import isolated_module_state


# Keep the policy values and locks native; only cache contents belong to a test.
_CACHE_POLICIES = (
    ("_FN_CALLED_INDEX_CACHE", "_FN_CALLED_INDEX_CACHE_MAX"),
    ("_BO_ITEM_INDEX_CACHE", "_BO_ITEM_INDEX_CACHE_MAX"),
    ("_INDEX_CACHE", "_CACHE_MAX_ENTRIES"),
    ("_ENTRY_SET_CACHE", "_ENTRY_SET_CACHE_MAX"),
    ("_FILES_BY_PATH_CACHE", "_FILES_BY_PATH_CACHE_MAX"),
    ("_ENTRY_REACHABLE_CACHE", "_ENTRY_REACHABLE_CACHE_MAX"),
)


@contextmanager
def isolated_reachability_caches():
    """Restore caller indexes by identity without mutating their LRU order.

    Each index uses its production lock for publication and restoration.
    The body can still acquire those locks and exercise real cache eviction.
    Register capacity bindings too, since eviction tests temporarily change them.
    """
    from core.analysis import reachability

    with ExitStack() as scope:
        for name, capacity in _CACHE_POLICIES:
            scope.enter_context(isolated_module_state(reachability, {
                name: OrderedDict(), capacity: getattr(reachability, capacity),
            }, lock=getattr(reachability, name + "_LOCK")))
        yield
