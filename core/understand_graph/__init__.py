"""Persistent graph memory for /understand-derived context.

The graph store is intentionally an internal substrate. Existing JSON
artefacts remain the public contract; callers should use this package rather
than querying SQLite directly.
"""

from .ingest import ingest_run
from .queries import (
    build_context_map,
    graph_summary,
    prompt_context_for_location,
    reachable_sinks,
)
from .store import (
    GRAPH_FILENAME,
    graph_path_for_run,
    open_graph,
)

__all__ = [
    "GRAPH_FILENAME",
    "build_context_map",
    "graph_path_for_run",
    "graph_summary",
    "ingest_run",
    "open_graph",
    "prompt_context_for_location",
    "reachable_sinks",
]
