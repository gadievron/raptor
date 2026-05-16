"""Per-run lifecycle integration for ``LLMDispatcher``.

Constructs a dispatcher tied to a RAPTOR run directory: the audit log
lands at ``<run_dir>/audit-llm-dispatcher.jsonl``, the dispatcher's
``run_id`` is the run dir's basename, and shutdown is wired through
either ``atexit`` (when used directly) or the context-manager exit
(when used via :func:`llm_dispatcher_in_run`).

Construction is opt-in. ``start_run`` does NOT spin one up
automatically — only callers that want credential isolation reach
for this helper, so the dispatcher's daemon thread doesn't spawn
unnecessarily for runs that don't dispatch any LLM calls.
"""

from __future__ import annotations

import atexit
import contextlib
from pathlib import Path
from typing import Iterator

from .server import LLMDispatcher


_AUDIT_FILENAME = "audit-llm-dispatcher.jsonl"


def dispatcher_for_run(run_dir: Path, **kwargs) -> LLMDispatcher:
    """Return a fresh ``LLMDispatcher`` whose audit log lives inside
    ``run_dir`` and whose ``run_id`` matches the run dir name.

    The caller is responsible for ``shutdown()``. An ``atexit`` hook
    is registered as defence-in-depth so a forgotten shutdown still
    releases the socket dir at interpreter exit.

    Extra kwargs flow through to :class:`LLMDispatcher` (for tuning
    ``token_ttl_s`` / ``token_budget`` per consumer).
    """
    run_dir = Path(run_dir)
    if not run_dir.exists():
        raise FileNotFoundError(f"run_dir does not exist: {run_dir}")
    audit_path = run_dir / _AUDIT_FILENAME
    run_id = run_dir.name
    d = LLMDispatcher(run_id=run_id, audit_path=audit_path, **kwargs)
    atexit.register(d.shutdown)
    return d


@contextlib.contextmanager
def llm_dispatcher_in_run(run_dir: Path, **kwargs) -> Iterator[LLMDispatcher]:
    """Context-manager flavour: dispatcher lives only inside the
    ``with`` block. Preferred when the dispatching scope is bounded
    (one analysis pass, one validation stage) — guarantees shutdown
    even on exception.
    """
    d = dispatcher_for_run(run_dir, **kwargs)
    try:
        yield d
    finally:
        d.shutdown()
