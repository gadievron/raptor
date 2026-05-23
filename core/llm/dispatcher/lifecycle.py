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
from typing import Iterator, Optional

from .auth import CredentialStore
from .server import LLMDispatcher


_AUDIT_FILENAME = "audit-llm-dispatcher.jsonl"


# Explicit pass-through signature, replacing an earlier ``**kwargs``
# fan-out. Pre-fix the wildcard accepted anything — typos like
# ``token_budget_s=10000`` (silently ignored) and undocumented
# ``LLMDispatcher`` keyword renames could regress without a single
# test failing because mypy/ruff have nothing to type-check the
# argument names against. Listing the supported knobs explicitly
# matches the ``LLMDispatcher.__init__`` contract at one place.
def dispatcher_for_run(
    run_dir: Path,
    *,
    token_ttl_s: Optional[int] = None,
    token_budget: Optional[int] = None,
    creds: Optional[CredentialStore] = None,
) -> LLMDispatcher:
    """Return a fresh ``LLMDispatcher`` whose audit log lives inside
    ``run_dir`` and whose ``run_id`` matches the run dir name.

    The caller is responsible for ``shutdown()``. An ``atexit`` hook
    is registered as defence-in-depth so a forgotten shutdown still
    releases the socket dir at interpreter exit.

    Keyword args flow through to :class:`LLMDispatcher` for tuning
    ``token_ttl_s`` / ``token_budget`` per consumer; ``creds`` lets
    tests substitute a fixture credential store.
    """
    run_dir = Path(run_dir)
    if not run_dir.exists():
        raise FileNotFoundError(f"run_dir does not exist: {run_dir}")
    audit_path = run_dir / _AUDIT_FILENAME
    run_id = run_dir.name
    # Use only the kwargs the caller actually set, so the dispatcher
    # keeps its module-level defaults for the rest.
    dispatcher_kwargs: dict = {}
    if token_ttl_s is not None:
        dispatcher_kwargs["token_ttl_s"] = token_ttl_s
    if token_budget is not None:
        dispatcher_kwargs["token_budget"] = token_budget
    if creds is not None:
        dispatcher_kwargs["creds"] = creds
    d = LLMDispatcher(
        run_id=run_id, audit_path=audit_path, **dispatcher_kwargs,
    )
    atexit.register(d.shutdown)
    return d


@contextlib.contextmanager
def llm_dispatcher_in_run(
    run_dir: Path,
    *,
    token_ttl_s: Optional[int] = None,
    token_budget: Optional[int] = None,
    creds: Optional[CredentialStore] = None,
) -> Iterator[LLMDispatcher]:
    """Context-manager flavour: dispatcher lives only inside the
    ``with`` block. Preferred when the dispatching scope is bounded
    (one analysis pass, one validation stage) — guarantees shutdown
    even on exception.
    """
    d = dispatcher_for_run(
        run_dir,
        token_ttl_s=token_ttl_s,
        token_budget=token_budget,
        creds=creds,
    )
    try:
        yield d
    finally:
        d.shutdown()
