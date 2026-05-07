"""LLM-call credential-isolation dispatcher.

API keys never enter analysis-subprocess address space. The parent
holds the keys; analysis subprocesses connect to a Unix-domain HTTP
endpoint and the dispatcher injects the real ``Authorization`` (or
``x-api-key`` / ``x-goog-api-key``) header before forwarding upstream.

Five security layers (see ``server.py`` for implementation detail):

  1. Filesystem isolation — ``mkdtemp`` 0700 dir + 0600 socket file.
  2. Peer-UID verification on every accept.
  3. Per-worker capability token, passed to the worker via inherited
     file descriptor (NOT env var, NOT argv).
  4. Single-use-per-connection tokens with per-token request budget.
  5. Audit log of every accept / token / dispatch event.

See ``project_sandbox_enhancements.md`` (item d) for the threat model
that motivated this work.

This module does NOT migrate any existing call site; it ships the
infrastructure and one PoC E2E flow. Phase B (separate PR) audits
each LLM-calling subprocess and switches it to ``spawn_worker`` +
``client.make_anthropic_client``.
"""

from .client import make_anthropic_client
from .lifecycle import dispatcher_for_run, llm_dispatcher_in_run
from .server import LLMDispatcher, AuditEvent
from .spawn import spawn_worker

__all__ = [
    "LLMDispatcher",
    "AuditEvent",
    "dispatcher_for_run",
    "llm_dispatcher_in_run",
    "make_anthropic_client",
    "spawn_worker",
]
