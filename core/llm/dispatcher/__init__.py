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
  4. Tokens bounded by request budget + TTL + explicit revocation —
     a token may establish multiple connections within those bounds,
     and worker tokens renew in place on the peer-UID-verified socket
     (``POST /_token/renew``); scoped child tokens are not renewable.
  5. Audit log of every accept / token / dispatch event.

See ``project_sandbox_enhancements.md`` (item d) for the threat model
that motivated this work.

Call sites are migrated: the SDK providers route through the
dispatcher whenever ``RAPTOR_LLM_SOCKET`` is present (the Bedrock
provider requires it), and CLI children reach it via the loopback /
child-plane bridges. New LLM-calling subprocesses use
``spawn_worker`` + the ``make_*_client`` factories below.
"""

from .client import (
    make_anthropic_client,
    make_bedrock_client,
    make_gemini_base_url,
    make_openai_client,
    relay_for_grandchild,
)
from .lifecycle import dispatcher_for_run, llm_dispatcher_in_run
from .server import LLMDispatcher, AuditEvent
from .spawn import spawn_worker

__all__ = [
    "AuditEvent",
    "LLMDispatcher",
    "dispatcher_for_run",
    "llm_dispatcher_in_run",
    "make_anthropic_client",
    "make_bedrock_client",
    "make_gemini_base_url",
    "make_openai_client",
    "relay_for_grandchild",
    "spawn_worker",
]
