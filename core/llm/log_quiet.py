"""Quiet noisy third-party loggers that flood operator output
during /agentic and other LLM-driven runs.

The Gemini SDK (``google.genai``) and the underlying ``httpx``
HTTP client both emit INFO-level lines on every API call:

* ``[INFO] AFC is enabled with max remote calls: 10.`` — google.genai's
  automatic-function-calling banner, logged on every model
  initialisation.
* ``[INFO] HTTP Request: POST https://generativelanguage.googleapis.com/...`` —
  httpx's per-request log; fires twice per RAPTOR LLM call
  (once for the real provider endpoint, once for the dispatcher
  proxy on the loopback unix socket).

Neither line carries operator-relevant signal at INFO. They're
debugging detail at the SDK / transport layer. Operators looking
at /agentic output want per-finding analysis progress and cost,
not the HTTP plumbing.

This module is the single chokepoint for these adjustments —
called once from the dispatcher's ``start()`` so EVERY run path
(/agentic, /codeql, /understand, /validate, /scan with LLM
enrichment) gets the quiet treatment uniformly.
"""

from __future__ import annotations

import logging

# Logger names known to flood INFO during normal RAPTOR operation.
# Order doesn't matter; ``setLevel`` is idempotent.
#
# Coverage rationale:
# * ``httpx`` — every API call emits ``HTTP Request: POST <url> "HTTP/1.1 NNN ..."``
#   at INFO. Fires on the real upstream call AND the dispatcher
#   proxy call (the unix-socket forwarder). Two lines per LLM
#   request before this module silenced them.
# * ``httpcore`` — httpx's underlying transport library; can emit
#   connection / TLS lines depending on configuration. Quieted
#   defensively.
# * ``google.genai`` and ``google_genai`` — both names appear
#   across SDK versions; alias-cover for safety.
# * ``google.api_core``, ``google.auth`` — supporting libraries
#   that occasionally emit auth-related INFO. Quiet by default;
#   anything that's actually wrong surfaces at WARNING regardless.
_NOISY_LOGGERS = (
    "httpx",
    "httpcore",
    "google.genai",
    "google_genai",
    "google.api_core",
    "google.auth",
)


def quiet_noisy_loggers(level: int = logging.WARNING) -> None:
    """Set the listed third-party loggers to ``level`` (default
    WARNING) so their INFO chatter stops flooding /agentic output.

    Idempotent — safe to call repeatedly. WARNING and above
    still surface so real failures (HTTP errors, auth failures)
    aren't hidden.
    """
    for name in _NOISY_LOGGERS:
        logging.getLogger(name).setLevel(level)


__all__ = ["quiet_noisy_loggers"]
