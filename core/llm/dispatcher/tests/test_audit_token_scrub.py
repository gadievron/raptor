"""token.reject audit lines carry the CLIENT's auth-header bytes.

``_audit`` scrubs ``worker_label`` and ``reason`` but the token_id
slot is assumed to be a dispatcher-minted hex prefix. On token.reject
it is the first 12 bytes of whatever the caller put in X-Raptor-Token
/ Authorization — the loopback TCP plane has no peer-UID gate, so any
local UID can drive raw ESC/OSC bytes into the INFO log line that
reaches the operator terminal. The scrub must cover token_id too
(a no-op for minted ids).
"""

from __future__ import annotations

import logging

from core.llm.dispatcher import server as srv

_HOSTILE_TOKEN_PREFIX = "AA\x1b]0;pwned\x07"


def _bare_dispatcher() -> srv.LLMDispatcher:
    d = srv.LLMDispatcher.__new__(srv.LLMDispatcher)
    d._audit_path = None  # terminal-lane only; no on-disk trail
    return d


def test_token_reject_audit_line_is_inert(caplog):
    d = _bare_dispatcher()
    ev = srv.AuditEvent(
        ts=0.0, event="token.reject", peer_pid=None, peer_uid=None,
        token_id=_HOSTILE_TOKEN_PREFIX, worker_label=None,
        status="reject", reason="unknown token",
    )
    with caplog.at_level(logging.INFO, logger=srv.__name__):
        d._audit(ev)
    assert caplog.records
    msg = caplog.records[-1].getMessage()
    assert "token.reject" in msg
    assert "\x1b" not in msg
    assert "\x07" not in msg
    assert "pwned" in msg  # correlation prefix survives, escaped


def test_minted_token_id_logs_unchanged(caplog):
    # Dispatcher-minted ids are hex/base64url — the scrub must be a
    # no-op for them so correlation prefixes stay grep-able.
    d = _bare_dispatcher()
    ev = srv.AuditEvent(
        ts=0.0, event="token.issue", peer_pid=None, peer_uid=None,
        token_id="abcdef012345", worker_label=None,
        status="ok", reason=None,
    )
    with caplog.at_level(logging.INFO, logger=srv.__name__):
        d._audit(ev)
    assert any("token=abcdef012345" in r.getMessage()
               for r in caplog.records)
