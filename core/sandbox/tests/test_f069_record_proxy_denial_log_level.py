"""Regression test for F069.

When `_record_proxy_denial` fails to write to sandbox-summary.json
(audit-mode hostname-deny path), the exception is caught and silently
swallowed by `logger.debug(...)`. Operators rarely run with DEBUG
enabled, so a regressed summary writer is invisible — the audit
record never lands, and the operator never knows.

This mirrors the family-wide DEBUG -> WARNING promotion in commit
c5a4505 (`fix(scorecard): promote producer-error logs DEBUG -> WARNING`)
applied to the scorecard producers. Same rationale, same shape: a
best-effort recorder whose failure was effectively muted at default
log levels.

This test monkeypatches the lazy `record_denial` import inside
`_record_proxy_denial` to raise, then asserts a WARNING-level log is
emitted (not DEBUG).
"""

from __future__ import annotations

import logging

from core.sandbox import proxy as proxy_mod


def test_record_proxy_denial_logs_at_warning_when_record_denial_raises(
    caplog, monkeypatch,
):
    """Failure to persist an audit-mode would-deny must surface at WARNING."""

    # Force the lazy `from core.sandbox.summary import record_denial`
    # inside `_record_proxy_denial` to import a record_denial that
    # raises. Patch the source module so the lazy import lands on our
    # stub.
    import core.sandbox.summary as summary_mod

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated record_denial failure")

    monkeypatch.setattr(summary_mod, "record_denial", _boom)

    with caplog.at_level(logging.DEBUG, logger="core.sandbox.proxy"):
        proxy_mod._record_proxy_denial(
            host="example.invalid",
            port=443,
            resolved_ip=None,
            would_deny="host_not_in_allowlist",
        )

    warnings = [
        r for r in caplog.records
        if r.levelname == "WARNING"
        and "_record_proxy_denial" in r.getMessage()
    ]
    assert warnings, (
        "expected WARNING log when record_denial raises; got "
        f"{[(r.levelname, r.getMessage()) for r in caplog.records]}"
    )
