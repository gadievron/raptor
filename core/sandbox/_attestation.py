"""Pid-namespace quiescence attestation (out-of-band result fact).

Opt-in (``run_sandboxed(..., pidns_attest=True)``): the RAPTOR-owned
pid-ns init (``_pid1_split_for_waiter``) reports, over a private pipe,
whether any process beyond the directly-supervised target ever existed
in the namespace.  Consumers that derive trust from files the target
could have written (e.g. the seccomp filter-listing probe) use the
verdict to refuse evidence that a tracing-escape survivor — a
``clone(CLONE_UNTRACED)`` child is invisible to a follow-fork tracer's
kill sweep — could have tampered with after the tool wrote it.

The channel is fail-closed by construction: only the exact single byte
``b"A"`` decodes to the clean verdict.  A same-uid target can reopen
the init's pipe fds via ``/proc/1/fd/N`` and inject bytes, but any
injection makes the stream longer than one byte (the init always
appends its own verdict after the namespace is provably empty, so
nothing can drain it first) — forgery can only cause refusals, never
trust.
"""

from __future__ import annotations

import subprocess

#: No process beyond the directly-supervised target tree ever existed.
PIDNS_ATTEST_CLEAN = "clean"
#: At least one additional process existed (orphan reaped, or the
#: post-exit sweep found live pids) — target-writable artifacts from
#: the run cannot be trusted.
PIDNS_ATTEST_FOREIGN = "foreign"
#: No verdict byte arrived (attestation not requested, init died early,
#: channel garbled/injected, or a non-pid-ns lane served the run).
PIDNS_ATTEST_UNATTESTED = "unattested"

_ATTR = "_pidns_attestation"


def decode_attestation_bytes(data: bytes) -> str:
    """Map the drained channel bytes to a verdict, fail-closed.

    Exactly ``b"A"`` is clean and exactly ``b"F"`` is foreign; anything
    else (empty, extra bytes, garbage) is unattested — an injected or
    garbled stream must never upgrade trust.
    """
    if data == b"A":
        return PIDNS_ATTEST_CLEAN
    if data == b"F":
        return PIDNS_ATTEST_FOREIGN
    return PIDNS_ATTEST_UNATTESTED


def record_pidns_attestation(
    result: subprocess.CompletedProcess, verdict: str
) -> None:
    """Attach the attestation verdict out-of-band on the result object.

    An attribute (not stream content) so target bytes can never forge
    or shadow it — same transport doctrine as ``record_truncation``.
    """
    setattr(result, _ATTR, verdict)


def pidns_attestation(result: subprocess.CompletedProcess) -> str:
    """Read the attestation verdict; absent means unattested.

    Lanes that never plumb the channel (macOS, fallback, daemon, or a
    run without ``pidns_attest=True``) leave the attribute off, and
    consumers must treat that as not-attested rather than clean.
    """
    return getattr(result, _ATTR, PIDNS_ATTEST_UNATTESTED)
