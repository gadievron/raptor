"""Per-run sandbox denial summary.

Aggregates sandbox enforcement events (network blocked, write blocked, syscall
killed) across all sandbox calls in a run, producing a structured
``sandbox-summary.json`` with suggested-fix hints. Useful regardless of profile
— even on ``--sandbox full``, operators benefit from a clean post-run report
of what their workflow tried that the sandbox blocked, instead of grepping
log lines.

Design:
- ``set_active_run_dir(path)`` is called by ``core/run/metadata.py:start_run``
  and cleared at run end.
- ``record_denial(...)`` is called by ``core/sandbox/observe.py:_check_blocked``
  for each detected denial. Appends one JSONL line to
  ``<run_dir>/.sandbox-denials.jsonl``.
- ``summarize_and_write(run_dir)`` is called by ``core/run/metadata.py``
  ``complete_run`` / ``fail_run`` / ``cancel_run``. Reads the JSONL, writes
  ``sandbox-summary.json``, removes the intermediate JSONL.

JSONL append is atomic on POSIX up to PIPE_BUF (~4KB) so concurrent writers
within the same run (multi-threaded callers) don't corrupt each other. Each
record is well under PIPE_BUF in practice — `cmd_display` is bounded by
``_CMD_DISPLAY_MAX_ARGS`` (3 args) and escape_nonprintable'd before reaching
us. Pathologically long cmd args could exceed PIPE_BUF; defer that defense
until it surfaces.

Concurrency assumption: the design assumes a single-process, single-active-run
model. Concurrent threads within a process can record_denial safely (POSIX
append atomicity). The cross-thread case where one thread is mid-write while
another thread calls summarize_and_write (which unlinks the JSONL after
aggregating) is a real but academic race — A's write lands in an orphaned
inode and is silently lost. If a future caller actually needs concurrent
finalize, add a per-run lock around record_denial / summarize_and_write.

Multiprocessing caveat: ``_active_run_dir`` is a module global, so child
processes spawned via ``multiprocessing.Pool`` (or fork+exec from Python)
inherit ``None`` (or whatever the parent had at fork time, depending on
the start method). Children's ``record_denial`` calls would no-op unless
the child explicitly re-establishes active-run state. Today's RAPTOR
parallelism uses ThreadPoolExecutor (same process, shared state) so this
isn't a current gap; future authors reaching for ``multiprocessing.Pool``
should call ``set_active_run_dir(run_dir)`` in the worker initializer.

Opt-out: there's no env var or flag to disable the summary. If a caller
genuinely doesn't want it (CI noise, perf-sensitive batch), call
``set_active_run_dir(None)`` after start_run. Per the project's "avoid
RAPTOR_* env var proliferation" feedback, opt-out via env var is not
provided.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from core.security.redaction import redact_secrets

logger = logging.getLogger(__name__)

# Module-level active-run state. Set by start_run, cleared at run end.
# Reads happen unlocked (Python attribute access is atomic — readers see
# either the old or new pointer, never a torn read). Writes are serialised
# via _lock so concurrent set/clear can't interleave (matters for
# tests that exercise the lifecycle from multiple threads).
_active_run_dir: Optional[Path] = None
_lock = threading.Lock()

DENIALS_FILE = ".sandbox-denials.jsonl"
SUMMARY_FILE = "sandbox-summary.json"
AUDIT_DEGRADED_FILE = "sandbox-audit-degraded.json"

# Per-run cap on recorded denials. A malicious target that triggers
# thousands of network attempts (or any chatty workflow) would otherwise
# accumulate unbounded GB-scale JSONL. After the cap, further denials
# are silently dropped with a one-time log warning. The cap reset
# happens in set_active_run_dir so each run starts fresh.
MAX_DENIALS_PER_RUN = 10000

# Per-record cmd_display truncation. cmd args are bounded by
# _CMD_DISPLAY_MAX_ARGS=3 at construction, but pathological single-arg
# values (very long paths) could push a record past PIPE_BUF (~4KB)
# and break POSIX append atomicity. 2KB cap leaves room for the rest of
# the JSON envelope.
MAX_CMD_LEN = 2048

_denial_count: int = 0  # reset by set_active_run_dir per run


def set_active_run_dir(run_dir: Optional[Path]) -> None:
    """Mark a run as active (or clear it). Subsequent record_denial() calls
    write to ``<run_dir>/.sandbox-denials.jsonl`` until cleared.

    Resets the per-run denial counter so each run starts with a fresh
    cap (see MAX_DENIALS_PER_RUN).
    """
    global _active_run_dir, _denial_count
    with _lock:
        _active_run_dir = Path(run_dir) if run_dir is not None else None
        _denial_count = 0


def get_active_run_dir() -> Optional[Path]:
    """Return current active run dir, or None if no run is being recorded."""
    return _active_run_dir


def record_denial(cmd_display: str, returncode: int,
                  denial_type: str, **details: Any) -> None:
    """Append a denial record to the active run's JSONL file.

    No-op if no active run is set (sandbox call from outside any tracked
    run, e.g., probes during test setup or sandbox CLI invocations).

    denial_type is one of: ``network``, ``write``, ``seccomp``.
    details vary by type — `path` for write, `profile` for seccomp, etc.
    """
    global _denial_count
    run_dir = _active_run_dir
    if run_dir is None:
        return
    # Per-run cap: silently drop denials past MAX_DENIALS_PER_RUN. Logs
    # once at the boundary so a developer can find it. Lock-free
    # increment is fine under CPython GIL (slight overcount past cap is
    # acceptable for a DoS defense).
    _denial_count += 1
    if _denial_count > MAX_DENIALS_PER_RUN:
        if _denial_count == MAX_DENIALS_PER_RUN + 1:
            logger.warning(
                "sandbox summary cap reached (%d denials this run); "
                "dropping further denials. Adversarial target or runaway "
                "workflow?", MAX_DENIALS_PER_RUN,
            )
        return
    # Truncate cmd_display before persisting — defends the POSIX append
    # atomicity (lines must stay under PIPE_BUF, ~4KB) and bounds JSONL
    # line size in adversarial cases. _CMD_DISPLAY_MAX_ARGS=3 already
    # bounds args at the construction site, but pathological single-arg
    # values (very long paths, env-string args) could still blow up.
    if len(cmd_display) > MAX_CMD_LEN:
        cmd_display = cmd_display[:MAX_CMD_LEN - 1] + "…"
    # Redact secrets in cmd_display before persisting. The string is already
    # escape_nonprintable'd by context.py at construction, but redact_secrets
    # is what catches user:pass@host URLs, Bearer/Basic headers, and similar
    # credential shapes that escape doesn't touch. Logs are typically rotated
    # frequently (hourly) by syslog/journald; summaries live in the run dir
    # until the operator runs `/project clean` (days-to-weeks), and operators
    # paste run-dir contents into bug reports without thinking. The longer
    # window + the "share without thinking" pattern justify the extra defense.
    # Spread `details` FIRST so the explicit reserved fields below override
    # — without this, a caller passing details={"type": "evil", "cmd": ...}
    # could mask the real denial values.
    record = {
        **details,
        "ts": datetime.now(timezone.utc).isoformat(),
        "cmd": redact_secrets(cmd_display),
        "returncode": returncode,
        "type": denial_type,
        "suggested_fix": _suggested_fix(denial_type, **details),
    }
    # JSONL append: open-write-close per line so each record is atomic.
    # POSIX guarantees writes < PIPE_BUF (~4KB) are atomic when the file
    # is opened O_APPEND. Each line is well under that threshold.
    #
    # `default=str` defends against future callers passing non-serializable
    # detail values (Path, datetime, etc.) — without it, json.dumps would
    # raise TypeError before any I/O, breaking the "sandbox calls must
    # succeed regardless of summary I/O" promise. We also wrap the whole
    # block in a broad except to honour that promise even if a future
    # change introduces a different exception path.
    try:
        line = json.dumps(record, ensure_ascii=True, default=str) + "\n"
        path = run_dir / DENIALS_FILE
        path.parent.mkdir(parents=True, exist_ok=True)
        # O_NOFOLLOW refuses if path is a symlink — defends against
        # symlink planted by an attacker who got write access to the
        # run dir (rare but possible on shared filesystems). Plain
        # open(path, "a") would have followed and written to the
        # symlink target. Mode 0o600 keeps the JSONL operator-only.
        fd = os.open(
            str(path),
            os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:  # noqa: BLE001 — best-effort; never fail the sandbox call
        # Debug-only log so a developer chasing "why is my summary empty?"
        # can find it via RAPTOR_DEBUG / per-module level adjustment.
        # INFO would be too noisy if the failure is recurrent (e.g., disk
        # full); DEBUG keeps it findable without flooding normal output.
        logger.debug("record_denial: failed to append JSONL", exc_info=True)


def _suggested_fix(denial_type: str, **details: Any) -> str:
    """Generate a one-line fix hint mapping denial → operator action.

    Suggestions reference only the actual operator-facing CLI flags
    exposed by ``core/sandbox/cli.py:add_cli_args`` —
    ``--sandbox {full,debug,network-only,none}`` and ``--no-sandbox``.
    Per-host / per-path overrides exist in the sandbox API as kwargs
    (``proxy_hosts``, ``writable_paths``, ``readable_paths``) but are
    NOT exposed as CLI flags, so suggesting them would mislead the
    operator into looking for non-existent flags. The detail value
    (host, path) appears in the message for context only.
    """
    if denial_type == "network":
        host = details.get("host")
        ctx = f" to `{host}`" if host else ""
        if details.get("audit"):
            # Audit-mode would-deny: informational only. The proxy_hosts
            # allowlist is a sandbox API kwarg, not a CLI flag — per the
            # round-2 PR #251 rule, suggestions must reference only
            # operator-facing CLI flags, so we don't suggest "add this
            # host to proxy_hosts". Operators wanting to keep the host
            # allowed under full enforcement need to modify the calling
            # code, which isn't a CLI affordance.
            return (f"audit: outbound network{ctx} would be blocked under "
                    f"`--sandbox full`")
        return (f"outbound network blocked{ctx}; use `--sandbox none` "
                f"to allow network (or accept the block)")
    if denial_type == "write":
        path = details.get("path")
        ctx = f" to `{path}`" if path else ""
        return (f"write outside allowed paths blocked{ctx}; use "
                f"`--sandbox network-only` or `--sandbox none` to drop "
                f"Landlock (or move write into target dir)")
    if denial_type == "seccomp":
        profile = details.get("profile")
        if profile == "full":
            return ("syscall blocked by seccomp; use `--sandbox debug` "
                    "(allows ptrace) or `--sandbox network-only`/`--sandbox none` "
                    "(drops seccomp)")
        return ("syscall blocked by seccomp; use `--sandbox network-only` or "
                "`--sandbox none` to drop seccomp")
    return "review denial; no specific suggestion available"


def record_audit_degraded(run_dir: Path, *, reason: str,
                          instructions: str = "") -> None:
    """Write a marker file when --audit was requested but couldn't run.

    Operators inspecting an output dir need to distinguish three states:
      (1) audit ran, recorded events  → sandbox-summary.json present
      (2) audit ran, no events        → no files (current convention)
      (3) audit was requested but did NOT run on this host → THIS file

    Without (3), an operator who runs `--audit` on Ubuntu 24.04 default
    (apparmor sysctl=1) sees no summary and may interpret it as "audit
    found nothing" rather than "audit didn't actually happen".

    Idempotent across multiple sandbox calls in one run: writes once,
    skips on subsequent calls. Safe to invoke from each per-call site
    that detected degradation.
    """
    run_dir = Path(run_dir)
    out = run_dir / AUDIT_DEGRADED_FILE
    if out.exists():
        return
    payload = {
        "audit_requested": True,
        "audit_engaged": False,
        "degraded": True,
        "reason": reason,
        "instructions": instructions,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    tmp = out.with_name(f".~{out.name}.tmp")
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(
            json.dumps(payload, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
        os.replace(tmp, out)
    except (OSError, ValueError, TypeError):
        # Marker is best-effort. The log warning is the primary signal.
        # Catch programming-error-shaped failures too (a future payload
        # change with non-serialisable types would otherwise propagate
        # and abort the caller's cleanup path while still leaking the
        # `.~sandbox-audit-degraded.json.tmp` file).
        pass
    finally:
        # Ensure the tmp file doesn't leak when write_text succeeded but
        # os.replace failed (e.g. EBUSY, EXDEV, target dir vanished).
        # Unlink missing_ok handles both "tmp never existed" and "replace
        # already moved it" cases as no-ops.
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass


def summarize_and_write(run_dir: Path) -> Optional[Dict[str, Any]]:
    """Read ``<run_dir>/.sandbox-denials.jsonl`` and write
    ``<run_dir>/sandbox-summary.json`` aggregating all denials.

    Returns the summary dict (also written to disk), or None if no denials
    were recorded for this run. The intermediate JSONL is removed after
    successful summary write — operators read the summary, not the JSONL.

    Idempotent: if called again with the same run_dir and no JSONL is
    present, returns None without writing.
    """
    run_dir = Path(run_dir)
    jsonl = run_dir / DENIALS_FILE
    if not jsonl.exists():
        return None

    denials = []
    try:
        with open(jsonl, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    denials.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # skip malformed lines, keep going
    except OSError:
        return None

    if not denials:
        try:
            jsonl.unlink()
        except OSError:
            pass
        return None

    # Enrich tracer-emitted records with `suggested_fix` if they lack it
    # (the tracer subprocess doesn't have the suggestion logic;
    # _suggested_fix lives here in summary). Records from
    # record_denial already include the field. After this loop,
    # every record in `denials` has a uniform `suggested_fix` field —
    # operators parsing sandbox-summary.json don't need defensive
    # `.get()` for cross-source consistency.
    for d in denials:
        if "suggested_fix" not in d:
            # Build details from the record's keys (type-specific
            # ones like host/path/profile/audit/etc.). _suggested_fix
            # accepts arbitrary kwargs and uses .get() internally.
            details = {k: v for k, v in d.items()
                       if k not in ("ts", "cmd", "returncode", "type",
                                    "suggested_fix")}
            d["suggested_fix"] = _suggested_fix(
                d.get("type", "unknown"), **details,
            )

    by_type: Dict[str, int] = {}
    for d in denials:
        t = d.get("type", "unknown")
        by_type[t] = by_type.get(t, 0) + 1

    summary = {
        "run_dir": str(run_dir),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_denials": len(denials),
        "by_type": by_type,
        "denials": denials,
    }

    summary_path = run_dir / SUMMARY_FILE
    tmp = summary_path.with_name(f".~{summary_path.name}.tmp")
    try:
        tmp.write_text(json.dumps(summary, indent=2, ensure_ascii=True) + "\n",
                       encoding="utf-8")
        os.replace(tmp, summary_path)
    except OSError:
        try:
            tmp.unlink()
        except OSError:
            pass
        return None

    # Remove the intermediate JSONL — summary supersedes it.
    try:
        jsonl.unlink()
    except OSError:
        pass

    return summary


def _cli_main(argv: Optional[list] = None) -> int:
    """Retroactive summarize CLI.

    Rarely needed in normal operation: ``core.run.metadata._cleanup_abandoned``
    already finalizes the summary for the common Esc-then-retry case (same
    Claude Code session, same command type) by promoting the prior run from
    ``status=running`` to ``failed`` — which routes through ``fail_run`` and
    therefore through the standard ``_finalize_sandbox_summary`` path.

    This CLI is the explicit fallback for cases the auto-recovery doesn't
    cover: a hard kill, a different session, a different command type, or
    operator-driven cleanup of a project dir with several stranded runs.

    Two modes:

        # Single-run mode — finalize one specific run dir.
        libexec/raptor-sandbox-summary <run_dir>

        # Sweep mode — finalize ALL stranded runs under a project dir.
        # Iterates direct subdirectories, finalizes any with a leftover
        # .sandbox-denials.jsonl, skips the rest. Useful for one-off
        # cleanup of a project that accumulated abandoned runs across
        # past sessions.
        libexec/raptor-sandbox-summary --sweep <project_dir>

    The ``python -m core.sandbox.summary`` form also works but emits a
    runpy double-import warning (``core.sandbox.__init__`` imports
    ``observe``, which imports this module before runpy executes it as
    ``__main__``). Prefer the libexec shim, which sidesteps runpy.
    """
    import argparse
    import sys  # local — keeps module import light for non-CLI consumers

    # No explicit prog= — argparse uses sys.argv[0]'s basename, so the
    # help text reflects whichever entry point invoked us
    # (libexec/raptor-sandbox-summary, or `python -m core.sandbox.summary`).
    parser = argparse.ArgumentParser(
        description="Retroactively finalize sandbox-summary.json for runs "
                    "whose lifecycle didn't complete.",
    )
    parser.add_argument(
        "path",
        help="run directory (single-run mode) or project directory (--sweep mode)",
    )
    parser.add_argument(
        "--sweep",
        action="store_true",
        help="finalize every stranded run under PATH (treats PATH as a "
             "project dir containing run subdirectories)",
    )
    try:
        args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    except SystemExit as e:
        # argparse exits 2 on bad args; preserve that contract
        return e.code if isinstance(e.code, int) else 2

    target = Path(args.path)
    if not target.is_dir():
        print(f"error: {target} is not a directory", file=sys.stderr)
        return 1

    if not args.sweep:
        # Single-run mode (original behaviour)
        result = summarize_and_write(target)
        if result is None:
            print(f"(no denials recorded for {target})")
            return 0
        print(f"Wrote {target / SUMMARY_FILE} ({result['total_denials']} denials, "
              f"by_type={result['by_type']})")
        return 0

    # Sweep mode — iterate children, finalize anything with a stranded JSONL.
    swept = 0
    written = 0
    total_denials = 0
    try:
        children = sorted(target.iterdir())
    except OSError as e:
        print(f"error: cannot list {target}: {e}", file=sys.stderr)
        return 1
    for child in children:
        try:
            if not child.is_dir() or child.name.startswith((".", "_")):
                continue
            if not (child / DENIALS_FILE).exists():
                continue
        except OSError:
            continue
        swept += 1
        result = summarize_and_write(child)
        if result is not None:
            written += 1
            total_denials += result.get("total_denials", 0)
            print(f"  {child.name}: {result['total_denials']} denials → "
                  f"{SUMMARY_FILE}")
        else:
            # JSONL was present but summarize_and_write returned None
            # (empty file or write failure); summarize_and_write already
            # cleaned the empty JSONL. No per-dir line — keeps output tight.
            pass
    print(f"Swept {swept} stranded run(s) under {target}: "
          f"{written} summary file(s) written, {total_denials} total denials.")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli_main())
