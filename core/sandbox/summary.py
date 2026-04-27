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

    Use case: a process crashed mid-run, leaving .sandbox-denials.jsonl
    on disk but no sandbox-summary.json (lifecycle complete/fail/cancel
    never ran). An operator (or a recovery script) can finalize the
    summary after the fact:

        python -m core.sandbox.summary <run_dir>
    """
    import sys  # local — keeps module import light for non-CLI consumers
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print("Usage: python -m core.sandbox.summary <run_dir>", file=sys.stderr)
        return 2
    run_dir = Path(args[0])
    if not run_dir.is_dir():
        print(f"error: {run_dir} is not a directory", file=sys.stderr)
        return 1
    result = summarize_and_write(run_dir)
    if result is None:
        print(f"(no denials recorded for {run_dir})")
        return 0
    print(f"Wrote {run_dir / SUMMARY_FILE} ({result['total_denials']} denials, "
          f"by_type={result['by_type']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(_cli_main())
