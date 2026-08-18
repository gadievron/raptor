"""CLI entry point for ``raptor-sandbox-observe``.

Wraps ``sandbox(observe=True)`` so an operator can quickly answer
"what does this binary touch?" without writing Python:

  raptor-sandbox-observe -- /usr/bin/true
  raptor-sandbox-observe --json -- claude --version
  raptor-sandbox-observe --out /tmp/probe -- ./scan-target

The shim spawns the command in observe mode against a fresh
audit-run-dir (own tmpdir by default; explicit ``--out`` lets the
operator keep the JSONL for later inspection), parses the resulting
``.sandbox-observe.jsonl`` into an ``ObserveProfile``, and renders
either a human-readable summary or the full profile as JSON.

This is the user-facing companion to the programmatic API:

  from core.sandbox import sandbox, parse_observe_log, ObserveProfile
  ...

Two modes:
  * default — pretty summary on stdout, exit 0 on success.
  * ``--json`` — the ObserveProfile serialised as JSON for piping
    into jq / other tooling. The exit code still reflects the
    spawned command's exit (forwarded through).

Exit codes:
  - the spawned command's exit code on success
  - 2 for arg-parse failures (argparse's parser.error default)
  - 64 (EX_USAGE) when the command to spawn cannot be found
  - 70 (EX_SOFTWARE) when observe-mode fails to engage (e.g. ptrace
    blocked) — operator can re-run on a host where it works.
  - 124 when the command exceeded ``--timeout`` and was killed
    (same convention as timeout(1)); any observe records captured
    before the kill are still rendered.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

_USAGE_EX = 64       # EX_USAGE — bad argv
_SOFTWARE_EX = 70    # EX_SOFTWARE — observe didn't engage
_TIMEOUT_EX = 124    # command exceeded --timeout (timeout(1) convention)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-sandbox-observe",
        description=(
            "Run a command under sandbox(observe=True) and print the "
            "set of paths read / written / stat'd and connect targets "
            "the binary touched."
        ),
    )
    p.add_argument(
        "--out", metavar="DIR",
        help=(
            "Directory to use as the sandbox audit-run-dir (also where "
            ".sandbox-observe.jsonl lands). Default: a fresh tmpdir "
            "that is removed after parsing the log unless --keep is set."
        ),
    )
    p.add_argument(
        "--target", metavar="DIR",
        help=(
            "Bind-mount this directory at /target inside the sandbox. "
            "Useful when the probe binary needs read access to a project "
            "tree. Default: same as --out."
        ),
    )
    p.add_argument(
        "--keep", action="store_true",
        help=(
            "Keep the audit-run-dir after parsing (for re-inspection). "
            "Implied when --out is given."
        ),
    )
    p.add_argument(
        "--json", action="store_true", dest="json_output",
        help=(
            "Emit the full ObserveProfile as JSON on stdout instead of "
            "the human-readable summary."
        ),
    )
    p.add_argument(
        "--timeout", type=float, default=30.0, metavar="SECONDS",
        help=(
            "Wall-clock timeout for the spawned command. Default: 30s."
        ),
    )
    p.add_argument(
        "--audit-budget", type=int, default=None, metavar="N",
        dest="audit_budget",
        help=(
            "Override the global audit-record cap (default 10000) for "
            "this run. Per-category and per-PID sub-caps scale "
            "proportionally. Raise it when the budget-truncation "
            "warning fires and the profile must capture every event."
        ),
    )
    p.add_argument(
        "cmd", nargs=argparse.REMAINDER,
        help="Command to run under observe-mode (use ``--`` to separate).",
    )
    return p


def _resolve_run_dir(args: argparse.Namespace,
                     stack) -> tuple[Path, bool]:
    """Pick the run dir based on args, registering cleanup on `stack`.

    Returns (path, keep) where keep tells the caller whether to leave
    the directory in place after parsing. Always honours --keep / --out;
    a default tmpdir is removed unless either was specified.
    """
    if args.out:
        path = Path(args.out).resolve()
        path.mkdir(parents=True, exist_ok=True)
        return path, True
    # Anonymous tmpdir — auto-clean unless --keep set.
    tmp = tempfile.mkdtemp(prefix="raptor-observe-")
    if not args.keep:
        # Lazy import so the help/parse path doesn't need shutil.
        import shutil

        def _cleanup():
            shutil.rmtree(tmp, ignore_errors=True)

        stack.callback(_cleanup)
    return Path(tmp), bool(args.keep)


def _format_summary(profile, *, run_dir: Path, kept: bool,
                    return_code: int | None) -> str:
    """Pretty multi-line summary for the default (non-JSON) mode.

    Counts + first-N path samples per category. Avoids dumping every
    single path because real probes can produce hundreds (claude
    enumerates many candidate config locations) and the tail is rarely
    useful at a glance.
    """
    SAMPLE = 10
    parts = []
    parts.append(f"command exit code: {return_code}")
    if kept:
        parts.append(f"audit-run-dir kept at: {run_dir}")

    # Surface budget truncation FIRST — if the probe hit any cap,
    # the rest of the summary is incomplete and operators need to
    # know before they reason about counts. The drops-by-category
    # detail tells them which cap to raise.
    if profile.budget_truncated:
        parts.append(
            "\n⚠️  budget truncated — AuditBudget caps fired during "
            "this run; profile is INCOMPLETE."
        )
        for cat, n in sorted(profile.dropped_by_category.items()):
            if n > 0:
                parts.append(f"   dropped {n} record(s) of category {cat!r}")
        parts.append(
            "   re-run with --audit-budget=<larger N> to capture "
            "every event."
        )

    def _section(label: str, items: list, total_label: str):
        parts.append(f"\n{label} ({len(items)}):")
        if not items:
            parts.append(f"  (none — binary did no {total_label})")
            return
        for p in items[:SAMPLE]:
            parts.append(f"  {p}")
        if len(items) > SAMPLE:
            parts.append(
                f"  ... (+{len(items) - SAMPLE} more; "
                f"--json for the complete list)"
            )

    _section("paths read", profile.paths_read, "reads")
    _section("paths written", profile.paths_written, "writes")
    _section("paths stat'd (probed but not opened)",
             profile.paths_stat, "stats")

    parts.append(f"\nconnect targets ({len(profile.connect_targets)}):")
    if not profile.connect_targets:
        parts.append("  (none — binary made no connect() calls)")
    else:
        for t in profile.connect_targets:
            parts.append(f"  {t.ip}:{t.port} ({t.family})")
    return "\n".join(parts)


def _connect_target_to_dict(target) -> dict:
    """Serialise a ConnectTarget for the ``--json`` output mode."""
    return {"ip": target.ip, "port": target.port, "family": target.family}


def _profile_to_json(profile, *, run_dir: Path, kept: bool,
                     return_code: int | None) -> str:
    """JSON output mode — full profile + meta. Stable schema for tooling."""
    payload = {
        "return_code": return_code,
        "run_dir": str(run_dir) if kept else None,
        "paths_read": list(profile.paths_read),
        "paths_written": list(profile.paths_written),
        "paths_stat": list(profile.paths_stat),
        "connect_targets": [
            _connect_target_to_dict(t) for t in profile.connect_targets
        ],
        "budget_truncated": bool(profile.budget_truncated),
        "dropped_by_category": dict(profile.dropped_by_category),
    }
    return json.dumps(payload, indent=2)


def _cli_main(argv: Sequence[str] | None = None) -> int:
    """Argparse → spawn → parse → render. Lives in this module so the
    libexec shim is a thin trust-marker + sys.exit wrapper.

    Imports `core.sandbox` at function scope so that `--help` does
    not pay the sandbox import cost (libseccomp probe, ctypes loads).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    cmd = list(args.cmd or [])
    # argparse.REMAINDER captures the leading "--" too; strip it so the
    # spawned subprocess gets just the command + its args.
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        parser.error("no command supplied — use ``-- <cmd> [args...]``")
        return _USAGE_EX  # parser.error exits, but for clarity

    # Same bounds the main sandbox CLI applies (core/sandbox/cli.py).
    # No "--audit-budget requires --audit" check here — observe mode
    # forces audit mode, so the precondition holds by construction.
    if args.audit_budget is not None:
        if args.audit_budget <= 0:
            parser.error(
                f"--audit-budget must be a positive integer; got "
                f"{args.audit_budget!r}"
            )
        _AUDIT_BUDGET_MAX = 10_000_000
        if args.audit_budget > _AUDIT_BUDGET_MAX:
            parser.error(
                f"--audit-budget={args.audit_budget} exceeds the upper "
                f"clamp ({_AUDIT_BUDGET_MAX}). At ~200 bytes per record "
                f"that's ~2GB of JSONL — almost certainly a typo."
            )

    # Lazy-import the sandbox layer — argparse setup + --help should
    # not require libseccomp / ctypes probing.
    import contextlib

    from core.sandbox import (
        parse_observe_log,
    )
    from core.sandbox import (
        run as sandbox_run,
    )

    if args.audit_budget is not None:
        # Same propagation path the main CLI's apply_cli_args uses:
        # the tracer builds its AuditBudget from this state slot.
        from core.sandbox import state as _sbx_state
        _sbx_state._cli_sandbox_audit_budget = int(args.audit_budget)

    with contextlib.ExitStack() as stack:
        run_dir, kept = _resolve_run_dir(args, stack)
        target_dir = Path(args.target).resolve() if args.target else run_dir

        # Capture the probed binary's stdout/stderr in --json mode
        # so they don't interleave with the JSON we write at the end
        # (operator-facing tooling pipes our stdout into jq / Python
        # and a stray byte from the probe corrupts the parse). In
        # human-readable mode let the binary's output pass through —
        # operators reading the summary like seeing what the probe
        # actually produced.
        timed_out = False
        # Pre-bind: the TimeoutExpired path continues with no completed
        # process, and the nonce-trust check reads getattr(result, ...).
        result = None
        return_code: int | None = None
        try:
            result = sandbox_run(
                cmd,
                target=str(target_dir),
                output=str(run_dir),
                observe=True,
                capture_output=bool(args.json_output),
                text=False,
                timeout=args.timeout,
            )
            return_code = result.returncode
        except FileNotFoundError as exc:
            sys.stderr.write(f"raptor-sandbox-observe: {exc}\n")
            return _USAGE_EX
        except subprocess.TimeoutExpired:
            # A first-class CLI flag must produce a diagnostic, not a
            # Python traceback. Render whatever observe records landed
            # before the kill — a partial profile is still useful.
            timed_out = True
            sys.stderr.write(
                f"raptor-sandbox-observe: command did not finish "
                f"within --timeout {args.timeout}s and was killed; "
                f"rendering observe records captured before the "
                f"kill.\n"
            )

        # When the operator did not pass --out / --keep AND no observe
        # records landed, surface a clear error rather than silently
        # printing an empty profile. Most likely cause: ptrace blocked
        # (Yama scope 3, container cap-drop) so audit-mode degraded.
        from .evidence import resolve_read_path as _resolve_evidence_path
        observe_log = _resolve_evidence_path(
            run_dir, ".sandbox-observe.jsonl",
        )
        if not observe_log.exists():
            if timed_out:
                # The kill explains the missing log — don't pile the
                # (misleading) degraded-audit diagnostic on top.
                return _TIMEOUT_EX
            sys.stderr.write(
                "raptor-sandbox-observe: observe log not produced — "
                "audit-mode likely degraded silently. Check that "
                "libseccomp is installed and ptrace is permitted on "
                "this host (Yama scope 0 or 1; not running with "
                "--cap-drop=SYS_PTRACE).\n"
            )
            return _SOFTWARE_EX

        # Spoof-resistant parse: pin records to the per-run nonce when
        # the sandbox stamped one, and hand over sandbox_info so the
        # parser can refuse nonce trust on runs where the nonce was
        # not delivered through a protected channel.
        _sbx_info = getattr(result, "sandbox_info", None) or {}
        profile = parse_observe_log(
            run_dir,
            expected_nonce=_sbx_info.get("observe_nonce"),
            sandbox_info=_sbx_info,
        )

        if args.json_output:
            sys.stdout.write(_profile_to_json(
                profile, run_dir=run_dir, kept=kept,
                return_code=return_code,
            ) + "\n")
        else:
            sys.stdout.write(_format_summary(
                profile, run_dir=run_dir, kept=kept,
                return_code=return_code,
            ) + "\n")

        if timed_out:
            return _TIMEOUT_EX
        # Forward the spawned command's exit code as our own — caller
        # composes naturally with shell pipelines that check $?.
        return return_code


if __name__ == "__main__":
    raise SystemExit(_cli_main())
