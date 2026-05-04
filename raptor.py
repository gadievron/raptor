#!/usr/bin/env python3
"""
RAPTOR - Unified Security Testing Launcher

Single entry point for all RAPTOR capabilities:
- Static analysis (Semgrep + CodeQL)
- Binary fuzzing (AFL++)
- Web application scanning
- Autonomous LLM-powered analysis
- And more...

Usage:
    raptor.py <mode> [options]

Available Modes:
    scan        - Static code analysis with Semgrep
    sca         - Software Composition Analysis (deps + advisories + SBOM)
    binary      - Black-box binary investigation and evidence collection
    fuzz        - Binary fuzzing with AFL++
    web         - Web application security testing
    agentic     - Full autonomous workflow (Semgrep + CodeQL + LLM analysis; --no-codeql skips CodeQL)
    codeql      - CodeQL-only analysis
    analyze     - LLM-powered vulnerability analysis (requires SARIF input)
    describe    - Pre-flight inspection: target type, tool readiness, cost estimate
    doctor      - Status report for local setup (no claude needed)
    frida       - Dynamic instrumentation via Frida (alpha)
  openant     - OpenAnt AST+LLM source-code vulnerability scan

Examples:
    # Full autonomous workflow
    python3 raptor.py agentic --repo /path/to/code

    # Static analysis only
    python3 raptor.py scan --repo /path/to/code --policy-groups secrets,owasp

    # Binary fuzzing
    python3 raptor.py fuzz --binary /path/to/binary --duration 3600

    # Black-box binary investigation
    python3 raptor.py binary investigate /path/to/binary

    # Web scanning
    python3 raptor.py web --url https://example.com

    # CodeQL analysis
    python3 raptor.py codeql --repo /path/to/code --languages java
"""

import argparse
import contextlib
import logging
import os
import subprocess
import sys
from pathlib import Path

# raptor.py -> repo root.
# Belt + braces against subprocess invocation under a sandboxed env
# that strips PYTHONPATH; today's "script-dir on sys.path[0]" default
# happens to land on the repo root because we live here, but explicit
# is safer than implicit.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import core.startup.process_init  # noqa: F401

# Cache-name helper lives in core.archive (shared with
# packages/describe/cli.py — extracts opportunistically into
# the same cache so /describe + /scan don't re-extract the
# same archive). Re-exported here under the old private name
# for backward compatibility with anything in this module that
# still references _safe_cache_name.
from core.archive import safe_cache_name as _safe_cache_name
from core.run.metadata import complete_run, fail_run, start_run
from core.run.output import (
    TargetMismatchError,
    get_output_dir,
    resolve_default_target,
)
from core.run.safe_io import safe_run_mkdir


def _extract_target(args: list) -> str | None:
    """Extract the target path from command args (--repo, --binary, or --url).

    Accepts both `--flag value` and `--flag=value` forms. Pre-fix
    only the space-separated form was recognised — operators
    using the canonical `--repo=/path/to/repo` form (common in
    CI YAML / scripts) had `_extract_target` return None,
    breaking downstream lifecycle initialisation that relies on
    the target path for project resolution.
    """
    for flag in ("--repo", "--binary", "--url"):
        # `--flag value` form.
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                return args[idx + 1]
        # `--flag=value` form.
        prefix = f"{flag}="
        for arg in args:
            if arg.startswith(prefix):
                return arg[len(prefix):]
    return None



def _extract_and_strip_max_cost_usd(args: list) -> tuple[float | None, list]:
    """Extract ``--max-cost-usd <USD>`` (or ``--max-cost-usd=<USD>``)
    from ``args``. Returns ``(cap_usd, args_without_flag)``.

    Stripped so the dispatcher can use the value for the pre-flight
    gate, then re-injected into downstream args for runtime
    enforcement via ``LLMConfig.max_cost_per_scan``.
    """
    flag = "--max-cost-usd"
    prefix = f"{flag}="
    cap_str: str | None = None
    out: list = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == flag and i + 1 < len(args):
            cap_str = args[i + 1]
            i += 2
            continue
        if a.startswith(prefix):
            cap_str = a[len(prefix):]
            i += 1
            continue
        out.append(a)
        i += 1
    if cap_str is None:
        return (None, args)
    try:
        cap = float(cap_str)
    except ValueError:
        print(
            f"WARNING: --max-cost-usd value {cap_str!r} is not a number; "
            "ignoring cap for this run",
            file=sys.stderr,
        )
        return (None, out)
    if cap <= 0:
        print(
            f"WARNING: --max-cost-usd must be > 0 (got {cap}); "
            "ignoring cap for this run",
            file=sys.stderr,
        )
        return (None, out)
    return (cap, out)


def _extract_and_strip_out(args: list) -> tuple[str | None, list]:
    """Extract ``--out <dir>`` (or ``--out=<dir>``) from ``args``.

    Returns ``(out_dir, args_without_flag)``. The lifecycle adopts an
    operator-supplied ``--out`` as THE run directory (``explicit_out``
    is priority 1 in ``get_output_dir``) and re-injects the resolved
    path downstream, so the sentinel, the lifecycle records, and the
    child all name one directory. A dangling ``--out`` with no value is
    left in place for the child's argparse to reject, matching every
    other malformed-flag path.
    """
    flag = "--out"
    prefix = f"{flag}="
    out_str: str | None = None
    out: list = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == flag and i + 1 < len(args):
            out_str = args[i + 1]
            i += 2
            continue
        if a.startswith(prefix):
            out_str = a[len(prefix):]
            i += 1
            continue
        out.append(a)
        i += 1
    if out_str is None:
        return (None, args)
    return (out_str, out)


def _extract_and_strip_project(args: list) -> tuple[str | None, list]:
    """Extract ``--project <name>`` (or ``--project=<name>``) from
    ``args``.

    Returns ``(project, args_without_flag)``. The wrapper records the
    value as the process-scoped project override BEFORE the lifecycle
    resolves the output directory and pins the run, then re-injects
    the flag for children that parse it — the run dir placement, the
    pin in ``.raptor-run.json``, and the child's own override all name
    one project. ``-`` = explicitly projectless. A dangling
    ``--project`` with no value is left for the child's argparse.
    """
    flag = "--project"
    prefix = f"{flag}="
    value: str | None = None
    out: list = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == flag and i + 1 < len(args):
            value = args[i + 1]
            i += 2
            continue
        if a.startswith(prefix):
            value = a[len(prefix):]
            i += 1
            continue
        out.append(a)
        i += 1
    if value is None:
        return (None, args)
    return (value, out)


def _preflight_cost_gate(
    target: str | None,
    max_cost_usd: float,
    out_dir: Path,
    *,
    estimate_stream=None,
) -> bool:
    """Pre-flight cost gate: refuse to start when the scorecard-
    derived estimate exceeds the operator's declared budget.

    Uses ``typical_findings_count`` from the catalog + per-model
    cost data from the scorecard. Returns True if the gate fires
    (run should be aborted), False otherwise.

    When no scorecard data is available the gate does not fire —
    the runtime cap still enforces during execution.

    ``estimate_stream`` routes the informational estimate line
    (default stdout). libexec/raptor-run-lifecycle passes stderr so
    its stdout stays single-line ``OUTPUT_DIR=`` for parsers; the
    shared implementation keeps the two entry points from drifting.
    """
    try:
        from core.llm.model_data import PROVIDER_DEFAULT_MODELS
        from core.run.estimator import estimate_from_scorecard, format_estimate
        from core.run.target_types import load
    except ImportError:
        return False
    try:
        entry = load(Path(target)) if target else None
    except Exception:  # noqa: BLE001
        return False
    n_findings = entry.typical_findings_count if entry else 0
    if n_findings <= 0:
        return False
    model = PROVIDER_DEFAULT_MODELS.get("anthropic", "")
    est = estimate_from_scorecard(model, n_findings)
    if est is None:
        return False
    est_line = format_estimate(est)
    if est_line:
        print(est_line, file=estimate_stream or sys.stdout, flush=True)
    if est.cost_high > max_cost_usd:
        print(
            f"✗ Pre-flight cost gate: scorecard estimate "
            f"upper bound (${est.cost_high:.2f}) exceeds "
            f"--max-cost-usd cap (${max_cost_usd:.2f}). "
            f"Raise the cap or re-run without --max-cost-usd.",
            file=sys.stderr, flush=True,
        )
        # Best-effort status flip: fail_run raises FileNotFoundError
        # when .raptor-run.json doesn't exist yet and ValueError when
        # it is malformed on disk — neither should mask the gate
        # verdict. Anything else (e.g. a miswired call) propagates.
        with contextlib.suppress(OSError, ValueError):
            fail_run(out_dir, "pre-flight cost gate exceeded")
        return True
    return False


def _extract_agentic_log_level(args: list) -> str | None:
    """Return a valid agentic --log-level value without consuming argv.

    The child parser remains the source of truth for invalid values. This
    early extraction is only so parent lifecycle/dispatcher console logs obey
    the operator's requested verbosity before raptor_agentic.py starts.
    """
    from core.logging import CONSOLE_LOG_LEVELS

    for i, arg in enumerate(args):
        if arg == "--log-level" and i + 1 < len(args):
            candidate = args[i + 1].upper()
        elif arg.startswith("--log-level="):
            candidate = arg.split("=", 1)[1].upper()
        else:
            continue
        if candidate in CONSOLE_LOG_LEVELS:
            return candidate
        return None
    return None


def _rewrite_target_arg(args: list, old: str, new: str) -> list:
    """Return ``args`` with the --repo/--binary/--url value ``old`` replaced by
    ``new`` (both ``--flag value`` and ``--flag=value`` forms)."""
    flags = ("--repo", "--binary", "--url")
    out: list = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in flags and i + 1 < len(args) and args[i + 1] == old:
            out += [a, new]
            i += 2
            continue
        matched = next((f for f in flags if a == f"{f}={old}"), None)
        out.append(f"{matched}={new}" if matched else a)
        i += 1
    return out


def _unpack_archive_target(target: str, args: list, out_dir: Path):
    """Extract an archive ``target`` into a CONTENT-ADDRESSED shared cache and
    point the scan at it.

    The extraction lives at ``<out_dir.parent>/_sources/<archive_sha256>/`` —
    automatically project-scoped (``<project>/_sources/…`` in project mode,
    ``out/_sources/…`` otherwise) and deduped by content: one copy per distinct
    archive shared across every run in that scope, never a per-run copy. A
    second scan of the same archive is a cache hit (no re-extraction). The
    extracted source persists (findings stay navigable; downstream can read the
    flagged code); a ``<out_dir>/_source`` symlink makes each run navigable.

    Returns ``(new_args, target_identity)`` — args with the target rewritten to
    the cache dir and the manifest archive-identity block — or ``None`` if
    extraction failed (caller should fail the run rather than scan the archive).
    """
    import shutil
    import tempfile

    from core.archive import extract_to_dir
    from core.run.provenance import archive_snapshot

    snap = archive_snapshot(target)
    if snap is None:
        return None
    sha = snap["archive_sha256"]
    sources_root = out_dir.parent / "_sources"
    sources_root.mkdir(parents=True, exist_ok=True)
    # <name>-<sha> so the dir is self-describing ("what is this?") while the sha
    # keeps it unique/collision-free.
    cache_name = _safe_cache_name(snap["archive_name"], sha)
    canonical = sources_root / cache_name

    if canonical.exists():
        print(f"[*] Reusing extracted {snap['format']} archive (cache hit {sha[:12]})")
    else:
        # Extract to a unique temp sibling, then atomically promote to <sha>/.
        # Presence of <sha>/ therefore means a COMPLETE extraction, and a
        # concurrent run racing us just loses the os.replace harmlessly.
        # Hand-rolled (not scratch_dir, not reaper-listed): publish-by-
        # rename ownership under the run output's _sources cache, not
        # the system tmp — the tmp reaper only sweeps the system tmp
        # root, so a SIGKILL residue here is operator-visible in the
        # cache instead.
        tmp = Path(tempfile.mkdtemp(dir=sources_root, prefix=".extract-"))
        try:
            stats = extract_to_dir(target, tmp)
        except Exception as e:  # noqa: BLE001
            # Broad on purpose: extraction runs on attacker-controlled input,
            # so ANY failure (ArchiveError, an unforeseen OSError/ValueError, or
            # a MemoryError from an oversized archive) must fail the run
            # gracefully — never crash raptor with a traceback.
            shutil.rmtree(tmp, ignore_errors=True)
            print(f"✗ archive extraction failed for {target}: {e}", file=sys.stderr)
            return None
        try:
            os.replace(tmp, canonical)
        except OSError:
            shutil.rmtree(tmp, ignore_errors=True)  # lost the race; canonical is there
        print(f"[*] Unpacked {stats['format']} archive: {stats['files']} files (cache {sha[:12]})")

    # Acquisition stamp only — {source, archive_sha256, archive_name, format}.
    # The extracted tree's content-equivalence id is the coverage store's to
    # derive from the inventory, not a second source of truth recorded here.
    identity = {"source": "archive", **snap}

    # Local navigation aid: <out_dir>/_source -> the cached tree (relative).
    try:
        link = out_dir / "_source"
        if not link.exists():
            link.symlink_to(os.path.relpath(canonical, out_dir))
    except OSError:
        pass

    new_args = _rewrite_target_arg(args, target, str(canonical))
    return new_args, identity


# Which modes carry their target in --repo (and may therefore be
# back-filled from the active project / RAPTOR_CALLER_DIR default).
# fuzz and web children do NOT parse --repo as their target: fuzz
# needs --binary and web needs --url, and a project target (a source
# directory) is meaningless for both.
_REPO_TARGET_COMMANDS = frozenset({"scan", "agentic", "codeql"})
_REQUIRED_TARGET_FLAG = {"fuzz": "--binary", "web": "--url"}
# fuzz utility modes that legitimately run without --binary.
_FUZZ_STANDALONE_FLAGS = ("--export-seed-corpus", "--prepare-corpus")


def _resolve_target_for_command(command: str, args: list,
                                target: str | None):
    """Per-mode default-target handling for the lifecycle wrapper.

    Returns ``(target, args, error)``. ``error`` is a message the
    caller must print and fail on BEFORE creating a run directory —
    pre-fix a fuzz/web invocation without its required flag had a
    project target injected as ``--repo`` (which the child either
    doesn't define or misreads as the binary), and the child's
    argparse error then left a spurious failed run dir behind.
    """
    if target is not None:
        return target, args, None
    if command in _REPO_TARGET_COMMANDS:
        # CLAUDE.md DEFAULT TARGET DIRECTORY: (1) active project,
        # (2) RAPTOR_CALLER_DIR. Explicit --repo always wins (the
        # caller only reaches here when args carry no target).
        target = resolve_default_target()
        if target is not None:
            args = args + ["--repo", target]
        return target, args, None
    required = _REQUIRED_TARGET_FLAG.get(command)
    if required is None:
        return None, args, None
    if command == "fuzz" and any(
            a in _FUZZ_STANDALONE_FLAGS
            or a.startswith(tuple(f + "=" for f in _FUZZ_STANDALONE_FLAGS))
            for a in args):
        # --export-seed-corpus / --prepare-corpus run without a binary.
        return None, args, None
    return None, args, (
        f"{command}: missing required argument {required} "
        f"(e.g. python3 raptor.py {command} {required} <value>)"
    )


def _wants_help(args: list) -> bool:
    """True if args request argparse help (``--help`` / ``-h``).

    Single source of truth for the help short-circuits. A help request is
    not a run: it must never resolve a target, create/seal an output
    directory, print the OUTPUT_DIR sentinel or license/cost preamble, or
    start the LLM dispatcher.
    """
    return "--help" in args or "-h" in args


def _run_with_lifecycle(command: str, script_path: Path, args: list,
                        label: str) -> int:
    """Run a script with lifecycle start/complete/fail wrapping.

    Resolves the output directory via the run lifecycle, injects --out
    into the downstream script args, and marks the run complete or failed.
    """
    # Defense-in-depth behind main()'s per-mode help short-circuit: if any
    # caller reaches the lifecycle wrapper with --help/-h, skip the entire
    # lifecycle and delegate straight to _run_script (which has its own
    # --help guard for the dispatcher). The child's argparse prints help and
    # exits during parse_args, before its body runs — so no run directory,
    # sentinel, license/cost preamble, coverage, or complete_run.
    if _wants_help(args):
        return _run_script(script_path, args)

    target = _extract_target(args)

    # Operator-declared per-run budget cap (QoL #21). Stripped
    # from args before forwarding — propagated via env var so
    # downstream commands can pick it up for runtime enforcement.
    max_cost_usd, args = _extract_and_strip_max_cost_usd(args)

    # Operator-supplied --out is adopted by the lifecycle as the run
    # directory (explicit_out is priority 1 in get_output_dir and wins
    # over the active project, with a logged warning) and re-injected
    # resolved below. Pre-fix the wrapper ignored it: the child
    # honoured --out while the lifecycle created and sealed a second,
    # project-attached directory and printed a divergent OUTPUT_DIR
    # sentinel.
    explicit_out, args = _extract_and_strip_out(args)

    # Operator-supplied --project pins the run before the output dir
    # is resolved: get_output_dir routes placement through the process
    # override and start_run seals the pin argv-first. Revalidation is
    # a hard error (never a fallback) — surfaced below at start_run.
    project_arg, args = _extract_and_strip_project(args)
    if project_arg is not None:
        from core.run.pin import set_process_project
        set_process_project(project_arg)

    # Per-mode default-target handling: back-fill --repo for the modes
    # whose child parses it; fail fast (no run dir) when fuzz/web lack
    # their mode-specific required flag. See _resolve_target_for_command.
    target, args, target_error = _resolve_target_for_command(
        command, args, target,
    )
    if target_error:
        print(f"✗ {target_error}", file=sys.stderr)
        return 2

    try:
        out_dir = get_output_dir(command, explicit_out=explicit_out,
                                 target_path=target)
    except TargetMismatchError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1

    # Trust-boundary mkdir: refuses if the predictable run-dir name has been
    # pre-positioned as a symlink, owned by another user, or world-writable.
    # Subprocesses re-verify on their side (defence in depth) but the parent
    # is the first writer and has to gate too — start_run below would
    # otherwise create .raptor-run.json along an attacker symlink.
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    _dir_preexisted = out_dir.exists()
    safe_run_mkdir(out_dir)

    # Archive target: unpack into the content-addressed shared cache
    # (<out_dir.parent>/_sources/<sha>), scan the extracted tree, and record the
    # archive<->tree binding in the manifest. Deduped across runs; a re-scan of
    # the same archive is a cache hit.
    target_identity = None
    if target and Path(target).is_file():
        from core.archive import is_archive
        if is_archive(target):
            res = _unpack_archive_target(target, args, out_dir)
            if res is None:
                # Extraction failed (message printed); no run sealed
                # yet — remove the pre-created dir so nothing later
                # JIT-promotes a metadata-less orphan to a phantom run.
                if not _dir_preexisted:
                    _cleanup_refused_run_dir(out_dir)
                return 1
            args, target_identity = res
            # args now points at the extracted directory; update the local
            # target variable so downstream consumers (license detection,
            # format_start_line, _preflight_cost_gate) operate on the
            # extracted tree, not the archive file.
            target = _extract_target(args)

    # Run-start contention (managed project dirs only): another
    # session's live run refuses the start with the holder named. The
    # pre-created (still empty) run dir is removed so a refused start
    # leaves nothing behind.
    from core.project.oplock import OpLockContention
    from core.run.pin import ProjectArgvError
    try:
        start_run(out_dir, command, target=target,
                  target_identity=target_identity)
    except (OpLockContention, ProjectArgvError) as e:
        # Only remove what THIS invocation created: a refused start
        # against a pre-existing shared --out dir (the documented
        # /understand → /validate reuse) must not strip that dir's
        # legitimate _source symlink.
        if not _dir_preexisted:
            _cleanup_refused_run_dir(out_dir)
        print(f"✗ {e}", file=sys.stderr)
        return 1

    # Surface the target's license at lifecycle start, BEFORE any
    # tool actually runs — operators about to use CodeQL get the
    # license-terms warning in time to Ctrl-C, not after they've
    # incurred LLM cost / DB-build time. Strictly informational —
    # RAPTOR doesn't gate the run on the result (operator may have
    # a CodeQL commercial license, may be authorised on first-party
    # code without a LICENSE file, etc.). Terse operator-line only;
    # the HOW (source file, confidence, additional files) lives at
    # debug-log level via log_license_details.
    #
    # CodeQL-use detection: only fires the codeql-terms warning when
    # this run is ACTUALLY going to invoke CodeQL — the ``codeql``
    # mode itself, or scan/agentic with ``--codeql`` /
    # ``--codeql-only``. Plain /agentic (no --codeql) doesn't reach
    # CodeQL, so the operator doesn't need the warning.
    if target:
        try:
            from core.license import (
                detect_target_license,
                format_license_summary,
                log_license_details,
            )
            _lic = detect_target_license(Path(target))
            log_license_details(_lic)
            _will_run_codeql = (
                command == "codeql"
                or "--codeql" in args
                or "--codeql-only" in args
            )
            _summary = format_license_summary(
                _lic, command="codeql" if _will_run_codeql else command,
            )
            if _summary:
                print(_summary, flush=True)
        except Exception as e:  # noqa: BLE001
            # License detection is non-essential; never fail the
            # lifecycle on a detector bug.
            print(f"  (license-detect skipped: {e})",
                  file=sys.stderr, flush=True)

    # Target shape summary — operator sees what RAPTOR detected
    # before any LLM cost incurs.
    if target:
        # format_start_line self-guards (returns None on any detector
        # failure); only the print can legitimately fail here — a
        # closed/broken stdout pipe. A miswired call propagates.
        with contextlib.suppress(OSError):
            from packages.describe.start_line import format_start_line
            _start_line = format_start_line(Path(target))
            if _start_line:
                print(_start_line, flush=True)

    # Pre-flight cost gate (scorecard-derived). When the operator
    # declared --max-cost-usd, compare the scorecard estimate
    # (using typical_findings_count from the catalog) against the
    # cap. Refuses to start when the estimate clearly exceeds the
    # budget. When no scorecard data exists the gate does not fire
    # — the runtime cap still enforces during execution.
    if max_cost_usd is not None:  # noqa: SIM102
        if _preflight_cost_gate(target, max_cost_usd, out_dir):
            return 1

    # Mirror libexec/raptor-run-lifecycle's sentinel so direct
    # `python3 raptor.py <mode>` invocation honours the OUTPUT_DIR=<path>
    # contract documented in CLAUDE.md (sentinel is the LAST line of the
    # lifecycle-start block). Printed after the license/target-shape/
    # estimate lines and after the failable pre-flight cost gate, so a
    # refused run never hands the caller a directory to write into, and
    # downstream tooling that greps stdout works on both invocation paths.
    print(f"OUTPUT_DIR={out_dir}", flush=True)


    # Re-inject --max-cost-usd for downstream runtime enforcement.
    # The pre-flight gate consumed the value above; downstream
    # scripts (raptor_agentic.py) read it into LLMConfig.max_cost_per_scan
    # so CostTracker enforces the cap during LLM calls.
    if max_cost_usd is not None:
        args = args + ["--max-cost-usd", str(max_cost_usd)]

    # Inject --out so the downstream script uses the lifecycle directory.
    # An operator --out was stripped above and adopted as out_dir, so the
    # child receives the RESOLVED path — parent and child agree byte-for-
    # byte even when the operator typed a relative path. The guard is
    # defensive (nothing should carry --out here after the strip).
    if not any(a == "--out" or a.startswith("--out=") for a in args):
        args = args + ["--out", str(out_dir)]
    # Re-inject --project so the child's own override agrees with the
    # pin the parent just sealed (children also bootstrap from the run
    # marker; the argv keeps direct-invocation and wrapper flows on
    # one code path).
    if project_arg is not None:
        args = args + ["--project", project_arg]

    # ``flush=True``: when stdout is piped (e.g. operator's ``| tee
    # run.log``) Python switches to block-buffering, so the banner
    # lands AFTER the subprocess's already-flushed output. The
    # subprocess uses its own writes (often flushed eagerly), so
    # without the explicit flush here the parent's "starting"
    # banner can appear near the END of the log after the child's
    # final summary — a confusing ordering artefact operators
    # actually noticed.
    print(f"\n[*] {label}\n", flush=True)
    rc = _run_script(script_path, args)

    # Write coverage records from tool outputs (before lifecycle complete)
    try:
        from core.coverage.record import (
            build_from_codeql,
            build_from_semgrep,
            write_record,
        )
        if not (out_dir / "coverage-semgrep.json").exists():
            for json_path in out_dir.glob("semgrep_*.json"):
                record = build_from_semgrep(out_dir, json_path)
                if record:
                    write_record(out_dir, record, tool_name="semgrep")
                    break
        if not (out_dir / "coverage-codeql.json").exists():
            # /scan writes codeql_*.sarif at the top level; /agentic writes it
            # into a codeql/ subdir. Search both. (First match wins — single-
            # language coverage; multi-language merge is a later refinement.)
            codeql_sarifs = (list(out_dir.glob("codeql_*.sarif"))
                             + list((out_dir / "codeql").glob("*.sarif")))
            for sarif_path in codeql_sarifs:
                record = build_from_codeql(sarif_path)
                if record:
                    write_record(out_dir, record, tool_name="codeql")
                    break
    except Exception as e:  # noqa: BLE001
        logging.getLogger(__name__).debug("SARIF record write failed: %s", e)


    if rc == 0:
        # Engine versions + deterministically_reproducible are filled by the
        # lifecycle itself now (core.run.complete_run), uniformly for every
        # command — no per-command manifest wiring here.
        complete_run(out_dir)
        # Print a coverage summary at the end of /agentic (after complete_run,
        # so the scanner + codeql + llm-read records are all materialised).
        # /scan and /validate print their own; this closes the agentic gap.
        if command == "agentic":
            try:
                from core.coverage.store_summary import render_run_coverage
                summary = render_run_coverage(out_dir)
                if summary:
                    print("\n" + summary)
            except Exception as e:  # noqa: BLE001
                logging.getLogger(__name__).debug("coverage summary skipped: %s", e)
    else:
        fail_run(out_dir, error=f"exit code {rc}")
    return rc


# Set True by main() when --trust-repo is seen (and stripped from argv).
# Read by the subprocess mode handlers (codeql/agentic) to re-inject the
# flag into their child args — see the note in main().
_TRUST_REPO_SEEN = False

# Set True by main() when --no-trust-repo is seen (and stripped from
# argv). The explicit negative wins over --trust-repo AND over a
# persisted project 'config' trust marker; re-injected into the
# codeql/agentic children so their own resolution sees it.
_NO_TRUST_REPO_SEEN = False

_active_dispatcher = None


def _get_or_start_dispatcher():
    """Lazy single dispatcher per ``raptor.py`` invocation.

    Credential-isolation: the spawned analysis script gets
    ``RAPTOR_LLM_SOCKET`` + a per-spawn token via ``spawn_worker``,
    and ``core/llm/providers.py`` routes its SDK calls through the
    dispatcher. API keys remain in env as fallback.
    """
    global _active_dispatcher
    if _active_dispatcher is not None:
        return _active_dispatcher
    try:
        import atexit
        import uuid

        from core.llm.dispatcher.auth import CredentialStore, seed_from_config
        from core.llm.dispatcher.server import LLMDispatcher
        # CredentialStore.__init__ reads env vars. Operators who keep
        # keys in ~/.config/raptor/models.json (the documented UX the
        # startup banner advertises) need the explicit seed pass —
        # without it the proxy 503s every request even though the
        # config "looks" populated. Env-set keys win; seed only fills
        # None slots.
        creds = CredentialStore()
        seed_from_config(creds)
        # Bedrock UX preflight — surface short-lived bearer tokens,
        # ASIA env vars that won't refresh, and SigV4 intent without
        # botocore, BEFORE the operator burns a long run discovering
        # them.  Silent for the well-trodden setups (no Bedrock
        # configured, bearer-only with long-term API key, SigV4 with
        # AKIA + botocore).
        for _bedrock_warning in creds.bedrock_session_warnings():
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "[Bedrock] %s", _bedrock_warning,
            )
        # Entitlement preflight: one cached 1-token probe per configured
        # Bedrock (model, surface, region, profile) combination, so an
        # un-entitled model surfaces as an actionable line NOW instead
        # of an AccessDenied mid-run.  Advisory — never blocks startup.
        try:
            from core.llm.bedrock_preflight import (
                preflight_configured_bedrock,
            )
            for _bedrock_warning in preflight_configured_bedrock(creds):
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    "[Bedrock] %s", _bedrock_warning,
                )
        except Exception as _pf_exc:  # noqa: BLE001 — advisory only
            import logging as _logging
            _logging.getLogger(__name__).debug(
                "bedrock preflight skipped: %s", _pf_exc,
            )
        _active_dispatcher = LLMDispatcher(
            run_id=f"raptor-{uuid.uuid4().hex[:8]}",
            creds=creds,
        )
        atexit.register(_active_dispatcher.shutdown)
        return _active_dispatcher
    except Exception as exc:  # noqa: BLE001
        # Failure to start the dispatcher must not break the run —
        # fall through to the env-direct path. The credential leak
        # channel stays open in this case but is no worse than today.
        # Surface the failure on stderr (in addition to the logger
        # warning) so operators see it regardless of log-level
        # config. Once API keys are stripped from ``get_llm_env``,
        # this fallback produces workers without auth — the symptom
        # is a confusing "first LLM call fails" 30 seconds later.
        # Surface it loudly now so operators see it immediately.
        import logging
        import sys as _sys
        msg = (
            f"raptor.py: credential-isolation dispatcher failed to "
            f"start ({type(exc).__name__}: {exc}). Falling back to "
            f"env-direct credential propagation."
        )
        _sys.stderr.write(msg + "\n")
        _sys.stderr.flush()
        logging.getLogger(__name__).warning(
            "credential-isolation dispatcher failed to start, falling back "
            "to env-direct: %s", exc,
        )
        return None


def _worker_keyless_enabled() -> bool:
    """RAPTOR_LLM_WORKER_KEYLESS=1: spawn analysis workers WITHOUT
    provider keys in env, relying on the dispatcher alone.

    The env-direct key fallback exists for a live reason — workers
    fall back to direct SDK calls when the dispatcher route is
    unusable, and some providers aren't dispatcher-routed — so the
    keyless posture is opt-in. When flipped, a worker whose provider
    isn't dispatcher-routed fails its LLM calls with a missing-key
    error rather than silently leaking credentials into env.
    """
    raw = (os.environ.get("RAPTOR_LLM_WORKER_KEYLESS") or "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _cleanup_refused_run_dir(out_dir: Path) -> None:
    """Remove a just-pre-created run dir after a refused start.

    Only the shapes this wrapper itself creates are removed: the
    ``_source`` symlink an archive unpack plants (which made the bare
    ``rmdir`` fail silently, leaving an orphan), then the empty dir.
    Anything else in the dir means it isn't ours to delete.
    """
    with contextlib.suppress(OSError):
        src_link = out_dir / "_source"
        if src_link.is_symlink():
            src_link.unlink()
    with contextlib.suppress(OSError):
        out_dir.rmdir()


def _run_script(script_path: Path, args: list) -> int:
    """
    Run a RAPTOR script with given arguments.

    Args:
        script_path: Path to the Python script to run
        args: Command-line arguments to pass to the script

    Returns:
        Exit code from the script
    """
    cmd = [sys.executable, str(script_path)] + args

    # --help/-h is not a run: render the child's argparse help with a plain
    # subprocess (safe env, short timeout) and skip the LLM dispatcher
    # entirely. argparse prints help and exits during parse_args, before the
    # script body — so starting the dispatcher would be a pure side effect.
    if _wants_help(args):
        from core.config import RaptorConfig
        try:
            return subprocess.run(
                cmd, env=RaptorConfig.get_safe_env(), timeout=15,
                check=False,
            ).returncode
        except subprocess.TimeoutExpired:
            print(f"✗ Help rendering for {script_path.name} timed out",
                  file=sys.stderr)
            return 1

    try:
        from core.config import RaptorConfig
        dispatcher = _get_or_start_dispatcher()
        if dispatcher is not None:
            from core.llm.dispatcher.spawn import spawn_worker
            # Worker credential posture. Default: provider keys still
            # ride the env as a fallback for the env-direct transport
            # paths (dispatcher-down resilience mid-run, and providers
            # the dispatcher doesn't route). RAPTOR_LLM_WORKER_KEYLESS=1
            # enforces the designed keyless posture: the worker gets
            # the safe baseline + routing NAMES only and relies on the
            # dispatcher alone for provider auth. Opt-in — flip it once
            # the install's providers are all dispatcher-routed.
            if _worker_keyless_enabled():
                worker_env = RaptorConfig.get_safe_env(
                    preserve_proxy=True,
                    include_python_user_base=True,
                )
                worker_env.update(RaptorConfig.llm_routing_env())
            else:
                worker_env = RaptorConfig.get_llm_env(
                    include_python_user_base=True,
                )
            proc = spawn_worker(
                dispatcher,
                cmd=cmd,
                label=script_path.name,
                env=worker_env,
            )
            return proc.wait()
        # Fallback: env-direct (no dispatcher available).
        # Same opt-in as the dispatcher path above — the canonical
        # operator entry point must preserve PYTHONUSERBASE for the
        # spawned ``raptor_<mode>.py`` subprocess.
        result = subprocess.run(
            cmd,
            env=RaptorConfig.get_llm_env(include_python_user_base=True),
            check=False,
        )
        return result.returncode
    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        # Mark any active run as cancelled. Pre-fix Ctrl-C
        # left runs in `status="in_progress"` forever — the
        # next /scan or /agentic invocation saw a stale
        # "active" run from yesterday's interrupted session
        # and either appended to it (corrupting findings
        # comparison) or refused to start ("a run is already
        # active"). cancel_run flips status to "cancelled"
        # and clears the active-run pointer; subsequent
        # invocations get a clean slate.
            # Best-effort. Don't mask the original Ctrl-C
            # by raising secondary errors during cleanup:
            # cancel_run raises FileNotFoundError when the run
            # metadata is gone and ValueError when it's malformed.
            # A miswired call (TypeError etc.) still propagates.
        with contextlib.suppress(OSError, ValueError):
            from core.run.metadata import cancel_run
            from core.sandbox.summary import get_active_run_dir
            active = get_active_run_dir()
            if active:
                cancel_run(active)
        return 130
    except Exception as e:  # noqa: BLE001
        # Pre-fix the blanket `return 1` collapsed every internal
        # exception (FileNotFoundError, ValueError, RuntimeError,
        # OSError, etc.) into the same exit code as a child process
        # that legitimately exited 1. Operators reading the rc had
        # no signal whether the child had failed or whether the
        # launcher itself had crashed before/after spawning.
        #
        # Distinguish via exit code 2 (launcher-internal failure)
        # from rc=1 (child returned 1). Print the exception CLASS
        # alongside the message so logs show the failure shape
        # without needing a traceback.
        print(f"\n✗ Error running {script_path.name}: "
              f"{type(e).__name__}: {e}", file=sys.stderr)
        return 2


def mode_scan(args: list) -> int:
    """Run static code analysis (Semgrep)."""
    script_root = Path(__file__).parent
    scanner_script = script_root / "packages/static-analysis/scanner.py"

    if not scanner_script.exists():
        print(f"✗ Scanner not found: {scanner_script}", file=sys.stderr)
        return 1

    return _run_with_lifecycle("scan", scanner_script, args,
                              "Running static analysis with Semgrep...")


def mode_sca(args: list) -> int:
    """Run mechanical Software Composition Analysis.

    Delegates to ``libexec/raptor-sca-run`` which manages the run-lifecycle
    metadata itself; we don't wrap with ``_run_with_lifecycle`` (which
    is shaped for the Semgrep/CodeQL/AFL++ external-tool workflow).
    """
    script_root = Path(__file__).parent
    sca_shim = script_root / "libexec" / "raptor-sca-run"
    if not sca_shim.exists():
        print(f"✗ SCA module not found: {sca_shim}", file=sys.stderr)
        return 1

    # Translate ``--repo <p>`` into the positional target the shim
    # expects, so ``raptor.py sca --repo /path`` matches the convention
    # of the other modes. When a subcommand follows --repo (e.g.,
    # ``raptor.py sca --repo /path fix --apply``), the path must be
    # inserted AFTER the subcommand so the libexec dispatch sees
    # ``fix /path --apply`` rather than ``/path fix --apply``.
    # Source of truth lives in packages.sca.cli.SUBCOMMANDS — import
    # it here to keep the lists in lock-step.
    from packages.sca.cli import SUBCOMMANDS
    _SCA_SUBCOMMANDS = set(SUBCOMMANDS)
    forwarded: list = []
    target_from_repo = None
    repo_seen = False
    skip_next = False
    for i, arg in enumerate(args):
        if skip_next:
            skip_next = False
            continue
        if arg == "--repo" and i + 1 < len(args):
            if repo_seen:
                print("raptor.py sca: --repo specified more than once; "
                      f"using the last value ({args[i + 1]!r})",
                      file=sys.stderr)
            target_from_repo = args[i + 1]
            repo_seen = True
            skip_next = True
            continue
        if arg.startswith("--repo="):
            val = arg[len("--repo="):]
            if repo_seen:
                print("raptor.py sca: --repo specified more than once; "
                      f"using the last value ({val!r})",
                      file=sys.stderr)
            target_from_repo = val
            repo_seen = True
            continue
        forwarded.append(arg)
    if target_from_repo is not None:
        # Insert after the subcommand if one is present, else at front.
        sub_idx = next(
            (i for i, a in enumerate(forwarded) if a in _SCA_SUBCOMMANDS),
            None,
        )
        if sub_idx is None:
            forwarded.insert(0, target_from_repo)
        else:
            forwarded.insert(sub_idx + 1, target_from_repo)

    cmd = [sys.executable, str(sca_shim)] + forwarded
    try:
        from core.config import RaptorConfig
        # Trust marker — libexec/raptor-sca-run refuses to run without
        # one of CLAUDECODE / _RAPTOR_TRUSTED in env. ``get_safe_env``'s
        # allowlist (in this branch) doesn't include the markers, so we
        # set the trust marker explicitly here. ``raptor.py`` is itself
        # a trusted entry point.
        # get_llm_env (proxy always preserved): the SCA child hosts
        # the egress proxy for OSV / registry / KEV traffic AND runs
        # LLM triage / upgrade-impact review (packages/sca/llm/*) —
        # it needs the operator's API keys and the transport-routing
        # family, not just the safe baseline.
        env = RaptorConfig.get_llm_env()
        env["_RAPTOR_TRUSTED"] = "1"
        result = subprocess.run(cmd, env=env, check=False)
        return result.returncode
    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        return 130
    except Exception as e:  # noqa: BLE001
        print(f"\n✗ Error running raptor-sca: {e}", file=sys.stderr)
        return 1


def mode_fuzz(args: list) -> int:
    """Run binary fuzzing with AFL++."""
    script_root = Path(__file__).parent
    fuzzing_script = script_root / "raptor_fuzzing.py"

    if not fuzzing_script.exists():
        print(f"✗ Fuzzing script not found: {fuzzing_script}", file=sys.stderr)
        return 1

    return _run_with_lifecycle("fuzz", fuzzing_script, args,
                              "Starting binary fuzzing workflow...")


def mode_binary(args: list) -> int:
    """Run the black-box binary operator surface.

    The binary CLI owns its own lifecycle for ``map`` and routes explicit
    runtime / fuzz follow-on work to the existing Frida and fuzz entry points.
    """
    from core.config import RaptorConfig

    wrapper = Path(__file__).parent / "libexec" / "raptor-binary"
    if not wrapper.exists():
        print(f"✗ Binary wrapper not found: {wrapper}", file=sys.stderr)
        return 1
    # get_llm_env (proxy always preserved): the binary surface
    # dispatches `claude` CLI children and spawns LLM-calling
    # grandchildren (raptor_fuzzing.py crash analysis) — both build
    # their env from THIS child's environ, so the keys and the
    # transport-routing family must survive this hop.
    env = RaptorConfig.get_llm_env()
    env["_RAPTOR_TRUSTED"] = "1"
    try:
        return subprocess.call([str(wrapper), *args], env=env)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"\n✗ Error running raptor-binary: {exc}", file=sys.stderr)
        return 1


def mode_web(args: list) -> int:
    """Run web application security testing."""
    script_root = Path(__file__).parent
    web_script = script_root / "packages/web/scanner.py"

    if not web_script.exists():
        print(f"✗ Web scanner not found: {web_script}", file=sys.stderr)
        return 1

    # Alpha warning — pre-fix this said "/web is a STUB and should
    # not be relied upon. Consider a placeholder/in alpha." which is
    # internally contradictory (stub OR alpha, not both) and landed
    # on stdout (captured in reports). Land on stderr and pick one
    # description.
    print(
        "\nWARNING: /web is in alpha — expect false positives and "
        "incomplete coverage.\n",
        file=sys.stderr,
    )

    return _run_with_lifecycle("web", web_script, args,
                              "Running web application scanner...")


def mode_agentic(args: list) -> int:
    """Run full autonomous workflow."""
    script_root = Path(__file__).parent
    agentic_script = script_root / "raptor_agentic.py"

    if not agentic_script.exists():
        print(f"✗ Agentic workflow script not found: {agentic_script}", file=sys.stderr)
        return 1

    # Enable CodeQL by default for comprehensive agentic mode
    # unless user explicitly specifies --codeql-only or --no-codeql
    # or CodeQL is disabled via config (tuning.json: codeql_enabled: false)
    if '--codeql' not in args and '--codeql-only' not in args and '--no-codeql' not in args:
        from core.config import RaptorConfig
        if RaptorConfig.CODEQL_ENABLED:
            args = ['--codeql'] + args
        else:
            print(
                "  CodeQL disabled via config (tuning.json). "
                "Pass --codeql to override for this run.",
                file=sys.stderr,
            )

    # Re-inject --trust-repo / --no-trust-repo stripped by main(): the
    # agentic child parses them to resolve the cc_trust + codeql_trust
    # overrides in its own process (negative wins there).
    if _TRUST_REPO_SEEN and '--trust-repo' not in args:
        args = ['--trust-repo'] + args
    if _NO_TRUST_REPO_SEEN and '--no-trust-repo' not in args:
        args = ['--no-trust-repo'] + args

    log_level = _extract_agentic_log_level(args)
    if log_level:
        from core.logging import configure_run_logging
        configure_run_logging(log_level=log_level, verbose=False)

    return _run_with_lifecycle("agentic", agentic_script, args,
                              "Starting full autonomous workflow...")


def mode_codeql(args: list) -> int:
    """Run CodeQL analysis (scan only — no autonomous analysis)."""
    script_root = Path(__file__).parent
    codeql_script = script_root / "raptor_codeql.py"

    if not codeql_script.exists():
        print(f"✗ CodeQL script not found: {codeql_script}", file=sys.stderr)
        return 1

    # Default to scan-only; autonomous analysis requires explicit --analyze.
    # Strip --analyze after using it as a sentinel — the codeql child
    # script does not define it in its argparse.
    analyze = '--analyze' in args
    args = [a for a in args if a != '--analyze']
    if '--scan-only' not in args and not analyze:
        args = ['--scan-only'] + args

    # Re-inject --trust-repo / --no-trust-repo stripped by main(): the
    # codeql child parses them to resolve the cc_trust + codeql_trust
    # overrides in its own process (negative wins there).
    if _TRUST_REPO_SEEN and '--trust-repo' not in args:
        args = ['--trust-repo'] + args
    if _NO_TRUST_REPO_SEEN and '--no-trust-repo' not in args:
        args = ['--no-trust-repo'] + args

    return _run_with_lifecycle("codeql", codeql_script, args,
                              "Running CodeQL analysis...")


def mode_llm_analysis(args: list) -> int:
    """Run LLM-powered vulnerability analysis on existing SARIF files."""
    script_root = Path(__file__).parent
    llm_script = script_root / "packages/llm_analysis/agent.py"

    if not llm_script.exists():
        print(f"✗ LLM analysis script not found: {llm_script}", file=sys.stderr)
        return 1

    print("\n[*] Running LLM-powered vulnerability analysis...\n")
    return _run_script(llm_script, args)


def mode_describe(args: list) -> int:
    """``raptor describe --target <path>`` — show target analysis,
    tool readiness, and recommended pipeline BEFORE running any
    analysis. No LLM cost, no side effects beyond stdout.

    Composes ``packages/describe`` substrates: target-shape
    inference + tool readiness + catalog defaults + cost
    estimate. JSON form via ``--json`` for CI / dashboards;
    text form (default) for human reading. Archive targets
    (.tar.gz / .zip / …) extracted on the fly via
    ``core.archive`` and described.
    """
    parser = argparse.ArgumentParser(
        prog="raptor describe",
        description=(
            "Pre-flight inspection: target type, tool readiness, "
            "recommended pipeline, and cost estimate. No LLM cost."
        ),
    )
    parser.add_argument(
        "--target", default=None, metavar="<path>",
        help=(
            "Path to the target codebase (directory OR archive: "
            "tar.gz / zip / …). Optional — falls back to the "
            "active project's target, then $RAPTOR_CALLER_DIR, "
            "per CLAUDE.md DEFAULT TARGET DIRECTORY."
        ),
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Emit machine-readable JSON instead of the text block",
    )
    try:
        parsed = parser.parse_args(args)
    except SystemExit as e:
        return int(e.code or 0)

    from packages.describe.cli import describe_main
    return describe_main(parsed.target, parsed.json)


def mode_doctor(args: list) -> int:
    """Run the on-demand status report.

    Wraps :mod:`core.startup.doctor` — see its docstring for the
    contract (no logo, failures-first, non-zero exit on real
    failure). All flags pass through to ``doctor.main``.
    """
    # One-line preamble: doctor is the ONE mode that runs without an
    # LLM. New operators hitting an LLM-config issue often don't
    # realise that. Printing the hint to stderr (operator-visible but
    # not captured into stdout-redirected reports) makes the
    # diagnostic path discoverable on first contact. Skip when the
    # ``--help`` flag is being parsed — argparse's auto-help renders
    # next and the preamble would just clutter the help block.
    if "--help" not in args and "-h" not in args:
        print(
            "[doctor] no LLM required — diagnostic only.",
            file=sys.stderr,
        )
    from core.startup.doctor import main as doctor_main
    return doctor_main(args)


def mode_frida(args: list) -> int:
    """Run a Frida dynamic-instrumentation session.

    The libexec wrapper owns lifecycle setup (output directory + run
    state tracking) and dispatches to :mod:`packages.frida.cli`.
    Routing through the wrapper rather than calling the cli module
    directly keeps the lifecycle behaviour identical whether the
    operator runs ``bin/raptor frida ...`` or invokes the wrapper
    directly from a /frida skill.
    """
    from core.config import RaptorConfig
    script_root = Path(__file__).parent
    wrapper = script_root / "libexec" / "raptor-frida"
    if not wrapper.exists():
        print(f"✗ Frida wrapper not found: {wrapper}", file=sys.stderr)
        return 1
    # get_llm_env (proxy always preserved): remote frida-server
    # targets need the operator's launch-time proxy, and the wrapper's
    # LLM-backed follow-on needs the keys + transport-routing family
    # in its own environ.
    env = RaptorConfig.get_llm_env()
    env.setdefault("_RAPTOR_TRUSTED", "1")
    return subprocess.call([str(wrapper), *args], env=env)


def _mode_help_scripts() -> dict:
    """Map mode name → the script whose argparse renders that mode's help.

    Single source of truth shared by show_mode_help (renders the help) and
    the `<mode> --help` short-circuit in main() (decides which modes get the
    side-effect-free help path vs. falling through to their handler).
    """
    script_root = Path(__file__).parent
    return {
        'scan': script_root / "packages/static-analysis/scanner.py",
        'binary': script_root / "packages/binary_analysis/cli.py",
        'fuzz': script_root / "raptor_fuzzing.py",
        'web': script_root / "packages/web/scanner.py",
        'agentic': script_root / "raptor_agentic.py",
        'codeql': script_root / "raptor_codeql.py",
        'analyze': script_root / "packages/llm_analysis/agent.py",
        'openant': script_root / "raptor_openant.py",
    }


# Modes whose `<mode> --help` is rendered by spawning the child script's own
# argparse (no run lifecycle). Derived from _mode_help_scripts so it stays in
# lockstep with what show_mode_help can actually render.
_HELP_RENDER_MODES = frozenset(_mode_help_scripts().keys())



def mode_openant(args: list) -> int:
    """Run OpenAnt AST+LLM source-code vulnerability scan."""
    script_root = Path(__file__).parent
    openant_script = script_root / "raptor_openant.py"

    if not openant_script.exists():
        print(f"\u2717 OpenAnt script not found: {openant_script}")
        return 1

    return _run_with_lifecycle("openant", openant_script, args,
                              "Running OpenAnt LLM-powered source-code scan...")


def show_mode_help(mode: str, preamble: bool = True) -> None:
    """Show detailed help for a specific mode.

    preamble=True prints a "[*] Help for mode: <mode>" header (the
    `raptor.py help <mode>` surface). The `<mode> --help` short-circuit
    passes preamble=False so the output is *only* the mode's argparse
    help, with nothing above it.
    """
    mode_scripts = _mode_help_scripts()

    if mode not in mode_scripts:
        all_modes = set(mode_scripts.keys()) | {'describe', 'doctor', 'sca', 'frida'}
        if mode not in all_modes:
            print(f"✗ Unknown mode: {mode}", file=sys.stderr)
            print(f"Available modes: {', '.join(sorted(all_modes))}", file=sys.stderr)
            return
        print(f"\n[*] Help for mode: {mode}\n", flush=True)
        mode_handlers = {
            'describe': mode_describe,
            'doctor': mode_doctor,
            'sca': mode_sca,
            'frida': mode_frida,
        'openant': mode_openant,
        }
        mode_handlers[mode](["--help"])
        return

    script_path = mode_scripts[mode]
    if not script_path.exists():
        print(f"✗ Script not found: {script_path}", file=sys.stderr)
        return

    if preamble:
        # flush=True so the header lands ABOVE the child's help. Without
        # it, Python block-buffers the print when stdout is a pipe while
        # the subprocess writes to fd 1 directly — interleaving the
        # header to the bottom of the output.
        print(f"\n[*] Help for mode: {mode}\n", flush=True)
    # `env=` to a stripped environment so the help-rendering
    # subprocess doesn't inherit the parent's full env. Pre-fix the
    # bare subprocess.run carried LD_PRELOAD / LD_LIBRARY_PATH /
    # PYTHONPATH through to the spawned `python3 raptor_<mode>.py
    # --help` — irrelevant for the help text itself but a
    # consistency hazard with the rest of raptor.py's spawn paths
    # (which all use safe env). `timeout=10` so a wedged help-text
    # rendering (rare, but a script with a side-effect import that
    # blocks at import time would hang the operator's terminal)
    # doesn't pin the shell.
    try:
        from core.config import RaptorConfig
        subprocess.run(
            [sys.executable, str(script_path), "--help"],
            env=RaptorConfig.get_safe_env(),
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print(f"✗ Help rendering for {mode} timed out after 10s", file=sys.stderr)


# Help epilog used by both the no-args path and the explicit
# --help/-h path. Centralised so the two help renderings cannot
# drift apart silently. Indented inside main()'s argparse calls
# via formatter_class=RawDescriptionHelpFormatter (which
# preserves leading whitespace and newlines verbatim).
_HELP_EPILOG = """
Available Modes:
  scan        - Static code analysis with Semgrep
  sca         - Software Composition Analysis (deps + advisories + SBOM)
  binary      - Black-box binary investigation and evidence collection
  fuzz        - Binary fuzzing with AFL++
  web         - Web application security testing
  agentic     - Full autonomous workflow (Semgrep + LLM analysis; --codeql adds CodeQL)
  codeql      - CodeQL-only analysis
  analyze     - LLM-powered vulnerability analysis (requires SARIF input)
  describe    - Pre-flight inspection: target type, tool readiness, cost estimate
  doctor      - Status report for local setup (no claude needed)
  frida       - Dynamic instrumentation via Frida (alpha)
  openant     - OpenAnt AST+LLM source-code vulnerability scan

Examples:
  # Full autonomous workflow
  python3 raptor.py agentic --repo /path/to/code

  # Static analysis only
  python3 raptor.py scan --repo /path/to/code --policy-groups secrets,owasp

  # Binary fuzzing
  python3 raptor.py fuzz --binary /path/to/binary --duration 3600

  # Black-box binary investigation
  python3 raptor.py binary investigate /path/to/binary

  # Web scanning
  python3 raptor.py web --url https://example.com

  # CodeQL analysis
  python3 raptor.py codeql --repo /path/to/code --languages java

  # LLM analysis of existing SARIF
  python3 raptor.py analyze --repo /path/to/code --sarif findings.sarif

Sandbox isolation (mode-level flags — pass them AFTER the mode name,
not before; the top-level parser does not declare them directly):
  --sandbox {full,strict,debug,target_run,frida,network-only,none}
                        Force a sandbox profile (default: full).
                        'strict' fails closed instead of degrading and
                        denies $HOME reads by default
  --no-sandbox          Alias for --sandbox none
  --audit               Log what enforcement WOULD have blocked
                        (composes with --sandbox profiles other than 'none')
  --audit-verbose       With --audit, log every traced syscall
                        (strace-style diagnostic)
  --sandbox-readable-path PATH
                        Extend the read allowlist (repeatable) — the
                        fix when a read-restricting run denies a path
                        a tool needs; --audit names the path
  --sandbox-tool-path DIR
                        Make an operator-installed tool dir visible
                        inside the sandbox (repeatable; read-only)

  Run ``python3 raptor.py <mode> --help`` to see them in the mode's
  own argparse-generated list (they are added by
  ``core.sandbox.add_cli_args``, not the top-level parser).

  # Examples
  python3 raptor.py agentic --repo /code --audit          # log + run
  python3 raptor.py scan --repo /code --sandbox debug     # gdb-friendly
  python3 raptor.py fuzz --binary /b --audit --audit-verbose  # full trace

  # Get help for a specific mode
  python3 raptor.py help scan
  python3 raptor.py help fuzz
  python3 raptor.py scan --help

For more information, visit: https://github.com/gadievron/raptor
"""


def main():
    """Main entry point for unified RAPTOR launcher."""
    # Pre-process --trust-repo at the top level so it works in any position
    # (`raptor --trust-repo scan /x` or `raptor scan /x --trust-repo`).
    # Sets the cc_trust module flag for in-process / parent-side checks.
    # SUBPROCESS mode handlers (codeql/agentic) can't rely on that flag —
    # module-level trust state doesn't cross the subprocess boundary, and
    # we strip the flag from argv here — so they re-inject --trust-repo into
    # their child args via _TRUST_REPO_SEEN. Without that, `raptor.py codeql
    # --trust-repo` silently fails to lift the child's target-repo trust
    # checks (fail-closed: it over-blocks, but the documented override breaks).
    # --no-trust-repo (explicit negative) beats --trust-repo and any
    # persisted project 'config' trust marker. Stripped here like the
    # positive flag so subcommands without the flag still parse; the
    # codeql/agentic handlers re-inject it for their children.
    global _TRUST_REPO_SEEN, _NO_TRUST_REPO_SEEN
    if "--no-trust-repo" in sys.argv:
        _NO_TRUST_REPO_SEEN = True
        sys.argv = [a for a in sys.argv if a != "--no-trust-repo"]
    if "--trust-repo" in sys.argv:
        from core.security.cc_trust import set_trust_override
        if not _NO_TRUST_REPO_SEEN:
            set_trust_override(True)
        _TRUST_REPO_SEEN = True
        sys.argv = [a for a in sys.argv if a != "--trust-repo"]

    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser = argparse.ArgumentParser(
            description="RAPTOR - Unified Security Testing Launcher",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=_HELP_EPILOG,
        )
        parser.print_help()
        return 0
    
    # Print the running framework version and exit. Uses effective_version()
    # so a checkout reports its true position past the last tag (git describe)
    # and an installed/archived copy reports the baked VERSION.
    if sys.argv[1] in ('--version', '-V', 'version'):
        from core.config import RaptorConfig
        print(RaptorConfig.effective_version())
        return 0

    # Get mode from first argument
    mode = sys.argv[1].lower()
    remaining = sys.argv[2:]

    # Handle --help or -h as first argument (show main help)
    if mode in ['-h', '--help']:
        parser = argparse.ArgumentParser(
            description="RAPTOR - Unified Security Testing Launcher",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=_HELP_EPILOG,
        )
        parser.print_help()
        return 0
    
    # Handle help mode
    if mode == 'help':
        if remaining:
            show_mode_help(remaining[0])
        else:
            print("Usage: raptor.py help <mode>")
            print("Example: raptor.py help scan")
        return 0

    # `<mode> --help` / `<mode> -h`: render the mode's own argparse help
    # WITHOUT entering the run lifecycle. Pre-fix, --help fell through to
    # the mode handler (mode_agentic etc.), which wraps the child in
    # _run_with_lifecycle — resolving a target, creating AND sealing an
    # output directory, printing the OUTPUT_DIR sentinel + license + cost
    # estimate preamble, starting the LLM dispatcher, then emitting a
    # coverage summary, all before the child's argparse ever saw --help.
    # A help request must be side-effect-free. show_mode_help spawns
    # `python3 raptor_<mode>.py --help` directly (safe env, timeout, no
    # lifecycle, no dispatcher). Gated to the modes show_mode_help knows
    # how to render; 'doctor' parses --help inside its own handler and
    # 'sca' has no subprocess help script, so both fall through.
    if mode in _HELP_RENDER_MODES and _wants_help(remaining):
        show_mode_help(mode, preamble=False)
        return 0

    # Route to appropriate mode
    mode_handlers = {
        'scan': mode_scan,
        'sca': mode_sca,
        'binary': mode_binary,
        'fuzz': mode_fuzz,
        'web': mode_web,
        'agentic': mode_agentic,
        'codeql': mode_codeql,
        'analyze': mode_llm_analysis,
        'doctor': mode_doctor,
        'describe': mode_describe,
        'frida': mode_frida,
        'openant': mode_openant,
    }
    
    if mode not in mode_handlers:
        print(f"✗ Unknown mode: {mode}", file=sys.stderr)
        # Suggest the closest match — typos like ``agantic`` for
        # ``agentic`` shouldn't force the operator to read the
        # full mode dump.
        import difflib
        suggestion = difflib.get_close_matches(
            mode, mode_handlers.keys(), n=1, cutoff=0.6,
        )
        if suggestion:
            print(f"  Did you mean '{suggestion[0]}'?", file=sys.stderr)
        # Slash-command hint when one exists — that's the
        # user-facing surface (operator types ``python3 raptor.py
        # project`` and we point them at the ``/project`` slash-
        # command in Claude Code). Automated callers (LLMs, skills,
        # CLAUDE.md procedures) invoke libexec scripts directly; the
        # libexec→mode mapping is arbitrary (``/project`` →
        # ``raptor-project-manager``, but ``/validate`` has no
        # libexec entry point — ``raptor-validate-schema`` is a
        # specialised JSON-schema helper), so we don't try to
        # auto-suggest libexec paths. The LLM context reads the
        # skill / CLAUDE.md for the canonical invocation.
        _slash = Path(__file__).parent / ".claude" / "commands" / f"{mode}.md"
        if _slash.is_file():
            print(
                f"\n  '{mode}' isn't a raptor.py mode — for the "
                f"operator-facing surface, run /{mode} in Claude "
                f"Code. Automated callers should read "
                f".claude/commands/{mode}.md for the canonical "
                f"invocation.",
                file=sys.stderr,
            )
        print(f"\nAvailable modes: {', '.join(mode_handlers.keys())}", file=sys.stderr)
        print("\nRun 'python3 raptor.py --help' for more information", file=sys.stderr)
        return 1
    
    # Execute the mode handler
    handler = mode_handlers[mode]
    return handler(remaining)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nInterrupted by user", file=sys.stderr)
        sys.exit(130)
    except Exception as e:  # noqa: BLE001
        from core.run.pin import ProjectArgvError
        if isinstance(e, ProjectArgvError):
            # The designed clean hard-error, not an internal fault —
            # it can fire before start_run (get_output_dir resolves
            # the override), so catch it here too, without traceback.
            print(f"✗ {e}", file=sys.stderr)
            sys.exit(1)
        print(f"\n✗ Fatal error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
