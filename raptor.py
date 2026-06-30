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
    scan        - Static code analysis (Semgrep + CodeQL)
    fuzz        - Binary fuzzing with AFL++
    web         - Web application security testing
    agentic     - Full autonomous workflow
    codeql      - CodeQL-only analysis
    doctor      - Status report for local setup (no claude needed)
    frida       - Dynamic instrumentation via Frida (alpha)
    help        - Show detailed help for a specific mode

Examples:
    # Full autonomous workflow
    python3 raptor.py agentic --repo /path/to/code

    # Static analysis only
    python3 raptor.py scan --repo /path/to/code --policy-groups secrets,owasp

    # Binary fuzzing
    python3 raptor.py fuzz --binary /path/to/binary --duration 3600

    # Web scanning
    python3 raptor.py web --url https://example.com

    # CodeQL analysis
    python3 raptor.py codeql --repo /path/to/code --languages java
"""

import argparse
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

from core.run.output import get_output_dir, resolve_default_target, TargetMismatchError
from core.run.metadata import start_run, complete_run, fail_run
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

    Lives at the lifecycle level so the operator can declare a
    per-run budget once at the entry point and the estimator gate
    + downstream loop both see the same cap. Stripped before
    forwarding so downstream scripts (scanner, agentic, codeql)
    don't have to recognise the flag.

    Invalid values (non-numeric, zero, negative) print a stderr
    warning and return ``(None, args)`` unchanged — operator's
    typo doesn't silently uncap the run, but the run also doesn't
    refuse to start over a bad cap value. (A hard error here
    would force every operator typo through a full lifecycle
    failure, which is more brittle than this warn-and-skip
    fallback.)
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
        return (None, args)
    if cap <= 0:
        print(
            f"WARNING: --max-cost-usd must be > 0 (got {cap}); "
            "ignoring cap for this run",
            file=sys.stderr,
        )
        return (None, args)
    return (cap, out)


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


# Cache-name helper lives in core.archive (shared with
# packages/describe/cli.py — extracts opportunistically into
# the same cache so /describe + /scan don't re-extract the
# same archive). Re-exported here under the old private name
# for backward compatibility with anything in this module that
# still references _safe_cache_name.
from core.archive import safe_cache_name as _safe_cache_name  # noqa: E402


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
        tmp = Path(tempfile.mkdtemp(dir=sources_root, prefix=".extract-"))
        try:
            stats = extract_to_dir(target, tmp)
        except Exception as e:
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


def _wants_help(args: list) -> bool:
    """True if args request argparse help (``--help`` / ``-h``).

    Single source of truth for the help short-circuits. A help request is
    not a run: it must never resolve a target, create/seal an output
    directory, print the OUTPUT_DIR sentinel or license/cost preamble, or
    start the LLM dispatcher.
    """
    return "--help" in args or "-h" in args


def _uses_codex_exec(script_path: Path, args: list) -> bool:
    """True when the child uses Codex CLI auth instead of LLM SDK creds."""

    return script_path.name == "raptor_agentic.py" and "--codex-exec" in args


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

    # Operator-declared per-run budget cap (QoL #21). Stripped from
    # ``args`` before forwarding so downstream scripts don't have
    # to recognise the flag. Pre-flight gate fires below, after
    # the catalog estimate is computed.
    max_cost_usd, args = _extract_and_strip_max_cost_usd(args)

    # CLAUDE.md DEFAULT TARGET DIRECTORY: back-fill --repo from
    # (1) active project → (2) RAPTOR_CALLER_DIR when args don't carry
    # an explicit target. Pre-fix, scanner.py's `--repo required=True`
    # crashed with "required: --repo" even when a project was active —
    # the dispatcher resolved the output dir correctly but never
    # forwarded the target into the downstream script's args.
    # Explicit --repo from args always wins (per the override pattern).
    if target is None:
        target = resolve_default_target()
        if target is not None:
            args = args + ["--repo", target]

    try:
        out_dir = get_output_dir(command, target_path=target)
    except TargetMismatchError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1

    # Trust-boundary mkdir: refuses if the predictable run-dir name has been
    # pre-positioned as a symlink, owned by another user, or world-writable.
    # Subprocesses re-verify on their side (defence in depth) but the parent
    # is the first writer and has to gate too — start_run below would
    # otherwise create .raptor-run.json along an attacker symlink.
    out_dir.parent.mkdir(parents=True, exist_ok=True)
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
                return 1  # extraction failed (message printed); no run sealed yet
            args, target_identity = res

    start_run(out_dir, command, target=target, target_identity=target_identity)
    # Mirror libexec/raptor-run-lifecycle's sentinel so direct
    # `python3 raptor.py <mode>` invocation honours the OUTPUT_DIR=<path>
    # contract documented in CLAUDE.md. Downstream tooling that greps
    # stdout for the sentinel works on both invocation paths.
    print(f"OUTPUT_DIR={out_dir}", flush=True)

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
        except Exception as e:
            # License detection is non-essential; never fail the
            # lifecycle on a detector bug.
            print(f"  (license-detect skipped: {e})",
                  file=sys.stderr, flush=True)

    # Cost-and-time estimate from the target-type catalog (QoL #21).
    # Operator sees the expected ballpark before any LLM cost
    # incurs; Ctrl-C is the cancel path. When ``--max-cost-usd``
    # is set, the upper bound of the catalog estimate is gated
    # against the cap pre-flight — runs that would obviously
    # blow the budget refuse to start rather than spending the
    # cap to discover the cap was insufficient.
    if target:
        try:
            from core.run.estimator import estimate_run, format_estimate
            _est = estimate_run(Path(target))
            # Richer start line: primary language + LOC + build
            # system + target type + cost estimate, all in one
            # line. Falls back to the bare estimate if /describe
            # substrate is unavailable so the budget gate still
            # surfaces.
            try:
                from packages.describe.start_line import format_start_line
                _start_line = format_start_line(Path(target))
            except Exception:  # noqa: BLE001
                _start_line = None
            if _start_line:
                print(_start_line, flush=True)
            else:
                _est_line = format_estimate(_est)
                if _est_line:
                    print(_est_line, flush=True)
            if (
                max_cost_usd is not None
                and _est is not None
                and _est.cost_high > max_cost_usd
            ):
                print(
                    f"✗ Pre-flight cost gate: catalog estimate "
                    f"upper bound (${_est.cost_high:.2f}) exceeds "
                    f"--max-cost-usd cap (${max_cost_usd:.2f}). "
                    f"Raise the cap or accept the risk and re-run "
                    f"without --max-cost-usd.",
                    file=sys.stderr, flush=True,
                )
                # Mark the run failed so the lifecycle metadata
                # reflects WHY this output dir didn't progress —
                # operator inspecting the dir later sees the
                # pre-flight refusal, not a phantom ``running``
                # state.
                try:
                    fail_run(out_dir, "pre-flight cost gate exceeded")
                except Exception:  # noqa: BLE001
                    pass
                return 1
        except Exception as e:
            # Estimator is best-effort; never break the lifecycle.
            print(f"  (estimate skipped: {e})",
                  file=sys.stderr, flush=True)

    # SAGE: Pre-scan recall
    try:
        from core.sage.hooks import recall_context_for_scan
        sage_context = recall_context_for_scan(target or "")
        if sage_context:
            # Same flush rationale as the lifecycle banner —
            # when stdout is piped (operator's ``| tee``), block-
            # buffering makes these lines appear AFTER the
            # subprocess output unless explicitly flushed.
            print(
                f"📚 SAGE: Recalled {len(sage_context)} historical memories",
                flush=True,
            )
            for mem in sage_context[:3]:
                print(
                    f"   [{mem['confidence']:.0%}] {mem['content'][:80]}...",
                    flush=True,
                )
    except Exception:
        pass

    # Inject --out so the downstream script uses the lifecycle directory
    if "--out" not in args:
        args = args + ["--out", str(out_dir)]

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
            build_from_semgrep, build_from_codeql, write_record,
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
    except Exception:
        pass

    # SAGE: Post-scan storage
    if rc == 0:
        try:
            from core.sage.hooks import store_scan_results
            import json
            # Try to find and store SARIF results.
            # `os.walk(followlinks=False)` instead of `Path.rglob`:
            # rglob follows symlinks under Python <3.13. A scanner
            # that drops a stray symlink into out_dir (some tools'
            # caches link to /tmp paths that themselves get cleaned
            # mid-run, leaving dangling symlinks) would either hang
            # the SARIF discovery in a loop or escape out of the
            # out_dir entirely and pick up an unrelated SARIF file
            # from somewhere else on the filesystem.
            sarif_files = []
            seen_sarif = set()
            for dirpath, _dirnames, filenames in os.walk(
                str(out_dir), followlinks=False
            ):
                for fname in filenames:
                    if not fname.endswith(".sarif"):
                        continue
                    fpath = Path(dirpath) / fname
                    if fpath.is_symlink():
                        continue
                    key = str(fpath.resolve())
                    if key in seen_sarif:
                        continue
                    seen_sarif.add(key)
                    sarif_files.append(fpath)
            sarif_files.sort()
            findings = []
            for sf in sarif_files:
                try:
                    # `encoding="utf-8-sig"` so a BOM-prefixed SARIF
                    # file (some Windows-edited tool outputs, certain
                    # MSBuild-emitted SARIFs, the IDE-reformatted
                    # exports operators sometimes round-trip through)
                    # parses cleanly. Pre-fix the bare `read_text()`
                    # used the host locale's preferred encoding;
                    # cp1252/latin-1 hosts mangled non-ASCII evidence,
                    # AND a leading BOM landed at char 0 which the
                    # JSON parser rejected with "Expecting value:
                    # line 1 column 1 (char 0)" — no breadcrumb that
                    # the encoding was the actual problem.
                    sarif = json.loads(sf.read_text(encoding="utf-8-sig"))
                    for run in (sarif.get("runs") or []):
                        for result in (run.get("results") or []):
                            # Defensive locations[] guard. Pre-fix
                            # `result.get("locations") or [{}]` only
                            # handled None and empty list — but
                            # malformed SARIF emitters sometimes ship
                            # `locations` as a single dict (instead
                            # of array of dicts). Then `locs[0]`
                            # raised KeyError 0 (dict has no integer
                            # key) and the whole sarif-parse loop
                            # crashed for the file. isinstance guard
                            # falls back to `[{}]` so we get the
                            # "unknown" path string instead of a
                            # crash.
                            locs = result.get("locations")
                            if not isinstance(locs, list) or not locs:
                                locs = [{}]
                            first = locs[0] if isinstance(locs[0], dict) else {}
                            findings.append({
                                "rule_id": result.get("ruleId", "unknown"),
                                "level": result.get("level", "warning"),
                                "message": (result.get("message") or {}).get("text", ""),
                                "file_path": (first
                                              .get("physicalLocation", {})
                                              .get("artifactLocation", {})
                                              .get("uri", "unknown")),
                            })
                except Exception:
                    continue
            if findings:
                stored = store_scan_results(target or "", findings, {"total_findings": len(findings)})
                if stored > 0:
                    print(f"\n📚 SAGE: Stored {stored} findings for cross-run learning")
        except Exception:
            pass

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
            except Exception:
                pass
    else:
        fail_run(out_dir, error=f"exit code {rc}")
    return rc


# Set True by main() when --trust-repo is seen (and stripped from argv).
# Read by the subprocess mode handlers (codeql/agentic) to re-inject the
# flag into their child args — see the note in main().
_TRUST_REPO_SEEN = False

_active_dispatcher = None


def _get_or_start_dispatcher():
    """Lazy single dispatcher per ``raptor.py`` invocation.

    Phase B credential-isolation: when this is called, the spawned
    analysis script gets ``RAPTOR_LLM_SOCKET`` + a per-spawn token
    via ``spawn_worker``, and ``core/llm/providers.py`` routes its
    SDK calls through the dispatcher. API keys are still in env (for
    fallback) until Phase C drops the passthrough.
    """
    global _active_dispatcher
    if _active_dispatcher is not None:
        return _active_dispatcher
    try:
        from core.llm.dispatcher.auth import CredentialStore, seed_from_config
        from core.llm.dispatcher.server import LLMDispatcher
        import uuid
        import atexit
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
        _active_dispatcher = LLMDispatcher(
            run_id=f"raptor-{uuid.uuid4().hex[:8]}",
            creds=creds,
        )
        atexit.register(_active_dispatcher.shutdown)
        return _active_dispatcher
    except Exception as exc:
        # Failure to start the dispatcher must not break the run —
        # fall through to the env-direct path. The credential leak
        # channel stays open in this case but is no worse than today.
        # Surface the failure on stderr (in addition to the logger
        # warning) so operators see it regardless of log-level
        # config. After Phase C activation strips API keys from
        # ``get_llm_env``, this fallback's "no worse than today"
        # guarantee no longer holds — the fallback path will produce
        # workers without auth, and the symptom will be a confusing
        # "first LLM call fails" 30 seconds later. Step 1 of the
        # phased Phase C rollout: make this failure mode loud at the
        # moment it happens, before activation depends on it.
        import logging
        import sys as _sys
        msg = (
            f"raptor.py: credential-isolation dispatcher failed to "
            f"start ({type(exc).__name__}: {exc}). Falling back to "
            f"env-direct credential propagation. Once Phase C "
            f"activation lands, this fallback will produce workers "
            f"without LLM auth — fix the dispatcher startup failure "
            f"or expect script-level auth errors."
        )
        _sys.stderr.write(msg + "\n")
        _sys.stderr.flush()
        logging.getLogger(__name__).warning(
            "credential-isolation dispatcher failed to start, falling back "
            "to env-direct: %s", exc,
        )
        return None


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
            ).returncode
        except subprocess.TimeoutExpired:
            print(f"✗ Help rendering for {script_path.name} timed out",
                  file=sys.stderr)
            return 1

    try:
        from core.config import RaptorConfig
        # Phase B: opt the spawn into the credential-isolation
        # dispatcher. Worker env still has API keys (fallback path
        # exists until Phase C); ``RAPTOR_LLM_SOCKET`` and
        # ``RAPTOR_LLM_TOKEN_FD`` direct the worker's SDK calls
        # through the dispatcher when present.
        # Codex exec uses the Codex CLI's own authenticated session, not the
        # HTTP LLM SDK credential dispatcher. Skipping dispatcher startup here
        # avoids requiring httpx for Codex-only runs and keeps the fallback
        # warning from looking like the actual failure.
        dispatcher = None if _uses_codex_exec(script_path, args) else _get_or_start_dispatcher()
        if dispatcher is not None:
            from core.llm.dispatcher.spawn import spawn_worker
            proc = spawn_worker(
                dispatcher,
                cmd=cmd,
                label=script_path.name,
                # F102b: preserve PYTHONUSERBASE for the child
                # ``raptor_<mode>.py`` subprocess so its own opt-in
                # at ``get_safe_env(include_python_user_base=True)``
                # (e.g. ``raptor_agentic.py:757`` semgrep spawn)
                # has the value to restore. Without this flag the
                # parent strips PYTHONUSERBASE here, leaving the
                # child's restoration a no-op for the canonical
                # operator path. See W14-E3 §F102b.
                env=RaptorConfig.get_llm_env(include_python_user_base=True),
            )
            return proc.wait()
        # Fallback: pre-Phase-B behaviour, env-direct.
        # F102b: same opt-in as the dispatcher path above — the
        # canonical operator entry point must preserve
        # PYTHONUSERBASE for the spawned ``raptor_<mode>.py``
        # subprocess. See comment at the spawn_worker call site.
        result = subprocess.run(
            cmd,
            env=RaptorConfig.get_llm_env(include_python_user_base=True),
        )
        return result.returncode
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        # Mark any active run as cancelled. Pre-fix Ctrl-C
        # left runs in `status="in_progress"` forever — the
        # next /scan or /agentic invocation saw a stale
        # "active" run from yesterday's interrupted session
        # and either appended to it (corrupting findings
        # comparison) or refused to start ("a run is already
        # active"). cancel_run flips status to "cancelled"
        # and clears the active-run pointer; subsequent
        # invocations get a clean slate.
        try:
            from core.sandbox.summary import get_active_run_dir
            from core.run.metadata import cancel_run
            active = get_active_run_dir()
            if active:
                cancel_run(active)
        except Exception:
            # Best-effort. Don't mask the original Ctrl-C
            # by raising secondary errors during cleanup.
            pass
        return 130
    except Exception as e:
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
              f"{type(e).__name__}: {e}")
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
        print(f"✗ SCA shim not found: {sca_shim}")
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
        env = RaptorConfig.get_safe_env()
        env["_RAPTOR_TRUSTED"] = "1"
        result = subprocess.run(cmd, env=env)
        return result.returncode
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"\n✗ Error running raptor-sca: {e}")
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

    # Re-inject --trust-repo stripped by main(): the agentic child parses it
    # to set the cc_trust + codeql_trust overrides in its own process.
    if _TRUST_REPO_SEEN and '--trust-repo' not in args:
        args = ['--trust-repo'] + args

    return _run_with_lifecycle("agentic", agentic_script, args,
                              "Starting full autonomous workflow (Semgrep + CodeQL)...")


def mode_codeql(args: list) -> int:
    """Run CodeQL analysis (scan only — no autonomous analysis)."""
    script_root = Path(__file__).parent
    codeql_script = script_root / "raptor_codeql.py"

    if not codeql_script.exists():
        print(f"✗ CodeQL script not found: {codeql_script}", file=sys.stderr)
        return 1

    # Default to scan-only; autonomous analysis requires explicit --analyze
    if '--scan-only' not in args and '--analyze' not in args:
        args = ['--scan-only'] + args

    # Re-inject --trust-repo stripped by main(): the codeql child parses it
    # to set the cc_trust + codeql_trust overrides in its own process.
    if _TRUST_REPO_SEEN and '--trust-repo' not in args:
        args = ['--trust-repo'] + args

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
    import argparse as _ap
    parser = _ap.ArgumentParser(
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
    import subprocess
    from core.config import RaptorConfig
    script_root = Path(__file__).parent
    wrapper = script_root / "libexec" / "raptor-frida"
    if not wrapper.exists():
        print(f"✗ Frida wrapper not found: {wrapper}")
        return 1
    env = RaptorConfig.get_safe_env()
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
        'fuzz': script_root / "raptor_fuzzing.py",
        'web': script_root / "packages/web/scanner.py",
        'agentic': script_root / "raptor_agentic.py",
        'codeql': script_root / "raptor_codeql.py",
        'analyze': script_root / "packages/llm_analysis/agent.py",
    }


# Modes whose `<mode> --help` is rendered by spawning the child script's own
# argparse (no run lifecycle). Derived from _mode_help_scripts so it stays in
# lockstep with what show_mode_help can actually render.
_HELP_RENDER_MODES = frozenset(_mode_help_scripts().keys())


def show_mode_help(mode: str, preamble: bool = True) -> None:
    """Show detailed help for a specific mode.

    preamble=True prints a "[*] Help for mode: <mode>" header (the
    `raptor.py help <mode>` surface). The `<mode> --help` short-circuit
    passes preamble=False so the output is *only* the mode's argparse
    help, with nothing above it.
    """
    mode_scripts = _mode_help_scripts()

    if mode not in mode_scripts:
        print(f"✗ Unknown mode: {mode}", file=sys.stderr)
        print(f"Available modes: {', '.join(mode_scripts.keys())}")
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
  fuzz        - Binary fuzzing with AFL++
  web         - Web application security testing
  agentic     - Full autonomous workflow (Semgrep + CodeQL + LLM analysis)
  codeql      - CodeQL-only analysis
  analyze     - LLM-powered vulnerability analysis (requires SARIF input)
  doctor      - Status report for local setup (no claude needed)
  frida       - Dynamic instrumentation via Frida (alpha)

Examples:
  # Full autonomous workflow
  python3 raptor.py agentic --repo /path/to/code

  # Static analysis only
  python3 raptor.py scan --repo /path/to/code --policy-groups secrets,owasp

  # Binary fuzzing
  python3 raptor.py fuzz --binary /path/to/binary --duration 3600

  # Web scanning
  python3 raptor.py web --url https://example.com

  # CodeQL analysis
  python3 raptor.py codeql --repo /path/to/code --languages java

  # LLM analysis of existing SARIF
  python3 raptor.py analyze --repo /path/to/code --sarif findings.sarif

Sandbox isolation (mode-level flags — pass them AFTER the mode name,
not before; the top-level parser does not declare them directly):
  --sandbox {full,debug,network-only,none}
                        Force a sandbox profile (default: full)
  --no-sandbox          Alias for --sandbox none
  --audit               Log what enforcement WOULD have blocked
                        (composes with --sandbox profiles other than 'none')
  --audit-verbose       With --audit, log every traced syscall
                        (strace-style diagnostic)

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
    if "--trust-repo" in sys.argv:
        from core.security.cc_trust import set_trust_override
        global _TRUST_REPO_SEEN
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
        'fuzz': mode_fuzz,
        'web': mode_web,
        'agentic': mode_agentic,
        'codeql': mode_codeql,
        'analyze': mode_llm_analysis,
        'doctor': mode_doctor,
        'describe': mode_describe,
        'frida': mode_frida,
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
        print("\n\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
