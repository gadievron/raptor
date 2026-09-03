#!/usr/bin/env python3
"""
RAPTOR Truly Agentic Workflow

Complete end-to-end autonomous security testing:
0. Pre-exploit mitigation analysis (optional)
1. Scan code with Semgrep and CodeQL (parallel)
2. Validate exploitability (filter false positives and unreachable code)
3. Analyse each finding (read code, understand context, assess impact)
4. Generate exploit PoCs for confirmed vulnerabilities
5. Create secure patches
6. Cross-finding analysis (structural grouping, shared root causes)
7. Multi-model consensus (when configured)
8. Report everything
"""

import argparse
import contextlib
import os
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import NoReturn

# Add the repo root to sys.path. resolve() first: invoked through a
# symlink (or relatively on interpreters that don't absolutise
# __file__), the unresolved parent points at the wrong tree and
# core/packages imports resolve against it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core.config import RaptorConfig
from core.json import load_json, save_json
from core.logging import CONSOLE_LOG_LEVELS, configure_run_logging, get_logger
from core.run.safe_io import safe_run_mkdir
from core.sandbox import SANDBOX_ENGAGE_EXIT_CODE, SandboxSetupError
from core.schema_constants import VULN_TYPE_TO_CWE as _CWE_FROM_VULN_TYPE
from core.security.cc_trust import check_repo_claude_trust, set_trust_override

logger = get_logger()


def _kill_process_tree(process: "subprocess.Popen") -> None:
    """SIGKILL the child's whole process group, then the child itself.

    The long-running children here are spawned with
    ``start_new_session=True``, so each leads its own session/process
    group. Killing only the direct child on a phase timeout orphans
    its already-spawned grandchildren (LLM workers, scanner
    subprocesses), which keep running — and spending — after the
    operator's timeout fired. ``killpg`` reaps the tree the
    sessionization isolated; the direct ``kill()`` fallback covers a
    group that is already gone or a child that never made it to
    ``setsid``.
    """
    import signal
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    with contextlib.suppress(OSError):
        process.kill()


def _count_dropped_suppressions(path: Path) -> int:
    """Count the records in ``suppressions.jsonl`` that describe an
    actual drop.

    The file is a shared audit surface: writers also append
    record-only rows with ``dropped: false`` (evidence that a finding
    SURVIVED to the LLM), so a raw line count over-reports and can
    falsely trip the >=50% build-mismatch warning. A record with no
    ``dropped`` key predates the field and always described a drop.
    Blank and malformed lines are skipped; extra keys are tolerated.
    """
    import json
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    count = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("dropped", True) is True:
            count += 1
    return count


def _fail_run_and_exit(out_dir: Path, reason: str) -> NoReturn:
    """Stamp the run failed, then hard-exit.

    Direct ``python3 raptor_agentic.py`` invocations (a documented
    usage) have no wrapper to backstop the lifecycle: a bare
    ``sys.exit(1)`` after ``start_run`` leaves ``.raptor-run.json``
    at status "running" forever, which /project status, the live-run
    contention gate, and stale-run tooling then treat as a live run.
    Best-effort — a missing or corrupt run marker must never mask the
    original failure (the wrapper's own ``fail_run`` on rc!=0 is
    idempotent against an already-failed run).
    """
    with contextlib.suppress(Exception):
        from core.run import fail_run
        fail_run(out_dir, reason)
    sys.exit(1)


def _materialise_threat_model_phase(
    *,
    target: Path,
    out_dir: Path,
    prepass_result,
    refresh: bool = False,
    allow_stale: bool = False,
) -> dict:
    """Create project/run threat-model artefacts from an understand pre-pass."""
    summary = {
        "enabled": True,
        "completed": False,
        "refresh": bool(refresh),
        "entry_points": 0,
        "trust_boundaries": 0,
        "sinks": 0,
        "unchecked_flows": 0,
        # ``hardcoded_literal_count`` — count of detected hardcoded-
        # literal-credential findings. The name avoids "secret" /
        # "credential" / "key" / "token" so CodeQL's
        # ``py/clear-text-logging-sensitive-data`` doesn't flag the
        # dict-access flow itself. Operator-visible labels keep
        # "hardcoded secrets" wording (clearest for the operator);
        # CodeQL FP at the print sites is suppressed via per-line
        # ``# lgtm[query-id]`` comments rather than degrade the
        # labels.
        "hardcoded_literal_count": 0,
        "generated_candidates": 0,
        "threat_model_json": None,
        "threat_model_markdown": None,
        "candidate_sarif": None,
        "context_map": None,
        "skipped_reason": None,
        "allow_stale": bool(allow_stale),
    }
    if not prepass_result or not prepass_result.ran or not prepass_result.context_map_path:
        reason = getattr(prepass_result, "skipped_reason", None) if prepass_result else "understand pre-pass did not run"
        try:
            from core.orchestration.understand_bridge import find_understand_output
            understand_dir, stale = find_understand_output(out_dir, target_path=str(target))
            if understand_dir and (understand_dir / "context-map.json").exists():
                context_map_path = understand_dir / "context-map.json"
                summary["reused_context_map"] = True
                if stale:
                    summary["stale_files"] = sorted(stale)
                    if not allow_stale:
                        summary["skipped_reason"] = (
                            "reused /understand context-map is stale; rerun "
                            "with --threat-model-use-stale to accept it"
                        )
                        return summary
                    logger.warning(
                        "Threat model reused stale /understand context-map from %s (%d stale files)",
                        understand_dir, len(stale),
                    )
            else:
                summary["skipped_reason"] = reason or "understand pre-pass did not produce context-map.json"
                return summary
        except Exception as e:  # noqa: BLE001
            logger.debug("Threat model fallback lookup failed: %s", e)
            summary["skipped_reason"] = reason or "understand pre-pass did not produce context-map.json"
            return summary
    else:
        context_map_path = Path(prepass_result.context_map_path)
    context_map = load_json(context_map_path)
    if not isinstance(context_map, dict):
        summary["skipped_reason"] = f"invalid context map: {context_map_path}"
        return summary

    from core.threat_model import (
        diff_context_map,
        enrich_from_context_map,
        from_context_map,
        link_verified_outcomes,
        lint_model,
        load_model,
        project_threat_model_paths,
        project_threat_model_report_path,
        save_model,
        save_report,
    )

    # OWNER RULE: the threat-model phase READS AND WRITES project
    # state (model, report, project.json mutation, verified-outcome
    # linking), so the project comes from the RUN PIN — and only when
    # the pinned project's target actually matches this run's target.
    # The pre-fix ``find_project_for_target`` was a FIRST-MATCH scan
    # over all projects: with twin/machine projects sharing a target,
    # a run pinned to A wrote its threat model into an arbitrary
    # sibling B. A standalone (pin-null) run keeps only run-local
    # artifacts — a projectless run must not refresh any project's
    # model.
    project = None
    try:
        from core.project.project import ProjectManager
        from core.run.pin import resolve_run_pin
        mgr = ProjectManager()
        pin = resolve_run_pin(out_dir)
        if pin.project is not None and pin.writes_allowed:
            candidate = mgr.load(pin.project)
            if candidate is not None:
                try:
                    same = (Path(candidate.target).resolve()
                            in [Path(target).resolve(),
                                *Path(target).resolve().parents])
                except OSError:
                    same = False
                if same:
                    project = candidate
                else:
                    logger.warning(
                        "threat model: pinned project '%s' does not own "
                        "target %s — keeping run-local artifacts only",
                        pin.project, target,
                    )
    except Exception:  # noqa: BLE001
        mgr = None

    project_backed = project is not None
    if project_backed:
        json_path, markdown_path = project_threat_model_paths(project)
    else:
        json_path = out_dir / "threat-model.json"
        markdown_path = out_dir / "THREAT_MODEL.md"
        project = type("_RunThreatProject", (), {
            "name": Path(target).name,
            "target": str(target),
            "output_dir": str(out_dir),
        })()

    # Capture mtime at load time so save_model can refuse if a
    # concurrent writer (a second /agentic run, an operator
    # editor session, ``threat-model lint`` in parallel) raced
    # us. Lost-update race protection.
    load_mtime: float | None = None
    if project_backed and json_path.exists():
        try:
            load_mtime = json_path.stat().st_mtime
        except OSError:
            load_mtime = None

    existing_model = load_model(json_path) if project_backed else None
    try:
        if existing_model is not None and not refresh:
            model = enrich_from_context_map(existing_model, context_map)
            save_model(model, json_path, markdown_path, expected_mtime=load_mtime)
            summary["model_preserved"] = True
            summary["model_refreshed"] = False
            summary["model_migrated"] = True
        else:
            model = from_context_map(project, context_map)
            save_model(model, json_path, markdown_path)
            summary["model_preserved"] = False
            summary["model_refreshed"] = True
            summary["model_migrated"] = False
    except RuntimeError as e:
        logger.warning("Threat model save refused (concurrent writer?): %s", e)
        model = existing_model or from_context_map(project, context_map)
        summary["model_preserved"] = existing_model is not None
        summary["model_refreshed"] = existing_model is None
    except Exception as e:  # noqa: BLE001
        logger.warning("Threat model construction failed: %s", e)
        model = existing_model or from_context_map(project, context_map)
        summary["model_preserved"] = existing_model is not None
        summary["model_refreshed"] = existing_model is None

    linked_outcomes = 0
    try:
        from core.labeled_attempts.view import collect_outcomes
        project_root = Path(project.output_dir) if project_backed else None
        outcomes = collect_outcomes(out_dir, project_root=project_root)
        linked_outcomes = len(outcomes)
        if outcomes:
            link_verified_outcomes(model, outcomes)
            # Capture mtime again (we just wrote above) before the
            # outcomes-merge save, so a concurrent writer that
            # sneaked in between the two saves is still caught.
            try:
                outcomes_mtime = json_path.stat().st_mtime
            except OSError:
                outcomes_mtime = None
            save_model(
                model, json_path, markdown_path,
                expected_mtime=outcomes_mtime,
            )
    except RuntimeError as e:
        logger.warning("Threat model save refused (concurrent writer?): %s", e)
    except Exception as e:  # noqa: BLE001
        logger.debug("Threat model verified-outcome linking skipped: %s", e)

    if mgr is not None and hasattr(project, "name") and hasattr(project, "to_dict"):
        try:
            project.threat_model_path = str(json_path)
            project.threat_model_updated = model.updated_at
            save_json(mgr.projects_dir / f"{project.name}.json", project.to_dict())
        except Exception as e:  # noqa: BLE001
            logger.debug("Threat model project metadata update skipped: %s", e)

    candidate_sarif = out_dir / "threat-model-candidates.sarif"
    candidate_count = _write_threat_model_candidate_sarif(context_map, candidate_sarif)
    lint = lint_model(model)
    drift = diff_context_map(model, context_map)
    report_path = (
        project_threat_model_report_path(project)
        if project_backed else out_dir / "threat-model-report.md"
    )
    save_report(model, report_path, lint=lint, drift=drift)
    lint_path = out_dir / "threat-model-lint.json"
    drift_path = out_dir / "threat-model-drift.json"
    threats_path = out_dir / "threats.json"
    save_json(lint_path, {"issues": lint})
    save_json(drift_path, drift)
    save_json(threats_path, {"threats": model.threats})

    summary.update({
        "completed": True,
        "entry_points": len(context_map.get("entry_points") or context_map.get("sources") or []),
        "trust_boundaries": len(context_map.get("trust_boundaries") or []),
        "sinks": len(context_map.get("sink_details") or context_map.get("sinks") or []),
        "unchecked_flows": len(context_map.get("unchecked_flows") or []),
        "hardcoded_literal_count": len(context_map.get("hardcoded_secrets") or []),
        "generated_candidates": candidate_count,
        "threat_model_json": str(json_path),
        "threat_model_markdown": str(markdown_path),
        "threat_model_report": str(report_path),
        "threat_model_lint": str(lint_path),
        "threat_model_drift": str(drift_path),
        "threats": str(threats_path),
        "threats_count": len(model.threats),
        "controls_count": len(model.controls),
        "evidence_count": len(model.evidence),
        "lint_issues": len(lint),
        "drifted": bool(drift.get("is_drifted")),
        "verified_outcomes_linked": linked_outcomes,
        "candidate_sarif": str(candidate_sarif) if candidate_count else None,
        "context_map": str(context_map_path),
    })
    save_json(out_dir / "threat-model-summary.json", summary)
    return summary


def _sarif_line(value, default: int = 1) -> int:
    try:
        line = int(value)
    except (TypeError, ValueError):
        return default
    return line if line > 0 else default


def _write_threat_model_candidate_sarif(context_map: dict, sarif_path: Path) -> int:
    flows = context_map.get("unchecked_flows") or []
    if not isinstance(flows, list) or not flows:
        return 0
    entries = {
        str(e.get("id")): e for e in (context_map.get("entry_points") or [])
        if isinstance(e, dict) and e.get("id")
    }
    sinks = {
        str(s.get("id")): s for s in (context_map.get("sink_details") or [])
        if isinstance(s, dict) and s.get("id")
    }
    results = []
    for idx, flow in enumerate(flows, start=1):
        if not isinstance(flow, dict):
            continue
        entry = entries.get(str(flow.get("entry_point") or ""), {})
        sink = sinks.get(str(flow.get("sink") or ""), {})
        sink_file = str(sink.get("file") or flow.get("file") or "unknown")
        sink_line = _sarif_line(sink.get("line") or flow.get("line"))
        entry_file = str(entry.get("file") or sink_file)
        entry_line = _sarif_line(entry.get("line"), default=sink_line)
        severity = str(flow.get("severity") or "warning").lower()
        level = "error" if severity in {"critical", "high"} else "warning"
        message = str(flow.get("missing_boundary") or "Unchecked flow from entry point to sink")
        flow_id = str(flow.get("id") or f"UF-{idx:03d}")
        rule_id = "raptor.threat_model.unchecked_flow"
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{flow_id}: {message}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": sink_file},
                    "region": {"startLine": sink_line, "endLine": sink_line},
                },
                "message": {"text": str(sink.get("notes") or message)},
            }],
            "codeFlows": [{
                "threadFlows": [{
                    "locations": [
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": entry_file},
                                    "region": {"startLine": entry_line},
                                },
                                "message": {"text": str(entry.get("notes") or flow.get("entry_point") or "entry point")},
                            }
                        },
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": sink_file},
                                    "region": {"startLine": sink_line},
                                },
                                "message": {"text": str(sink.get("notes") or flow.get("sink") or "sink")},
                            }
                        },
                    ]
                }]
            }],
            "properties": {
                "source": "threat_model",
                "entry_point": flow.get("entry_point"),
                "sink": flow.get("sink"),
                "severity": severity,
            },
            "fingerprints": {
                "matchBasedId/v1": f"threat-model:{flow_id}:{flow.get('entry_point')}:{flow.get('sink')}",
            },
        })

    if not results:
        return 0
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "RAPTOR Threat Model",
                    "rules": [{
                        "id": "raptor.threat_model.unchecked_flow",
                        "name": "Unchecked flow from mapped entry point to sink",
                        "shortDescription": {
                            "text": "Threat-model candidate from /understand unchecked flow"
                        },
                    }],
                }
            },
            "results": results,
        }],
    }
    save_json(sarif_path, sarif)
    return len(results)


def _print_threat_model_phase(summary: dict) -> None:
    print("\n" + "=" * 70)
    print("THREAT MODEL PHASE")
    print("=" * 70)
    if not summary.get("completed"):
        print(f"Skipped: {summary.get('skipped_reason') or 'not available'}")
        return
    print(f"  entry_points:         {summary.get('entry_points', 0)}")
    print(f"  trust_boundaries:     {summary.get('trust_boundaries', 0)}")
    print(f"  sinks:                {summary.get('sinks', 0)}")
    print(f"  unchecked_flows:      {summary.get('unchecked_flows', 0)}")
    # CodeQL ``py/clear-text-logging-sensitive-data`` flags this
    # print because the f-string literal contains "hardcoded_secrets".
    # The value is the integer COUNT of detected findings; the label
    # is the clearest wording for the operator surface. Suppress at
    # the print site rather than degrade the label.
    print(  # lgtm[py/clear-text-logging-sensitive-data]
        f"  hardcoded_secrets:    "
        f"{summary.get('hardcoded_literal_count', 0)}"
    )
    print(f"  generated_candidates: {summary.get('generated_candidates', 0)}")
    print(f"  threats:              {summary.get('threats_count', 0)}")
    print(f"  controls:             {summary.get('controls_count', 0)}")
    print(f"  evidence:             {summary.get('evidence_count', 0)}")
    print(f"  lint_issues:          {summary.get('lint_issues', 0)}")
    print(f"  drifted:              {'yes' if summary.get('drifted') else 'no'}")
    if summary.get("model_migrated"):
        print("  model_migrated:       yes")
    print(f"  model:                {summary.get('threat_model_json')}")
    if summary.get("threat_model_report"):
        print(f"  report:               {summary.get('threat_model_report')}")
    if summary.get("reused_context_map"):
        print(f"  reused_context_map:   {summary.get('context_map')}")
    if summary.get("stale_files"):
        print(f"  stale_files:          {len(summary.get('stale_files') or [])}")
    if summary.get("candidate_sarif"):
        print(f"  handoff:              {summary.get('candidate_sarif')}")


def run_command_streaming(
    cmd: list,
    description: str,
    timeout: int = 1800,
) -> tuple[int, str, str]:
    """
    Run a command and stream output in real-time while also capturing it.

    This is useful for long-running commands where you want to show progress
    to the user but still capture the full output for processing.

    Args:
        cmd: Command and arguments as a list
        description: Human-readable description of the command
        timeout: Wall-clock timeout in seconds (default 1800 = 30 min).
            ``0`` disables the timeout entirely — caller's responsibility
            to Ctrl-C if the subprocess hangs. Operator-overridable via
            the ``--phase-timeout`` CLI flag for kernel-scale targets
            where the analysis subprocess can take hours.

    Returns:
        Tuple of (return_code, stdout, stderr)
    """
    import threading

    logger.info("Running: %s", description)
    print(f"\n[*] {description}...")

    def stream_output(pipe, storage, prefix: str="") -> None:
        """Read from pipe line by line and print while storing."""
        try:
            for line in iter(pipe.readline, ''):
                if line:
                    storage.append(line)
                    # Strip [INFO] prefix for cleaner output.
                    # Keep [WARNING], [ERROR], [DEBUG] visible.
                    display = line.rstrip()
                    display = display.removeprefix("[INFO] ")
                    print(f"{prefix}{display}", flush=True)
        except Exception as exc:  # noqa: BLE001
            # Pre-fix the exception silently exited the reader thread.
            # Parent never learned the child's output stopped
            # streaming, and the consumed-but-not-stored output was
            # dropped from run logs. Push a sentinel so the caller
            # can detect truncation post-hoc, and surface the cause
            # to stderr (loggers may not be configured at this depth
            # of the call stack).
            sentinel = (
                f"[RAPTOR stream_output reader aborted: "
                f"{type(exc).__name__}: {exc!s}]\n"
            )
            storage.append(sentinel)
            # Last-ditch surface at thread abort: stderr may be a
            # closed/broken pipe (OSError) or a closed text stream
            # (ValueError) — nothing else is worth dying over here.
            with contextlib.suppress(OSError, ValueError):
                print(sentinel, end="", file=sys.stderr, flush=True)
        finally:
            pipe.close()

    # Phase B credential-isolation: when raptor_agentic.py was
    # itself spawned with a dispatcher session (RAPTOR_LLM_SOCKET +
    # RAPTOR_LLM_TOKEN_FD), relay the session to the grandchild so
    # ``--sequential`` mode of ``packages/llm_analysis/agent.py`` can
    # reach the LLM after Phase C drops API keys from the env. Same
    # token value, fresh inheritable FD — see
    # ``core.llm.dispatcher.client.relay_for_grandchild``.
    # preserve_proxy: these children are RAPTOR's own analysis
    # scripts; they host egress proxies and spawn `claude` CLI
    # grandchildren, all of which resolve the upstream route from
    # their own process env. Without this, the operator's mandatory
    # proxy is gone one level down and every outbound call dials
    # direct (and gets blocked).
    child_env = RaptorConfig.get_safe_env(preserve_proxy=True)
    # Transport-routing family (CLAUDE_CODE_USE_*, ANTHROPIC_MODEL,
    # AWS profile/region NAMES, RAPTOR_BEDROCK_*/RAPTOR_CC_*): the
    # child's claudecode transport builds cc_subprocess_env() from
    # ITS OWN environ, and Bedrock entry backfill reads these — a
    # starved child flips the operator's backend selection. Names
    # and flags only; API keys stay OUT of this env by design
    # (Phase B relays the dispatcher session instead).
    child_env.update(RaptorConfig.llm_routing_env())
    child_pass_fds: list[int] = []
    if os.environ.get("RAPTOR_LLM_SOCKET"):
        try:
            from core.llm.dispatcher.client import relay_for_grandchild
            socket_path, token_fd = relay_for_grandchild()
            child_env["RAPTOR_LLM_SOCKET"] = socket_path
            child_env["RAPTOR_LLM_TOKEN_FD"] = str(token_fd)
            child_pass_fds.append(token_fd)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "credential-isolation relay to grandchild failed, "
                "falling back to env-direct: %s",
                exc,
            )
            # Make the env-direct fallback real: the safe env built
            # above carries neither the dispatcher socket nor any API
            # keys (they stay out by design when the relay works), so
            # without re-adding the keys the child would silently run
            # with no external-LLM access at all. get_llm_env is the
            # same env-direct posture raptor.py itself falls back to
            # when the dispatcher fails to start.
            child_env = RaptorConfig.get_llm_env()
            token_fd = None
    else:
        token_fd = None

    process = None
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=child_env,
            pass_fds=tuple(child_pass_fds),
            # Detach from parent's process group so operator
            # Ctrl-C in the parent doesn't propagate SIGINT
            # to the child via the controlling terminal. The
            # parent handles its own KeyboardInterrupt and
            # decides what to do with the child (terminate
            # gracefully, kill, or let finish). Pre-fix
            # SIGINT reached the child too — race-condition
            # cleanup where the child died mid-write before
            # the parent's handler could log a meaningful
            # message.
            start_new_session=True,
        )
        # The child has inherited the FD; close our copy so the
        # pipe's EOF tracks the child's lifetime, not ours. Clear the
        # local afterwards so the error paths below never double-close
        # a number the OS may have already reused.
        if token_fd is not None:
            try:
                os.close(token_fd)
            except OSError:
                pass
            token_fd = None

        stdout_lines = []
        stderr_lines = []

        # Create threads to read stdout and stderr concurrently.
        #
        # `daemon=True` so an unexpected interpreter exit doesn't
        # block on a stuck reader. Pre-fix the threads were
        # foreground (default `daemon=False`); on a failure path
        # where the parent's main thread raised before reaching
        # the bounded join (e.g. a downstream lifecycle helper
        # crashing during `_complete_lifecycle`), Python's atexit
        # path waited indefinitely for the readers to finish —
        # which they wouldn't, because the child process was
        # gone but its grandchildren held the pipe FDs open.
        # Operators saw RAPTOR "complete" then HANG at exit
        # instead of returning to the prompt; the only escape
        # was Ctrl-C, which often killed the run summary too.
        # With daemon=True the interpreter exits regardless,
        # losing any in-flight stream lines (acceptable — by
        # then the run is already over and post-processing is
        # done).
        stdout_thread = threading.Thread(
            target=stream_output,
            args=(process.stdout, stdout_lines),
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=stream_output,
            args=(process.stderr, stderr_lines),
            daemon=True,
        )

        # Start reading threads
        stdout_thread.start()
        stderr_thread.start()

        # Wait for process to complete. ``timeout=0`` means unbounded
        # — pass ``None`` to subprocess.wait so the operator can run
        # kernel-scale analyses that legitimately take hours.
        # ``RaptorConfig.DEFAULT_TIMEOUT`` may itself be ``None``
        # (set by --phase-timeout 0 mutation at startup) — fall
        # through gracefully in that case too.
        process.wait(timeout=(timeout or None))

        # Wait for all output to be read.
        # Bounded join: pre-fix `.join()` (no timeout) hung forever
        # if the reader thread blocked on a stuck pipe (process is
        # gone but the OS pipe-buffer drain isn't progressing — rare
        # with subprocess.PIPE + .wait() done first, but seen on
        # macOS with zombie children that keep the pipe FD alive).
        # 5s is plenty after process.wait() returned — by then the
        # OS has flushed everything that's coming.
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)

        stdout = ''.join(stdout_lines)
        stderr = ''.join(stderr_lines)

        return process.returncode, stdout, stderr

    except subprocess.TimeoutExpired:
        logger.error("Command timed out: %s", description)
        # Reap properly: kill THEN wait. Pre-fix `process.kill()`
        # alone left the child as a zombie until the OS reaped it
        # via SIGCHLD (or until our parent process exited),
        # potentially holding open pipe FDs and sandbox resources.
        # The follow-up `wait(timeout=5)` collects the exit status
        # and frees the kernel slot. Group kill, not just the child —
        # see _kill_process_tree: grandchildren (LLM workers) must not
        # keep spending after the timeout.
        _kill_process_tree(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            logger.warning(
                "Process %d did not exit within 5s of SIGKILL — "
                "leaving as zombie (OS will reap on parent exit)",
                process.pid,
            )
        # Bounded thread join after kill so we don't hang on the
        # pipe-reader threads — same rationale as the success path.
        stdout_thread.join(timeout=5)
        stderr_thread.join(timeout=5)
        return -1, "", "Timeout"
    except Exception as e:  # noqa: BLE001
        logger.error("Command failed: %s", e)
        # ``process`` stays None when Popen itself raised (bad
        # executable, exec failure) — kill() on the unbound name
        # raised UnboundLocalError here pre-fix, masking the real
        # error instead of returning the graceful (-1, "", str(e)).
        # In that same case the relayed token FD was never handed to a
        # child and never closed above — close it here or every failed
        # spawn leaks one fd.
        if token_fd is not None:
            with contextlib.suppress(OSError):
                os.close(token_fd)
        if process is not None:
            # kill() on an already-dead child raises OSError; wait() can
            # time out (SubprocessError). A miswired handle propagates.
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                _kill_process_tree(process)
                process.wait(timeout=5)
        return -1, "", str(e)


def _prepare_fuzz_crashes_for_validate(
    *,
    binary_path: Path,
    fuzzing_result: dict,
    fuzz_out: Path,
    limit: int,
) -> dict:
    """Analyse fuzz crashes and emit /validate FindingsContainer input."""
    from packages.binary_analysis import CrashAnalyser

    fuzz_out = Path(fuzz_out)
    crash_analysis_dir = fuzz_out / "crash_analysis"
    crash_analysis_dir.mkdir(parents=True, exist_ok=True)

    crashes_dir = fuzzing_result.get("crashes_dir")
    crash_files = _collect_crash_files(Path(crashes_dir)) if crashes_dir else []
    if limit > 0:
        crash_files = crash_files[:limit]

    replay_outputs = _replay_fuzz_crashes(
        binary_path=Path(binary_path),
        crash_files=crash_files,
        out_dir=crash_analysis_dir / "replay",
    )

    analyser = CrashAnalyser(binary_path)
    contexts = []
    findings = []
    seen_roots = set()

    for index, crash_file in enumerate(crash_files, start=1):
        signal = _infer_fuzz_signal(crash_file)
        crash_id = f"CRASH-{index:04d}"
        context = analyser.analyse_crash(crash_id, crash_file, signal)
        context.crash_type = analyser.classify_crash_type(context)
        context_dict = asdict(context)
        context_dict["replay"] = replay_outputs.get(str(crash_file), [])
        contexts.append(context_dict)

        root_key = (
            context.stack_hash
            or f"{context.signal}:{context.crash_type}:{context.function_name}:{context.crash_address}"
        )
        if root_key in seen_roots:
            continue
        seen_roots.add(root_key)
        findings.append(_crash_context_to_validate_finding(context, context_dict["replay"]))

    contexts_path = crash_analysis_dir / "crash-contexts.json"
    triage_path = crash_analysis_dir / "triage-summary.json"
    findings_path = fuzz_out / "crashes_for_validation.json"
    save_json(
        contexts_path,
        {
            "binary": str(Path(binary_path).resolve()),
            "crashes_dir": fuzzing_result.get("crashes_dir", ""),
            "stats": fuzzing_result.get("stats", {}),
            "contexts": contexts,
        },
    )
    save_json(
        triage_path,
        {
            "total_crashes": len(crash_files),
            "unique_root_causes": len(findings),
            "replay_binaries": _candidate_replay_binaries(Path(binary_path)),
            "dedupe_key": "stack_hash or signal:type:function:address",
        },
    )
    save_json(
        findings_path,
        {
            "stage": "fuzzing-crash-analysis",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_path": str(Path(binary_path).resolve()),
            "source": "raptor-fuzzing",
            "findings": findings,
        },
    )
    return {"contexts": contexts_path, "findings": findings_path, "triage": triage_path}


def _candidate_replay_binaries(binary_path: Path) -> list[str]:
    """Find ASAN/debug sibling binaries for crash replay."""
    binary_path = Path(binary_path).resolve()
    stem = binary_path.stem
    suffix = binary_path.suffix
    names = []
    if stem.endswith("_afl"):
        base = stem[:-4]
        names.extend([f"{base}_asan{suffix}", f"{base}_debug{suffix}", f"{base}{suffix}"])
    names.extend([f"{stem}_asan{suffix}", f"{stem}_debug{suffix}"])

    candidates = []
    for name in names:
        path = binary_path.with_name(name)
        if path == binary_path or not path.exists() or not path.is_file():
            continue
        if path.stat().st_mode & 0o111:
            candidates.append(str(path))
    return list(dict.fromkeys(candidates))


# Sanitizer report markers that count as crash evidence on replay.
# LeakSanitizer is deliberately absent: a benign leak reported at
# process exit is not a reproduction of the fuzzed crash.
_REPLAY_CRASH_MARKERS = (
    b"ERROR: AddressSanitizer",
    b"ERROR: MemorySanitizer",
    b"ERROR: ThreadSanitizer",
    b"UndefinedBehaviorSanitizer",
    b"AddressSanitizer:DEADLYSIGNAL",
    b"Segmentation fault",
    b"stack smashing detected",
)


def _replay_reproduced(returncode: int, stderr_data: bytes) -> bool:
    """Whether a replay run counts as reproducing the crash.

    Any-nonzero-exit is too loose: a replay binary that exits 1 on a
    usage error (it wanted argv while the input arrived on stdin), or
    that merely reports a benign leak at exit, is not a reproduction —
    and those entries ride into the /validate handoff as dynamic
    confirmation. Count only real crash evidence: death by signal
    (negative returncode, or the shell-style 128+signal some sandbox
    wrappers surface) or a sanitizer crash report on stderr.
    """
    if returncode < 0 or returncode >= 128:
        return True
    if returncode == 0:
        return False
    return any(marker in stderr_data for marker in _REPLAY_CRASH_MARKERS)


def _replay_fuzz_crashes(*, binary_path: Path, crash_files: list[Path], out_dir: Path) -> dict:
    """Replay crash inputs against ASAN/debug sibling binaries and save logs.

    Crash inputs are attacker-controlled by definition (the fuzzer searched
    the input space for crashes); each candidate binary is run under
    ``core.sandbox`` with ``block_network=True`` and ``restrict_reads=True``
    so a malicious crash input that triggers code in the binary can't reach
    the operator's credentials, network, or filesystem outside the replay
    workspace. Mirrors the pattern used by ``packages/fuzzing/libfuzzer_runner.py``.
    """
    from core.sandbox import run as _sandbox_run

    out_dir.mkdir(parents=True, exist_ok=True)
    candidates = [Path(p) for p in _candidate_replay_binaries(binary_path)]
    results: dict[str, list[dict]] = {}
    if not candidates:
        return results

    env = RaptorConfig.get_safe_env()
    # detect_leaks=0: LeakSanitizer fires at process exit on benign
    # leaks and (with abort_on_error) turns a clean replay into a
    # nonzero exit — replay is asking "does this input crash the
    # binary", not "does the binary leak".
    env.setdefault("ASAN_OPTIONS", "abort_on_error=1:symbolize=1:detect_leaks=0")
    env.setdefault("UBSAN_OPTIONS", "abort_on_error=1:symbolize=1:print_stacktrace=1")

    for crash_file in crash_files:
        entries = []
        if not crash_file.is_file():
            results[str(crash_file)] = entries
            continue
        for candidate in candidates:
            label = f"{crash_file.name}__{candidate.name}".replace("/", "_")
            stdout_path = out_dir / f"{label}.stdout.log"
            stderr_path = out_dir / f"{label}.stderr.log"
            try:
                # block_network=True: a malicious replay binary cannot
                # exfiltrate ASAN output or fingerprint metadata over
                # the network. target+output give mount-ns something
                # to bind-mount so the tracer can attach. We open the
                # crash file as a file descriptor and pass stdin= —
                # sandbox.run's mount-ns spawn doesn't plumb the
                # input=<bytes> kwarg cleanly (see core/sandbox/
                # context.py audit), but a real FD survives the
                # fork+exec.
                with open(crash_file, "rb") as crash_fh:
                    proc = _sandbox_run(
                        [str(candidate)],
                        stdin=crash_fh,
                        block_network=True,
                        target=str(candidate.parent),
                        output=str(out_dir),
                        restrict_reads=True,
                        fake_home=True,
                        capture_output=True,
                        timeout=15,
                        env=env,
                    )
                stdout_path.write_bytes(proc.stdout or b"")
                stderr_path.write_bytes(proc.stderr or b"")
                entries.append({
                    "binary": str(candidate),
                    "returncode": proc.returncode,
                    "stdout": str(stdout_path),
                    "stderr": str(stderr_path),
                    "reproduced": _replay_reproduced(
                        proc.returncode, proc.stderr or b"",
                    ),
                })
            except subprocess.TimeoutExpired as e:
                stdout_path.write_bytes(e.stdout or b"")
                stderr_path.write_bytes(e.stderr or b"")
                entries.append({
                    "binary": str(candidate),
                    "returncode": "timeout",
                    "stdout": str(stdout_path),
                    "stderr": str(stderr_path),
                    # A hang only reproduces a hang: for a timeout-
                    # class input the replay confirmed the finding;
                    # for a crash-class input it did not crash.
                    "reproduced": crash_file.name.startswith("timeout-"),
                })
            except (OSError, subprocess.SubprocessError, ValueError) as e:
                # Narrowed from `except Exception` per PR #488 review.
                # OSError covers file IO (write_bytes on stdout/stderr
                # paths, missing binary). subprocess.SubprocessError
                # covers CalledProcessError + TimeoutExpired.
                # ValueError covers bad-arg shapes. Anything else
                # (RuntimeError, MemoryError, KeyboardInterrupt etc.)
                # propagates — operators see real bugs instead of
                # silently turning them into "reproduced=False"
                # replay entries.
                entries.append({
                    "binary": str(candidate),
                    "error": str(e),
                    "reproduced": False,
                })
        results[str(crash_file)] = entries
    save_json(out_dir / "replay-summary.json", results)
    return results


def _collect_crash_files(crashes_dir: Path) -> list[Path]:
    # Path("") stringifies to "." — `not str(crashes_dir)` can never be
    # true, and falling through would scan the CWD (the RAPTOR repo
    # dir) for crash files. Treat both spellings as "no crashes dir".
    if str(crashes_dir) in ("", ".") or not crashes_dir.exists():
        return []
    prefixes = ("crash-", "timeout-", "oom-", "id:")
    return sorted(
        path for path in crashes_dir.iterdir()
        if path.is_file() and path.name.startswith(prefixes)
    )


def _infer_fuzz_signal(crash_file: Path) -> str:
    name = crash_file.name.lower()
    if name.startswith("timeout-"):
        return "timeout"
    if name.startswith("oom-"):
        return "oom"
    if "sig:" in name:
        return name.split("sig:", 1)[1].split(",", 1)[0]
    return "libfuzzer"


def _crash_context_to_validate_finding(context, replay: list[dict] | None = None) -> dict:
    vuln_type = context.crash_type or "crash"
    description = (
        f"Fuzzing crash in {context.function_name or 'unknown function'} "
        f"with signal {context.signal}."
    )
    return {
        "id": context.crash_id,
        "file": str(context.binary_path),
        "function": context.function_name or "unknown",
        "line": 0,
        "vuln_type": vuln_type,
        "status": "confirmed",
        "confidence": "high",
        "description": description,
        "candidate_reasoning": description,
        "dataflow_summary": (
            f"{context.input_file} -> {context.function_name or 'unknown'} -> "
            f"{context.crash_instruction or context.crash_address or 'crash'}"
        ),
        "proof_lines": [context.crash_instruction] if context.crash_instruction else [],
        "proof_source": str(context.input_file),
        "proof_sink": context.crash_instruction or context.crash_address or "",
        "origin": "fuzzing",
        "ruling": {
            "status": "confirmed",
            "reason": "Crash reproduced during RAPTOR fuzzing and analysed by CrashAnalyser.",
        },
        "crash": {
            "input_file": str(context.input_file),
            "signal": context.signal,
            "stack_hash": context.stack_hash,
            "crash_address": context.crash_address,
            "function": context.function_name,
            "replay": replay or [],
        },
    }


def _run_fuzz_validation_smoke(findings_path: Path, target: Path, out_dir: Path) -> dict:
    """Materialise a validate-style run from fuzz findings and run stage-1 outputs."""
    validation_dir = out_dir / "fuzz_validation"
    validation_dir.mkdir(parents=True, exist_ok=True)
    findings = load_json(findings_path)
    if not findings:
        return {"ran": False, "reason": "no fuzz findings"}
    # Provenance chokepoint for the validate-style handoff: crash
    # analysis mixes mechanical reproduction data with LLM-derived
    # narrative, so the container is stamped untrusted (docs/security.md
    # I2-(b)) and marked free-text fields are defanged.
    from core.artifacts.provenance import sanitise_free_text, stamp_provenance
    from packages.exploitability_validation.schemas import FINDINGS_SCHEMA
    if isinstance(findings, dict):
        sanitise_free_text(findings, FINDINGS_SCHEMA)
    stamp_provenance(findings, "agentic-fuzz", untrusted=True,
                     overwrite_generator=False)
    save_json(validation_dir / "findings.json", findings)
    helper = Path(__file__).resolve().parent / "libexec" / "raptor-validation-helper"
    stdout_path = validation_dir / "validation-helper.stdout.log"
    stderr_path = validation_dir / "validation-helper.stderr.log"
    try:
        proc = subprocess.run(
            [str(helper), "1", str(validation_dir), "--target", str(target)],
            capture_output=True,
            text=True,
            timeout=120,
            # get_llm_env: the helper's witness stage builds an
            # LLMClient — a bare safe env silently degrades it to
            # "no LLM available" and strips the backend routing.
            env=RaptorConfig.get_llm_env(),
            check=False,
        )
        stdout_path.write_text(proc.stdout or "", encoding="utf-8")
        stderr_path.write_text(proc.stderr or "", encoding="utf-8")
    except Exception as e:  # noqa: BLE001
        save_json(validation_dir / "validation-error.json", {"error": str(e)})
        return {"ran": False, "reason": str(e), "dir": str(validation_dir)}
    report_path = validation_dir / "validation-report.md"
    if proc.returncode != 0 or not report_path.exists():
        save_json(validation_dir / "validation-error.json", {
            "returncode": proc.returncode,
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        })
        return {
            "ran": False,
            "reason": f"raptor-validation-helper exited {proc.returncode}",
            "dir": str(validation_dir),
            "stdout": str(stdout_path),
            "stderr": str(stderr_path),
        }
    return {
        "ran": True,
        "dir": str(validation_dir),
        "findings": str(validation_dir / "findings.json"),
        "report": str(report_path),
        "stdout": str(stdout_path),
        "stderr": str(stderr_path),
    }


class _PipeDrainer:
    """Concurrently drain a child's stdout/stderr PIPEs into memory.

    The Semgrep and CodeQL scanner children are spawned in parallel with
    PIPE streams. Draining them sequentially (communicate() on one, then
    the other) let the not-yet-drained child block in write() once its
    output exceeded the OS pipe buffer (~64KB), silently serializing the
    "parallel" phase and skewing its timeout budget. One reader thread
    per stream keeps both children draining while the parent waits.
    """

    def __init__(self, proc: subprocess.Popen) -> None:
        self._proc = proc
        self._chunks: dict[str, list[str]] = {"stdout": [], "stderr": []}
        self._threads: list[threading.Thread] = []
        for name in ("stdout", "stderr"):
            stream = getattr(proc, name)
            if stream is None:
                continue
            t = threading.Thread(
                target=self._read,
                args=(stream, self._chunks[name]),
                name=f"pipe-drain-{name}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

    @staticmethod
    def _read(stream, chunks: list[str]) -> None:
        try:
            # Incremental line reads (not readlines()/list()) so a
            # killed child's partial output is kept up to the error.
            for line in stream:
                chunks.append(line)  # noqa: PERF402 — incremental drain, not a copy
        except (OSError, ValueError):
            # Pipe closed under us (child killed) — keep what we have.
            pass

    def collect(self, timeout: float | None = None) -> tuple[str, str]:
        """Wait for child exit and return (stdout, stderr).

        Raises subprocess.TimeoutExpired like communicate(); safe to
        call again after killing the child.
        """
        self._proc.wait(timeout=timeout)
        for t in self._threads:
            t.join(timeout=10)
        return (
            "".join(self._chunks["stdout"]),
            "".join(self._chunks["stderr"]),
        )


def _safe_int(value) -> int:
    if value is None:
        return 0
    text = str(value).strip().replace(",", "").rstrip("%")
    try:
        return int(float(text))
    except (TypeError, ValueError):
        return 0


def _safe_float(value) -> float | None:
    if value is None:
        return None
    text = str(value).strip().replace(",", "").rstrip("%")
    try:
        return float(text)
    except (TypeError, ValueError):
        return None


def _build_fuzz_phase_summary(fuzzing_result: dict | None, fuzz_out: Path | None) -> dict:
    if not fuzzing_result:
        return {"completed": False}
    if fuzzing_result.get("campaign_failed"):
        # Every AFL instance died without a clean exit and nothing was
        # found — the campaign may have executed zero inputs. Reporting
        # completed=True here would contradict the runner's own
        # CAMPAIGN FAILED verdict (and its non-zero exit).
        return {
            "completed": False,
            "campaign_failed": True,
            "fuzzer": fuzzing_result.get("fuzzer"),
            "crashes": 0,
            "telemetry": fuzzing_result.get("telemetry"),
        }
    stats = fuzzing_result.get("stats") or {}
    telemetry = {}
    telemetry_path = fuzzing_result.get("telemetry")
    if telemetry_path:
        _raw = load_json(telemetry_path)
        telemetry = _raw if isinstance(_raw, dict) else {}
    crashes_dir = fuzzing_result.get("crashes_dir")
    crash_paths = []
    if crashes_dir:
        crash_paths = [str(p) for p in _collect_crash_files(Path(crashes_dir))]
    executions = max(
        _safe_int(stats.get("execs_done")),
        _safe_int(stats.get("total_executions")),
        _safe_int(telemetry.get("total_executions")),
    )
    from packages.fuzzing.afl_runner import AFL_PATHS_FOUND_KEYS
    paths_found = max(
        *(_safe_int(stats.get(key)) for key in AFL_PATHS_FOUND_KEYS),
        _safe_int(telemetry.get("paths_found")),
    )
    coverage_percent = next(
        (v for v in (
            _safe_float(telemetry.get("coverage_percent")),
            _safe_float(stats.get("bitmap_cvg")),
            _safe_float(stats.get("coverage_percent")),
        ) if v is not None),
        0.0,
    )
    return {
        "completed": True,
        "fuzzer": fuzzing_result.get("fuzzer"),
        "executions": executions,
        "execs_per_second": (
            _safe_int(telemetry.get("executions_per_second"))
            or _safe_int(stats.get("execs_per_sec"))
            or _safe_int(stats.get("executions_per_second"))
        ),
        "coverage_percent": coverage_percent,
        "paths_found": paths_found,
        "crashes": fuzzing_result.get("crashes", 0),
        "crashes_dir": crashes_dir,
        "crash_paths": crash_paths,
        "telemetry": fuzzing_result.get("telemetry"),
        "events": fuzzing_result.get("events"),
        "generated_corpus": fuzzing_result.get("generated_corpus"),
        "output_dir": str(fuzz_out) if fuzz_out else None,
    }



def _should_run_mechanical_sca(sca_agent, deep_sca_requested: bool) -> bool:
    """Gate for the always-on mechanical SCA subprocess phase.

    Run it only when an SCA agent is installed AND the deep --sca
    pipeline is not going to analyse the same dependency set later in
    the run. Running both would produce the same dependency findings
    twice — once via the mechanical phase's findings.sarif and once via
    the deep phase's findings.json merged during validation — and add
    both counts into total_findings.
    """
    return bool(sca_agent) and not deep_sca_requested


def _build_completion_manifest(orch_meta, import_result, import_sarif_files,
                               reanalyze_dir=None):
    manifest = {
        "models": orch_meta.get("fired_models", []),
    }
    if import_result and import_result.stats.total_imported:
        from core.sarif.import_normalizer import import_provenance_block
        tools = sorted({f.get("tool", "external") for f in import_result.findings})
        manifest["sarif_import"] = import_provenance_block(
            import_result,
            sarif_files=[Path(f).name for f in import_sarif_files],
            tools=tools,
        )
    if reanalyze_dir:
        manifest["reanalysis_of"] = str(reanalyze_dir)
    return manifest


# ============================================================================
# AUDIT POST-PASS (opt-in via --gap-audit)
# ============================================================================

def _discover_codeql_dbs(out_dir: Path) -> list:
    """Successfully-created CodeQL database paths from this run's
    codeql phase (one per language).

    ``raptor-audit run`` takes ``--codeql-db`` repeatably and routes
    per-function dispatch by the file's language, so every database
    the scan phase built is handed over.
    """
    report = load_json(out_dir / "codeql" / "codeql_report.json")
    if not isinstance(report, dict):
        return []
    dbs = []
    for result in (report.get("databases_created") or {}).values():
        if not isinstance(result, dict):
            continue
        db_path = result.get("database_path")
        if db_path and result.get("success", True) and Path(db_path).is_dir():
            dbs.append(db_path)
    return dbs


def _gap_audit_adversarial(args: argparse.Namespace) -> bool:
    """Whether the post-pass enables the adversarial reviewer.

    Auto-enabled when two or more analysis models are configured (the
    reviewer needs a second model to challenge positive verdicts);
    --gap-audit-no-adversarial opts out. The decision is recorded in
    the run report so the auto-enable's value can be measured across
    runs instead of staying an unexamined default.
    """
    models = args.model or []
    return len(models) >= 2 and not getattr(
        args, "gap_audit_no_adversarial", False,
    )


def _build_audit_postpass_cmd(
    args: argparse.Namespace, target: Path, audit_dir: Path, agentic_out: Path,
) -> list:
    """argv for the ``raptor-audit run`` subprocess.

    Shared inputs are inherited from the agentic run (models, binaries,
    CodeQL database, the agentic journal as prior finding-grade
    claims); the audit-specific surface is the small prefixed flag set
    (--audit-budget / --audit-strategy / --audit-scope). Anything finer
    belongs in a standalone /audit run.
    """
    raptor_dir = Path(__file__).parent.resolve()
    cmd = [
        str(raptor_dir / "libexec" / "raptor-audit"), "run", str(target),
        "--out", str(audit_dir),
    ]
    # Same-project threading for the gap-audit child (the third
    # sibling chain): its trust markers, binaries, annotations, and
    # journal merges must follow THIS run's project, not whatever the
    # session resolves when the child starts.
    try:
        from core.run.pin import get_process_project
        _pinned = get_process_project()
        if _pinned is not None:
            cmd += ["--project", _pinned]
    except Exception:  # noqa: BLE001 — child falls back to its own layers
        pass
    cmd += [
        # Validation is unified at the pipeline level: audit findings
        # join the --validate post-pass selection instead of spawning
        # a second validate run.
        "--no-validate",
        # Budget-capped pass over an unknown-size residual: review the
        # most promising functions first.
        "--schedule", "priority",
        # The agentic run completes AFTER this subprocess, so its
        # journals are not yet merged into any project index — hand
        # them over directly as prior finding-grade claims. The
        # analysis agent journals under autonomous/; the run root is
        # included for producers that write there (and costs nothing
        # when absent).
        "--prior-journal", str(agentic_out),
        "--prior-journal", str(agentic_out / "autonomous"),
    ]
    if args.gap_audit_reserved_cost:
        cmd += ["--max-cost", str(args.gap_audit_reserved_cost)]
    elif getattr(args, "max_cost_usd", None):
        cmd += ["--max-cost", str(args.max_cost_usd)]
    if args.gap_audit_budget:
        cmd += ["--budget", str(args.gap_audit_budget)]
    if args.gap_audit_strategy:
        cmd += ["--strategy", args.gap_audit_strategy]
    for scope in args.gap_audit_scope or []:
        cmd += ["--scope", scope]
    models = args.model or []
    for model in models:
        cmd += ["--model", model]
    if _gap_audit_adversarial(args):
        cmd.append("--adversarial")
    for binary in args.binary or []:
        cmd += ["--binary", str(binary)]
    if getattr(args, "binary_auto", False):
        cmd.append("--binary-auto")
    if getattr(args, "no_binary_oracle", False):
        cmd.append("--no-binary-oracle")
    for codeql_db in _discover_codeql_dbs(agentic_out):
        cmd += ["--codeql-db", codeql_db]
    return cmd


def _audit_run_status(audit_dir: Path) -> str | None:
    """Lifecycle status recorded in the audit run dir, or None."""
    meta = load_json(audit_dir / ".raptor-run.json")
    if isinstance(meta, dict):
        return meta.get("status")
    return None


def _run_audit_feedback(audit_dir: Path, validate_dir: Path) -> bool:
    """Import /validate verdicts into the audit journal (Reflexion loop).

    Best-effort: a feedback failure costs the correction entries, never
    the run. Uses the same annotations-dir default the audit run itself
    resolved (project-level in project mode).
    """
    validation_report = Path(validate_dir) / "findings.json"
    if not validation_report.is_file():
        logger.info(
            "audit feedback skipped: validate run wrote no findings.json",
        )
        return False
    # Same resolution the audit run applied for its own default.
    from core.audit.record import _resolve_annotations_dir
    raptor_dir = Path(__file__).parent.resolve()
    cmd = [
        str(raptor_dir / "libexec" / "raptor-audit"), "feedback",
        "--validation-report", str(validation_report),
        "--annotations-dir", str(_resolve_annotations_dir(Path(audit_dir))),
        "--audit-out", str(audit_dir),
    ]
    rc, _stdout, stderr = run_command_streaming(
        cmd, "Importing validation verdicts into the audit journal",
        timeout=300,
    )
    if rc != 0:
        logger.warning(
            "audit feedback exited %d: %s", rc, (stderr or "")[-300:],
        )
    return rc == 0


def _gap_audit_skip_reason(args: argparse.Namespace, llm_env, *, block_cc_dispatch: bool) -> str | None:
    """None when the gap-audit post-pass can run, else the skip reason.

    An explicit --model or a configured external LLM always qualifies
    (the audit subprocess builds its own client). Otherwise the
    claudecode transport (claude -p as a real LLM provider — the audit
    orchestrator's documented fallback) carries the run, gated on the
    target-repo trust check since the transport dispatches claude
    against content from the scanned repo.
    """
    if (args.model or []) or llm_env.external_llm:
        return None
    if not llm_env.claude_code:
        return (
            "no LLM available — configure an API key, pass --model, "
            "or install Claude Code"
        )
    if block_cc_dispatch:
        return (
            "no external LLM and the target repo failed the Claude "
            "Code trust check — the claudecode transport will not "
            "dispatch against an untrusted repo (pass --model, or "
            "review with /audit --local)"
        )
    return None


def run_audit_postpass(args: argparse.Namespace, target: Path, out_dir: Path) -> dict:
    """Run ``raptor-audit run`` over the residual coverage gaps.

    Creates a proper lifecycle-managed sibling /audit run (project
    sibling in project mode, global out/ otherwise) so the artifacts
    are discoverable by /review, /validate's audit bridge, and
    cross-run verdict reuse. The subprocess manages its own lifecycle
    completion/failure; this wrapper only backstops early exits that
    die before the orchestrator takes over.

    Returns a phase dict for the final report. Never raises.
    """
    from core.orchestration.skill_dispatch import (
        fail_lifecycle,
        start_lifecycle,
    )

    phase: dict = {"enabled": True, "completed": False}
    t0 = time.time()
    try:
        audit_dir = start_lifecycle("audit", target)
        if audit_dir is None:
            phase["skipped_reason"] = "lifecycle start failed"
            return phase
        phase["audit_dir"] = str(audit_dir)

        # Reuse the agentic checklist — same target, same parser;
        # skips a full re-parse of the repo. raptor-audit builds a
        # fresh one when the copy is missing.
        agentic_checklist = out_dir / "checklist.json"
        if agentic_checklist.is_file():
            import shutil
            try:
                shutil.copyfile(
                    agentic_checklist, audit_dir / "checklist.json",
                )
            except OSError as e:
                logger.warning(
                    "audit post-pass: checklist copy failed (%s); "
                    "raptor-audit will rebuild it", e,
                )

        # Stage the deferred-tail marker: this audit runs with
        # --no-validate because the parent pipeline validates the
        # findings itself. If the audit is interrupted and resumed
        # later, the parent has completed — the marker lets
        # `raptor-audit resume` tell the operator which tail steps
        # remain (see core.audit.resume.pipeline_tail_hint).
        try:
            save_json(audit_dir / "pipeline-tail.json", {
                "parent_run": str(out_dir),
                "deferred": ["validate", "feedback"],
                "reason": "validation unified in the parent /agentic "
                          "run (--gap-audit)",
            })
        except Exception:  # noqa: BLE001 — marker is best-effort
            logger.debug("pipeline-tail marker write failed", exc_info=True)

        # Record the adversarial decision: on this surface every
        # enable is the auto rule (2+ models), so the flag's value can
        # be measured across runs rather than staying an unexamined
        # default. adversarial_opted_out marks runs where the operator
        # suppressed an enable the rule would have made.
        phase["adversarial"] = _gap_audit_adversarial(args)
        if len(args.model or []) >= 2 and not phase["adversarial"]:
            phase["adversarial_opted_out"] = True

        cmd = _build_audit_postpass_cmd(args, target, audit_dir, out_dir)
        # No wall timeout here: the audit self-bounds via --max-cost /
        # its own supervisor bound, and a wall kill would waste the
        # spend (an interrupted run stays resumable via
        # `raptor-audit resume`).
        rc, _stdout, stderr = run_command_streaming(
            cmd, "Auditing coverage residual", timeout=0,
        )
        phase["duration_seconds"] = round(time.time() - t0, 1)
        phase["exit_code"] = rc

        if rc == 130:
            phase["skipped_reason"] = (
                "interrupted — resume with: libexec/raptor-audit "
                f"resume {audit_dir}"
            )
            return phase
        if rc != 0:
            # raptor-audit marks its own lifecycle failure for pipeline
            # errors; backstop the early-exit paths (argparse, trust
            # gate) that die before lifecycle handling exists.
            if _audit_run_status(audit_dir) == "running":
                fail_lifecycle(
                    audit_dir, f"audit post-pass exited {rc}",
                )
            phase["skipped_reason"] = (
                f"raptor-audit exited {rc}: {(stderr or '')[-300:]}"
            )
            return phase

        phase["completed"] = True
        report = load_json(audit_dir / "audit-report.json")
        if isinstance(report, dict):
            stats = report.get("stats")
            if isinstance(stats, dict):
                for key in ("reviewed", "clean", "suspicious", "finding",
                            "dormant", "error"):
                    if isinstance(stats.get(key), int):
                        phase[key] = stats[key]
            for key in ("findings_count", "gaps_remaining"):
                if isinstance(report.get(key), int):
                    phase[key] = report[key]
            completeness = report.get("completeness")
            if isinstance(completeness, dict):
                phase["completeness"] = completeness
                phase["partial"] = bool(completeness.get("partial"))

        # The reconciled audit ledger is authoritative. Audit can spend most
        # of the workflow budget, so excluding it makes the parent total
        # materially misleading.
        cost_breakdown = load_json(audit_dir / "cost-breakdown.json")
        if isinstance(cost_breakdown, dict):
            totals = cost_breakdown.get("totals")
            if isinstance(totals, dict):
                spend = totals.get("total_spend_usd")
                if isinstance(spend, (int, float)):
                    phase["cost_usd"] = float(spend)
        return phase
    except Exception as e:
        logger.exception("audit post-pass crashed unexpectedly")
        phase["skipped_reason"] = f"unexpected {type(e).__name__}: {e}"
        phase.setdefault("duration_seconds", round(time.time() - t0, 1))
        return phase


def _workflow_cost_summary(
    orchestration_result: dict | None,
    audit_postpass: dict | None,
    prepass_result=None,
    postpass_result=None,
) -> dict:
    """Combine every paid phase into one operator-facing total."""
    by_phase: dict[str, float] = {}

    orchestration = (
        orchestration_result.get("orchestration", {})
        if isinstance(orchestration_result, dict) else {}
    )
    main_cost = orchestration.get("cost", {})
    if isinstance(main_cost, dict):
        value = main_cost.get("total_cost")
        if isinstance(value, (int, float)) and value > 0:
            by_phase["analysis"] = float(value)

    for name, result in (("understand", prepass_result),
                         ("validate", postpass_result)):
        value = getattr(result, "cost_usd", 0.0) if result else 0.0
        if isinstance(value, (int, float)) and value > 0:
            by_phase[name] = float(value)

    audit_cost = (
        audit_postpass.get("cost_usd", 0.0)
        if isinstance(audit_postpass, dict) else 0.0
    )
    if isinstance(audit_cost, (int, float)) and audit_cost > 0:
        by_phase["audit"] = float(audit_cost)

    summary = {
        "total_cost": round(sum(by_phase.values()), 4),
        "cost_by_phase": by_phase,
    }
    # Retain the useful token/model detail from the main analysis ledger while
    # making clear that its dollar subtotal is only one workflow phase.
    if isinstance(main_cost, dict):
        for key in ("thinking_tokens", "cost_by_model"):
            if key in main_cost:
                summary[key] = main_cost[key]
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(
        description="RAPTOR Agentic Security Testing - Scan, Analyse, Exploit, Patch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full autonomous workflow (Semgrep + LLM analysis; CodeQL is opt-in via --codeql)
  python3 raptor.py agentic --repo /path/to/code

  # Semgrep only
  python3 raptor_agentic.py --repo /path/to/code --no-codeql --policy-groups crypto,secrets

  # CodeQL only (skip Semgrep)
  python3 raptor_agentic.py --repo /path/to/code --codeql-only --languages java

  # With custom build command
  python3 raptor_agentic.py --repo /path/to/code --codeql --languages java \\
    --build-command "mvn clean compile -DskipTests"

  # Limit number of findings processed
  python3 raptor.py agentic --repo /path/to/code --max-findings 20

  # Skip exploit generation (analysis + patches only)
  python3 raptor.py agentic --repo /path/to/code --no-exploits

  # Skip exploitability validation (faster, but may include false positives)
  python3 raptor.py agentic --repo /path/to/code --skip-dedup

  # Build a project threat model from /understand and feed it into analysis
  python3 raptor.py agentic --repo /path/to/code --threat-model --validate

  # Focus validation on specific vulnerability type
  python3 raptor.py agentic --repo /path/to/code --vuln-type sql_injection

  # Choose a specific analysis model (overrides models.json auto-detection)
  python3 raptor.py agentic --repo /path/to/code --model gemini-2.5-pro

  # Multi-model: N models independently analyse, results correlated
  python3 raptor.py agentic --repo /path/to/code \\
    --model gemini-2.5-pro --model gpt-5 --model claude-opus-4-6

  # Two analysis models + one aggregate model for downstream triage
  python3 raptor.py agentic --repo /path/to/code \\
    --model claude-opus-4-6 --model gpt-5.4 --aggregate claude-sonnet-4-6

  # Single model + consensus second opinion
  python3 raptor.py agentic --repo /path/to/code --model gemini-2.5-pro \\
    --consensus claude-opus-4-6

  # Single model + judge review
  python3 raptor.py agentic --repo /path/to/code --model gemini-2.5-pro \\
    --judge claude-opus-4-6
        """
    )

    parser.add_argument(
        "--repo", default=os.environ.get("RAPTOR_CALLER_DIR"),
        help=(
            "Path to repository to analyse (default: $RAPTOR_CALLER_DIR "
            "— set by the bin/raptor wrapper to the operator's cwd at "
            "launch time. When the script is invoked directly without "
            "the wrapper, RAPTOR_CALLER_DIR is unset and --repo is "
            "required)."
        ),
    )
    parser.add_argument(
        "--sarif", action="append", default=None, metavar="FILE",
        help=(
            "Import external SARIF file(s) instead of scanning. Repeatable. "
            "Findings are normalized against the source tree at --repo "
            "(URI rebasing, snippet synthesis, CWE inference). "
            "Skips the scan phase unless --also-scan is set."
        ),
    )
    parser.add_argument(
        "--also-scan", action="store_true",
        help=(
            "When --sarif is provided, also run RAPTOR's own scanners "
            "(Semgrep / CodeQL) and merge the results with imported "
            "findings. Without this flag, --sarif replaces the scan step."
        ),
    )
    parser.add_argument(
        "--sarif-out", metavar="FILE",
        help=(
            "Write enriched SARIF after analysis. Each result carries "
            "properties.raptor with RAPTOR's verdict, reachability, "
            "exploitability score, and reasoning. Binary-oracle-suppressed "
            "findings get standard SARIF suppressions."
        ),
    )
    parser.add_argument(
        "--reanalyze", metavar="DIR",
        help=(
            "Re-run analysis on a previous run's output directory. "
            "Reads .raptor-run.json to recover target path and SARIF files, "
            "skips scanning. Equivalent to --sarif <previous SARIFs> --repo <previous target>."
        ),
    )
    parser.add_argument("--policy-groups", default="all", help="Comma-separated policy groups (default: all)")
    parser.add_argument("--max-findings", type=int, default=10, help="Maximum findings to process (default: 10; codeql-only default is 20, agentic is lower because each finding runs the full multi-pass LLM analysis chain at ~3-5x the per-finding cost)")
    parser.add_argument(
        "--prefer", action="append", default=None, metavar="GLOB",
        help=(
            "Prioritise findings whose file_path matches GLOB. Repeatable for "
            "multiple patterns (OR semantics). Matching findings sort to the "
            "front of the analysis queue before --max-findings caps the set, "
            "so a low cap reaches your attack-surface targets first instead "
            "of analysing in arbitrary file-order. Within each bucket, the "
            "existing ordering (dataflow-prioritised then SARIF-order) is "
            "preserved for stable diffs across re-runs. Example: "
            "``--prefer 'src/http/*' --prefer 'src/protocols/*'``"
        ),
    )
    parser.add_argument(
        "--exclude-dir", action="append", default=None, metavar="GLOB",
        dest="exclude_dir",
        help=(
            "Drop findings whose file_path matches GLOB before analysis. "
            "Repeatable for multiple patterns (OR semantics). Operator escape "
            "hatch for vendored third-party code, test fixtures, generated "
            "dirs the structural filters (binary-oracle, dataflow priority) "
            "can't cover. Applied before --prefer + --max-findings so excluded "
            "paths don't push attack-surface candidates out of the captured "
            "set. Example: ``--exclude-dir 'vendor/*' --exclude-dir '**/tests/*'``"
        ),
    )
    parser.add_argument(
        "--phase-timeout", type=int,
        default=RaptorConfig.DEFAULT_TIMEOUT, metavar="SECONDS",
        help=(
            "Per-phase wall-clock timeout in seconds for the three "
            "long-running subprocess calls (Semgrep scan, CodeQL scan, "
            "analysis subprocess). Default: %(default)s (sourced from "
            "RaptorConfig.DEFAULT_TIMEOUT). Set to 0 to disable the "
            "timeout entirely — useful for kernel-scale targets where "
            "source_intel spatch + LLM analysis can take hours. "
            "Operator is responsible for Ctrl-C when unbounded."
        ),
    )
    parser.add_argument("--no-exploits", action="store_true", help="Skip exploit generation")
    parser.add_argument(
        "--execute-exploits", action="store_true",
        help="Run compiled LLM-emitted exploits in the sandbox and record "
             "the observed outcome (P9 execution oracle). Without an "
             "explicit flag the project 'dynamic' trust marker decides; "
             "default off. Forwarded to the analysis subprocess.",
    )
    parser.add_argument(
        "--no-execute-exploits", action="store_true",
        help="Explicitly disable sandboxed exploit execution, overriding "
             "the project 'dynamic' trust marker. Takes precedence over "
             "--execute-exploits.",
    )
    parser.add_argument("--no-patches", action="store_true", help="Skip patch generation")
    parser.add_argument(
        "--no-journal",
        action="store_true",
        help="Skip per-finding journal emission (default: emit)",
    )
    parser.add_argument(
        "--max-cost-usd", dest="max_cost_usd", type=float, default=None,
        help="Per-run USD budget cap; overrides LLMConfig.max_cost_per_scan "
             "so CostTracker enforces the cap during LLM calls",
    )
    parser.add_argument("--out", help="Output directory")
    parser.add_argument(
        "--project", default=None, metavar="NAME",
        help="Pin this run to the named project (precedence over the "
             "session binding and the last-activated default). '-' = "
             "explicitly projectless. Invalid values are a hard error, "
             "never a fallback.",
    )

    # Sanitizer-cut value-bound suppression mode (review #4, PR #794).
    # Replaces the RAPTOR_SANITIZER_CUT* env vars. configure() below
    # exports the resolved state so spawned scan/analysis subprocesses
    # inherit it.
    from core.dataflow import sanitizer_cut_config
    sanitizer_cut_config.add_cli_arguments(parser)

    # CodeQL integration — mutually exclusive. Pre-fix all three
    # flags were independent ``store_true`` booleans, so combinations
    # like ``--codeql-only --no-codeql`` resolved to
    # ``run_semgrep=False, run_codeql=False`` (neither scanner runs)
    # and the pipeline still reported "complete" with zero findings.
    # Mutually exclusive group rejects the contradictory combo at
    # argparse time with a clear error.
    _codeql_group = parser.add_mutually_exclusive_group()
    _codeql_group.add_argument("--codeql", action="store_true", help="Enable CodeQL scanning (in addition to Semgrep)")
    _codeql_group.add_argument("--codeql-only", action="store_true", help="Run CodeQL only (skip Semgrep)")
    _codeql_group.add_argument("--no-codeql", action="store_true", help="Disable CodeQL scanning (Semgrep only)")
    parser.add_argument("--languages", help="Languages for CodeQL (comma-separated, auto-detected if not specified)")
    parser.add_argument("--build-command", help="Custom build command for CodeQL")
    parser.add_argument("--extended", action="store_true", help="Use CodeQL extended security suites")
    parser.add_argument("--codeql-cli", help="Path to CodeQL CLI (auto-detected if not specified)")
    parser.add_argument(
        "--traced-build", action="store_true",
        help="Opt into traced-build C/C++ CodeQL extraction (executes the "
             "repo's build system — asserts trust in the repo). Default is "
             "buildless: no repo code runs during database creation.",
    )
    parser.add_argument(
        "--no-traced-build", action="store_true",
        help="Force buildless CodeQL extraction for this run, overriding "
             "both --traced-build and the active project's 'build' trust "
             "marker (raptor project trust build).",
    )
    parser.add_argument("--no-visualizations", action="store_true", help="Disable dataflow visualizations for CodeQL findings")

    # Compiler-analyzer scan channel (forwarded to the scanner subprocess
    # like --traced-build is forwarded to the codeql agent).
    parser.add_argument(
        "--compiler-scan", action="store_true",
        help="Run the compiler-analyzer scan channel during the scan phase: "
             "gcc -fanalyzer / clang --analyze per C/C++ translation unit, "
             "diagnostics become findings for dedup/analysis. Sandboxed, "
             "network blocked, no build system — no repo code executes. "
             "Off by default (operator opt-in); rides the Semgrep scan "
             "stage, so it is skipped under --codeql-only.",
    )
    parser.add_argument(
        "--no-compiler-scan", action="store_true",
        help="Explicitly disable the compiler-analyzer scan stage. Takes "
             "precedence over --compiler-scan.",
    )
    parser.add_argument(
        "--compiler-scan-max-tus", type=int, default=None, metavar="N",
        help="Cap the number of translation units the compiler-analyzer "
             "scan compiles (default 2000). Skipped TUs are reported "
             "loudly, never silently truncated.",
    )
    parser.add_argument(
        "--expanded-semgrep", action="store_true",
        help="Re-run the loaded Semgrep ruleset over fidelity-3 "
             "preprocessor-expanded views of macro-heavy C/C++ TUs, with "
             "matches line-mapped back to original coordinates — catches "
             "sinks hidden behind macros (LIST_FOREACH wrappers, allocator "
             "macros). Budget-bounded; preprocessing is sandboxed and no "
             "repo code executes. Off by default; rides the Semgrep scan "
             "stage, so it is skipped under --codeql-only.",
    )
    parser.add_argument(
        "--no-graduated-rules", action="store_true",
        help="Disable the graduated synthesized-rules scan stage "
             "(default on at the scanner: the active project's "
             "precision-gated rules from engine-rules/semgrep/rules/ "
             "run as a standard stage). Rides the Semgrep scan stage.",
    )
    # Reachability gating control
    parser.add_argument(
        "--allow-unreachable",
        action="store_true",
        help=(
            "Admit findings on functions the reachability substrate "
            "marks NOT_CALLED. Default behaviour filters / demotes "
            "these and the analysis prompt asks the LLM to defer. "
            "Use when evaluating code in isolation: CTF challenges, "
            "vendor reference snippets, exploit-research targets, "
            "deliberate dead-code review. Does NOT change handling "
            "of UNCERTAIN cases — those always flow through to "
            "avoid false confidence in non-reachability. Affects 4 "
            "wiring sites: reachability_enrichment (no priority=low "
            "demotion), CodeQL prefilter (no short-circuit), attack-"
            "path demoter (no demote), analysis prompt (engagement "
            "text → informational only)."
        ),
    )
    parser.add_argument(
        "--target-kind",
        choices=("auto", "library", "hybrid", "application"),
        default="auto",
        help=(
            "Classify the target so reachability treats a library's "
            "exported/public symbols as entry points (its API is reachable by "
            "external consumers). 'auto' (default) classifies from package "
            "manifests; force it when auto is wrong. 'library' and 'hybrid' "
            "both enable export-as-entry (a hybrid = lib + CLI, e.g. seer, so "
            "BOTH its API and its CLI/main are entries); 'application' "
            "disables it. Only affects the dynamic/JVM languages "
            "(Python/JS/TS/Java/C#/PHP) — native code (C/C++/Rust/Go) uses "
            "sound linkage regardless. Sets RAPTOR_TARGET_KIND so the "
            "inventory honours it across subprocess boundaries (e.g. the "
            "/validate helper)."
        ),
    )

    # Mitigation analysis options (NEW)
    parser.add_argument(
        "--binary", action="append", default=None,
        help=(
            "Target binary path. Used for (a) mitigation analysis "
            "(pre-exploit checks) and (b) binary-oracle inventory "
            "enrichment — DWARF-joined per-function classification, "
            "drives finding suppression on dead functions. Repeat for "
            "hybrid targets (e.g. --binary lib.so --binary app); a "
            "function is classified ``absent`` only when EVERY declared "
            "binary lacks it."
        ),
    )
    parser.add_argument(
        "--binary-auto", action="store_true",
        help=(
            "Auto-detect debug binaries under the target's build "
            "directories. Honours --target-kind; appends detected paths "
            "to any --binary values."
        ),
    )
    parser.add_argument(
        "--binary-edges", action="store_true",
        help=(
            "Inc 2b Tier 1: extract direct call edges (r2) and "
            "annotate inventory functions with binary-found callers. "
            "Slow; requires --binary."
        ),
    )
    # Keep in sync with core/analysis/binary_oracle_cli.add_binary_args
    # (raptor_codeql.py takes the whole set from that helper; this CLI
    # declares the flags inline because its --binary help documents the
    # agentic-specific mitigation-analysis use). The downstream code
    # has always read no_binary_oracle defensively via getattr, and the
    # >=50%-suppression warning tells operators to re-run with this
    # flag — it must actually parse.
    parser.add_argument(
        "--no-binary-oracle", action="store_true",
        dest="no_binary_oracle",
        help=(
            "Disable binary-oracle reachability filtering for this run. "
            "Default behaviour auto-detects locally-built debug binaries "
            "(untracked by git — repo-committed binaries skipped as "
            "unverified provenance) and uses them to filter dead-code "
            "findings. Pass this flag for library-only targets with no "
            "main binary, runs where you want every finding unfiltered "
            "for review, or when a build mismatch is causing the oracle "
            "to over-suppress. Overrides --binary / --binary-auto with "
            "a warning if combined."
        ),
    )
    parser.add_argument("--check-mitigations", action="store_true",
                       help="Run mitigation analysis before scanning (for binary exploit targets)")

    # Exploitability validation options
    parser.add_argument("--skip-dedup", action="store_true",
                       help="Skip deduplication (pass all scanner findings directly to analysis)")
    parser.add_argument("--vuln-type", help="Vulnerability type to focus on (e.g., command_injection, sql_injection)")

    # Orchestration options
    parser.add_argument("--max-parallel", type=int, default=None,
                       help="Maximum parallel dispatch threads (0 = auto from model RPM)")
    parser.add_argument("--understand", action="store_true",
                        help="Run /understand --map before scanning for architectural context")
    parser.add_argument(
        "--threat-model",
        action="store_true",
        help=(
            "Run /understand --map, create a project threat-model if missing, "
            "and hand unchecked-flow candidates into the normal analysis "
            "pipeline. Existing project models are preserved unless "
            "--threat-model-refresh is set. Implies --understand."
        ),
    )
    parser.add_argument(
        "--threat-model-only",
        action="store_true",
        help=(
            "Run only the /understand-backed threat-model phase, write "
            "threat-model.json, THREAT_MODEL.md, and candidate SARIF, then exit."
        ),
    )
    parser.add_argument(
        "--threat-model-refresh",
        action="store_true",
        help="Overwrite any existing project threat model with the latest /understand map.",
    )
    parser.add_argument(
        "--threat-model-use-stale",
        action="store_true",
        help=(
            "Allow threat-model fallback to reuse a stale /understand "
            "context-map when a fresh map cannot be produced."
        ),
    )
    parser.add_argument("--validate", action="store_true",
                        help="Run /validate on exploitable/high-confidence findings after analysis")
    audit_group = parser.add_argument_group(
        "audit post-pass",
        "Run the /audit orchestrator over the residual — functions no "
        "phase reviewed — after analysis completes. Opt-in: per-function "
        "hypothesis-driven review is the most expensive pass available.",
    )
    audit_group.add_argument(
        "--gap-audit", action="store_true", dest="gap_audit",
        help="Audit the coverage residual after analysis (sibling /audit "
             "run; findings join the --validate post-pass when both flags "
             "are set). Uses the configured external LLM (or --model); "
             "with only Claude Code available it runs on the claudecode "
             "transport, gated on the repo trust check. "
             "Unrelated to --audit, which is the sandbox audit mode.",
    )
    audit_group.add_argument(
        "--gap-audit-budget", type=int, default=None, metavar="N",
        help="Max functions the audit post-pass reviews (default: all gaps)",
    )
    audit_group.add_argument(
        "--gap-audit-strategy", default=None, metavar="NAME",
        help="Restrict the audit post-pass to one strategy (general, "
             "input_handling, concurrency, memory, auth, crypto, "
             "aliasing, integer)",
    )
    audit_group.add_argument(
        "--gap-audit-scope", action="append", default=None, metavar="DIR",
        help="Restrict the audit post-pass to a subdirectory (repeatable)",
    )
    audit_group.add_argument(
        "--gap-audit-no-adversarial", action="store_true",
        help="Do not auto-enable the adversarial reviewer when two or "
             "more --model values are configured. The auto-enable is "
             "recorded in the run report either way, so its value can "
             "be measured across runs.",
    )
    audit_group.add_argument(
        "--gap-audit-share", type=float, default=0.35, metavar="FRACTION",
        help="Fraction of --max-cost-usd reserved UP FRONT for the audit "
             "post-pass (default: 0.35). Analysis phases run under the "
             "remainder, so the audit keeps its budget even when analysis "
             "hits its adaptive cutoff. No effect without --max-cost-usd.",
    )
    parser.add_argument("--sequential", action="store_true",
                       help="Sequential analysis in Phase 3 instead of parallel Phase 4 orchestration")
    parser.add_argument(
        "--rank", action="store_true",
        help=(
            "Reorder findings most-promising-first (listwise LLM "
            "ranking) before Phase 4 analysis, so --max-findings / "
            "--max-cost caps cut the least promising tail. Needs an "
            "external analysis model (--model). Ordering only — no "
            "finding is dropped."
        ),
    )
    parser.add_argument("--verbose", action="store_true",
                       help="Drop console log level from INFO to DEBUG. "
                            "Surfaces per-LLM-call detail (cache hits, retries, "
                            "per-call cost/duration). Useful for debugging "
                            "multi-model dispatches or schema validation failures.")
    parser.add_argument(
        "--log-level",
        choices=CONSOLE_LOG_LEVELS,
        type=str.upper,
        help=(
            "Set console log level for this run. Use WARNING to hide INFO "
            "sandbox/proxy chatter; overrides --verbose."
        ),
    )

    # Fuzzing integration (Phase 5: dynamic confirmation)
    parser.add_argument("--fuzz", action="store_true",
                       help="Run a short fuzzing campaign (AFL++ or libFuzzer) against --binary "
                            "after SAST findings. Auto-detects target type and selects fuzzer "
                            "based on host capabilities.")
    parser.add_argument("--fuzz-duration", type=int, default=600,
                       help="Fuzzing campaign duration in seconds when --fuzz is set (default: 600)")
    parser.add_argument("--fuzz-corpus", help="Seed corpus for the fuzzing campaign")
    parser.add_argument("--fuzz-dict", help="AFL/libFuzzer dictionary file")
    parser.add_argument("--fuzz-plan-only", action="store_true",
                       help="Print fuzzing campaign plan and exit without running. "
                            "Use this to verify host capabilities before a long campaign.")

    parser.add_argument(
        "--accept-weakened-defenses",
        action="store_true",
        help="Allow analysis to proceed when a model fails the defense envelope "
             "probe. Without this flag, probe failure aborts orchestration. "
             "With it, model-dependent defenses (envelope tags, datamarking, "
             "base64) are disabled; model-independent floor still holds. "
             "Logged in run metadata and flagged in the final report.",
    )
    model_group = parser.add_argument_group(
        "multi-model analysis",
        "Choose which LLMs analyse findings. The primary model is auto-detected "
        "from models.json / API key env vars unless --model overrides it. "
        "Role models (consensus, judge, aggregate) are optional additions.",
    )
    model_group.add_argument(
        "--model",
        metavar="MODEL",
        action="append",
        default=[],
        help="Analysis model (repeatable). Single: --model gemini-2.5-pro. "
             "Multi: --model gemini-2.5-pro --model gpt-5 — each independently "
             "analyses every finding, then results are correlated.",
    )
    model_group.add_argument(
        "--consensus",
        metavar="MODEL",
        help="Blind second opinion — re-analyses each finding independently "
             "without seeing the primary verdict. Majority vote decides.",
    )
    model_group.add_argument(
        "--judge",
        metavar="MODEL",
        help="Non-blind review — sees and critiques the primary analysis "
             "reasoning. Flags missed attack paths or flawed logic.",
    )
    model_group.add_argument(
        "--aggregate",
        metavar="MODEL",
        help="Optional. LLM-written synthesis on top of the deterministic "
             "multi-model correlation. Adds a narrative summary, top findings, "
             "and recommended next actions to the report. Requires at least "
             "two --model values; without --aggregate you still get the "
             "correlation results.",
    )
    parser.add_argument(
        "--no-validate-dataflow",
        action="store_true",
        help="Disable IRIS-style dataflow validation entirely. By default, "
             "Tier 1 (free, CodeQL-only — runs the pre-built RemoteFlowSource "
             "and RAPTOR-shipped LocalFlowSource queries against the project "
             "database) is on whenever --codeql produced a database. Pass this "
             "flag to skip validation completely.",
    )
    # --deep-validate / --no-deep-validate are contradictory; the
    # help text claimed "Takes precedence over --deep-validate" but
    # argparse didn't enforce that — both flags landed on args and
    # downstream code read them independently. Mutex group makes
    # argparse reject the contradictory combo with a clear error.
    _deep_group = parser.add_mutually_exclusive_group()
    _deep_group.add_argument(
        "--deep-validate",
        action="store_true",
        help="Force-enable Tier 2 / Tier 3 of IRIS validation for ALL "
             "findings: when Tier 1 is inconclusive, ask the LLM to write "
             "source+sink predicates and retry on compile errors. Costs LLM "
             "tokens. Implies dataflow validation is enabled (see "
             "--no-validate-dataflow to opt out). Without this flag, Tier 2/3 "
             "auto-enables per-finding when the LLM emits `path_conditions` "
             "(usage-driven default — only spends tokens on findings the LLM "
             "thinks it can SMT-check); pass --no-deep-validate to disable "
             "even that auto-enable path.",
    )
    _deep_group.add_argument(
        "--no-deep-validate",
        action="store_true",
        help="Hard kill-switch: disable Tier 2 / Tier 3 entirely, including "
             "the default usage-driven auto-enable on findings where the LLM "
             "emitted `path_conditions`. Use when budget pressure is acute or "
             "when bisecting whether deep-validate is responsible for a "
             "verdict change. Takes precedence over --deep-validate.",
    )
    parser.add_argument(
        "--deep-validate-budget",
        type=float,
        default=0.60,
        metavar="FRACTION",
        help="Fraction of LLM budget (0.0-1.0) above which --deep-validate's "
             "Tier 2 / 3 LLM calls are skipped to leave room for downstream "
             "tasks (consensus, exploit, patch). Tier 1 has no LLM cost so "
             "this budget never gates it. Default 0.60.",
    )
    parser.add_argument(
        "--trust-repo",
        action="store_true",
        help="Trust the target repo's config and skip safety checks. Covers the "
             "Claude Code config check (core/security/cc_trust.py) AND the "
             "CodeQL pack/config check (core/security/codeql_trust.py). New "
             "trust checks read the same signal.",
    )
    parser.add_argument(
        "--no-trust-repo",
        action="store_true",
        help="Keep the strict trust checks for this run, overriding both "
             "--trust-repo and the active project's 'config' trust marker "
             "(raptor project trust config).",
    )

    # SCA integration
    parser.add_argument("--sca", action="store_true",
                        help="Run /sca dependency analysis between scanning and validation")
    parser.add_argument("--skip-sca-review", action="store_true",
                        help="Skip LLM review stages in /sca (mechanical-only)")
    parser.add_argument("--skip-sca-triage", action="store_true",
                        help="Skip LLM triage stage in /sca")

    from core.sandbox import add_cli_args, apply_cli_args
    add_cli_args(parser)
    args = parser.parse_args()

    apply_cli_args(args, parser=parser)

    if args.project is not None:
        from core.run.pin import set_process_project
        set_process_project(args.project)

    # The parent pipeline bootstraps its own pin after start_run (see
    # below at the lifecycle start): mid-session /project switches must
    # not move this process's ambient consumers once the run is pinned.

    if args.threat_model_only:
        args.threat_model = True
    if args.threat_model:
        args.understand = True

    # --gap-audit budget reserve: carve the audit share out of
    # --max-cost-usd UP FRONT so an analysis-phase overrun can't starve
    # the pass the operator explicitly asked for. args.max_cost_usd is
    # reduced in place — every downstream consumer (the Phase 4
    # llm_config cap) sees only the analysis share. Without
    # --max-cost-usd the audit post-pass runs uncapped, matching a
    # bare standalone /audit.
    args.gap_audit_reserved_cost = None
    if args.gap_audit and getattr(args, "max_cost_usd", None):
        share = min(max(args.gap_audit_share, 0.05), 0.95)
        args.gap_audit_reserved_cost = round(args.max_cost_usd * share, 2)
        args.max_cost_usd = round(
            args.max_cost_usd - args.gap_audit_reserved_cost, 2,
        )

    # Apply --phase-timeout uniformly. ``0`` is the unbounded
    # sentinel — set RaptorConfig.DEFAULT_TIMEOUT to None so
    # downstream subprocess calls that use the named constant
    # (or that read ``args.phase_timeout or None``) all see the
    # operator's choice. Same pattern as raptor_codeql.py for
    # cross-command consistency.
    if args.phase_timeout != RaptorConfig.DEFAULT_TIMEOUT:
        RaptorConfig.DEFAULT_TIMEOUT = args.phase_timeout if args.phase_timeout > 0 else None

    # Run-level console verbosity. File audit logging remains DEBUG;
    # this only controls what the operator sees on stderr.
    configure_run_logging(
        getattr(args, "log_level", None),
        getattr(args, "verbose", False),
    )

    # --reanalyze: seed --sarif and --repo from a previous run's metadata
    if getattr(args, "reanalyze", None):
        from core.run.metadata import load_run_metadata
        reanalyze_dir = Path(args.reanalyze).resolve()
        args.reanalyze = str(reanalyze_dir)
        if not reanalyze_dir.is_dir():
            parser.error(f"--reanalyze directory does not exist: {args.reanalyze}")
        prev_meta = load_run_metadata(reanalyze_dir)
        if not prev_meta:
            parser.error(f"--reanalyze: no .raptor-run.json in {reanalyze_dir}")
        prev_target = prev_meta.get("target_path")
        if not prev_target:
            parser.error("--reanalyze: previous run has no target_path in metadata")
        if args.repo and str(Path(args.repo).resolve()) != str(Path(prev_target).resolve()):
            logger.warning(
                "--reanalyze: explicit --repo %s differs from previous run's "
                "target %s — using --repo (SARIF may not match)",
                args.repo, prev_target,
            )
        if not args.repo:
            args.repo = prev_target
        prev_sarif = []
        for s in prev_meta.get("extra", {}).get("sarif_files", []):
            candidate = reanalyze_dir / Path(s).name
            if candidate.exists():
                prev_sarif.append(str(candidate))
            else:
                logger.warning("--reanalyze: SARIF file missing: %s", candidate)
        if not prev_sarif:
            prev_sarif.extend(str(f) for f in sorted(reanalyze_dir.glob("*.sarif")))
        if not prev_sarif:
            parser.error(f"--reanalyze: no SARIF files found in {reanalyze_dir}")
        args.sarif = (args.sarif or []) + prev_sarif
        logger.info("--reanalyze: re-using %d SARIF files from %s", len(prev_sarif), reanalyze_dir)
        # The NEW run adopts the OLD run's project pin: a reanalysis
        # of project P's SARIF must consume P's trust markers and
        # write into P's stores, whatever the session happens to be
        # bound to today. An explicit --project must AGREE or it is a
        # hard error — never a silent pick.
        try:
            from core.run.pin import (
                ProjectArgvError,
                resolve_run_pin,
                set_process_project,
            )
            _old_pin = resolve_run_pin(reanalyze_dir)
            if _old_pin.authoritative:
                _wanted = _old_pin.project if _old_pin.project else "-"
                if args.project is not None and args.project != _wanted:
                    msg = (
                        f"--project {args.project!r} conflicts with the "
                        f"reanalyzed run's pin {_old_pin.project!r} — "
                        "a reanalysis runs under the original run's "
                        "project"
                    )
                    raise ProjectArgvError(msg)
                if args.project is None:
                    args.project = _wanted
                    set_process_project(_wanted)
                    logger.info(
                        "--reanalyze: adopting the previous run's "
                        "project pin (%s)",
                        _old_pin.project or "projectless")
        except Exception as _e:  # noqa: BLE001 — hard error passes through
            from core.run.pin import ProjectArgvError as _PAE
            if isinstance(_e, _PAE):
                parser.error(str(_e))
            logger.debug("--reanalyze: pin adoption failed", exc_info=True)

    # (Runs BEFORE apply_project_trust_flags: the adopted pin
    # must steer trust-marker resolution, not the session's
    # ambient project.)

    # Project trust markers (schema v4): resolve the active project's
    # 'config' / 'build' markers into args.trust_repo / args.traced_build.
    # Per-run flags always win (negative > positive > marker > off);
    # a banner line prints when a marker affects this run. Mirrors the
    # persisted-binaries loading path (binary_oracle_cli).
    from core.project.trust import apply_project_trust_flags
    apply_project_trust_flags(args)

    # Propagate --trust-repo to every target-repo trust check so each
    # in-process consumer (cc_trust, codeql_trust, build_detector, ...)
    # agrees on the operator's intent. New checks added here must keep
    # this list in sync.
    if getattr(args, "trust_repo", False):
        set_trust_override(True)
        from core.security.codeql_trust import set_trust_override as _ql_set
        _ql_set(True)

    # --target-kind: translate the operator's choice into RAPTOR_TARGET_KIND
    # (the env override consulted by inventory's library-mode resolver). 'auto'
    # leaves it unset → per-target manifest detection. Setting the env var is
    # how the intent reaches build_inventory both in-process and across the
    # /validate libexec subprocess boundary.
    _target_kind = getattr(args, "target_kind", "auto")
    if _target_kind != "auto":
        os.environ[RaptorConfig.ENV_TARGET_KIND] = _target_kind

    if not args.repo:
        parser.error("--repo is required (or launch via `raptor` from the target directory)")
    if not Path(args.repo).exists():
        parser.error(f"--repo path does not exist: {args.repo}")

    # Resolve paths
    script_root = Path(__file__).parent.resolve()  # RAPTOR-daniel-modular directory
    repo_path = Path(args.repo).resolve()
    if not repo_path.exists():
        print(f"✗ Repository not found: {repo_path}", file=sys.stderr)
        sys.exit(1)

    # Track temp git copy for cleanup
    _git_temp_dir = None
    # Keep original target path for metadata/findings (even if we scan a temp copy)
    original_repo_path = repo_path

    # Clean up stale raptor_git_* dirs leaked by prior runs killed with
    # SIGKILL (atexit handlers don't fire on SIGKILL). Defer to the
    # shared tmp reaper: it covers the raptor_git_ prefix and applies
    # the age floor, ownership, and liveness gates. The pre-fix bare
    # glob+rmtree here deleted EVERY raptor_git_* unconditionally, so
    # two concurrent agentic runs destroyed each other's live clone
    # scratch at start.
    from core.run.tmp_reaper import reap_stale_tmp
    reap_stale_tmp()

    # Check for .git directory (required for semgrep)
    git_dir = repo_path / ".git"
    if not git_dir.exists():
        print(f"\n  No .git directory found in {repo_path}")
        print("    Semgrep requires a git repository. Creating a temporary copy...")
        logger.info("Target %s is not a git repo — creating temp copy", repo_path)

        try:
            import atexit
            import shutil
            import tempfile
            temp_dir = Path(tempfile.mkdtemp(prefix="raptor_git_"))
            _git_temp_dir = temp_dir
            # atexit-register BEFORE any work that can sys.exit — otherwise the
            # end-of-function rmtree (line ~1033) is bypassed on the sys.exit(1)
            # paths in the except handlers below, leaking raptor_git_*/ under
            # /tmp on every failed non-git target. atexit fires on sys.exit too.
            def _cleanup_git_temp(p=temp_dir) -> None:
                # ``atexit`` callbacks run after most interpreter
                # shutdown teardown — by which point the logging
                # module may have closed its file handles. Pre-fix
                # we relied on ``logger.warning(...)`` to surface
                # cleanup failures, but at exit time that often
                # raised "I/O operation on closed file" and the
                # warning was swallowed by the surrounding
                # ``except Exception: pass``. Defer to ``sys.stderr``
                # which is fd-2 and stays writable past logging
                # shutdown — cleanup failures are visible to the
                # operator even on Ctrl-C.
                try:
                    shutil.rmtree(str(p))
                except OSError as e:
                    # At interpreter teardown stderr can be a closed
                    # stream (ValueError) or broken fd (OSError).
                    with contextlib.suppress(OSError, ValueError):
                        sys.stderr.write(
                            f"[atexit] git_temp_dir cleanup failed for "
                            f"{p}: {e}\n",
                        )
            atexit.register(_cleanup_git_temp)
            temp_repo = temp_dir / repo_path.name
            # Copy symlinks as-is, don't follow them into files outside the repo
            shutil.copytree(str(repo_path), str(temp_repo), symlinks=True)

            env = RaptorConfig.get_safe_env()
            env.update({
                "GIT_TERMINAL_PROMPT": "0",
                # Prevent git hooks and filters from executing on untrusted content
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null",
            })
            # Disable hooks and filters — a malicious .gitattributes filter
            # directive would otherwise execute arbitrary commands during
            # git add. The canonical per-invocation pins live in
            # core.git._SAFE_GIT_OVERRIDES (hooksPath, diff.external,
            # gpg.*, askPass, fsmonitor, credential.helper, ...) — build
            # the argv via safe_git_command so this site stops drifting
            # behind core's list, and layer the site-specific extras
            # (LFS filter neutralisation + identity for the snapshot
            # commit) on top. git honours the LAST -c for a key, so the
            # extras win where they overlap.
            from core.git import safe_git_command as _safe_git_command
            git_extra = ["-c", "filter.lfs.clean=true",
                         "-c", "filter.lfs.smudge=true",
                         "-c", "filter.lfs.process=true",
                         "-c", "user.name=raptor",
                         "-c", "user.email=raptor@local"]
            # Suppress per-call sandbox INFO lines for internal git
            # housekeeping — the operator already sees the "Creating a
            # temporary copy" message; 3 repeated sandbox lines are noise.
            import logging as _logging

            from core.sandbox import run as sandbox_run
            _sb_log = _logging.getLogger("core.sandbox.context")
            _sb_prev = _sb_log.level
            _sb_log.setLevel(_logging.WARNING)
            try:
                result = sandbox_run(
                    _safe_git_command(*git_extra, "init"), block_network=True,
                    cwd=temp_repo, capture_output=True, text=True, timeout=30,
                    env=env, env_caller_filtered=True,
                )
                if result.returncode == 0:
                    add_result = sandbox_run(
                        _safe_git_command(*git_extra, "add", "."),
                        block_network=True,
                        cwd=temp_repo, capture_output=True, text=True, timeout=60,
                        env=env, env_caller_filtered=True,
                    )
                    if add_result.returncode != 0:
                        result = add_result
                    else:
                        commit_result = sandbox_run(
                            _safe_git_command(
                                *git_extra, "commit", "-m",
                                "RAPTOR scan snapshot"),
                            block_network=True,
                            cwd=temp_repo, capture_output=True, text=True, timeout=60,
                            env=env, env_caller_filtered=True,
                        )
                        if commit_result.returncode != 0:
                            result = commit_result
            finally:
                _sb_log.setLevel(_sb_prev)
            if result.returncode == 0:
                repo_path = temp_repo
                print("  Temporary git repo created for scanning")
                logger.debug("Using temp git repo: %s", temp_repo)
            else:
                print(f"  ✗ Failed to initialize git repository: {result.stderr}", file=sys.stderr)
                logger.error("Git init failed: %s", result.stderr)
                sys.exit(1)

        except SandboxSetupError:
            # Sandbox couldn't engage — not a git error. Propagate to the
            # top-level handler so the operator gets the actionable message.
            raise
        except subprocess.TimeoutExpired:
            print("  ✗ Git initialisation timed out", file=sys.stderr)
            logger.error("Git init timeout")
            sys.exit(1)
        except FileNotFoundError:
            print("  ✗ Git is not installed. Please install git and try again.", file=sys.stderr)
            logger.error("Git not found in PATH")
            sys.exit(1)
        except Exception as e:  # noqa: BLE001
            print(f"  ✗ Error initializing git: {e}", file=sys.stderr)
            logger.error("Git init error: %s", e)
            sys.exit(1)

    # Generate output directory with repository name and timestamp
    repo_name = repo_path.name  # Define repo_name for logging
    from core.run import get_output_dir
    # target_path wired through so the project target-mismatch gate
    # actually fires for direct invocations (pre-fix it only ran when
    # RAPTOR_CALLER_DIR happened to be set).
    out_dir = get_output_dir(
        "agentic", target_name=repo_name,
        explicit_out=args.out or None,
        target_path=str(repo_path),
    )
    # Parent (RAPTOR_DIR/out/, project dir, or --out target's parent) is
    # raptor-controlled — plain mkdir is fine. The leaf is the predictable
    # timestamp+PID name and gets the symlink/UID/world-write check.
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    safe_run_mkdir(out_dir)

    # Resolve the sanitizer-cut mode now the run dir is known, and
    # export it so the scan / codeql / analysis subprocesses inherit it
    # (review #4, PR #794). No-op when --sanitizer-cut isn't passed.
    _sc = sanitizer_cut_config.configure_from_args(
        args, run_dir=str(out_dir), export_env=True,
    )
    if _sc is not None:
        logger.info("Sanitizer-cut mode: %s", _sc.mode)

    try:
        from core.run import start_run
        start_run(out_dir, "agentic", target=str(original_repo_path))
        # Pin bootstrap: freeze THIS process's ambient project
        # resolution to the run's recorded pin — a mid-session
        # /project switch must not move trust markers, IRIS stores,
        # exemplar pools, or threat models under an in-flight run
        #. No-op when --project already set the override.
        from core.run.pin import bootstrap_process_pin
        bootstrap_process_pin(out_dir)
    except Exception as e:  # noqa: BLE001
        # Run-start contention must not be swallowed like an optional
        # metadata failure: another session's live run owns the project.
        # (When raptor.py's lifecycle wrapper drove this run, it already
        # stamped the dir and this start_run is a re-entrant enrich —
        # the gate skips those, so reaching here means a DIRECT
        # raptor_agentic.py invocation raced a live run.)
        from core.project.oplock import OpLockContention
        from core.run.pin import ProjectArgvError
        if isinstance(e, (OpLockContention, ProjectArgvError)):
            # ProjectArgvError is a hard error by contract: an invalid
            # --project must never fall back to an ambient layer.
            # Remove the just-created (still empty) dir so a refused
            # direct invocation leaves no phantom run behind.
            import contextlib as _ctx
            with _ctx.suppress(OSError):
                out_dir.rmdir()
            print(f"✗ {e}", file=sys.stderr)
            sys.exit(1)
        logger.debug("Run metadata: %s", e)  # Optional — don't fail the pipeline

    logger.info("=" * 70)
    logger.info("RAPTOR AGENTIC WORKFLOW STARTED")
    logger.info("=" * 70)
    logger.info("Repository: %s", repo_name)
    logger.info("Full path: %s", original_repo_path)
    logger.info("Output: %s", out_dir)
    logger.info("Policy groups: %s", args.policy_groups)
    logger.info("Max findings: %s", args.max_findings)
    if args.binary:
        logger.info("Target binary(s): %s", args.binary)
    # All ``--binary`` / ``--binary-auto`` / ``--binary-edges`` plumbing
    # — path validation, auto-detect walk, active-project binary
    # layering, RaptorConfig mutation, and the no-leak-across-runs
    # guarantee — lives in the shared CLI helper. raptor_codeql.py
    # uses the same call site to keep behaviour aligned.
    #
    # Explicit --binary paths resolve early here (Phase 0 mitigation
    # check needs them). Default autodetect is deferred to the
    # post-scan call site below — CodeQL may compile the target
    # (C/C++/Go/Java), leaving build artefacts that autodetect finds.
    from core.analysis.binary_oracle_cli import apply_to_config
    if getattr(args, "binary", None) or getattr(args, "no_binary_oracle", False):
        apply_to_config(args, Path(args.repo))

    workflow_start = time.time()

    # Detect LLM availability once — single source of truth for all phases
    from packages.llm_analysis import detect_llm_availability
    llm_env = detect_llm_availability()

    # ========================================================================
    # PHASE 0: PRE-EXPLOIT MITIGATION ANALYSIS (Optional but recommended)
    # ========================================================================
    mitigation_result = None
    if args.check_mitigations or args.binary:
        print("\n" + "=" * 70)
        print("MITIGATION ANALYSIS")
        print("=" * 70)
        print("\nChecking system and binary mitigations BEFORE scanning...")
        print("This prevents wasted effort on impossible exploits.\n")

        try:
            # Optional source_intel wire: hand the reconciler the
            # target's compile-time _FORTIFY_SOURCE level (extracted
            # from compile_commands.json / Makefile / kconfig by
            # ``core.build.build_flags.extract_flags``) so the %n
            # verdict can override the ELF-derived ``__printf_chk``
            # heuristic when they disagree. Defensive — returns an
            # empty BuildFlagsContext on missing build metadata, which
            # leaves the reconciler's pre-wire behaviour intact.
            from core.build.build_flags import extract_flags
            from packages.exploit_feasibility import (
                analyze_binary,
                format_analysis_summary,
            )
            _agentic_build_flags = extract_flags(
                Path(args.repo) if args.repo else Path.cwd()
            )

            # --binary is action='append' (list) for binary-oracle's
            # hybrid multi-binary case; mitigation analysis is per-binary,
            # so analyse the FIRST declared binary.
            binary_path = (
                str(Path(args.binary[0])) if args.binary else None)
            mitigation_result = analyze_binary(
                binary_path,
                output_dir=str(out_dir),
                build_flags=_agentic_build_flags,
            )

            # Display formatted summary
            print(format_analysis_summary(mitigation_result, verbose=True))

            verdict = mitigation_result.get('verdict', 'unknown')
            if verdict == 'unsupported_platform':
                print("\n" + "=" * 70)
                print("NOTE: EXPLOIT FEASIBILITY REQUIRES LINUX — SKIPPED")
                print("=" * 70)
                print("\nContinuing scan without mitigation analysis...")

            elif verdict == 'unlikely':
                print("\n" + "=" * 70)
                print("NOTE: EXPLOITATION UNLIKELY WITH CURRENT MITIGATIONS")
                print("=" * 70)
                print("\nContinuing scan anyway (for vulnerability discovery)...")

            elif verdict == 'difficult':
                print("\n" + "=" * 70)
                print("NOTE: EXPLOITATION DIFFICULT - REVIEW CONSTRAINTS ABOVE")
                print("=" * 70)

            else:
                print("\nMitigation check passed - exploitation may be feasible")

            logger.info("Mitigation analysis complete: %s", verdict)

        except ImportError:
            print("Mitigation analysis module not available")
        except Exception as e:  # noqa: BLE001
            print(f"⚠️  Mitigation check failed: {e}", file=sys.stderr)
            logger.error("Mitigation check error: %s", e)

    # ========================================================================
    # PRE-SCAN: Check target repo for malicious Claude Code settings
    # ========================================================================
    # Early loud warning only — the verdict is NOT threaded through the
    # phases. Scanning/analysis runs untrusted target code and LLM-driven
    # sessions that can write .claude/settings.json / .mcp.json mid-run,
    # so each CC dispatch site below re-invokes check_repo_claude_trust
    # immediately before dispatching (the scan cache is keyed on a
    # config-file fingerprint, so an unchanged repo re-checks for free).
    check_repo_claude_trust(original_repo_path)

    # ========================================================================
    # PHASE 1: CODE SCANNING (Semgrep + CodeQL)
    # ========================================================================
    print("\n" + "=" * 70)
    print("SCANNING")
    print("=" * 70)

    # Build inventory checklist (independent of scanning, available to all phases)
    try:
        from core.inventory import build_inventory
        if not (out_dir / "checklist.json").exists():
            build_inventory(str(original_repo_path), str(out_dir))
            logger.debug("Inventory checklist built: %s", out_dir / "checklist.json")
    except Exception as e:  # noqa: BLE001
        logger.warning("Inventory build failed (continuing without metadata): %s", e)

    # ========================================================================
    # PRE-PASS: /understand --map (opt-in via --understand)
    # Creates a lifecycle-managed sibling /understand run (discoverable to the
    # bridge tier-2/3) AND enriches the agentic checklist with priority
    # markers. The analysis prompt surfaces those markers per finding, so
    # --understand pays off in this run too — not just in any later /validate.
    # ========================================================================
    # --gap-audit depends on a context map for sink/entry-point priority
    # ordering. Bridge-search first (co-located, project siblings,
    # global out/ with hash-freshness ranking) — only enable the
    # understand pre-pass when nothing usable exists, so projects that
    # already carry a map don't pay for a re-map.
    if args.gap_audit and not args.understand:
        _map_dir = None
        try:
            from core.orchestration.understand_bridge import (
                find_understand_output,
            )
            _map_dir, _ = find_understand_output(
                out_dir, str(original_repo_path),
            )
        except Exception:  # noqa: BLE001 — bridge miss = run the map
            logger.debug("--gap-audit map bridge-search failed", exc_info=True)
        if _map_dir is None:
            print("\n  --gap-audit: no /understand map found for this "
                  "target — enabling the understand pre-pass")
            args.understand = True

    prepass_result = None
    threat_model_phase = {"enabled": bool(args.threat_model), "completed": False}
    if args.understand:
        from core.orchestration import run_understand_prepass
        print("\n" + "=" * 70)
        print("UNDERSTAND PRE-PASS")
        print("=" * 70)
        prepass_result = run_understand_prepass(
            target=original_repo_path,
            agentic_out_dir=out_dir,
            # Re-check at dispatch time — the pre-scan verdict may be stale.
            block_cc_dispatch=check_repo_claude_trust(original_repo_path),
        )
        if prepass_result.ran:
            logger.info(
                "Pre-pass wrote %s in %s (checklist enriched: %s, took %.1fs)",
                prepass_result.context_map_path,
                prepass_result.understand_dir,
                prepass_result.checklist_enriched,
                prepass_result.duration_s,
            )
        else:
            logger.warning("Pre-pass skipped: %s", prepass_result.skipped_reason)

    if args.threat_model:
        try:
            threat_model_phase = _materialise_threat_model_phase(
                target=original_repo_path,
                out_dir=out_dir,
                prepass_result=prepass_result,
                refresh=args.threat_model_refresh,
                allow_stale=args.threat_model_use_stale,
            )
        except Exception as e:  # noqa: BLE001
            logger.error("Threat model phase failed: %s", e)
            threat_model_phase = {"enabled": True, "completed": False, "skipped_reason": str(e)}
        _print_threat_model_phase(threat_model_phase)

        if args.threat_model_only:
            report_file = out_dir / "raptor_agentic_report.json"
            final_report = {
                "repository": str(original_repo_path),
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "duration_seconds": time.time() - workflow_start,
                "phases": {
                    "threat_model": threat_model_phase,
                    "scanning": {"enabled": False, "skipped_reason": "--threat-model-only"},
                    "exploitability_validation": {"completed": False},
                    "autonomous_analysis": {"completed": False},
                },
                "outputs": {
                    "threat_model_json": threat_model_phase.get("threat_model_json"),
                    "threat_model_markdown": threat_model_phase.get("threat_model_markdown"),
                    "threat_model_report": threat_model_phase.get("threat_model_report"),
                    "threat_model_lint": threat_model_phase.get("threat_model_lint"),
                    "threat_model_drift": threat_model_phase.get("threat_model_drift"),
                    "threats": threat_model_phase.get("threats"),
                    "threat_model_summary": str(out_dir / "threat-model-summary.json") if threat_model_phase.get("completed") else None,
                    "threat_model_candidates": threat_model_phase.get("candidate_sarif"),
                    "context_map": threat_model_phase.get("context_map"),
                },
            }
            save_json(report_file, final_report)
            try:
                if threat_model_phase.get("completed"):
                    from core.run import complete_run
                    complete_run(out_dir, extra={
                        "findings_count": threat_model_phase.get("generated_candidates", 0),
                        "threat_model": threat_model_phase,
                        "duration_seconds": round(time.time() - workflow_start, 1),
                    })
                else:
                    from core.run import fail_run
                    fail_run(out_dir, threat_model_phase.get("skipped_reason") or "threat model phase did not complete")
            except Exception as e:  # noqa: BLE001
                logger.debug("Run metadata: %s", e)
            if _git_temp_dir and _git_temp_dir.exists():
                import shutil
                try:
                    shutil.rmtree(str(_git_temp_dir))
                except Exception as e:  # noqa: BLE001
                    logger.debug("Failed to clean temp git dir: %s", e)
            completed = threat_model_phase.get("completed", False)
            print(f"\nThreat model only {'complete' if completed else 'skipped'}.")
            print(f"   Report: {report_file}")
            return 0 if completed else 1

    # ========================================================================
    # PRE-PASS: reachability — always-on companion to /understand.
    # Marks dead-code functions priority=low in the agentic checklist using
    # core.analysis.reachability. Runs regardless of --understand because
    # the agentic LLM analysis prompt reads priority/priority_reason and
    # benefits from the dead-code signal even without context-map upgrades.
    # The returned inventory is threaded through to downstream consumers
    # (codeql analyzer, /validate post-pass) so they don't re-walk the tree.
    # ========================================================================
    reachability_prepass_result = None
    scan_inventory = None
    _checklist_path = out_dir / "checklist.json"
    if _checklist_path.exists():
        # load_json is non-strict: returns None on unreadable/corrupt
        # input and logs a warning naming the file — nothing to suppress.
        scan_inventory = load_json(_checklist_path)
    def _try_cached_joern(target: Path, run_out_dir: Path):
        """Start a Joern server only if a cached CPG exists for this project."""
        try:
            from packages.joern.prereqs import is_available
            if not is_available():
                return None
            project_dir = run_out_dir.parent
            if project_dir == run_out_dir:
                return None
            from packages.joern.runner import load_cached_cpg
            cpg = load_cached_cpg(target, project_dir)
            if cpg is None:
                return None
            from packages.joern.server import JoernServer
            srv = JoernServer()
            srv.start()
            srv.import_cpg(cpg.path)
            logger.info("Joern server started with cached CPG for prepass")
            return srv
        except Exception:
            logger.debug("Joern cached CPG not available for prepass",
                         exc_info=True)
            return None

    try:
        from core.orchestration import run_reachability_prepass
        joern_srv = _try_cached_joern(original_repo_path, out_dir)
        try:
            reachability_prepass_result = run_reachability_prepass(
                target=original_repo_path,
                agentic_out_dir=out_dir,
                allow_unreachable=getattr(args, "allow_unreachable", False),
                joern_server=joern_srv,
                inventory=scan_inventory,
            )
        finally:
            if joern_srv is not None:
                joern_srv.stop()
        if reachability_prepass_result.ran:
            logger.info(
                "Reachability pre-pass marked "
                "%s dead-code "
                "function(s) priority=low "
                "(took %.1fs)",
                reachability_prepass_result.marked_count,
                reachability_prepass_result.duration_s,
            )
        else:
            logger.debug(
                "Reachability pre-pass skipped: %s", reachability_prepass_result.skipped_reason
            )
    except Exception:
        logger.warning(
            "Reachability pre-pass failed; continuing without it",
            exc_info=True,
        )

    all_sarif_files = []
    semgrep_metrics = {}
    codeql_metrics = {}
    threat_candidate_sarif = threat_model_phase.get("candidate_sarif")
    if threat_candidate_sarif and Path(threat_candidate_sarif).exists():
        all_sarif_files.append(Path(threat_candidate_sarif))
    import_sarif_files: list = getattr(args, "sarif", None) or []

    if args.also_scan and not import_sarif_files:
        logger.warning("--also-scan has no effect without --sarif; ignoring")

    # When --sarif is provided without --also-scan, skip RAPTOR's own
    # scanners entirely — the imported SARIF replaces the scan step.
    skip_scan = bool(import_sarif_files) and not args.also_scan

    # Launch scanners in parallel when both are enabled
    run_semgrep = not args.codeql_only and not skip_scan
    run_codeql = (args.codeql or args.codeql_only) and not args.no_codeql and not skip_scan

    # Defensive guard for the "no scanners enabled" case.
    if not skip_scan and not (run_semgrep or run_codeql):
        print(
            "\n✗ Both Semgrep and CodeQL are disabled — nothing to scan.\n"
            "  Re-run without --codeql-only / --no-codeql, or pass only one "
            "of those flags.",
            file=sys.stderr,
        )
        return 2

    semgrep_cmd = None
    codeql_cmd = None
    semgrep_proc = None
    codeql_proc = None
    semgrep_drain = None
    codeql_drain = None

    # Propagate sandbox CLI flags to the scanner subprocesses. Without
    # this, `python raptor.py agentic --audit` would set audit mode in
    # the agentic process but the actual sandbox-using subprocesses
    # (scanner.py, codeql/agent.py) would inherit nothing — audit signal
    # in the run dir would be empty even though --audit was requested.
    # Discovered by E2E against /tmp/vulns: the outer process logged
    # "audit engaged" but no sandbox-summary.json appeared in any
    # subprocess's run dir.
    sandbox_passthrough = []
    if getattr(args, "sandbox", None) is not None:
        sandbox_passthrough.extend(["--sandbox", args.sandbox])
    if getattr(args, "no_sandbox", False):
        sandbox_passthrough.append("--no-sandbox")
    if getattr(args, "audit", False):
        sandbox_passthrough.append("--audit")
    if getattr(args, "audit_verbose", False):
        sandbox_passthrough.append("--audit-verbose")

    if run_semgrep:
        print("\n[*] Running Semgrep analysis...")
        semgrep_cmd = [
            "python3",
            str(script_root / "packages/static-analysis/scanner.py"),
            "--repo", str(repo_path),
            "--policy_groups", args.policy_groups,
            # Write into the run dir's scan/ subdir (mirrors codeql/) so the
            # scanner's coverage records (semgrep + cocci) are first-class run
            # artifacts the coverage store reads — no transient dir, no copy.
            "--out", str(out_dir / "scan"),
            *sandbox_passthrough,
        ]
        # Compiler-analyzer + expanded-semgrep channels ride the scanner
        # subprocess — forwarded verbatim (same pattern as --traced-build
        # on the codeql agent). --no wins over --on at the scanner too,
        # but resolve here so the child's argv reflects the decision.
        if args.compiler_scan and not args.no_compiler_scan:
            semgrep_cmd.append("--compiler-scan")
            if args.compiler_scan_max_tus is not None:
                semgrep_cmd.extend([
                    "--compiler-scan-max-tus",
                    str(args.compiler_scan_max_tus),
                ])
        if args.expanded_semgrep:
            semgrep_cmd.append("--expanded-semgrep")
        # Graduated synthesized rules are default-on at the scanner;
        # forward only the opt-out.
        if args.no_graduated_rules:
            semgrep_cmd.append("--no-graduated-rules")
        logger.debug("Running: Scanning code with Semgrep")
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        # ``semgrep_cmd`` is a list of RAPTOR-constructed argv;
        # env inherits from RAPTOR's own process (the operator's
        # env). PYTHONUSERBASE inheritance is intentional — see
        # F102 comment below.
        semgrep_proc = subprocess.Popen(
            semgrep_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            bufsize=1,  # Line-buffered, see main-Popen comment.
            # F102: semgrep is typically installed via
            # ``pip install --user``; without PYTHONUSERBASE flowing
            # through, an operator with a non-default user-base sees
            # ``ModuleNotFoundError: No module named 'semgrep'`` here.
            # PYTHONUSERBASE remains stripped by default (it is a real
            # RCE vector via .pth files); the opt-in restores it only
            # for this scanner spawn.
            # preserve_proxy: the scanner fetches registry packs via
            # its own egress proxy, whose upstream autodetect reads
            # this child's env.
            env=RaptorConfig.get_safe_env(
                preserve_proxy=True, include_python_user_base=True,
            ),
            start_new_session=True,  # See main-Popen comment.
        )
        # Drain immediately — see _PipeDrainer: without concurrent
        # readers the sibling child deadlocks on a full pipe.
        semgrep_drain = _PipeDrainer(semgrep_proc)

    if run_codeql:
        print("\n[*] Running CodeQL analysis...")
        codeql_cmd = [
            "python3",
            str(script_root / "packages/codeql/agent.py"),
            "--repo", str(repo_path),
            "--out", str(out_dir / "codeql"),
            *sandbox_passthrough,
        ]
        if args.languages:
            codeql_cmd.extend(["--languages", args.languages])
        if args.traced_build:
            codeql_cmd.append("--traced-build")
        if args.build_command:
            # SECURITY: build_command flows to `codeql database
            # create --command <cmd>`. CodeQL splits --command on
            # whitespace WITHOUT shell interpretation (no &&, ||,
            # ;, | etc.), then either runs the resulting argv
            # directly OR wraps it in a temp shell script when
            # the operator's command needs shell semantics
            # (handled in `database_manager._wrap_in_shell_script`
            # — see its docstring).
            #
            # Pre-fix this comment said "build_command is
            # shell-evaluated" without context. That's true for
            # the SHELL-WRAPPED path (database_manager wraps in
            # bash when `;`/`&&` are present) but NOT for the
            # default direct-argv path. The misleading absolute
            # made operators assume any shell-meta in
            # build_command was always live, which is true for
            # security purposes (the value MUST be operator-
            # supplied, never repo-derived) but the runtime
            # behaviour is more nuanced.
            #
            # Net: same security requirement (operator-supplied
            # only), but the comment now reflects reality:
            # CodeQL's own splitter is no-shell; only the
            # explicit shell-script wrap path runs under bash.
            codeql_cmd.extend(["--build-command", args.build_command])
        if args.extended:
            codeql_cmd.append("--extended")
        if args.codeql_cli:
            codeql_cmd.extend(["--codeql-cli", args.codeql_cli])
        logger.debug("Running: Scanning code with CodeQL")
        # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
        # Explicit ``env=RaptorConfig.get_safe_env()`` — strips
        # DANGEROUS_ENV_VARS (LD_PRELOAD / DYLD_* / GCONV_PATH
        # etc.) per the env-allowlist convention. Semgrep's rule
        # can't infer that the helper is safety-strip-aware.
        # preserve_proxy: pack downloads inside the CodeQL agent
        # chain through an egress proxy fed from this child's env.
        codeql_proc = subprocess.Popen(
            codeql_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            bufsize=1,  # Line-buffered, see main-Popen comment.
            env=RaptorConfig.get_safe_env(preserve_proxy=True),
            start_new_session=True,  # See main-Popen comment.
        )
        codeql_drain = _PipeDrainer(codeql_proc)

    # ---- Collect Semgrep results ----
    if semgrep_proc:
        try:
            # ``args.phase_timeout`` 0 → ``None`` = unbounded (operator
            # opt-in for kernel-scale targets via ``--phase-timeout 0``).
            _semgrep_stdout, _semgrep_stderr = semgrep_drain.collect(
                timeout=(args.phase_timeout or None)
            )
            rc = semgrep_proc.returncode
        except subprocess.TimeoutExpired:
            # Group kill — see _kill_process_tree: the scanner's own
            # subprocesses must not survive the phase timeout.
            _kill_process_tree(semgrep_proc)
            # Bound the post-kill drain — pre-fix bare
            # ``communicate()`` had no timeout and could wedge on a
            # child stuck in uninterruptible IO inside the sandbox.
            # 30s is generous for a kill-9'd process to release its
            # FDs; on TimeoutExpired here we abandon the streams
            # (FDs leaked, but the kill has already been sent).
            try:
                semgrep_drain.collect(timeout=30)
            except subprocess.TimeoutExpired:
                logger.warning(
                    "Semgrep child did not drain after kill; "
                    "abandoning communicate (FDs may leak)"
                )
            rc = -1
            print(
                f"✗ Semgrep scan timed out ({args.phase_timeout}s)",
                file=sys.stderr,
            )
            logger.error("Semgrep scan timed out")
            # Surface the timeout in the agentic-run summary even when
            # CodeQL also runs. Pre-fix the `if not run_codeql:
            # sys.exit(1)` asymmetry made the timeout LOUDLY fail
            # Semgrep-only runs but SILENTLY continue mixed runs —
            # operator scrolling past the error mid-run could miss
            # it and ship a "scan complete" report that was actually
            # missing all Semgrep findings. Write a marker file so
            # downstream consumers (project merge, /project status,
            # final summary) see an unambiguous "Semgrep timed out"
            # signal instead of just absent semgrep_*.json files
            # (which look indistinguishable from "scan was disabled").
            try:
                from core.json import save_json as _save_json
                _save_json(
                    out_dir / ".semgrep_timeout",
                    {
                        "timed_out_at_seconds": args.phase_timeout,
                        "stage": "semgrep",
                    },
                )
            except Exception as e:  # noqa: BLE001
                logger.warning("failed to write semgrep timeout marker: %s", e)
            if not run_codeql:
                _fail_run_and_exit(
                    out_dir,
                    f"Semgrep scan timed out ({args.phase_timeout}s)",
                )

        if rc == SANDBOX_ENGAGE_EXIT_CODE:
            # The semgrep subprocess reported the sandbox could not engage
            # (it already printed the actionable message). Abort the whole
            # run loud — never fall through into LLM analysis on a silent
            # "0 findings". Kill the sibling codeql child first.
            if codeql_proc and codeql_proc.poll() is None:
                _kill_process_tree(codeql_proc)
                try:
                    codeql_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            msg = (
                "the semgrep scan subprocess reported the sandbox could not "
                f"engage (exit {SANDBOX_ENGAGE_EXIT_CODE}); see its output above"
            )
            raise SandboxSetupError(
                msg,
                "re-run with --sandbox network-only (or --sandbox none). "
                "RAPTOR will not silently downgrade.",
            )

        if rc in (0, 1):
            # The scanner now writes into the run dir's scan/ subdir (--out
            # above), so its outputs — combined.sarif, scan_metrics.json, and
            # the coverage records — are first-class run artifacts. No transient
            # dir to discover, no copy.
            actual_scan_dir = out_dir / "scan"
            logger.debug("Semgrep output in run dir: %s", actual_scan_dir)

            scan_metrics_file = actual_scan_dir / "scan_metrics.json"
            if scan_metrics_file.exists():
                semgrep_metrics = load_json(scan_metrics_file)
                if not isinstance(semgrep_metrics, dict):
                    semgrep_metrics = {}

                print("\n✓ Semgrep scan complete:")
                print(f"  - Files scanned: {semgrep_metrics.get('total_files_scanned', 0)}")
                print(f"  - Findings: {semgrep_metrics.get('total_findings', 0)}")
                print(f"  - Critical: {semgrep_metrics.get('findings_by_severity', {}).get('error', 0)}")
                print(f"  - Warnings: {semgrep_metrics.get('findings_by_severity', {}).get('warning', 0)}")

            sarif_file = actual_scan_dir / "combined.sarif"
            if sarif_file.exists():
                all_sarif_files.append(sarif_file)
            else:
                semgrep_sarifs = list(actual_scan_dir.glob("semgrep_*.sarif"))
                all_sarif_files.extend(semgrep_sarifs)
        elif rc != -1:  # -1 is timeout, already reported
            print(f"✗ Semgrep scan failed (exit code {rc})", file=sys.stderr)
            if not run_codeql:
                _fail_run_and_exit(out_dir, f"Semgrep scan failed (exit code {rc})")

    # ---- Collect CodeQL results ----
    if codeql_proc:
        codeql_stderr = ""
        try:
            _codeql_stdout, codeql_stderr = codeql_drain.collect(
                timeout=(args.phase_timeout or None)
            )
            rc = codeql_proc.returncode
        except subprocess.TimeoutExpired:
            # Group kill — see _kill_process_tree.
            _kill_process_tree(codeql_proc)
            # See Semgrep post-kill drain above for the rationale.
            try:
                codeql_drain.collect(timeout=30)
            except subprocess.TimeoutExpired:
                logger.warning(
                    "CodeQL child did not drain after kill; "
                    "abandoning communicate (FDs may leak)"
                )
            rc = -1
            print(
                f"✗ CodeQL scan timed out ({args.phase_timeout}s)",
                file=sys.stderr,
            )
            logger.error("CodeQL scan timed out")

        if rc == SANDBOX_ENGAGE_EXIT_CODE:
            # CodeQL subprocess reported the sandbox could not engage —
            # abort loud rather than continuing with partial findings.
            msg = (
                "the codeql scan subprocess reported the sandbox could not "
                f"engage (exit {SANDBOX_ENGAGE_EXIT_CODE}); see its output above"
            )
            raise SandboxSetupError(
                msg,
                "re-run with --sandbox network-only (or --sandbox none). "
                "RAPTOR will not silently downgrade.",
            )

        if rc != 0:
            if all_sarif_files:
                print("⚠️  CodeQL scan failed — continuing with existing findings", file=sys.stderr)
            else:
                print("⚠️  CodeQL scan failed — no findings from any scanner", file=sys.stderr)
            # Surface the captured stderr so the operator can see WHY codeql
            # exited non-zero. Pre-fix the agentic wrapper threw away
            # codeql_stderr and only logged "rc={rc}", leaving the operator
            # to spelunk through out/codeql_*/ to find the actual reason
            # (often empty on early failure — language detector returns
            # before writing any report).
            stderr_tail = (codeql_stderr or "").rstrip().splitlines()[-15:]
            if stderr_tail:
                print("   CodeQL stderr (last 15 lines):")
                for line in stderr_tail:
                    print(f"     {line}")
            if any("No CodeQL-supported languages detected" in line for line in stderr_tail):
                print(
                    "   Hint: language auto-detection rejected every candidate "
                    "(typically because the target has no build files — go.mod, "
                    "package.json, pyproject.toml, CMakeLists.txt, etc.). "
                    "Pass --languages cpp,python,javascript,go (or a subset) "
                    "to bypass auto-detection."
                )
            logger.warning("CodeQL scan failed - rc=%d", rc)
            if args.codeql_only:
                print("✗ CodeQL-only mode failed", file=sys.stderr)
                _fail_run_and_exit(out_dir, "CodeQL-only mode failed")
        else:
            codeql_out_dir = out_dir / "codeql"
            codeql_report = codeql_out_dir / "codeql_report.json"

            if codeql_report.exists():
                codeql_metrics = load_json(codeql_report)
                if not isinstance(codeql_metrics, dict):
                    codeql_metrics = {}

                total_findings = codeql_metrics.get('total_findings', 0)
                sarif_files = codeql_metrics.get('sarif_files', [])

                print("\n✓ CodeQL scan complete:")
                print(f"  - Languages: {', '.join(codeql_metrics.get('languages_detected', {}).keys())}")
                print(f"  - Findings: {total_findings}")
                print(f"  - SARIF files: {len(sarif_files)}")

                all_sarif_files.extend(Path(sarif) for sarif in sarif_files)

    # Check if we have any findings from source-code scanners.
    # SCA may still contribute findings even when Semgrep/CodeQL found nothing,
    # so we don't exit here — we proceed to the SCA phase first.
    source_scan_empty = not all_sarif_files

    # ========================================================================
    # PHASE 1b: SOFTWARE COMPOSITION ANALYSIS
    # ========================================================================
    sca_metrics = {}
    mechanical_sca_error = None
    sca_out = out_dir / "sca"
    try:
        from packages.sca.agent import _find_sca_agent, run_sca_subprocess
        sca_agent = _find_sca_agent()
    except ImportError:
        sca_agent = None

    run_mechanical_sca = _should_run_mechanical_sca(sca_agent, args.sca)
    if sca_agent and not run_mechanical_sca:
        # Deferred: the opt-in deep SCA phase (PHASE 1b below) analyses
        # the same dependency set with LLM review + triage. Running the
        # mechanical subprocess phase too would double-produce and
        # double-count dependency findings.
        sca_findings_count = 0
        logger.info("--sca set — deferring dependency analysis to the deep SCA phase")
    elif run_mechanical_sca:
        print("\n" + "=" * 70)
        print("SOFTWARE COMPOSITION ANALYSIS")
        print("=" * 70)
        print("\n[*] Running SCA (dependencies, supply chain, reachability)...")
        try:
            # Route via sandbox egress proxy so SCA's HTTP calls are
            # hostname-allowlisted when --sandbox is active. The allowlist
            # is SCA_ALLOWED_HOSTS (vuln feeds + registries + archives).
            rc, sca_stdout, sca_stderr = run_sca_subprocess(
                sca_agent,
                original_repo_path,
                sca_out,
                sandbox_args=sandbox_passthrough,
            )
            if rc == 0:
                sca_sarif = sca_out / "findings.sarif"
                if sca_sarif.exists():
                    all_sarif_files.append(sca_sarif)
                # Parse the one-line JSON summary from stdout
                import json as _json
                for line in reversed(sca_stdout.strip().splitlines()):
                    line = line.strip()
                    if line.startswith("{"):
                        try:
                            sca_metrics = _json.loads(line)
                        except Exception as e:  # noqa: BLE001
                            logger.warning("failed to parse SCA metrics from %s: %s", sca_out, e)
                        break
                sca_findings_count = sca_metrics.get("vuln_findings", 0) + \
                                     sca_metrics.get("supply_chain_findings", 0)
                print("\n✓ SCA complete:")
                print(f"  - Dependencies: {sca_metrics.get('deps_analysed', 0)}")
                print(f"  - Vulnerability findings: {sca_metrics.get('vuln_findings', 0)}")
                print(f"  - Supply chain findings: {sca_metrics.get('supply_chain_findings', 0)}")
                print(f"  - Hygiene findings: {sca_metrics.get('hygiene_findings', 0)}")

                # SAGE: store SCA vulnerability findings for cross-run learning
                try:
                    from core.sage.hooks import store_sca_outcomes
                    sca_findings_path = sca_out / "findings.json"
                    if sca_findings_path.exists():
                        import json as _sca_json
                        sca_data = _sca_json.loads(
                            sca_findings_path.read_text(encoding="utf-8")
                        )
                        sca_sage_outcomes = []
                        for row in (sca_data if isinstance(sca_data, list) else []):
                            sca_info = row.get("sca") or {}
                            if not sca_info.get("name"):
                                continue
                            cve_ids = []
                            if row.get("cve_id"):
                                cve_ids.append(row["cve_id"])
                            sca_sage_outcomes.append({
                                "package_name": sca_info["name"],
                                "ecosystem": sca_info.get("ecosystem", ""),
                                "version": sca_info.get("installed_version", ""),
                                "kind": "vuln",
                                "verdict": "vulnerable",
                                "severity": row.get("severity", ""),
                                "cve_ids": cve_ids,
                                "detail": row.get("message", "")[:200],
                            })
                        if sca_sage_outcomes:
                            stored = store_sca_outcomes(
                                repo_path=str(original_repo_path),
                                outcomes=sca_sage_outcomes[:30],
                            )
                            if stored:
                                print(f"📚 SAGE: Stored {stored} SCA outcomes")
                except Exception:
                    logger.debug("SAGE SCA store skipped", exc_info=True)
            else:
                detail = (sca_stderr or "").strip()[-1000:]
                mechanical_sca_error = (
                    f"SCA subprocess exited {rc}"
                    + (f": {detail}" if detail else "")
                )
                logger.warning(
                    "SCA failed (rc=%d) — continuing without dep findings: %s",
                    rc, detail or "no stderr captured",
                )
                sca_findings_count = 0
        except Exception as e:  # noqa: BLE001
            print(f"⚠️  SCA failed: {e}", file=sys.stderr)
            logger.warning("SCA failed — continuing without dep findings: %s", e)
            mechanical_sca_error = f"{type(e).__name__}: {e}"
            sca_findings_count = 0
    else:
        sca_findings_count = 0
        if not source_scan_empty:
            logger.info("raptor-sca not installed — skipping SCA phase")

    # ---- External SARIF import ----
    import_result = None
    if import_sarif_files:
        from core.sarif.import_normalizer import (
            findings_to_sarif,
            format_import_summary,
            normalize_imported_findings,
        )
        from core.sarif.parser import parse_sarif_findings

        print("\n" + "=" * 70)
        print("SARIF IMPORT")
        print("=" * 70)

        imported_findings = []
        for sf in import_sarif_files:
            sf_path = Path(sf)
            if not sf_path.exists():
                print(f"  ✗ SARIF file not found: {sf}", file=sys.stderr)
                continue
            findings = parse_sarif_findings(sf_path)
            logger.info("Parsed %d findings from %s", len(findings), sf_path.name)
            imported_findings.extend(findings)

        if imported_findings:
            import_result = normalize_imported_findings(
                imported_findings,
                original_repo_path,
            )
            print(format_import_summary(
                import_result,
                [Path(f).name for f in import_sarif_files],
            ))
            normalized_sarif = findings_to_sarif(import_result.findings)
            normalized_path = out_dir / "imported-normalized.sarif"
            save_json(normalized_path, normalized_sarif)
            all_sarif_files.append(normalized_path)
        elif not all_sarif_files:
            print("\n✗ No findings in imported SARIF and no scan results", file=sys.stderr)
            _fail_run_and_exit(
                out_dir, "no findings in imported SARIF and no scan results",
            )

    if not all_sarif_files:
        print("\n✗ No SARIF files generated from scanning", file=sys.stderr)
        _fail_run_and_exit(out_dir, "no SARIF files generated from scanning")

    # Combine metrics
    threat_model_findings_count = (
        threat_model_phase.get("generated_candidates", 0)
        if threat_model_phase.get("completed") else 0
    )
    imported_findings_count = import_result.stats.total_imported if import_result else 0
    total_findings = (semgrep_metrics.get('total_findings', 0)
                      + codeql_metrics.get('total_findings', 0)
                      + sca_findings_count
                      + threat_model_findings_count
                      + imported_findings_count)
    scan_metrics = {
        'total_findings': total_findings,
        'total_files_scanned': semgrep_metrics.get('total_files_scanned', 0),
        'findings_by_severity': semgrep_metrics.get('findings_by_severity', {}),
        'semgrep': semgrep_metrics,
        'codeql': codeql_metrics,
        'sca': sca_metrics,
        'threat_model': threat_model_phase,
    }
    if import_result:
        scan_metrics['import'] = {
            'total_imported': import_result.stats.total_imported,
            'findings_skipped': import_result.stats.findings_skipped,
            'cwe_inferred': import_result.stats.cwe_inferred,
        }

    sarif_files = all_sarif_files

    print(f"\nTotal findings: {total_findings}")
    if semgrep_metrics:
        print(f"  Semgrep: {semgrep_metrics.get('total_findings', 0)} findings")
    if codeql_metrics:
        print(f"  CodeQL: {codeql_metrics.get('total_findings', 0)} findings")
    if sca_findings_count:
        print(f"  SCA: {sca_findings_count} findings")
    if threat_model_findings_count:
        print(f"  Threat model: {threat_model_findings_count} candidates")
    if imported_findings_count:
        print(f"  Imported: {imported_findings_count} findings")
    print(f"SARIF files: {len(sarif_files)}")

    # ========================================================================
    # PHASE 1b: SCA — DEPENDENCY ANALYSIS (opt-in via --sca)
    # ========================================================================
    sca_result = None
    sca_findings_path = None
    if args.sca:
        print("\n" + "=" * 70)
        print("SCA — DEPENDENCY ANALYSIS")
        print("=" * 70)

        try:
            from packages.sca.pipeline import RunOptions as ScaRunOptions
            from packages.sca.pipeline import run_sca

            sca_deep_out = out_dir / "sca_deep"
            sca_deep_out.mkdir(exist_ok=True)
            sca_options = ScaRunOptions(
                enable_llm_review=not args.skip_sca_review,
                enable_triage=not args.skip_sca_triage,
            )
            sca_result = run_sca(
                target=original_repo_path,
                output_dir=sca_deep_out,
                options=sca_options,
            )
            sca_findings_path = sca_deep_out / "findings.json"

            print("\n✓ SCA complete:")
            print(f"  - Dependencies analysed: {sca_result.deps_analysed}")
            print(f"  - Vulnerability findings: {sca_result.vuln_findings}")
            print(f"  - Hygiene findings: {sca_result.hygiene_findings}")
            print(f"  - Supply-chain findings: {sca_result.supply_chain_findings}")
            if sca_result.llm_reviews_run:
                print(f"  - LLM reviews: {sca_result.llm_reviews_run}")
            if sca_result.triage_run:
                print("  - Triage: completed")
            logger.info("SCA complete: %d vulns, %d hygiene, %d supply-chain",
                        sca_result.vuln_findings, sca_result.hygiene_findings,
                        sca_result.supply_chain_findings)
            sca_deep_count = sca_result.vuln_findings + sca_result.supply_chain_findings
            total_findings += sca_deep_count
        except ImportError:
            print("⚠️  SCA package not available — skipping dependency analysis", file=sys.stderr)
            logger.warning("SCA import failed — packages/sca not installed")
        except Exception as e:
            print(f"⚠️  SCA failed: {e}", file=sys.stderr)
            logger.exception("SCA phase failed: %s", e)  # noqa: TRY401

    # ========================================================================
    # PHASE 2: EXPLOITABILITY VALIDATION
    # ========================================================================
    # Run validation phase (handles all modes: skip, dedup-only, full validation)
    from packages.exploitability_validation import run_validation_phase

    validation_result, validated_findings = run_validation_phase(
        repo_path=str(original_repo_path),
        out_dir=out_dir,
        sarif_files=sarif_files,
        total_findings=total_findings,
        vuln_type=args.vuln_type,
        # First binary used for downstream per-binary helpers (mitigation,
        # fuzzing). Binary-oracle's multi-binary combine still happens via
        # RaptorConfig.BINARY_ORACLE_PATHS independently.
        binary_path=args.binary[0] if args.binary else None,
        skip_dedup=args.skip_dedup,
        skip_feasibility=not (args.binary or args.check_mitigations),
        external_llm=llm_env.external_llm,
        sca_findings_path=sca_findings_path,
    )

    # Enrichment summary — pre-LLM visibility of mechanical enrichments
    _enrichment_lines = []
    if validation_result and validation_result.get("completed"):
        dupes = validation_result.get("duplicates_removed", 0)
        if dupes > 0:
            _enrichment_lines.append(f"  Dedup: {dupes} duplicates removed")
        sca_m = validation_result.get("sca_merged", 0)
        if sca_m > 0:
            _enrichment_lines.append(f"  SCA: {sca_m} dependency findings merged")
    if import_result and import_result.stats.total_imported > 0:
        stats = import_result.stats
        _enrichment_lines.append(
            f"  SARIF import: {stats.total_imported} findings "
            f"({stats.cwe_inferred} CWEs inferred, "
            f"{stats.findings_skipped} skipped)"
        )
        sca_tagged = sum(
            1 for f in import_result.findings if f.get("source_type") == "dependency"
        )
        if sca_tagged > 0:
            _enrichment_lines.append(f"  SCA tagged: {sca_tagged} imported findings")
    if reachability_prepass_result and reachability_prepass_result.ran:
        _enrichment_lines.append(
            f"  Reachability: {reachability_prepass_result.marked_count} "
            f"dead-code marks"
        )
    suppression_file = out_dir / "suppressions.jsonl"
    if suppression_file.exists():
        # dropped:true records only — the file also carries record-only
        # evidence rows (see _count_dropped_suppressions).
        suppressed = _count_dropped_suppressions(suppression_file)
        if suppressed > 0:
            _enrichment_lines.append(
                f"  Binary oracle: {suppressed} findings suppressed (absent)"
            )
    if _enrichment_lines:
        print("\n" + "-" * 40)
        print("ENRICHMENT SUMMARY (pre-LLM)")
        print("-" * 40)
        for line in _enrichment_lines:
            print(line)
        print(f"  Findings entering LLM analysis: {validated_findings}")

    # ========================================================================
    # POST-SCAN: Binary oracle autodetect (deferred from pre-scan)
    # ========================================================================
    # Autodetect runs AFTER CodeQL because CodeQL may compile the target
    # (C/C++/Go/Java), leaving build artefacts that autodetect can find.
    # Explicit --binary and --no-binary-oracle are handled early (before
    # Phase 0); this covers the default autodetect + --binary-auto paths.
    if not getattr(args, "binary", None) and not getattr(args, "no_binary_oracle", False):
        apply_to_config(args, repo_path)

    # ========================================================================
    # PHASE 3: AUTONOMOUS ANALYSIS
    # ========================================================================
    print("\n" + "=" * 70)
    print("PREPARING FINDINGS")
    print("=" * 70)

    analysis = {}
    autonomous_out = None
    analysis_report = None
    if not llm_env.llm_available:
        print("\n⚠️  Phase 3 skipped - No LLM provider available")
        print("    To enable autonomous analysis, either:")
        print("    1. Set ANTHROPIC_API_KEY environment variable, OR")
        print("    2. Set OPENAI_API_KEY / GEMINI_API_KEY / MISTRAL_API_KEY, OR")
        print("    3. Run Ollama locally (https://ollama.ai), OR")
        print("    4. Run inside Claude Code (claude)")
        logger.warning("Phase 3 skipped - No LLM provider configured")
    else:
        autonomous_out = out_dir / "autonomous"
        autonomous_out.mkdir(exist_ok=True)

        # Check if validation produced enriched findings
        validated_findings_path = out_dir / "validation" / "findings.json"
        if validated_findings_path.exists():
            logger.info("Using findings from Phase 2 for analysis")
            analysis_cmd = [
                "python3",
                str(script_root / "packages/llm_analysis/agent.py"),
                "--repo", str(repo_path),
                "--findings", str(validated_findings_path),
                "--out", str(autonomous_out),
                "--max-findings", str(args.max_findings)
            ]
        else:
            analysis_cmd = [
                "python3",
                str(script_root / "packages/llm_analysis/agent.py"),
                "--repo", str(repo_path),
                "--sarif"
            ] + [str(f) for f in sarif_files] + [
                "--out", str(autonomous_out),
                "--max-findings", str(args.max_findings)
            ]

        # Forward --prefer GLOB(s) so the agent re-orders findings
        # before applying --max-findings. Each --prefer becomes a
        # separate flag on the child argv.
        for pref in (args.prefer or []):
            analysis_cmd += ["--prefer", pref]
        # Same forwarding for --exclude-dir; agent applies it before
        # the prefer/cap so excluded paths don't compete for slots.
        for excl in (args.exclude_dir or []):
            analysis_cmd += ["--exclude-dir", excl]

        # Attach checklist for metadata lookup
        if (out_dir / "checklist.json").exists():
            analysis_cmd.extend(["--checklist", str(out_dir / "checklist.json")])

        # Forward --no-journal opt-out so operators who don't
        # want journal side effects (CI / scratch runs) can suppress.
        if args.no_journal:
            analysis_cmd.append("--no-journal")
        # NOTE: an earlier design forwarded a SAGE pre-recall file
        # (sage_precall_scan.json) to the analysis child here, but no
        # producer ever wrote the file and the child never accepted
        # the flag — the forwarding was removed as dead plumbing. If a
        # scan-time SAGE precall is designed, it needs a producer
        # (core.sage.hooks recall writing the file before this exec)
        # and an envelope-disciplined consumer in the analysis agent.
        if args.no_exploits:
            analysis_cmd.append("--no-exploits")
        if args.no_patches:
            analysis_cmd.append("--no-patches")
        # P9 execution-oracle flags ride the analysis subprocess; the
        # child resolves them against the project 'dynamic' trust
        # marker (explicit flag > marker > off).
        if args.execute_exploits:
            analysis_cmd.append("--execute-exploits")
        if args.no_execute_exploits:
            analysis_cmd.append("--no-execute-exploits")

        # Phase 3 preps data; Phase 4 handles LLM work (unless --sequential)
        if (llm_env.claude_code or llm_env.external_llm) and not args.sequential:
            analysis_cmd.append("--prep-only")

        rc, _stdout, stderr = run_command_streaming(
            analysis_cmd, "Preparing findings for analysis",
            timeout=args.phase_timeout,
        )

        if rc == SANDBOX_ENGAGE_EXIT_CODE:
            # The analysis subprocess reported the sandbox could not engage.
            # Abort loud rather than degrading the analysis phase to an
            # empty `analysis = {}` (a silent "produced no output").
            msg = (
                "the analysis subprocess reported the sandbox could not "
                f"engage (exit {SANDBOX_ENGAGE_EXIT_CODE}); see its output above"
            )
            raise SandboxSetupError(
                msg,
                "re-run with --sandbox network-only (or --sandbox none). "
                "RAPTOR will not silently downgrade.",
            )

        # Parse analysis results
        analysis_report = autonomous_out / "autonomous_analysis_report.json"
        if analysis_report.exists():
            analysis = load_json(analysis_report)
            if not isinstance(analysis, dict):
                analysis = {}

            if analysis.get('mode') == 'prep_only':
                print(f"\n✓ {analysis.get('processed', 0)} findings prepared for analysis")
            else:
                print("\n✓ Analysis complete:")
                print(f"  - Analysed: {analysis.get('analyzed', 0)}")
                print(f"  - Exploitable: {analysis.get('exploitable', 0)}")
                print(f"  - Exploits generated: {analysis.get('exploits_generated', 0)}")
                print(f"  - Patches generated: {analysis.get('patches_generated', 0)}")

                if args.codeql or args.codeql_only:
                    print(f"  - CodeQL dataflow paths validated: {analysis.get('dataflow_validated', 0)}")

                # Witness summary — recorded by ``AutonomousSecurityAgentV2``
                # when ``--no-record-witnesses`` wasn't passed. Lives under
                # ``<autonomous_out>/witnesses/``. Silent when empty.
                from core.reporting import render_witness_summary
                witness_block = render_witness_summary(
                    autonomous_out / "witnesses",
                )
                if witness_block:
                    print(f"\n  Witnesses ({autonomous_out / 'witnesses'}):")
                    for line in witness_block.splitlines():
                        # Strip one level of leading indent so it sits
                        # consistently under the analysis-complete bullets.
                        print(f"  {line}")

                # ZKPoX eligibility — FREE surfacing: classification only, no bundle assembly,
                # no execution. Shows how many witnesses are ZK-proof
                # candidates.
                from packages.zkpox import render_run_eligibility
                elig_block = render_run_eligibility(
                    autonomous_out / "witnesses",
                )
                if elig_block:
                    for line in elig_block.splitlines():
                        print(f"  {line}")
        else:
            print("⚠️  Analysis failed or produced no output", file=sys.stderr)
            if stderr:
                print(f"    Error: {stderr[:500]}", file=sys.stderr)
            logger.warning("Phase 3 failed - rc=%d, stderr=%s", rc, stderr[:200])
            analysis = {}

    # ========================================================================
    # PHASE 4: AGENTIC ORCHESTRATION
    # ========================================================================
    try:
        from core.llm.log_quiet import quiet_noisy_loggers
        quiet_noisy_loggers()
    except ImportError:
        pass
    orchestration_result = None
    if getattr(args, "rank", False) and args.sequential:
        print(
            "⚠️  --rank has no effect with --sequential "
            "(Phase 4 orchestration is skipped)",
            file=sys.stderr,
        )
    if (llm_env.claude_code or llm_env.external_llm) and not args.sequential:
        print("\n" + "=" * 70)
        print("ANALYSING", flush=True)
        print("=" * 70)

        if analysis_report and analysis_report.exists():
            from packages.llm_analysis.orchestrator import (
                build_llm_config_from_flags,
                orchestrate,
            )

            llm_config = build_llm_config_from_flags(
                models=getattr(args, "model", []) or [],
                consensus=getattr(args, "consensus", None),
                judge=getattr(args, "judge", None),
                aggregate=getattr(args, "aggregate", None),
                auto_detect=llm_env.external_llm,
            )
            if llm_config and getattr(args, "max_cost_usd", None) is not None:
                llm_config.max_cost_per_scan = args.max_cost_usd
            # Dataflow validation is on by default when CodeQL ran;
            # `--no-validate-dataflow` opts out entirely. `--deep-validate`
            # opts into LLM-backed Tier 2/3 on top of the always-free Tier 1.
            orchestration_result = orchestrate(
                prep_report_path=analysis_report,
                repo_path=original_repo_path,
                out_dir=out_dir,
                max_parallel=args.max_parallel or 0,
                max_findings=args.max_findings,
                no_exploits=args.no_exploits,
                no_patches=args.no_patches,
                llm_config=llm_config,
                # Re-check at dispatch time — scanning phases ran untrusted
                # target code after the pre-scan; the verdict may be stale.
                block_cc_dispatch=check_repo_claude_trust(original_repo_path),
                accept_weakened_defenses=args.accept_weakened_defenses,
                dataflow_validation_enabled=not getattr(args, "no_validate_dataflow", False),
                deep_validate=getattr(args, "deep_validate", False),
                deep_validate_disabled=getattr(args, "no_deep_validate", False),
                deep_validate_budget=getattr(args, "deep_validate_budget", 0.60),
                allow_unreachable=getattr(args, "allow_unreachable", False),
                checklist=scan_inventory,
                rank_findings=getattr(args, "rank", False),
            )

            # Journal the orchestrated per-finding analyses. The
            # orchestrator has no journal writer of its own, so without
            # this the review journal carries only the prep phase's
            # mechanical suppressions in the default mode — downstream
            # kind-aware consumers (audit prior claims, agentic-labelled
            # coverage) saw nothing from the actual LLM analyses.
            if orchestration_result and not args.no_journal:
                try:
                    from packages.llm_analysis.journal_emit import (
                        journal_orchestrated_results,
                    )
                    journal_orchestrated_results(
                        out_dir, original_repo_path,
                        orchestration_result.get("results") or [],
                    )
                except Exception:  # noqa: BLE001 — journaling is best-effort
                    logger.debug(
                        "orchestrated journal emit failed", exc_info=True,
                    )
        else:
            print("\n  No analysis report from Phase 3 — skipping orchestration")
    elif not llm_env.llm_available:
        print("\n  No LLM available. Findings prepared for manual review.")
        print("  For automated analysis, set an API key or install Claude Code.")

    # ========================================================================
    # POST-PASS: /audit (opt-in via --gap-audit)
    # Runs the audit orchestrator over the coverage residual — functions
    # neither the scanners nor the analysis phase reviewed — as a proper
    # sibling /audit run. The kind-aware gap fold makes "residual" exact:
    # this run's per-finding analyses never count as function reviews,
    # but ride into the audit as prior claims (--prior-journal).
    # ========================================================================
    audit_postpass: dict = {"enabled": bool(args.gap_audit), "completed": False}
    audit_dir = None
    if args.gap_audit:
        print("\n" + "=" * 70)
        print("AUDIT POST-PASS")
        print("=" * 70)
        _audit_skip = _gap_audit_skip_reason(
            args, llm_env,
            # Re-check at dispatch time — the pre-scan verdict may be
            # stale (scanning ran untrusted target code since).
            block_cc_dispatch=check_repo_claude_trust(original_repo_path),
        )
        if _audit_skip is None:
            audit_postpass = run_audit_postpass(
                args, original_repo_path, out_dir,
            )
            if audit_postpass.get("audit_dir"):
                audit_dir = Path(audit_postpass["audit_dir"])
            if audit_postpass.get("completed"):
                logger.info(
                    "Audit post-pass reviewed %s functions, %s findings "
                    "(took %.1fs)",
                    audit_postpass.get("reviewed", "?"),
                    audit_postpass.get("findings_count", "?"),
                    audit_postpass.get("duration_seconds", 0.0),
                )
            else:
                logger.warning(
                    "Audit post-pass did not complete: %s",
                    audit_postpass.get("skipped_reason"),
                )
        else:
            audit_postpass["skipped_reason"] = _audit_skip
            print(f"\n  ⚠️  --gap-audit skipped: {_audit_skip}")

    # ========================================================================
    # POST-PASS: /validate (opt-in via --validate)
    # Selects findings flagged exploitable or high-confidence, runs full
    # validate pipeline against them.
    # ========================================================================
    postpass_result = None
    if args.validate:
        from core.orchestration import run_validate_postpass
        print("\n" + "=" * 70)
        print("VALIDATE POST-PASS")
        print("=" * 70)
        validate_input_report = (
            out_dir / "orchestrated_report.json"
            if orchestration_result
            else (analysis_report or out_dir / "autonomous" / "autonomous_analysis_report.json")
        )
        postpass_result = run_validate_postpass(
            target=original_repo_path,
            agentic_out_dir=out_dir,
            analysis_report=validate_input_report,
            # Re-check at dispatch time — the pre-scan verdict may be stale.
            block_cc_dispatch=check_repo_claude_trust(original_repo_path),
            allow_unreachable=getattr(args, "allow_unreachable", False),
            # --gap-audit: the sibling audit run's findings join the
            # selection, so one validate pass covers both pipelines.
            audit_dir=audit_dir if audit_postpass.get("completed") else None,
        )
        if postpass_result.ran:
            logger.info(
                "Post-pass validated %d findings (took %.1fs)",
                postpass_result.selected_count,
                postpass_result.duration_s,
            )
            # Close the Reflexion loop: import the validation verdicts
            # into the audit journal (disproven findings downgrade,
            # corroborated ones get confirmation entries).
            if audit_dir is not None and audit_postpass.get("completed") \
                    and postpass_result.validate_dir is not None:
                _run_audit_feedback(audit_dir, postpass_result.validate_dir)
        else:
            logger.warning("Post-pass skipped: %s", postpass_result.skipped_reason)
    elif audit_postpass.get("completed"):
        print(
            "\n  ⚠️  --gap-audit findings are UNVALIDATED (--validate not "
            "set). The audit is the wide net; /validate is the filter "
            "that kills false positives. Re-run with --validate, or run "
            f"/validate against {audit_postpass.get('audit_dir')}/findings.json."
        )

    # ========================================================================
    # FINAL REPORT
    # ========================================================================
    workflow_duration = time.time() - workflow_start

    print("\n" + "=" * 70)
    print("🎉 RAPTOR AGENTIC WORKFLOW COMPLETE")
    print("=" * 70)

    # Coverage nudge: /agentic reviews what the scanners flag; make the
    # size of what it DIDN'T review visible instead of implying
    # "scanned = reviewed". Estimate only — the audit's own gap
    # computation is authoritative.
    if not args.gap_audit:
        residual = _estimate_review_residual(out_dir)
        if residual and residual[0] > 0:
            unreviewed, total_funcs = residual
            print(
                f"\n  Coverage: ~{unreviewed} of {total_funcs} inventory "
                "functions have no review record — /agentic analyses "
                "scanner findings only. Add --gap-audit (or run /audit) "
                "to review the residual."
            )

    workflow_cost = _workflow_cost_summary(
        orchestration_result, audit_postpass, prepass_result, postpass_result,
    )

    final_report = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "repository": str(original_repo_path),
        "duration_seconds": workflow_duration,
        "cost": workflow_cost,
        "tools_used": {
            "semgrep": not args.codeql_only,
            "codeql": args.codeql or args.codeql_only,
            "sca": bool(sca_agent and sca_metrics),
        },
        "phases": {
            "scanning": {
                "completed": not skip_scan,
                "total_findings": scan_metrics.get('total_findings', 0),
                "files_scanned": scan_metrics.get('total_files_scanned', 0),
                "threat_model_candidates": threat_model_findings_count,
                "semgrep": {
                    "enabled": not args.codeql_only,
                    "findings": semgrep_metrics.get('total_findings', 0) if semgrep_metrics else 0,
                },
                "codeql": {
                    "enabled": args.codeql or args.codeql_only,
                    "findings": codeql_metrics.get('total_findings', 0) if codeql_metrics else 0,
                    "languages": list(codeql_metrics.get('languages_detected', {}).keys()) if codeql_metrics else [],
                },
            },
            "threat_model": threat_model_phase,
            "sca": {
                "enabled": args.sca,
                "completed": sca_result is not None,
                "deps_analysed": sca_result.deps_analysed if sca_result else 0,
                "vuln_findings": sca_result.vuln_findings if sca_result else 0,
                "hygiene_findings": sca_result.hygiene_findings if sca_result else 0,
                "supply_chain_findings": sca_result.supply_chain_findings if sca_result else 0,
                "llm_reviews": sca_result.llm_reviews_run if sca_result else 0,
                "triage_run": sca_result.triage_run if sca_result else False,
            },
            "exploitability_validation": {
                "completed": bool(validation_result),
                "skipped": args.skip_dedup,
                "original_findings": total_findings,
                "validated_findings": validated_findings,
                "noise_reduction_percent": ((total_findings - validated_findings) / total_findings * 100) if total_findings > 0 else 0,
            },
            "autonomous_analysis": {
                "completed": bool(analysis),
                "skipped": not llm_env.llm_available,
                "exploitable": analysis.get('exploitable', 0),
                "exploits_generated": analysis.get('exploits_generated', 0),
                "patches_generated": analysis.get('patches_generated', 0),
                "dataflow_validated": analysis.get('dataflow_validated', 0) if (args.codeql or args.codeql_only) else 0,
            },
            "orchestration": orchestration_result.get("orchestration", {}) if orchestration_result else {
                "completed": False,
                "mode": "none",
            },
            "audit": audit_postpass,
        },
        "outputs": {
            "sarif_files": [str(f) for f in sarif_files],
            "threat_model_json": threat_model_phase.get("threat_model_json"),
            "threat_model_markdown": threat_model_phase.get("threat_model_markdown"),
            "threat_model_report": threat_model_phase.get("threat_model_report"),
            "threat_model_lint": threat_model_phase.get("threat_model_lint"),
            "threat_model_drift": threat_model_phase.get("threat_model_drift"),
            "threats": threat_model_phase.get("threats"),
            "threat_model_summary": str(out_dir / "threat-model-summary.json") if threat_model_phase.get("completed") else None,
            "threat_model_candidates": threat_model_phase.get("candidate_sarif"),
            "sca_findings": str(sca_findings_path) if sca_findings_path and sca_findings_path.exists() else None,
            "sca_report": str(out_dir / "sca" / "report.md") if sca_result else None,
            "validation_report": str(out_dir / "validation" / "findings.json") if validation_result else None,
            "autonomous_report": str(analysis_report) if analysis_report and analysis_report.exists() else None,
            "orchestrated_report": str(out_dir / "orchestrated_report.json") if orchestration_result else None,
            "aggregation_report": str(out_dir / "aggregation.json") if orchestration_result and orchestration_result.get("aggregation") else None,
            "exploits_directory": str(autonomous_out / "exploits") if autonomous_out else None,
            "patches_directory": str(autonomous_out / "patches") if autonomous_out else None,
            "audit_report": (
                str(audit_dir / "audit-report.json")
                if audit_dir and (audit_dir / "audit-report.json").exists()
                else None
            ),
            "audit_findings": (
                str(audit_dir / "findings.json")
                if audit_dir and (audit_dir / "findings.json").exists()
                else None
            ),
            "exploit_feasibility": str(out_dir / "exploit_feasibility.txt") if mitigation_result else None,
            "enriched_sarif": None,  # populated after --sarif-out write
        }
    }

    report_file = out_dir / "raptor_agentic_report.json"
    save_json(report_file, final_report)

    # ========================================================================
    # PHASE 5: DYNAMIC CONFIRMATION VIA FUZZING (optional)
    # ========================================================================
    # If --fuzz is set and a binary target is configured, run a short fuzzing
    # campaign and merge any crashes into the final report. The fuzzing
    # orchestrator handles platform compatibility, target type detection,
    # and fuzzer selection automatically.
    fuzzing_result = None
    if getattr(args, "fuzz", False) or getattr(args, "fuzz_plan_only", False):
        if not args.binary:
            print("\n⚠️  --fuzz requires --binary <path>; skipping fuzz phase.")
            logger.warning("--fuzz requested but no --binary specified")
            final_report["phases"]["dynamic_fuzzing"] = {
                "completed": False,
                "skipped_reason": "--fuzz requires --binary",
            }
            save_json(report_file, final_report)
        else:
            print("\n" + "=" * 70)
            print("PHASE 5: Fuzzing")
            print("=" * 70)
            try:
                from packages.fuzzing.orchestrator import FuzzingOrchestrator
                orch = FuzzingOrchestrator(llm=None)
                # Fuzzing is per-binary; use the first --binary.
                plan = orch.plan(Path(args.binary[0]))
                print(plan.summary())

                if args.fuzz_plan_only:
                    print("\n  --fuzz-plan-only set; not running campaign.")
                    final_report["phases"]["dynamic_fuzzing"] = {
                        "completed": False,
                        "plan_only": True,
                        "fuzzer": plan.fuzzer,
                        "can_run": plan.can_run,
                        "blockers": plan.blockers,
                    }
                    final_report["outputs"]["fuzzing_result"] = None
                    save_json(report_file, final_report)
                elif not plan.can_run:
                    print("\n  Cannot run fuzz campaign on this host. See blockers above.")
                    final_report["phases"]["dynamic_fuzzing"] = {
                        "completed": False,
                        "fuzzer": plan.fuzzer,
                        "can_run": False,
                        "blockers": plan.blockers,
                    }
                    save_json(report_file, final_report)
                else:
                    fuzz_out = out_dir / "fuzzing"
                    fuzz_out.mkdir(parents=True, exist_ok=True)
                    fuzzing_result = orch.execute(
                        plan,
                        out_dir=fuzz_out,
                        duration_seconds=args.fuzz_duration,
                        corpus_dir=Path(args.fuzz_corpus) if args.fuzz_corpus else None,
                        dict_path=Path(args.fuzz_dict) if args.fuzz_dict else None,
                        source_context_dir=original_repo_path,
                    )
                    fuzz_phase = _build_fuzz_phase_summary(fuzzing_result, fuzz_out)
                    final_report["phases"]["dynamic_fuzzing"] = fuzz_phase
                    final_report["outputs"]["fuzzing_result"] = str(fuzz_out / "fuzzing_plan.json")
                    final_report["outputs"]["fuzzing_output_dir"] = str(fuzz_out)
                    final_report["outputs"]["fuzzing_telemetry"] = str(fuzz_out / "fuzz-summary.json")
                    final_report["outputs"]["fuzzing_events"] = str(fuzz_out / "fuzz-events.jsonl")
                    final_report["outputs"]["fuzzing_crashes_dir"] = fuzzing_result.get("crashes_dir")
                    final_report["outputs"]["fuzzing_crash_paths"] = fuzz_phase.get("crash_paths", [])
                    final_report["outputs"]["fuzzing_generated_corpus"] = fuzzing_result.get("generated_corpus")
                    print(f"   Fuzzing complete: {fuzzing_result}")
                    save_json(report_file, final_report)

                    # Analyse fuzz crashes immediately so the final report has
                    # deduped root causes, replay logs, and a validation handoff.
                    if fuzzing_result and fuzzing_result.get("crashes", 0) > 0:
                        try:
                            print(f"\n  Triaging {fuzzing_result['crashes']} fuzz crashes...")
                            crash_outputs = _prepare_fuzz_crashes_for_validate(
                                # Per-binary crash triage uses the first --binary.
                                binary_path=Path(args.binary[0]),
                                fuzzing_result=fuzzing_result,
                                fuzz_out=fuzz_out,
                                limit=args.max_findings,
                            )
                            final_report["outputs"]["fuzzing_crash_analysis"] = str(
                                crash_outputs["contexts"]
                            )
                            final_report["outputs"]["fuzzing_validation_findings"] = str(
                                crash_outputs["findings"]
                            )
                            final_report["outputs"]["fuzzing_validation_handoff"] = str(
                                crash_outputs["findings"]
                            )
                            final_report["outputs"]["fuzzing_triage"] = str(
                                crash_outputs["triage"]
                            )
                            final_report["phases"]["dynamic_fuzzing"]["validation_handoff"] = str(
                                crash_outputs["findings"]
                            )
                            final_report["phases"]["dynamic_fuzzing"]["triage"] = str(
                                crash_outputs["triage"]
                            )
                            if args.validate:
                                validation_smoke = _run_fuzz_validation_smoke(
                                    crash_outputs["findings"],
                                    Path(args.binary[0]),
                                    fuzz_out,
                                )
                                final_report["outputs"]["fuzzing_validation_run"] = validation_smoke.get("dir")
                                final_report["outputs"]["fuzzing_validation_report"] = validation_smoke.get("report")
                                final_report["phases"]["dynamic_fuzzing"]["validation_smoke"] = validation_smoke
                            save_json(report_file, final_report)
                            print(
                                "   Crash findings ready for validation at "
                                f"{crash_outputs['findings']}"
                            )
                        except Exception as e:  # noqa: BLE001
                            # Mirror the outer fuzz-phase handler: at the
                            # default INFO console level a debug-only log
                            # made a failed triage look like a silent
                            # no-op right after the "Triaging N fuzz
                            # crashes..." progress line.
                            logger.warning(
                                "Crash → validate handoff failed: %s", e
                            )
                            print(
                                f"\n  ✗ Crash triage / validation handoff "
                                f"failed: {e}",
                                file=sys.stderr,
                            )
            except Exception as e:
                logger.exception("Fuzz phase failed: %s", e)  # noqa: TRY401
                print(f"\n  ✗ Fuzz phase error: {e}", file=sys.stderr)

    print("\n📊 Summary:")
    print(f"   Total findings: {scan_metrics.get('total_findings', 0)}")
    if threat_model_findings_count:
        print(f"     Threat model candidates: {threat_model_findings_count}")
    if semgrep_metrics:
        print(f"     Semgrep: {semgrep_metrics.get('total_findings', 0)}")
    if codeql_metrics:
        print(f"     CodeQL: {codeql_metrics.get('total_findings', 0)}")
    # Build findings funnel from orchestration results
    analysed_count = 0
    true_positives = 0
    false_positives = 0
    unverdicted = 0
    exploitable_count = 0
    inconsistent_count = 0
    inconsistent_findings: list = []
    failed_count = 0
    blocked_count = 0
    severity_mismatches = []
    exploits_count = analysis.get('exploits_generated', 0)
    patches_count = analysis.get('patches_generated', 0)

    if orchestration_result:
        orch = orchestration_result.get("orchestration", {})
        analysed_count = orch.get("findings_analysed", 0)
        exploits_count = max(exploits_count, orchestration_result.get('exploits_generated', 0))
        patches_count = max(patches_count, orchestration_result.get('patches_generated', 0))
        # gh #549: distinguish is_true_positive=None (q<0.5 empty
        # dispatch) from True at bucket time; otherwise total
        # dispatch failure looks like a successful run.
        from core.orchestration.funnel import bucket_orchestration_results
        _buckets = bucket_orchestration_results(orchestration_result.get("results", []))
        true_positives = _buckets["true_positives"]
        false_positives = _buckets["false_positives"]
        unverdicted = _buckets["unverdicted"]
        exploitable_count = _buckets["exploitable"]
        inconsistent_count = _buckets["inconsistent"]
        inconsistent_findings = _buckets["inconsistent_findings"]
        failed_count = _buckets["failed"]
        blocked_count = _buckets["blocked"]
        severity_mismatches = _buckets["severity_mismatches"]
    else:
        analysed_count = analysis.get('analyzed', 0)
        exploitable_count = analysis.get('exploitable', 0)

    # Post-process orchestration results: compute CVSS, infer CWE, fix severity
    if orchestration_result:
        _postprocess_findings(orchestration_result.get("results", []))
        # Write corrected results back to disk
        orch_report_path = out_dir / "orchestrated_report.json"
        if orch_report_path.exists():
            save_json(orch_report_path, orchestration_result)

    # Enriched SARIF output
    sarif_out_path = getattr(args, "sarif_out", None)
    if sarif_out_path:
        from core.sarif.enriched_writer import write_enriched_sarif
        analysed_results = (
            orchestration_result.get("results", [])
            if orchestration_result else []
        )
        if analysed_results:
            sarif_out_resolved = Path(sarif_out_path)
            if not sarif_out_resolved.is_absolute():
                sarif_out_resolved = out_dir / sarif_out_resolved
            n = write_enriched_sarif(analysed_results, sarif_out_resolved)
            print(f"\n✓ Enriched SARIF written: {sarif_out_resolved} ({n} findings)")
            final_report["outputs"]["enriched_sarif"] = str(sarif_out_resolved)
            save_json(report_file, final_report)
        else:
            logger.warning("--sarif-out: no analysed findings to write")

    # Findings funnel
    if validation_result:
        print(f"   After dedup: {validated_findings}")
        if total_findings > validated_findings:
            reduction = ((total_findings - validated_findings) / total_findings) * 100
            print(f"   Duplicates removed: {reduction:.0f}%")
    if analysed_count > 0 and analysed_count < validated_findings:
        skipped = validated_findings - analysed_count
        print(f"   Analysed: {analysed_count} of {validated_findings}")
        print(f"   ⚠️  {skipped} finding{'s' if skipped != 1 else ''} skipped (--max-findings {args.max_findings})")
    elif analysed_count > 0:
        print(f"   Analysed: {analysed_count}")
    if failed_count > 0 or blocked_count > 0:
        parts = []
        if blocked_count > 0:
            parts.append(f"{blocked_count} blocked by content filter")
        if failed_count > 0:
            parts.append(f"{failed_count} failed")
        print(f"   ⚠️  {', '.join(parts)}")
        # Per-model failure breakdown — operator can see which model
        # failed and why (first error truncated to 200 chars).
        if orchestration_result:
            failed_by_model = (
                orchestration_result.get("orchestration", {})
                .get("failed_by_model", {})
            )
            for model, info in sorted(failed_by_model.items()):
                first_err = info.get("first_error") or ""
                err_snippet = (first_err[:120] + "...") if len(first_err) > 120 else first_err
                print(f"     {model}: {info.get('count', 0)} error{'s' if info.get('count') != 1 else ''}"
                      + (f" — {err_snippet}" if err_snippet else ""))
    if true_positives > 0 or false_positives > 0:
        print(f"   True positives: {true_positives}")
        if false_positives > 0:
            print(f"   False positives: {false_positives}")
    if unverdicted > 0:
        # Per-finding LLM dispatch returned empty / low-quality response
        # (q<0.5 from cc_dispatch leaves verdict fields as None). Pre-fix
        # `else: true_positives += 1` counted these as confirmed findings,
        # so total dispatch failure looked like a successful run.
        # gh #549 — print loudly so the operator sees the analysis gap.
        print(f"   ⚠️  Unverdicted: {unverdicted} "
              f"(LLM dispatch returned empty/low-quality — analysis is incomplete)")
    contradictions = sum(1 for r in orchestration_result.get("results", [])
                         if r.get("self_contradictory")) if orchestration_result else 0
    if contradictions > 0:
        print(f"   ⚠️  Self-contradictory: {contradictions} (review recommended)")
    if severity_mismatches:
        print(f"   ⚠️  {len(severity_mismatches)} high-severity finding{'s' if len(severity_mismatches) != 1 else ''} "
              f"ruled as false positive (review recommended)")
    # Binary-oracle suppression visibility: when the chokepoint
    # dropped a meaningful fraction of candidate findings as
    # ``absent`` from the analysed binary, surface that BEFORE the
    # Exploitable count so the operator can spot a build-mismatch
    # signal (oracle filtering too aggressively against a binary
    # that doesn't match the analysis target). At >=50% suppression,
    # the soft summary becomes a loud warning with the re-run hint —
    # the most common cause is a partial / wrong-target build, and
    # ``--no-binary-oracle`` is the right escape hatch.
    _suppr_path = out_dir / "suppressions.jsonl"
    if _suppr_path.is_file():
        # dropped:true records only — record-only (dropped:false) rows
        # describe findings that SURVIVED to the LLM and must not
        # inflate the count that trips the build-mismatch warning.
        _suppr_count = _count_dropped_suppressions(_suppr_path)
        if _suppr_count > 0:
            _candidates = total_findings or _suppr_count
            _pct = (_suppr_count / _candidates * 100) if _candidates else 0
            if _pct >= 50.0:
                print(
                    f"   ⚠️  binary-oracle suppressed: {_suppr_count} of "
                    f"{_candidates} candidates ({_pct:.0f}%) — likely "
                    f"build mismatch; verify binary matches analysis "
                    f"target or re-run with --no-binary-oracle. See "
                    f"suppressions.jsonl."
                )
            else:
                print(
                    f"   binary-oracle suppressed: {_suppr_count} of "
                    f"{_candidates} candidates ({_pct:.0f}%, see "
                    f"suppressions.jsonl)"
                )
    print(f"   Exploitable: {exploitable_count}")
    if inconsistent_count > 0:
        # Findings the LLM marked exploitable but whose own reasoning
        # was internally contradictory (post-Stage-F retry). Excluded
        # from the Exploitable count above to keep the headline
        # arithmetic honest — operator can review these separately.
        print(f"   ⚠️  Inconsistent (review needed): {inconsistent_count} "
              f"(exploitable verdict but self-contradictory reasoning)")
        # Per-finding list so the operator doesn't have to grep the
        # report for which findings these were. Truncated at 10 to
        # keep the summary scannable on larger runs; full set is in
        # ``orchestrated_report.json::results[*].self_contradictory``.
        from core.reporting.formatting import display_rule_id
        for r in inconsistent_findings[:10]:
            fp = r.get("file_path") or "?"
            line = r.get("line") or r.get("start_line") or "?"
            rule = display_rule_id(r.get("rule_id") or r.get("rule"))
            fid = r.get("finding_id") or ""
            tag = f"[{fid}] " if fid else ""
            print(f"      {tag}{fp}:{line} — {rule}")
        if len(inconsistent_findings) > 10:
            print(f"      ... and {len(inconsistent_findings) - 10} more")
        print("      → re-run with --judge <model> to break ties, or inspect manually")
    if exploits_count > 0:
        print(f"   Exploits generated: {exploits_count}")
    if patches_count > 0:
        print(f"   Patches generated: {patches_count}")
    # IRIS Tier 1 / 2 / 3 / 4 + path_conditions telemetry surfacing.
    # Helper lives in core/reporting/dataflow_summary.py so /analyze
    # (packages/llm_analysis/agent.py) can render the same block —
    # operators running /analyze standalone after /scan would
    # otherwise miss whether IRIS validated findings, populated
    # path_conditions, or fired SMT.
    from core.reporting.dataflow_summary import render_dataflow_validation_lines
    dv = (orchestration_result or {}).get("dataflow_validation") or {}
    for line in render_dataflow_validation_lines(dv, indent="   "):
        print(line)
    aggregation = orchestration_result.get("aggregation", {}) if orchestration_result else {}
    if aggregation:
        summary = str(aggregation.get("summary") or "").strip()
        if summary:
            print(f"   Aggregate synthesis: {summary[:120]}{'...' if len(summary) > 120 else ''}")
    from core.reporting import (
        FINDINGS_COLUMNS,
        build_findings_rows,
        build_findings_spec,
        build_findings_summary,
        findings_summary_line,
        render_console_table,
        render_report,
    )
    from core.reporting.formatting import format_elapsed
    print(f"   Duration: {format_elapsed(workflow_duration)}")
    # Gated on spend, not on the orchestrator: the understand / validate /
    # audit passes cost money in --sequential runs too, where
    # orchestration_result is None.
    cost_summary = final_report.get("cost", {})
    cost = cost_summary.get("total_cost", 0)
    if cost > 0:
        thinking = cost_summary.get("thinking_tokens", 0)
        cost_str = f"   Cost: ${cost:.2f}"
        if thinking > 0:
            cost_str += f" ({thinking:,} thinking tokens)"
        print(cost_str)
        by_phase = cost_summary.get("cost_by_phase", {})
        if len(by_phase) > 1:
            for phase_name, phase_cost in by_phase.items():
                print(f"     {phase_name}: ${phase_cost:.2f}")
        # Per-model breakdown if multiple models used. Only the analysis
        # ledger has one, so it stays sourced from the orchestration block.
        by_model = (
            orchestration_result.get("orchestration", {}).get("cost", {})
            .get("cost_by_model", {}) if orchestration_result else {}
        )
        if len(by_model) > 1:
            for model, mcost in by_model.items():
                print(f"     {model}: ${mcost:.2f}")
        # Fast-tier scorecard savings — surface concrete behaviour
        # of the prefilter (full ANALYSE calls skipped on findings
        # the cheap tier confidently classified as FPs and the
        # scorecard trusted).
        short_circuits = orchestration_result.get("orchestration", {}).get(
            "fast_tier_short_circuits", 0
        ) if orchestration_result else 0
        if short_circuits > 0:
            plural = "s" if short_circuits != 1 else ""
            print(f"   Fast-tier saved: {short_circuits} full ANALYSE call{plural}")

    print("\n📁 Outputs:")
    print(f"   Main report: {report_file}")
    if mitigation_result:
        print(f"   Exploit feasibility: {out_dir / 'exploit_feasibility.txt'}")
    # Dedup results are intermediate — don't list in user-facing outputs
    if analysis_report and analysis_report.exists():
        print(f"   Analysis: {analysis_report}")
    if exploits_count > 0 and autonomous_out:
        print(f"   Exploits: {autonomous_out / 'exploits'}/")
    if patches_count > 0 and autonomous_out:
        print(f"   Patches: {autonomous_out / 'patches'}/")

    # Filter to analysed results (used by both console table and report)
    results = orchestration_result.get("results", []) if orchestration_result else []
    analysed_results = [r for r in results if "is_true_positive" in r or "error" in r]

    # Results at a Glance table (matches /validate console output)
    if orchestration_result:  # noqa: SIM102
        if analysed_results:
            rows = build_findings_rows(analysed_results, filename_only=True)
            columns = FINDINGS_COLUMNS
            counts = build_findings_summary(analysed_results)
            footer = findings_summary_line(counts) + "\n\n  CVSS scores reflect inherent vulnerability impact — not binary mitigations."
            print(render_console_table(columns, rows, max_widths={3: 28, 4: 25}, footer=footer))

    print("\n" + "=" * 70)
    print("RAPTOR has autonomously:")
    if threat_model_phase.get("completed"):
        print(
            f"   ✓ Built threat model "
            f"({threat_model_phase.get('unchecked_flows', 0)} unchecked flows, "
            # Same CodeQL FP + suppression rationale as the
            # hardcoded_secrets summary print above.
            f"{threat_model_phase.get('hardcoded_literal_count', 0)} hardcoded secrets)"  # lgtm[py/clear-text-logging-sensitive-data]
        )
    # Gate the green-tick "Scanned with Semgrep" line on actual scan
    # success — `semgrep_metrics` is a truthy dict only when the
    # subprocess ran, didn't time out, returned rc in {0, 1}, and
    # produced a scan_metrics.json the loader could parse. Pre-fix the
    # tick fired solely on `not args.codeql_only`, so timed-out and
    # errored scans showed a misleading "✓" alongside the CodeQL line
    # below — which already gates on `codeql_metrics` for exactly this
    # reason. Mirror that asymmetry away.
    if not args.codeql_only and semgrep_metrics:
        print("   ✓ Scanned with Semgrep")
    if codeql_metrics:
        print("   ✓ Scanned with CodeQL")
        if codeql_metrics.get('total_findings', 0) > 0:
            print("   ✓ Validated dataflow paths")
    if sca_metrics:
        print(f"   ✓ Analysed {sca_metrics.get('deps_analysed', 0)} dependencies (SCA)")
    if validation_result:
        print("   ✓ Deduplicated findings")
    print("   ✓ Analysed vulnerabilities")
    if exploits_count > 0:
        print(f"   ✓ Generated {exploits_count} exploit{'s' if exploits_count != 1 else ''}")
    if patches_count > 0:
        print(f"   ✓ Created {patches_count} patch{'es' if patches_count != 1 else ''}")
    if orchestration_result:
        orch = orchestration_result.get("orchestration", {})
        mode = orch.get("mode", "unknown")
        if mode == "cc_dispatch":
            via = "Claude Code"
        elif mode == "external_llm":
            via = orch.get("analysis_model") or "external LLM"
        elif mode == "cc_fallback":
            via = "Claude Code (fallback)"
        else:
            via = mode
        n = orch.get('findings_analysed', 0)
        print(f"   ✓ Analysed {n} finding{'s' if n != 1 else ''} via {via}")
        if orch.get("aggregated"):
            print("   ✓ Aggregated multi-model findings")
    print("\nReview the outputs and apply patches as needed.")

    # Generate markdown report

    phases = final_report.get("phases", {})
    scanning = phases.get("scanning", {})
    validation = phases.get("exploitability_validation", {})
    orch_phase = phases.get("orchestration", {})
    duration = final_report.get("duration_seconds", 0)

    # Determine model
    mode = orch_phase.get("mode", "none")
    if mode == "cc_dispatch":
        via = "Claude Code"
    elif mode == "external_llm":
        via = orch_phase.get("analysis_model") or "external LLM"
    elif mode == "cc_fallback":
        via = "Claude Code (fallback)"
    else:
        via = None

    pipeline_parts = ["Threat Model"] if threat_model_phase.get("completed") else []
    pipeline_parts.append("Scan")
    if sca_metrics:
        pipeline_parts.append("SCA")
    if validation.get("completed"):
        pipeline_parts.append("Dedup")
    if analysed_count > 0:
        pipeline_parts.append("Analyse")
    if exploits_count > 0:
        pipeline_parts.append("Exploit")
    if patches_count > 0:
        pipeline_parts.append("Patch")

    metadata = {
        "Target": f"`{final_report.get('repository', 'unknown')}`",
        "Date": final_report.get("timestamp", "unknown")[:10],
        "Pipeline": f"{' → '.join(pipeline_parts)} ({format_elapsed(duration)})",
    }
    if via:
        metadata["Model"] = via

    # Build extra summary (scanning/dedup metrics go before findings counts)
    extra_summary = {}
    if threat_model_phase.get("completed"):
        extra_summary["Threat model candidates"] = threat_model_phase.get("generated_candidates", 0)
        extra_summary["Unchecked flows"] = threat_model_phase.get("unchecked_flows", 0)
    extra_summary["Total findings"] = scanning.get("total_findings", 0)
    semgrep = scanning.get("semgrep", {})
    if semgrep.get("enabled"):
        extra_summary["Semgrep"] = semgrep.get("findings", 0)
    codeql = scanning.get("codeql", {})
    if codeql.get("enabled"):
        extra_summary["CodeQL"] = codeql.get("findings", 0)
    if sca_findings_count:
        extra_summary["SCA"] = sca_findings_count
    if validation.get("completed"):
        extra_summary["After deduplication"] = validation.get("validated_findings", 0)
    if analysed_count > 0:
        extra_summary["Analysed"] = analysed_count
    if failed_count > 0:
        extra_summary["Failed"] = failed_count
    if blocked_count > 0:
        extra_summary["Blocked (content filter)"] = blocked_count
    if exploits_count > 0:
        extra_summary["Exploits generated"] = exploits_count
    if patches_count > 0:
        extra_summary["Patches generated"] = patches_count
    cost_summary = final_report.get("cost", {})
    cost = cost_summary.get("total_cost", 0)
    if cost > 0:
        extra_summary["Cost"] = f"${cost:.2f}"
    if aggregation:
        aggregate_model = aggregation.get("analysed_by")
        extra_summary["Aggregate synthesis"] = aggregate_model or "completed"

    # Warnings
    warnings = []
    if severity_mismatches:
        warnings.append(f"{len(severity_mismatches)} high-severity finding(s) ruled as false positive — review recommended")
    if contradictions > 0:
        warnings.append(f"{contradictions} self-contradictory verdict(s) — reasoning conflicts with conclusion")
    if orch_phase.get("weakened_defenses"):
        warnings.append(
            "Model-dependent defenses disabled (--accept-weakened-defenses). "
            "Envelope tags, datamarking, and base64 wrapping were not applied. "
            "Findings may be influenced by adversarial content in the target."
        )

    # Output files — significant outputs only, not per-category SARIF
    outputs = final_report.get("outputs", {})
    output_files = []
    if outputs.get("orchestrated_report"):
        output_files.append(outputs["orchestrated_report"])
    if outputs.get("aggregation_report"):
        output_files.append(outputs["aggregation_report"])
    if outputs.get("autonomous_report"):
        output_files.append(outputs["autonomous_report"])
    if outputs.get("audit_report"):
        output_files.append(outputs["audit_report"])
    if outputs.get("audit_findings"):
        output_files.append(outputs["audit_findings"])
    if outputs.get("threat_model_json"):
        output_files.append(outputs["threat_model_json"])
    if outputs.get("threat_model_markdown"):
        output_files.append(outputs["threat_model_markdown"])
    if outputs.get("threat_model_report"):
        output_files.append(outputs["threat_model_report"])
    if outputs.get("threat_model_lint"):
        output_files.append(outputs["threat_model_lint"])
    if outputs.get("threat_model_drift"):
        output_files.append(outputs["threat_model_drift"])
    if outputs.get("threats"):
        output_files.append(outputs["threats"])
    sarif_files = outputs.get("sarif_files", [])
    combined = [sf for sf in sarif_files if "combined" in sf]
    if combined:
        output_files.append(combined[0])
    elif len(sarif_files) == 1:
        output_files.append(sarif_files[0])
    output_files.append("agentic-report.md")

    extra_sections = []
    if audit_postpass.get("enabled"):
        extra_sections.append(_build_audit_report_section(
            audit_postpass,
            validate_dir=(
                postpass_result.validate_dir
                if postpass_result and postpass_result.ran else None
            ),
        ))
    if threat_model_phase.get("completed"):
        extra_sections.append(_build_threat_model_report_section(threat_model_phase))
    if aggregation:
        extra_sections.append(_build_aggregation_report_section(aggregation))
    dv = (orchestration_result or {}).get("dataflow_validation") or {}
    if dv and (dv.get("n_validated") or dv.get("n_cache_hits") or dv.get("skipped_reason")):
        extra_sections.append(_build_dataflow_validation_report_section(dv))

    spec = build_findings_spec(
        analysed_results,
        title="RAPTOR Agentic Security Report",
        metadata=metadata,
        extra_summary=extra_summary,
        warnings=warnings,
        extra_sections=extra_sections,
        output_files=output_files,
        include_details=False,
    )

    md_report = render_report(spec)
    md_path = out_dir / "agentic-report.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md_report)
    print(f"   Report: {md_path}")

    # Generate summary diagrams (verdict + type pies from orchestrated results)
    try:
        from packages.diagram import render_and_write
        diagrams_path = render_and_write(out_dir)
        if diagrams_path.stat().st_size > 200:
            print(f"   Diagrams: {diagrams_path}")
    except Exception:
        logger.debug("diagram rendering failed", exc_info=True)

    # Mark run as completed
    try:
        from core.run import complete_run
        orch_meta = (orchestration_result or {}).get("orchestration", {})
        complete_run(out_dir, extra={
            "findings_count": analysed_count,
            "exploitable_count": exploitable_count,
            "duration_seconds": round(workflow_duration, 1),
            "analysis_model": orch_meta.get("analysis_model"),
            "analysis_models": orch_meta.get("analysis_models", []),
            "aggregate_models": orch_meta.get("aggregate_models", []),
            "aggregated": orch_meta.get("aggregated", False),
        }, manifest=_build_completion_manifest(
            orch_meta, import_result, import_sarif_files,
            reanalyze_dir=getattr(args, "reanalyze", None),
        ))
    except Exception as e:  # noqa: BLE001
        logger.debug("Run metadata: %s", e)  # Optional — don't fail the pipeline

    # Clean up temporary git copy (if we created one for a non-git target)
    if _git_temp_dir and _git_temp_dir.exists():
        import shutil
        try:
            shutil.rmtree(str(_git_temp_dir))
            logger.debug("Cleaned up temp git dir: %s", _git_temp_dir)
        except Exception as e:  # noqa: BLE001
            logger.debug("Failed to clean temp git dir: %s", e)

    # Successful end of the full pipeline: the run was marked complete
    # above, in-band hard failures already called sys.exit(1)/return 2.
    # ``main`` feeds ``sys.exit(main())`` — the exit code must be an
    # explicit int, not an implicit-None fallthrough.
    return 0


#: Cap on gap-audit finding rows inlined into the agentic report —
#: the full list stays in the audit run's findings.json.
_AUDIT_REPORT_FINDINGS_CAP = 10


def _load_validate_outcomes(validate_dir) -> dict:
    """``finding id → Title Case outcome`` from a validate run's
    findings.json. Best-effort; empty when absent or unreadable."""
    if not validate_dir:
        return {}
    data = load_json(Path(validate_dir) / "findings.json")
    if isinstance(data, dict):
        data = data.get("findings")
    outcomes: dict = {}
    for f in data if isinstance(data, list) else []:
        if not isinstance(f, dict) or not f.get("id"):
            continue
        status = f.get("final_status") or f.get("status")
        if not status:
            ruling = f.get("ruling")
            status = ruling.get("status") if isinstance(ruling, dict) else ruling
        if status:
            outcomes[str(f["id"])] = str(status).replace("_", " ").title()
    return outcomes


def _build_audit_report_section(audit_phase, validate_dir=None):
    """Render the --gap-audit post-pass outcome for the final report.

    The audit's findings live in a sibling run dir; without inlining
    them here the main report reduces the whole pass to counts and a
    pointer, and the operator has to open a second report to learn
    WHAT was found. Rows come from the sibling's audit-report.json
    (journal-verdict-corrected findings), joined with the merged
    validate pass's per-finding outcome when one ran.
    """
    from core.reporting import ReportSection
    from core.security.prompt_output_sanitise import sanitise_string

    if not audit_phase.get("completed"):
        content = (
            f"- Status: **Skipped** — "
            f"{audit_phase.get('skipped_reason', 'unknown')}"
        )
        return ReportSection(title="Gap Audit Post-Pass", content=content)

    lines = [
        f"- Functions reviewed: **{audit_phase.get('reviewed', 0)}**",
        f"- Findings: **{audit_phase.get('findings_count', 0)}**",
        f"- Suspicious: **{audit_phase.get('suspicious', 0)}**",
        f"- Clean: **{audit_phase.get('clean', 0)}**",
        f"- Dormant: **{audit_phase.get('dormant', 0)}**",
        f"- Gaps remaining: **{audit_phase.get('gaps_remaining', 0)}**",
    ]
    if audit_phase.get("audit_dir"):
        lines.append(f"- Run directory: `{audit_phase['audit_dir']}`")

    findings = []
    if audit_phase.get("audit_dir"):
        report = load_json(
            Path(audit_phase["audit_dir"]) / "audit-report.json")
        if isinstance(report, dict) and isinstance(
                report.get("findings"), list):
            findings = [f for f in report["findings"] if isinstance(f, dict)]

    if findings:
        severities = {}
        for f in findings:
            sev = str(f.get("severity") or "medium").lower()
            severities[sev] = severities.get(sev, 0) + 1
        roll_up = ", ".join(
            f"{severities[s]} {s}"
            for s in ("critical", "high", "medium", "low")
            if s in severities
        )
        if roll_up:
            lines.append(f"- Severity: {roll_up}")

        outcomes = _load_validate_outcomes(validate_dir)
        header = "| Finding | Location | Severity | Evidence |"
        divider = "|---|---|---|---|"
        if outcomes:
            header += " Validation |"
            divider += "---|"
        lines.append("")
        lines.append(header)
        lines.append(divider)

        def _cell(value, cap: int=120):
            return sanitise_string(
                str(value or "").strip(), max_chars=cap,
            ).replace("|", "\\|").replace("\n", " ")

        for f in findings[:_AUDIT_REPORT_FINDINGS_CAP]:
            location = f"{f.get('file', '?')}:{f.get('function', '?')}"
            evidence = ", ".join(
                str(t.get("tool") or t)
                for t in (f.get("tool_evidence") or [])[:2]
                if t
            ) or f.get("cwe") or f.get("vuln_type") or ""
            row = (
                f"| {_cell(f.get('title') or f.get('id'))} "
                f"| `{_cell(location, cap=100)}` "
                f"| {_cell(f.get('severity') or 'medium', cap=20)} "
                f"| {_cell(evidence, cap=60)} |"
            )
            if outcomes:
                row += f" {_cell(outcomes.get(str(f.get('id'))) or '—', cap=30)} |"
            lines.append(row)
        if len(findings) > _AUDIT_REPORT_FINDINGS_CAP:
            lines.append(
                f"\n{len(findings) - _AUDIT_REPORT_FINDINGS_CAP} more in "
                f"`{audit_phase.get('audit_dir')}/findings.json`."
            )

    return ReportSection(
        title="Gap Audit Post-Pass",
        content="\n".join(lines),
    )


def _estimate_review_residual(out_dir: Path) -> tuple | None:
    """Rough (unreviewed, total) function count for the end-of-run
    coverage nudge.

    Total = reviewable checklist items; reviewed = distinct
    ``file:function`` keys journaled by this run (root + one-level tool
    subdirs). An estimate, not the audit's gap computation — good
    enough to say "most of the inventory was never reviewed".
    """
    checklist = load_json(out_dir / "checklist.json")
    if not isinstance(checklist, dict):
        return None
    total = 0
    for file_info in checklist.get("files", []) or []:
        if not isinstance(file_info, dict):
            continue
        items = file_info.get("items", file_info.get("functions", []))
        for item in items or []:
            if isinstance(item, dict) and item.get("kind", "") in (
                "function", "method", "",
            ):
                total += 1
    if total == 0:
        return None
    try:
        from core.coverage.journal import load_entries
        reviewed: set = set()
        candidates = [out_dir]
        candidates += [d for d in out_dir.iterdir() if d.is_dir()]
        for d in candidates:
            reviewed.update(
                e.key for e in load_entries(d) if e.verdict != "error"
            )
    except Exception:  # noqa: BLE001 — nudge is best-effort
        logger.debug("residual estimate failed", exc_info=True)
        return None
    return (max(total - len(reviewed), 0), total)


def _build_threat_model_report_section(summary):
    from core.reporting import ReportSection

    lines = [
        f"- Entry points: **{summary.get('entry_points', 0)}**",
        f"- Trust boundaries: **{summary.get('trust_boundaries', 0)}**",
        f"- Sinks: **{summary.get('sinks', 0)}**",
        f"- Unchecked flows: **{summary.get('unchecked_flows', 0)}**",
        # Same CodeQL FP + suppression rationale as the summary
        # print of hardcoded_secrets above.
        f"- Hardcoded secrets: **{summary.get('hardcoded_literal_count', 0)}**",  # lgtm[py/clear-text-logging-sensitive-data]
        f"- Generated candidates: **{summary.get('generated_candidates', 0)}**",
        f"- Threats: **{summary.get('threats_count', 0)}**",
        f"- Controls: **{summary.get('controls_count', 0)}**",
        f"- Evidence records: **{summary.get('evidence_count', 0)}**",
        f"- Lint issues: **{summary.get('lint_issues', 0)}**",
        f"- Drifted: **{'yes' if summary.get('drifted') else 'no'}**",
    ]
    if summary.get("threat_model_json"):
        lines.append(f"- Model: `{summary['threat_model_json']}`")
    if summary.get("threat_model_markdown"):
        lines.append(f"- Markdown: `{summary['threat_model_markdown']}`")
    if summary.get("threat_model_report"):
        lines.append(f"- Report: `{summary['threat_model_report']}`")
    if summary.get("threat_model_lint"):
        lines.append(f"- Lint: `{summary['threat_model_lint']}`")
    if summary.get("threat_model_drift"):
        lines.append(f"- Drift: `{summary['threat_model_drift']}`")
    if summary.get("candidate_sarif"):
        lines.append(f"- Validation handoff: `{summary['candidate_sarif']}`")
    if summary.get("reused_context_map"):
        lines.append(f"- Reused context map: `{summary.get('context_map')}`")
    if summary.get("stale_files"):
        lines.append(f"- Stale files: **{len(summary.get('stale_files') or [])}**")
        if summary.get("allow_stale"):
            lines.append("- Stale context reuse was explicitly allowed.")

    return ReportSection(
        title="Threat Model Phase",
        content="\n".join(lines),
    )


def _build_aggregation_report_section(aggregation):
    """Render aggregate-model synthesis for the final agentic report."""
    from core.reporting import ReportSection
    from core.security.prompt_output_sanitise import sanitise_string

    def _text(value, max_chars: int=1500):
        return sanitise_string(str(value or "").strip(), max_chars=max_chars)

    lines = []
    analysed_by = aggregation.get("analysed_by")
    if analysed_by:
        lines.append(f"**Model:** `{_text(analysed_by, max_chars=200)}`")

    summary = _text(aggregation.get("summary"), max_chars=2000)
    if summary:
        lines.append(f"\n**Summary:**\n{summary}")

    model_agreement = _text(aggregation.get("model_agreement"), max_chars=1500)
    if model_agreement:
        lines.append(f"\n**Model Agreement:**\n{model_agreement}")

    high_confidence = aggregation.get("highest_confidence_findings") or []
    if isinstance(high_confidence, list) and high_confidence:
        lines.append("\n**Highest Confidence Findings:**")
        for item in high_confidence[:10]:
            if not isinstance(item, dict):
                continue
            fid = _text(item.get("finding_id"), max_chars=120)
            verdict = _text(item.get("verdict"), max_chars=120)
            confidence = _text(item.get("confidence"), max_chars=120)
            reason = _text(item.get("reason"), max_chars=300)
            lines.append(f"- `{fid}`: {verdict} ({confidence}) — {reason}")

    disputed = aggregation.get("disputed_findings") or []
    if isinstance(disputed, list) and disputed:
        lines.append("\n**Disputed Findings:**")
        for item in disputed[:10]:
            if not isinstance(item, dict):
                continue
            fid = _text(item.get("finding_id"), max_chars=120)
            disagreement = _text(item.get("disagreement"), max_chars=300)
            needed = _text(item.get("resolution_needed"), max_chars=300)
            lines.append(f"- `{fid}`: {disagreement}. Resolution needed: {needed}")

    actions = aggregation.get("recommended_next_actions") or []
    if isinstance(actions, list) and actions:
        lines.append("\n**Recommended Next Actions:**")
        lines.extend(f"- {_text(action, max_chars=300)}" for action in actions[:10])

    risk_notes = aggregation.get("risk_notes") or []
    if isinstance(risk_notes, list) and risk_notes:
        lines.append("\n**Risk Notes:**")
        lines.extend(f"- {_text(note, max_chars=300)}" for note in risk_notes[:10])

    return ReportSection(
        title="Aggregate Synthesis",
        content="\n".join(lines) if lines else "Aggregate synthesis was requested, but the model returned no reportable fields.",
    )


def _build_dataflow_validation_report_section(dv):
    """Render IRIS dataflow-validation metrics for the agentic report.

    Surfaces the same Tier 1 / Tier 2 / 3 + downgrade breakdown that
    the console summary shows, plus a couple of fields useful for
    post-hoc review (skipped reasons, stale-DB warnings) that aren't
    worth taking up a console line for.
    """
    from core.reporting import ReportSection

    skipped = dv.get("skipped_reason") or ""
    if skipped:
        return ReportSection(
            title="IRIS Dataflow Validation",
            content=f"Validation was attempted but skipped: `{skipped}`.",
        )

    n_eligible = dv.get("n_eligible", 0)
    n_validated = dv.get("n_validated", 0)
    n_cache_hits = dv.get("n_cache_hits", 0)
    n_errors = dv.get("n_errors", 0)
    n_skip_no_db = dv.get("n_skipped_no_db_for_language", 0)
    n_stale_warnings = dv.get("n_stale_db_warnings", 0)
    n_tier1 = dv.get("n_tier1_prebuilt", 0)
    n_tier2 = dv.get("n_tier2_template", 0)
    n_tier3 = dv.get("n_tier3_retry", 0)
    n_smt_refuted = dv.get("n_tier4_smt_refuted", 0)
    n_smt_witness = dv.get("n_tier4_smt_witness", 0)
    n_smt_disagree = dv.get("n_tier4_smt_disagree", 0)
    n_recommended = dv.get("n_recommended_downgrades", 0)
    n_hard = dv.get("n_applied_downgrades", 0)
    n_soft = dv.get("n_soft_downgrades", 0)

    lines = []
    lines.append(
        f"Eligible findings: **{n_eligible}** · "
        f"validated: **{n_validated}**"
        + (f" (+{n_cache_hits} cache hit{'s' if n_cache_hits != 1 else ''})"
           if n_cache_hits else "")
    )
    if n_tier1 or n_tier2 or n_tier3:
        lines.append("")
        lines.append("**By tier:**")
        # Tier 1 is mechanical / free (CodeQL only — pre-built or
        # in-repo LocalFlowSource queries). Tier 2 and 3 burn LLM
        # tokens; only run when `--deep-validate` is set.
        if n_tier1:
            lines.append(f"- Tier 1 (free, prebuilt query): {n_tier1}")
        if n_tier2:
            lines.append(f"- Tier 2 (LLM-customised predicates): {n_tier2}")
        if n_tier3:
            lines.append(f"- Tier 3 (LLM compile-error retry): {n_tier3}")
    if n_smt_refuted or n_smt_witness or n_smt_disagree:
        lines.append("")
        lines.append("**Tier 4 SMT path-feasibility refinement:**")
        # Tier 4 outcomes are additive on top of the Tier 1/2/3
        # verdict. Listed separately because a single finding can
        # have a confirmed-by-Tier-1 verdict AND a witness-attached-
        # by-Tier-4 outcome — they aren't exclusive.
        if n_smt_refuted:
            lines.append(
                f"- Refuted (inconclusive → refuted on unsat conditions): "
                f"{n_smt_refuted}"
            )
        if n_smt_witness:
            lines.append(
                f"- Witness attached to confirmed (concrete attacker-input "
                f"values, usable as PoC seed): {n_smt_witness}"
            )
        if n_smt_disagree:
            lines.append(
                f"- SMT-CodeQL disagreement (kept CodeQL signal — see "
                f"warning logs): {n_smt_disagree}"
            )
    # path_conditions population telemetry — answers "is the LLM
    # actually emitting the SMT-checkable conditions the schema
    # asks for?" Without this, all-zero Tier 4 counts are ambiguous
    # between "LLM never populates" and "LLM populates but every
    # case resolves to no_check" — different remediations.
    n_pc_pop = dv.get("n_path_conditions_populated", 0)
    if n_pc_pop:
        lines.append("")
        lines.append("**Schema population — `path_conditions`:**")
        lines.append(
            f"- Findings with non-empty `path_conditions`: {n_pc_pop} "
            f"of {n_validated} validated"
        )
        cwe_breakdown = dv.get("path_conditions_by_cwe") or {}
        if cwe_breakdown:
            lines.append("- By CWE:")
            for cwe, count in sorted(cwe_breakdown.items(), key=lambda kv: -kv[1]):
                lines.append(f"  - {cwe}: {count}")
    if n_recommended:
        lines.append("")
        lines.append("**Downgrades:**")
        lines.append(f"- Recommended (validation refuted claim): {n_recommended}")
        if n_hard:
            lines.append(f"- Applied hard (no consensus override): {n_hard}")
        if n_soft:
            lines.append(
                f"- Applied soft (kept exploitable, lowered confidence — "
                f"consensus or judge agreed with original analysis): {n_soft}"
            )
        if not (n_hard or n_soft):
            lines.append(
                "- *Note:* recommendations were not applied — "
                "reconciliation may have been skipped or all overruled."
            )
    if n_errors:
        lines.append("")
        lines.append(f"**Errors:** {n_errors} validation(s) failed (loop did not crash).")
    if n_skip_no_db:
        lines.append(
            f"**Skipped (no CodeQL DB for finding's language):** {n_skip_no_db}"
        )
    if n_stale_warnings:
        lines.append(
            f"**Stale-DB warnings:** {n_stale_warnings} — DB mtime predates "
            "recent source changes; results may not reflect current code."
        )

    return ReportSection(
        title="IRIS Dataflow Validation",
        content="\n".join(lines),
    )


def _postprocess_findings(results) -> None:
    """Post-process LLM results: compute CVSS scores, infer CWE, check consistency."""
    from packages.cvss import score_finding
    from packages.llm_analysis.validation import check_self_contradiction

    for r in results:
        if "error" in r:
            continue

        score_finding(r)

        # Infer CWE from vuln_type if LLM didn't provide one
        if not r.get("cwe_id"):
            vuln_type = r.get("vuln_type", "")
            cwe = _CWE_FROM_VULN_TYPE.get(vuln_type)
            if cwe:
                r["cwe_id"] = cwe

    # Flag self-contradictory findings (reasoning vs verdict mismatch)
    by_id = {r.get("finding_id", f"idx-{i}"): r for i, r in enumerate(results) if "error" not in r}
    check_self_contradiction(by_id)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SandboxSetupError as e:
        # Fail loud with the actionable message, not a traceback — the run
        # did NOT analyse anything, so never let it look like a clean pass.
        print(
            f"\nRAPTOR: run aborted — sandbox isolation could not engage.\n{e}",
            file=sys.stderr,
        )
        sys.exit(SANDBOX_ENGAGE_EXIT_CODE)
