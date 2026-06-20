"""Command-line entry point: ``cve-env build CVE-YYYY-NNNN``.

Minimal CLI that renders + runs the agent. Intended for ad-hoc build
requests and smokes; the parallel bench runner lives in ``scripts/bench_parallel.sh``.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import re
import sys
import time
from pathlib import Path
from typing import Any

from cve_env.agent.loop import build
from cve_env.config import AGENTIC_AUDIT_ROOT, VERSION_ASSERTION_CMD_PATTERN
from cve_env.models import CveRecord, HostInfo, derive_build_method
from cve_env.tools.arch import detect_host_arch

# Validate CVE-ID format BEFORE invoking build()/LLM. Stops bogus IDs
# (lowercase, missing dash, wrong year width, etc.) at argparse time
# instead of wasting an SDK round-trip on certain failure.
# Pattern: CVE-YYYY-NNNN+ (4-digit year, 4+ digit serial; cve.org canonical).
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _validate_cve_id(value: str) -> str:
    """argparse ``type=`` validator for the build subcommand cve_id arg."""
    if not _CVE_ID_RE.fullmatch(value):
        raise argparse.ArgumentTypeError(
            f"invalid CVE-ID format: {value!r} — expected CVE-YYYY-NNNN+ "
            f"(e.g. CVE-2018-7600)"
        )
    return value


def _cmd_build(args: argparse.Namespace) -> int:
    cve = CveRecord(
        cve_id=args.cve_id,
        product=args.product or "",
        version=args.version or "",
        description=args.description or "",
    )
    host_arch = detect_host_arch()
    host = HostInfo(
        arch=host_arch.arch,
        os=host_arch.os,
        rosetta_available=host_arch.rosetta_available,
    )
    run_id = f"manual-{int(time.time())}"
    audit_root = Path(args.audit_root) if args.audit_root else AGENTIC_AUDIT_ROOT

    # Acquire lockfile so concurrent cve-env builds can detect each other.
    # Released in the finally block before any auto-stop-colima check (so
    # own PID doesn't count itself as "active").
    from cve_env.utils.lifecycle import acquire_lock, release_lock

    lock_path = acquire_lock()

    try:
        # Probe service health pre-run; pass any CRITICAL-service constraints
        # to the agent as SYSTEM_PROMPT prefix. Empty in the common case;
        # non-empty when DH rate-limited / etc.
        from cve_env.agent.health_constraints import probe_for_constraints

        constraints = probe_for_constraints()

        # Use getattr with config defaults so test fixtures that build a
        # minimal Args object don't have to know about every CLI flag.
        # argparse always populates these attrs at real CLI invocation.
        from cve_env.config import MAX_TURN_EXTENSIONS, TURN_EXTENSION_PCT

        outcome = asyncio.run(
            build(
                cve,
                host,
                run_id=run_id,
                audit_root=audit_root,
                max_turns=args.max_turns,
                max_cost_usd=args.max_cost_usd,
                max_turn_extensions=getattr(
                    args, "max_turn_extensions", MAX_TURN_EXTENSIONS
                ),
                turn_extension_pct=getattr(
                    args, "turn_extension_pct", TURN_EXTENSION_PCT
                ),
                constraints=constraints,
            )
        )
        outcome_dict = {
            "cve_id": outcome.cve_id,
            "status": outcome.status,
            "verify_passed": outcome.verify_passed,
            "give_up_reason": outcome.give_up_reason,
            "give_up_detail": outcome.give_up_detail,
            "num_turns": outcome.num_turns,
            "total_cost_usd": outcome.total_cost_usd,
            "stop_reason": outcome.stop_reason,
            "reason": outcome.reason,
            "tool_names_called": outcome.tool_names_called,
            # Derived build-method label(s) for post-bench analysis.
            # Taxonomy mirrors scripts/heartbeat_status.sh.
            "method": derive_build_method(outcome.tool_names_called),
            "final_text": outcome.final_text,
            "audit_path": str(outcome.audit_path) if outcome.audit_path else None,
            # Expose refusal count to per-CVE JSON so post-bench analysis can
            # tally rates without re-parsing bench.log.
            "refusals": outcome.refusals,
            # Host containerd-corruption flag → lets the bench heal +
            # bench_select_retry detect it without parsing the audit JSONL.
            "daemon_corruption": outcome.daemon_corruption,
            # Per-stage telemetry fields. `outcome_dict` is a manual whitelist,
            # so these must be listed explicitly to reach the sidecar.
            "stage_costs": outcome.stage_costs,
            "stage_calls": outcome.stage_calls,
            "over_budget_stages_list": outcome.over_budget_stages_list,
        }
        # Write sidecar before stdout so the result survives a SIGKILL that
        # fires after build() returns but before the stdout pipe flushes.
        # bench50.sh recovers from this file when $OUTDIR/$cve.json is empty.
        sidecar = audit_root / f"{cve.cve_id}.outcome.json"
        with contextlib.suppress(OSError):
            sidecar.write_text(json.dumps(outcome_dict, indent=2, default=str))
        print(  # noqa: T201 -- CLI output
            json.dumps(outcome_dict, indent=2, default=str)
        )
        # The human-readable summary is DEFAULT-ON. Use --silent to suppress.
        # The summary on stderr answers "what worked / what failed / where" +
        # credential nudges and rate-limit visibility, so users running
        # cve-env build always see why the run ended the way it did.
        if not args.silent:
            _print_human_report(outcome)
        return 0 if outcome.status == "success" else 1
    finally:
        # Opt-in lifecycle teardown. Each hook is individually
        # exception-suppressed so a failing teardown doesn't
        # mask the build's actual outcome. Container cleanup and image
        # prune run BEFORE colima stop (need docker daemon up). Lock is
        # released BETWEEN docker work and colima stop so the idle-check
        # excludes own PID.
        try:
            from cve_env import config as _config
            from cve_env.utils.lifecycle import (
                cleanup_containers,
                cleanup_result_images,
                prune_images,
                stop_colima_if_idle,
            )

            auto_cleanup = (
                getattr(args, "auto_cleanup_containers", False)
                or _config.AUTO_CLEANUP_CONTAINERS
            )
            auto_prune = (
                getattr(args, "auto_prune_images", False) or _config.AUTO_PRUNE_IMAGES
            )
            auto_stop = (
                getattr(args, "auto_stop_colima", False) or _config.AUTO_STOP_COLIMA
            )
            if auto_cleanup:
                with contextlib.suppress(Exception):
                    cleanup_containers(cve.cve_id)
                # Remove THIS CVE's tagged result images too (containers first,
                # so the images are no longer held). Rides the same
                # AUTO_CLEANUP_CONTAINERS gate — "clean up this CVE's
                # artifacts". prune_images (dangling-only) below is unchanged.
                with contextlib.suppress(Exception):
                    cleanup_result_images(cve.cve_id)
            if auto_prune:
                with contextlib.suppress(Exception):
                    prune_images()
            # Release own lock BEFORE colima-stop so idle-check excludes us.
            release_lock(lock_path)
            if auto_stop:
                with contextlib.suppress(Exception):
                    stop_colima_if_idle()
        finally:
            # Defensive: even if the lifecycle import/dispatch raised,
            # the lock must be released.
            release_lock(lock_path)


# Stage-grouped end-of-run report. Maps tool names to the pipeline stage
# they belong to. Stage order = pipeline order.
#
# Schema: lowercase keys ("research", "acquire") for end-of-run human report.
# Three sibling tables exist with intentionally-different value schemas
# (kept apart because each serves a different consumer):
#   - scripts/cve_evidence.py::_STAGE_BY_TOOL — 3-letter codes ("RES", "ACQ")
#     for compact per-tool evidence JSONL rendering
#   - scripts/heartbeat_status.sh::STAGE_BY_TOOL — long names ("RESEARCH",
#     "ACQUIRE") for live human-readable heartbeat output
#   - src/cve_env/config.py::TOOL_TO_STAGE — uppercase names
#     for budget-engine per-stage cost attribution
# When adding a new tool, update all four. Drift across the first three is
# blocked by refactor/tests/unit/test_stage_table_sync.py; drift between
# the first three and config.py is allowed only via the _KNOWN_DIVERGENCE
# allowlist in that test.
_STAGE_BY_TOOL: dict[str, str] = {
    "nvd_lookup": "research",
    "github_fetch": "research",
    "web_fetch": "research",
    "WebFetch": "research",
    "WebSearch": "research",
    "image_resolve": "resolve",
    "source_build": "acquire",
    "dockerfile_gen": "acquire",
    "docker_build": "acquire",
    "docker_compose_up": "acquire",
    "docker_run": "launch",
    "run_in_container": "launch",
    "verify": "verify",
    # Non-pipeline tools — kept here so the sibling tables in
    # scripts/cve_evidence.py and scripts/heartbeat_status.sh stay in sync
    # (test_stage_table_sync.py enforces this). _STAGE_ORDER below limits
    # the human report to the 5 pipeline stages, so these don't appear in
    # the end-of-run summary even though they're tracked.
    "give_up": "give_up",
    "ToolSearch": "meta",
    "Bash": "meta",
    "Read": "meta",
    "Write": "meta",
    "Grep": "meta",
    "Glob": "meta",
}
_STAGE_ORDER: list[str] = ["research", "resolve", "acquire", "launch", "verify"]
_STAGE_LABEL: dict[str, str] = {
    "research": "RESEARCH",
    "resolve": "RESOLVE (image discovery)",
    "acquire": "ACQUIRE / BUILD",
    "launch": "LAUNCH",
    "verify": "VERIFY",
}


def _truncate(s: str, n: int = 70) -> str:
    s = str(s).replace("\n", " ")
    return s if len(s) <= n else s[: n - 1] + "…"


# Single source of truth in cve_env.config.VERSION_ASSERTION_CMD_PATTERN.
# An inlined copy here would risk classification drift between the two gates
# (e.g. alternations like ``apache2ctl -M``, ``-V`` short-flag, bare
# ``\bversion\b``, ``httpd -M``, ``java -version``), so this aliases the
# config-side pattern directly.
_VERSION_ASSERTION_CMD_RE = VERSION_ASSERTION_CMD_PATTERN
_LIFECYCLE_CHECK_TYPES_FOR_TAG: frozenset[str] = frozenset(
    {"container_status", "stability_wait", "log_check"}
)
_ACTIVE_REQUEST_CHECK_TYPES_FOR_TAG: frozenset[str] = frozenset(
    {"http_request_check", "tcp_probe_check"}
)


def _classify_check(ctype: str, details: dict[str, Any]) -> str:
    """Return a 1-letter tag: L=lifecycle, V=version-assertion, F=functional
    (http_check with content_check), P=payload, A=active exec_check (intent
    not classified), ?=unknown."""
    if ctype in _LIFECYCLE_CHECK_TYPES_FOR_TAG:
        return "L"
    if ctype == "http_check":
        return "F" if details.get("content_check_performed") else "L"
    if ctype == "exec_check":
        cmd = str(details.get("command", ""))
        if _VERSION_ASSERTION_CMD_RE.search(cmd):
            return "V"
        return "A"
    if ctype in _ACTIVE_REQUEST_CHECK_TYPES_FOR_TAG:
        return "P"
    return "?"


def _render_verify_checks(tool_result: dict[str, Any]) -> list[str]:
    """For a verify tool_result, return one line per check showing
    pass/fail glyph, classification tag, command/path, and brief receipt.
    """
    rows: list[str] = []
    if not isinstance(tool_result, dict):
        return rows
    results = tool_result.get("results")
    if not isinstance(results, list):
        return rows
    for r in results:
        if not isinstance(r, dict):
            continue
        ctype = str(r.get("type", "?"))
        passed = r.get("passed")
        details = r.get("details") if isinstance(r.get("details"), dict) else {}
        if not isinstance(details, dict):
            details = {}
        glyph = "✓" if passed else "✗"
        tag = _classify_check(ctype, details)
        receipt = ""
        focus = ""
        if ctype == "container_status":
            receipt = f"running={details.get('running', '?')}"
        elif ctype == "stability_wait":
            ws = details.get("wait_seconds", "?")
            receipt = f"wait={ws}s"
        elif ctype == "http_check":
            path = str(details.get("url") or details.get("path") or "")
            status = details.get("actual_status", "?")
            focus = _truncate(path, 40) if path else ""
            receipt = f"status={status}"
        elif ctype == "log_check":
            tail = str(details.get("logs_tail", ""))
            receipt = _truncate(tail, 50)
        elif ctype == "exec_check":
            cmd = _truncate(str(details.get("command", "")), 50)
            stdout = _truncate(str(details.get("stdout_tail", "")), 50)
            focus = f"`{cmd}`" if cmd else ""
            receipt = stdout
        elif ctype == "http_request_check":
            path = str(details.get("url") or details.get("path") or "")
            status = details.get("actual_status", "?")
            body = _truncate(str(details.get("response_tail", "")), 40)
            focus = _truncate(path, 30) if path else ""
            receipt = f"status={status} body={body!r}"
        elif ctype == "tcp_probe_check":
            tail = _truncate(str(details.get("response_tail", "")), 50)
            receipt = f"resp={tail!r}"
        focus_part = f" {focus}" if focus else ""
        rows.append(f"      {glyph} [{tag}] {ctype:<22}{focus_part}  {receipt}")
    return rows


def _summarize_call(tool: str, ti: dict[str, Any]) -> str:
    """One-line summary of relevant tool inputs."""
    if tool == "nvd_lookup":
        return str(ti.get("cve_id", ""))
    if tool == "github_fetch":
        owner = ti.get("owner", "?")
        repo = ti.get("repo", "?")
        path = ti.get("path", "")
        return _truncate(f"{owner}/{repo}{':' + path if path else ''}", 70)
    if tool == "image_resolve":
        return f"{ti.get('product', '?')}:{ti.get('version', '?')}"
    if tool == "source_build":
        return f"{ti.get('source_url', '?')} v={ti.get('version', '?')}"
    if tool == "dockerfile_gen":
        return _truncate(f"base={ti.get('base_image', '?')}", 60)
    if tool == "docker_build":
        return _truncate(f"tag={ti.get('image_tag', '?')}", 60)
    if tool == "docker_run":
        img = _truncate(str(ti.get("image", "?")), 50)
        return f"image={img} port={ti.get('container_port', '?')}"
    if tool == "verify":
        plan = ti.get("plan")
        if isinstance(plan, str):
            try:
                plan = json.loads(plan)
            except json.JSONDecodeError:
                plan = []
        if isinstance(plan, list):
            types = [str(s.get("type", "?")) for s in plan if isinstance(s, dict)]
            shown = ", ".join(types[:5])
            more = "…" if len(types) > 5 else ""
            return f"{len(types)}-check plan ({shown}{more})"
        return "(plan)"
    return ""


def _summarize_result(tool: str, tr: dict[str, Any]) -> tuple[str, str]:
    """Returns (status_glyph, receipt_summary)."""
    if not isinstance(tr, dict):
        return "", ""
    if tool == "nvd_lookup":
        cpes = tr.get("cpes")
        return (
            ("✓", f"{len(cpes)} CPEs") if isinstance(cpes, list) else ("✓", "(record)")
        )
    if tool == "github_fetch":
        if tr.get("ok"):
            return "✓", str(tr.get("kind", ""))
        return "✗", _truncate(str(tr.get("reason", "fetch failed")), 50)
    if tool == "image_resolve":
        decision = str(tr.get("decision") or "?")
        rc = tr.get("reason_class") or ""
        if decision in ("native", "rosetta_ok"):
            ref = _truncate(str(tr.get("digest_pinned_ref", "")), 60)
            return "✓", f"{decision} → {ref}"
        return "✗", f"{decision}{f' ({rc})' if rc else ''}"
    if tool == "source_build":
        if tr.get("ok"):
            return "✓", _truncate(str(tr.get("repo_dir", "cloned")), 60)
        return "✗", _truncate(str(tr.get("error", "failed")), 60)
    if tool == "dockerfile_gen":
        if tr.get("ok"):
            return "✓", "Dockerfile rendered"
        issues = tr.get("issues") or []
        if isinstance(issues, list) and issues:
            return "✗", _truncate(str(issues[0]), 60)
        return "✗", "rejected"
    if tool == "docker_build":
        if tr.get("ok"):
            return "✓", f"built {tr.get('image_tag', '')}"
        return "✗", _truncate(str(tr.get("reason", "build failed")), 60)
    if tool == "docker_run":
        if tr.get("ok"):
            cid = _truncate(str(tr.get("container_id", "")), 14)
            port = tr.get("host_port", "?")
            return "✓", f"container={cid} port={port}"
        return "✗", _truncate(str(tr.get("reason", "run failed")), 60)
    if tool == "verify":
        passed = tr.get("passed")
        glyph = "✓" if passed else "✗"
        results = tr.get("results") or []
        if isinstance(results, list):
            ok = sum(1 for r in results if isinstance(r, dict) and r.get("passed"))
            return glyph, f"{ok}/{len(results)} checks passed"
        return glyph, ""
    if tool == "run_in_container":
        if tr.get("ok"):
            stdout = _truncate(str(tr.get("stdout_tail", "")), 50)
            return "✓", stdout
        return "✗", _truncate(str(tr.get("reason", "exec failed")), 50)
    return "", ""


def _stage_grouped_calls(
    audit_path: Path | None,
) -> dict[str, list[dict[str, Any]]]:
    """Read audit JSONL, group tool calls by pipeline stage.

    Returns {stage_name: [{turn, tool, summary, glyph, receipt}, ...]}.
    Each stage entry is one call → matched to its result.
    """
    out: dict[str, list[dict[str, Any]]] = {s: [] for s in _STAGE_ORDER}
    if audit_path is None or not audit_path.exists():
        return out
    # First pass: index llm_turns and results.
    calls: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    try:
        with audit_path.open() as f:
            for raw in f:
                if not raw.strip():
                    continue
                try:
                    e = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if not isinstance(e, dict):
                    continue
                st = e.get("status", "")
                tn = e.get("tool_name") or ""
                if st == "llm_turn" and isinstance(tn, str) and tn:
                    calls.append(
                        {
                            "turn": e.get("turn", 0),
                            "tool": tn,
                            "input": e.get("tool_input") or {},
                        }
                    )
                elif st in ("tool_ok", "tool_error") and isinstance(tn, str) and tn:
                    results.append(
                        {
                            "turn": e.get("turn", 0),
                            "tool": tn,
                            "result": e.get("tool_result") or {},
                            "ok": st == "tool_ok",
                        }
                    )
    except OSError:
        return out
    # Second pass: match each call to its result (most recent result with
    # same tool name at turn > call.turn).
    for call in calls:
        stage = _STAGE_BY_TOOL.get(call["tool"])
        # Skip unknown tools AND tools whose stage is outside _STAGE_ORDER
        # ('meta' / 'give_up' map there — present in _STAGE_BY_TOOL so the
        # cve_evidence.py + heartbeat_status.sh sibling tables stay in sync,
        # but not part of the human pipeline report).
        if stage is None or stage not in out:
            continue
        ti = call["input"] if isinstance(call["input"], dict) else {}
        summary = _summarize_call(call["tool"], ti)
        # Find matching result.
        glyph, receipt = "", ""
        matched_result: dict[str, Any] = {}
        for r in results:
            if r["tool"] == call["tool"] and r["turn"] > call["turn"]:
                tr = r["result"] if isinstance(r["result"], dict) else {}
                glyph, receipt = _summarize_result(call["tool"], tr)
                matched_result = tr
                # Mark the result as consumed by removing it (avoid
                # matching the same result to multiple calls).
                results.remove(r)
                break
        out[stage].append(
            {
                "turn": call["turn"],
                "tool": call["tool"],
                "summary": summary,
                "glyph": glyph,
                "receipt": receipt,
                # Full tool_result kept for verify per-check rendering.
                "result": matched_result,
            }
        )
    return out


def _audit_pressure_summary(audit_path: Path | None) -> dict[str, Any]:
    """Extract reason_class + tried-registries narrative from the audit JSONL
    so the end-of-run summary can show credential nudges + tried-and-skipped
    chains. Returns empty dict on any read error.
    """
    if audit_path is None or not audit_path.exists():
        return {}
    reason_class_to_key = {
        "rate_limited": "rate_limited",
        "auth": "auth_failed",
        "disk_full": "disk_full",
        "transport": "transport",
    }
    rc_counts: dict[str, int] = dict.fromkeys(reason_class_to_key.values(), 0)
    image_resolve_chain: list[dict[str, str]] = []
    verify_check_types: list[str] = []
    verify_passed_count = 0
    verify_failed_count = 0
    verify_quality_warnings: list[str] = []
    nvd_blocked = 0
    try:
        with audit_path.open() as f:
            for line in f:
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # A valid-JSON non-object line (e.g. a bare list/string) would
                # make entry.get() raise — guard it, mirroring
                # _stage_grouped_calls.
                if not isinstance(entry, dict):
                    continue
                tr = entry.get("tool_result") or {}
                if not isinstance(tr, dict):
                    continue
                rc = tr.get("reason_class") or ""
                bucket = reason_class_to_key.get(rc)
                if bucket is not None:
                    rc_counts[bucket] += 1
                tool_name = entry.get("tool_name") or ""
                if tool_name == "image_resolve" and entry.get("status") == "tool_ok":
                    image_resolve_chain.append(
                        {
                            "decision": str(tr.get("decision") or "?"),
                            "reason_class": str(rc) if rc else "?",
                            "image_ref": str(tr.get("image_ref") or ""),
                            "product": str(
                                (entry.get("tool_input") or {}).get("product") or "?"
                            ),
                        }
                    )
                if tool_name == "verify" and entry.get("status") in (
                    "tool_ok",
                    "tool_error",
                ):
                    if tr.get("passed") is True:
                        verify_passed_count += 1
                        for r in tr.get("results") or []:
                            if not isinstance(r, dict):
                                continue
                            t = r.get("type")
                            if isinstance(t, str):
                                verify_check_types.append(t)
                    elif tr.get("passed") is False:
                        verify_failed_count += 1
                    if tr.get("verify_quality_warning"):
                        warning = str(tr["verify_quality_warning"])
                        verify_quality_warnings.append(warning[:200])
                if tool_name == "nvd_lookup" and tr.get("blocked") is True:
                    nvd_blocked += 1
    except OSError:
        return {}
    return {
        **rc_counts,
        "image_resolve_chain": image_resolve_chain,
        "verify_check_types": sorted(set(verify_check_types)),
        "verify_passed_count": verify_passed_count,
        "verify_failed_count": verify_failed_count,
        "verify_quality_warnings": verify_quality_warnings,
        "nvd_blocked": nvd_blocked,
    }


def _print_human_report(outcome: Any) -> None:  # noqa: ANN401
    """Human-readable summary on stderr after build.

    Default-on. Suppress with `cve-env build --silent`. Shows:
    - outcome icon + 1-line summary
    - pathway chosen
    - turn / cost / tool counts
    - verify check types used + pass/fail
    - tried-and-skipped registries (image_resolve chain)
    - credential nudges on rate_limited / auth / disk_full / NVD-blocked
    - audit path for deep-dive
    """
    tools = [t for t in outcome.tool_names_called if t != "ToolSearch"]
    counts: dict[str, int] = {}
    for t in tools:
        counts[t] = counts.get(t, 0) + 1
    # API-Overload aborts produce empty tool_names_called AND status=error
    # AND final_text matches the 529 Overloaded pattern. Without this branch
    # they would be mislabeled "research-only" because the default fires on an
    # empty tool list. Use the shared classifier for consistency.
    from cve_env.agent.loop import _classify_api_overload

    if (
        not tools
        and outcome.status == "error"
        and _classify_api_overload(outcome.final_text or "") == "api_overload"
    ):
        pathway = "api-aborted"
    elif "docker_compose_up" in tools:
        pathway = "vulhub-compose"
    elif "source_build" in tools and "docker_build" in tools:
        pathway = "source-build"
    elif "docker_build" in tools:
        pathway = "custom-dockerfile"
    elif "docker_run" in tools:
        pathway = "vulhub-image"
    elif "verify" in tools:
        pathway = "no-launch"
    else:
        pathway = "research-only"

    icon = "?"
    summary = outcome.status
    if outcome.verify_passed and outcome.num_turns > 0:
        if outcome.status == "success":
            icon = "✓ BUILT"
            summary = (
                "pre-patch environment built and verified (version + functional smoke)"
            )
        elif outcome.status in ("verified_partial", "success_partial"):
            # verified_partial is the canonical name; success_partial remains
            # accepted for back-compat with historical outcome JSONs.
            icon = "⊕ PARTIAL"
            summary = (
                "container ran + verify passed, but build evidence is "
                "incomplete: "
                + (outcome.reason or "missing version-assertion or functional smoke")
            )
    elif outcome.status == "rate_limited":
        # Anthropic API 529/overload throttle. Distinct icon (⏳ wait/retry) so
        # a reader does NOT confuse it with a merit failure (the ⊘
        # give_up_reason branch below would otherwise show ⊘ api_overload, which
        # looks like a hard stop). The build did not get a fair chance — it is
        # re-runnable on quota recovery; best-of-N will retry it.
        icon = "⏳ rate_limited"
        summary = (
            outcome.give_up_detail[:200]
            if outcome.give_up_detail
            else "Anthropic API rate-limited (529 Overloaded) — re-runnable, not a merit failure"
        )
    elif outcome.give_up_reason:
        icon = f"⊘ {outcome.give_up_reason}"
        summary = (
            outcome.give_up_detail[:200]
            if outcome.give_up_detail
            else outcome.give_up_reason
        )
    elif outcome.status in ("verify_failed", "no_verify_pass"):
        # verify_failed is canonical; no_verify_pass back-compat.
        icon = f"⚠ {outcome.status}"
        summary = "agent ended without a passing verify"
    elif outcome.status in {"turn_cap", "budget_exhausted"}:
        icon = f"✗ {outcome.status}"
        summary = (
            f"hit the cap. Retry with --max-turns {outcome.num_turns * 2} "
            f"--max-cost-usd {round(outcome.total_cost_usd * 2.5, 2)} "
            "to extend"
        )
    elif outcome.status == "error":
        icon = "✗ error"
        summary = outcome.error[:200] if outcome.error else "unknown error"

    pressure = _audit_pressure_summary(outcome.audit_path)

    def _e(msg: str) -> None:
        print(msg, file=sys.stderr)  # noqa: T201 -- intentional CLI output

    _e("")
    _e("=" * 72)
    _e(f"  cve-env report: {outcome.cve_id}")
    _e("=" * 72)
    _e(f"  outcome:       {icon}")
    _e(f"  what happened: {summary}")
    _e(
        f"  pathway:       {pathway}  |  turns: {outcome.num_turns}  |  "
        f"cost: ${outcome.total_cost_usd:.4f}"
    )

    # Stage-grouped tool calls: one section per pipeline stage, showing what
    # the agent actually did.
    stages = _stage_grouped_calls(outcome.audit_path)
    for stage in _STAGE_ORDER:
        calls = stages.get(stage) or []
        if not calls:
            continue
        _e("")
        label = _STAGE_LABEL.get(stage, stage.upper())
        _e(f"  ── {label} {'─' * max(1, 60 - len(label))}")
        for c in calls:
            turn = c.get("turn", "?")
            tool = str(c.get("tool", ""))
            sm = str(c.get("summary", ""))
            glyph = str(c.get("glyph", ""))
            recv = str(c.get("receipt", ""))
            left = f"  T{turn:<4} {tool:<18}{sm}"
            right = f"  {glyph} {recv}" if (glyph or recv) else ""
            _e(left + right)
            # For verify calls, expand to show each check on its own indented
            # line — answers "what was actually checked under this plan?"
            # (versions, functional smoke, payload, etc.)
            if tool == "verify":
                tr = c.get("result")
                if isinstance(tr, dict):
                    for line in _render_verify_checks(tr):
                        _e(line)

    _e("")
    # Verify narrative.
    if (
        pressure.get("verify_check_types")
        or pressure.get("verify_passed_count")
        or pressure.get("verify_failed_count")
    ):
        types_str = ", ".join(pressure.get("verify_check_types") or []) or "(none)"
        _e(
            f"  verify summary: {pressure.get('verify_passed_count', 0)} pass / "
            f"{pressure.get('verify_failed_count', 0)} fail; types: {types_str}"
        )
    for warning in pressure.get("verify_quality_warnings") or []:
        _e(f"  ⚠ verify quality: {warning}")

    # Credential + rate-limit nudges.
    nudges: list[str] = []
    if pressure.get("rate_limited", 0) >= 3:
        nudges.append(
            f"⓵ {pressure['rate_limited']} rate_limited events — "
            "consider `docker login` (Docker Hub anon=100 pulls/6h, authed=200) "
            "or set NVD_API_KEY (5 req/30s anon → 50 req/30s authed). "
            "Run `cve-env doctor` to see current state."
        )
    elif pressure.get("rate_limited", 0) > 0:
        nudges.append(
            f"⓵ {pressure['rate_limited']} rate_limited event(s) — "
            "watch for more, set credentials if it persists across runs."
        )
    if pressure.get("auth_failed", 0) > 0:
        nudges.append(
            f"⓶ {pressure['auth_failed']} auth-failed event(s) — registry "
            "refused credentials. If using private images, run `docker login` for "
            "the relevant registry (quay.io / ghcr.io / mcr.microsoft.com)."
        )
    if pressure.get("disk_full", 0) > 0:
        nudges.append(
            f"⓷ {pressure['disk_full']} disk_full event(s) — Colima VM filled. "
            "Bump disk: `colima stop && colima start --disk 40`. Or run "
            "`scripts/warm_image_cache.sh` between benches."
        )
    if pressure.get("nvd_blocked", 0) > 0:
        nudges.append(
            f"⓸ nvd_lookup guard fired {pressure['nvd_blocked']} time(s) — "
            "agent attempted to re-research mid-CVE; runtime blocked it. "
            "This is working-as-designed."
        )
    if nudges:
        _e("")
        _e("  hints:")
        for n in nudges:
            _e(f"    {n}")

    if outcome.audit_path:
        _e(f"  audit:         {outcome.audit_path}")
    _e("=" * 72)


def _cmd_doctor(args: argparse.Namespace) -> int:
    """Print service-health probe table; exit non-zero on critical failure.

    Each probe contacts the live service, measures latency, and reads any
    rate-limit headers it exposes. Useful as a pre-bench check ("is everything
    set up properly?") and a credential setup feedback loop ("did adding
    NVD_API_KEY raise the tier from 5/30s to 50/30s?").
    """
    # Import here so the build path doesn't pay the requests import cost.
    from cve_env.infra.service_health import (
        has_critical_failure,
        render_table,
        run_all,
    )

    results = run_all()
    print(render_table(results))  # noqa: T201 -- CLI output
    if has_critical_failure(results):
        return 2
    # Strict mode: even non-critical failure (e.g. NVD throttled) returns 1 so
    # CI / bench preflight can fail-fast on misconfiguration.
    if args.strict and any(not r.ok for r in results):
        return 1
    return 0


def _build_argparser() -> argparse.ArgumentParser:
    """Build the top-level argparser. Extracted so tests can introspect
    defaults + accepted args without going through ``main()``."""
    from cve_env.config import MAX_TURN_EXTENSIONS, TURN_EXTENSION_PCT

    parser = argparse.ArgumentParser(
        prog="cve-env",
        description="LLM-agentic CVE -> Docker environment builder",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    b = sub.add_parser("build", help="Build + verify one CVE")
    b.add_argument(
        "cve_id",
        type=_validate_cve_id,
        help="e.g. CVE-2018-7600 (format: CVE-YYYY-NNNN+)",
    )
    b.add_argument("--product", default=None, help="product name hint")
    b.add_argument("--version", default=None, help="vulnerable version")
    b.add_argument("--description", default=None, help="short description")
    # Composition flows (source-build + dockerfile_gen + multiple verify
    # retries) often need 60-80 turns, so the defaults are sized to give
    # agentic recovery room without disabling the cap.
    b.add_argument("--max-turns", type=int, default=96)
    b.add_argument("--max-cost-usd", type=float, default=1.80)
    # Productive-extension knobs. Auto-extend the turn cap by
    # ``--turn-extension-pct`` when the agent is approaching the cap AND made
    # build progress within the recent window. Up to ``--max-turn-extensions``
    # extensions per CVE. Set max=0 to disable.
    b.add_argument(
        "--max-turn-extensions",
        type=int,
        default=MAX_TURN_EXTENSIONS,
        help=f"max turn-cap extensions per CVE (default: {MAX_TURN_EXTENSIONS}). "
        "Each extension grants ``--turn-extension-pct`` more turns when the "
        "agent is on a productive build path. Set 0 to disable.",
    )
    b.add_argument(
        "--turn-extension-pct",
        type=float,
        default=TURN_EXTENSION_PCT,
        help=f"per-extension cap bump as fraction (default: {TURN_EXTENSION_PCT}). "
        "0.20 means each extension adds 20%% more turns.",
    )
    b.add_argument("--audit-root", default=None)
    # Human-readable summary is DEFAULT-ON. Use --silent to suppress
    # (e.g., for bench runners that scrape JSON from stdout).
    b.add_argument(
        "--silent",
        action="store_true",
        help="Suppress the end-of-run human-readable summary on "
        "stderr. Useful for scripts that parse the JSON from stdout. The "
        "summary (pathway, outcome, verify check types, registries tried, "
        "credential nudges, audit path) is on by default.",
    )
    # Opt-in lifecycle hooks. Default off. CLI flag OR-merges with the env
    # var (either enables → effective on).
    b.add_argument(
        "--auto-cleanup-containers",
        action="store_true",
        help="Opt-in: post-build, `docker rm -f` this run's labeled "
        "containers. Default off; also enabled via env CVE_ENV_AUTO_CLEANUP_CONTAINERS=1.",
    )
    b.add_argument(
        "--auto-prune-images",
        action="store_true",
        help="Opt-in: post-build, `docker image prune -f` (dangling layers "
        "only). Default off; also enabled via env CVE_ENV_AUTO_PRUNE_IMAGES=1.",
    )
    b.add_argument(
        "--auto-stop-colima",
        action="store_true",
        help="Opt-in: post-build, `colima stop` IFF no other cve-env build "
        "is running. Default off; also enabled via env CVE_ENV_AUTO_STOP_COLIMA=1.",
    )
    b.set_defaults(func=_cmd_build)

    d = sub.add_parser(
        "doctor",
        help="Probe external services (NVD, OSV, GitHub, Docker Hub, alt registries) "
        "and print a health table",
    )
    d.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 even on non-critical failure (e.g. NVD throttled). "
        "default: only critical failures return non-zero",
    )
    d.set_defaults(func=_cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_argparser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
