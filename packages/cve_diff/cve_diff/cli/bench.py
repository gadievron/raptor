"""
`cve-diff bench` — run the pipeline across a sample of CVEs.

Two execution modes:
  * workers=1 → sequential (easier to debug, no fork overhead for small samples)
  * workers>1 → ProcessPoolExecutor

Per-CVE outputs:
  * {output_dir}/{cve_id}.osv.json
Summary outputs:
  * {output_dir}/summary.json
  * {output_dir}/summary.html
"""

from __future__ import annotations

import json
import shutil
import signal
import tempfile
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import date
from pathlib import Path

import typer

from cve_diff.core.exceptions import CveDiffError
from cve_diff.infra import api_status
from cve_diff.infra.github_client import warn_if_token_missing
from cve_diff.pipeline import Pipeline, PipelineResult
from cve_diff.report import osv_schema

_PER_CVE_TIMEOUT_S = 300  # 5 min. Any upstream-slice clone finishes well under.
_PACKAGE_DATA_DIR = Path(__file__).resolve().parents[2] / "data"  # packages/cve_diff/data/


class _PerCveTimeout(Exception):
    pass


def _alarm_handler(_signum, _frame):
    raise _PerCveTimeout(f"exceeded {_PER_CVE_TIMEOUT_S}s budget")


@dataclass
class _CveResult:
    cve_id: str
    ok: bool
    elapsed_s: float
    files_changed: int = 0
    diff_bytes: int = 0
    shape: str = ""
    error: str = ""
    # Structured failure class — set at construction so the report
    # writer doesn't have to regex an unstructured error string.
    # "PASS" for ok=True; one of {"UnsupportedSource", "no_evidence",
    # "budget_cost_usd", "budget_iterations", "budget_tokens",
    # "llm_error", "model_stopped_without_submit", "client_init_failed",
    # "PerCveTimeout", "AnalysisError", "DiscoveryError", "Other"} for
    # ok=False.
    error_class: str = ""
    # Agent attribution — populated on every CVE (pass or fail) from
    # AgentLoop.last_telemetry, which is set on every loop exit.
    agent_iterations: int = 0
    agent_tokens: int = 0
    agent_cost_usd: float = 0.0
    agent_tool_calls: tuple[str, ...] = ()
    # Per-call (tool_name, args_repr_first_120_chars). Lets post-hoc
    # analysis distinguish "agent re-queried with same args" from
    # "agent re-queried with varied args" — relevant for validating
    # Action A's claims and analyzing walker patterns.
    agent_tool_calls_with_args: tuple[tuple[str, str], ...] = ()
    agent_model: str = ""
    # Recovery telemetry: how many in-loop LLM retries fired (3-attempt
    # backoff inside AgentLoop), whether the pipeline's meta-retry on
    # budget+candidates ran, and whether the bench-layer retry pass
    # re-ran this CVE after a transient failure.
    llm_retries: int = 0
    meta_retry_attempted: bool = False
    # True when the pipeline's post-submit retry fired (stages 2-5
    # failed on the agent's first pick; agent re-run picked a new
    # candidate). Distinct from ``meta_retry_attempted`` (budget walks).
    post_submit_retry_attempted: bool = False
    bench_retry_attempted: bool = False
    # Gate-firing telemetry: how many times each agent-loop submit gate
    # fed back rejection during this run. Distinct from the terminal
    # surrender (which lands as ``error_class``); these counters surface
    # the recoverable feedback path. ``unverified_submits`` = verified-SHA
    # gate firings; ``not_found_submits`` = SHA-existence gate firings.
    unverified_submits: int = 0
    not_found_submits: int = 0
    # Integrity signals — populated on PASS only (failures don't have a
    # bundle to compare). `consensus_agree` is the count of OSV/NVD
    # methods that agree on the pointer (0, 1, or 2). `extraction_agree`
    # is the clone-vs-API content verdict ("agree" / "partial" /
    # "disagree" / "single_source") — see DiffBundle.extraction_agreement.
    consensus_agree: int | None = None
    extraction_agree: str = ""


@dataclass
class _BenchSummary:
    sample: str
    total: int
    passed: int
    results: list[_CveResult] = field(default_factory=list)


def _run_one(cve_id: str, output_dir: str, disk_limit_pct: float = 80.0,
             max_file_bytes: int = 128 * 1024) -> _CveResult:
    """Worker entry point — runs pipeline + dumps OSV JSON for a single CVE.

    Each worker installs a SIGALRM watchdog so a runaway clone (e.g. a
    multi-GB writeup archive that slipped past the metadata scorer) cannot
    hang the harness indefinitely. The signal fires inside this worker
    process; the parent's `as_completed` loop continues unaffected.
    """
    t0 = time.monotonic()
    out = Path(output_dir)
    # SIGALRM only delivers to the main thread; if we install it in the
    # parent process (workers <= 1 path), and the agent / DistroFetcher
    # spins up its own ThreadPoolExecutor, SIGALRM can fire from inside
    # an unrelated `as_completed` loop while a worker thread is the one
    # actually stuck — the worker thread + its subprocess get orphaned.
    # Install the alarm only when we're in a ProcessPoolExecutor child
    # (its own process, separate signal disposition); the sequential
    # path relies on per-subprocess timeouts (RaptorConfig.GIT_CLONE_TIMEOUT
    # + httpx.timeout) for runaway protection.
    import multiprocessing
    install_alarm = multiprocessing.current_process().name != "MainProcess"
    prev_handler = None
    if install_alarm:
        prev_handler = signal.signal(signal.SIGALRM, _alarm_handler)
        signal.alarm(_PER_CVE_TIMEOUT_S)
    # Bench enables both consensus (pointer-level) and extraction
    # agreement (content-level) — the user's primary integrity signals.
    # Cost is near-zero because OSV / NVD / GitHub-commit fetches share
    # caches with the agent's tool calls.
    pipeline = Pipeline(disk_limit_pct=disk_limit_pct, max_file_bytes=max_file_bytes)
    model_id = "claude-opus-4-7"  # AgentConfig default
    try:
        with tempfile.TemporaryDirectory(prefix=f"bench-{cve_id}-") as tmp:
            try:
                result = pipeline.run(cve_id, Path(tmp))
                osv = osv_schema.render(result.bundle)
                (out / f"{cve_id}.osv.json").write_text(
                    json.dumps(osv, indent=2) + "\n"
                )
                consensus = result.bundle.consensus or {}
                ext_agree = result.bundle.extraction_agreement or {}
                r = _CveResult(
                    cve_id=cve_id, ok=True,
                    elapsed_s=round(time.monotonic() - t0, 1),
                    files_changed=result.bundle.files_changed,
                    diff_bytes=result.bundle.bytes_size,
                    shape=result.bundle.shape,
                    error_class="PASS",
                    consensus_agree=consensus.get("agreement_count"),
                    extraction_agree=ext_agree.get("verdict") or "single_source",
                    **_agent_attrs(pipeline, model_id),
                )
                _write_flow(out, cve_id, r, pipeline=pipeline, pipeline_result=result)
                # Save each extraction method's raw diff body as a
                # `.patch` file so the partial/disagree cases are easy
                # to audit. Best-effort; never blocks the bench.
                from cve_diff.report.flow import write_outcome_patches
                api_bundle = getattr(pipeline, "_last_api_bundle", None)
                api_method = None
                if api_bundle is not None:
                    from core.url_patterns import (
                        is_github_url, is_gitlab_url,
                    )
                    url = result.bundle.repo_ref.repository_url or ""
                    api_method = (
                        "github_api" if is_github_url(url)
                        else "gitlab_api" if is_gitlab_url(url)
                        else "api"
                    )
                write_outcome_patches(
                    out, cve_id,
                    clone_diff_text=result.bundle.diff_text,
                    api_diff_text=api_bundle.diff_text if api_bundle else None,
                    api_method=api_method,
                )
                return r
            except _PerCveTimeout as exc:
                err = f"PerCveTimeout: {exc}"
                _write_failure_md(out, cve_id, _classify_error(err), err)
                r = _CveResult(
                    cve_id=cve_id, ok=False,
                    elapsed_s=round(time.monotonic() - t0, 1),
                    error=err,
                    error_class=_classify_error(err),
                    **_agent_attrs(pipeline, model_id),
                )
                _write_flow(out, cve_id, r, pipeline=pipeline)
                return r
            except CveDiffError as exc:
                err = f"{type(exc).__name__}: {exc}"[:300]
                _write_failure_md(out, cve_id, _classify_error(err), err)
                r = _CveResult(
                    cve_id=cve_id, ok=False,
                    elapsed_s=round(time.monotonic() - t0, 1),
                    error=err,
                    error_class=_classify_error(err),
                    **_agent_attrs(pipeline, model_id),
                )
                _write_flow(out, cve_id, r, pipeline=pipeline)
                return r
            except Exception as exc:  # noqa: BLE001 — bench must not abort on one CVE
                err = f"{type(exc).__name__}: {exc}"[:300]
                _write_failure_md(out, cve_id, _classify_error(err), err)
                r = _CveResult(
                    cve_id=cve_id, ok=False,
                    elapsed_s=round(time.monotonic() - t0, 1),
                    error=err,
                    error_class=_classify_error(err),
                    **_agent_attrs(pipeline, model_id),
                )
                _write_flow(out, cve_id, r, pipeline=pipeline)
                return r
    finally:
        if install_alarm:
            signal.alarm(0)
            if prev_handler is not None:
                signal.signal(signal.SIGALRM, prev_handler)


def _agent_attrs(pipeline: "Pipeline", model_id: str) -> dict:
    """Pull agent telemetry off the loop's last_telemetry + pipeline state."""
    tel = getattr(pipeline.agent, "last_telemetry", None) or {}
    return {
        "agent_iterations": int(tel.get("iterations", 0)),
        "agent_tokens": int(tel.get("tokens", 0)),
        "agent_cost_usd": float(tel.get("cost_usd", 0.0)),
        "agent_tool_calls": tuple(tel.get("tool_calls", ())),
        "agent_tool_calls_with_args": tuple(
            tuple(t) for t in tel.get("tool_calls_with_args", [])
        ),
        "agent_model": model_id,
        "llm_retries": int(tel.get("llm_retries", 0)),
        "meta_retry_attempted": bool(getattr(pipeline, "_last_meta_retry_attempted", False)),
        "post_submit_retry_attempted": bool(getattr(pipeline, "_last_post_submit_retry_attempted", False)),
        "unverified_submits": int(tel.get("unverified_submits", 0)),
        "not_found_submits": int(tel.get("not_found_submits", 0)),
    }


# Maps exception type or AgentSurrender reason → structured error_class
# string. Order matters: the surrender-reason patterns are checked
# before exception-type fallback.
_SURRENDER_REASONS = (
    "budget_cost_usd", "budget_iterations", "budget_tokens",
    "llm_error", "no_evidence", "UnsupportedSource",
    "model_stopped_without_submit", "client_init_failed",
    "repeated_tool_call", "sha_not_found_in_repo",
    "submit_unverified_sha",
    "malformed_repository_url",
)


def _write_failure_md(output_dir: Path, cve_id: str, error_class: str,
                      error_text: str) -> None:
    """Write a per-CVE failure markdown alongside the OSV JSON. Surfaces
    the agent's surrender rationale so users browsing the bench output
    can see WHY each non-PASS CVE was refused. Best-effort — never let
    a render failure abort the bench."""
    try:
        from cve_diff.report.markdown import render_failure
        text = render_failure(cve_id, error_class, error_text)
        (output_dir / f"{cve_id}.md").write_text(text)
    except Exception:  # noqa: BLE001 — report write must not abort bench
        pass


def _write_flow(output_dir: Path, cve_id: str, result: "_CveResult",
                pipeline: "Pipeline | None" = None,
                pipeline_result: "PipelineResult | None" = None) -> None:
    """Emit `<cve>.flow.jsonl` + `<cve>.flow.md` for one bench result.

    When ``pipeline`` is supplied, this delegates to
    ``cve_diff.cli.main._flow_from_pipeline`` so the bench's per-CVE
    flow.md gets the same stage_signals + stage_status that single-run
    flow.md already has — without that plumbing, every stages 2-5 row
    rendered "(not reached)" even on a successful PASS.
    """
    if pipeline is not None:
        from cve_diff.cli.main import _flow_from_pipeline
        _flow_from_pipeline(
            output_dir, cve_id, pipeline,
            ok=result.ok,
            error_class=result.error_class,
            pipeline_result=pipeline_result,
        )
        return
    # Fallback path: pipeline not available (e.g. raised before assignment).
    from cve_diff.report.flow import write_flow_files
    write_flow_files(
        output_dir, cve_id,
        tool_calls_with_args=result.agent_tool_calls_with_args or (),
        ok=result.ok,
        error_class=result.error_class,
    )


# Outcome classes the agent decided are out-of-scope (correct refusals,
# not pipeline failures). Visible in the end-of-bench summary so a user
# can tell deliberate scope decisions from pipeline misses.
_CORRECT_REFUSAL_CLASSES = frozenset({"UnsupportedSource", "no_evidence"})


def _outcome_buckets(summary: "_BenchSummary") -> tuple[int, int, int]:
    """Return (pass, correct_refusal, pipeline_issue) counts.

    - pass: ``r.ok=True``
    - correct_refusal: agent's deliberate scope decisions
      (``UnsupportedSource``, ``no_evidence``) — these are correct
      outcomes, not failures.
    - pipeline_issue: everything else (budget caps, AnalysisError,
      AcquisitionError, llm_error, etc.) — actual pipeline misses.
    """
    pass_n = sum(1 for r in summary.results if r.ok)
    refusal_n = sum(
        1 for r in summary.results
        if not r.ok and r.error_class in _CORRECT_REFUSAL_CLASSES
    )
    issue_n = len(summary.results) - pass_n - refusal_n
    return pass_n, refusal_n, issue_n


def _classify_error(error_text: str) -> str:
    """Extract the structured error class from an error string."""
    for reason in _SURRENDER_REASONS:
        # The DiscoveryError pattern is "agent surrendered (REASON):"
        if f"({reason})" in error_text:
            return reason
    if error_text.startswith("PerCveTimeout"):
        return "PerCveTimeout"
    if error_text.startswith("UnsupportedSource"):
        return "UnsupportedSource"
    if error_text.startswith("AnalysisError"):
        return "AnalysisError"
    if error_text.startswith("DiscoveryError"):
        return "DiscoveryError"
    if error_text.startswith("AcquisitionError"):
        return "AcquisitionError"
    return "Other"


def _echo_result(i: int, n: int, r: _CveResult) -> None:
    if r.ok:
        tag = "" if r.shape == "source" else f" [{r.shape}]"
        typer.echo(f"[{i}/{n}] PASS {r.cve_id}{tag} ({r.elapsed_s}s)")
    else:
        typer.echo(f"[{i}/{n}] FAIL {r.cve_id} — {r.error}", err=True)


def _render_bench_markdown(summary: _BenchSummary) -> str:
    """Single-page markdown report covering: headline, outcome
    distribution, recovery-layer effectiveness, tool-usage histogram,
    failure cluster. Sits alongside summary.json + summary.html.
    """
    from collections import Counter
    from datetime import datetime

    total = summary.total
    passed = summary.passed
    pct = 100.0 * passed / total if total else 0.0
    cost_total = sum(r.agent_cost_usd for r in summary.results)
    cost_avg = cost_total / total if total else 0.0
    wall_s = sum(r.elapsed_s for r in summary.results)
    wall_min = wall_s / 60.0
    source_hits = sum(1 for r in summary.results if r.ok and r.shape == "source")
    non_source = passed - source_hits
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")

    # Outcome distribution by error_class.
    outcome_counts = Counter(r.error_class or ("PASS" if r.ok else "Other") for r in summary.results)
    outcome_order = [
        "PASS", "UnsupportedSource", "no_evidence",
        "budget_cost_usd", "budget_iterations", "budget_tokens",
        "llm_error", "model_stopped_without_submit", "client_init_failed",
        "PerCveTimeout", "AnalysisError", "DiscoveryError",
        "AcquisitionError", "Other",
    ]
    outcome_lines = []
    seen: set[str] = set()
    for cls in outcome_order:
        c = outcome_counts.get(cls, 0)
        if c == 0:
            continue
        seen.add(cls)
        outcome_lines.append(f"| {cls} | {c} | {100.0 * c / total:.1f}% |")
    for cls, c in outcome_counts.items():
        if cls in seen or c == 0:
            continue
        outcome_lines.append(f"| {cls} | {c} | {100.0 * c / total:.1f}% |")

    # Recovery layers.
    in_loop_retry_triggered = sum(1 for r in summary.results if r.llm_retries > 0)
    in_loop_retry_recovered = sum(1 for r in summary.results if r.ok and r.llm_retries > 0)
    meta_retry_triggered = sum(1 for r in summary.results if r.meta_retry_attempted)
    meta_retry_recovered = sum(1 for r in summary.results if r.ok and r.meta_retry_attempted)
    bench_retry_triggered = sum(1 for r in summary.results if r.bench_retry_attempted)
    bench_retry_recovered = sum(1 for r in summary.results if r.ok and r.bench_retry_attempted)

    # Tool usage.
    tool_calls_total: Counter[str] = Counter()
    cves_per_tool: Counter[str] = Counter()
    for r in summary.results:
        seen_in_cve = set()
        for t in r.agent_tool_calls or ():
            tool_calls_total[t] += 1
            if t not in seen_in_cve:
                cves_per_tool[t] += 1
                seen_in_cve.add(t)
    tool_lines = [
        f"| {t} | {n} | {cves_per_tool[t]} |"
        for t, n in tool_calls_total.most_common()
    ]

    # Failure cluster (excluding PASS).
    fail_lines = [
        f"| {r.cve_id} | {r.error_class or 'Other'} | {(r.error or '')[:200].replace('|', '\\|').replace(chr(10), ' ')} |"
        for r in summary.results
        if not r.ok
    ]

    # Integrity signals — pointer consensus + extraction agreement
    # tallies. Empty if no PASSes (nothing to integrity-check).
    pass_results = [r for r in summary.results if r.ok]
    consensus_counts: Counter[str] = Counter()
    extract_counts: Counter[str] = Counter()
    for r in pass_results:
        if r.consensus_agree is None:
            consensus_counts["—"] += 1
        elif r.consensus_agree >= 2:
            consensus_counts["both methods agree"] += 1
        elif r.consensus_agree == 1:
            consensus_counts["only one method had data"] += 1
        else:
            consensus_counts["neither method had data"] += 1
        extract_counts[r.extraction_agree or "—"] += 1
    integrity_lines = []
    if pass_results:
        integrity_lines.append("| Pointer consensus (OSV refs + NVD Patch-tagged) | Count |")
        integrity_lines.append("|---|---:|")
        for k in ("both methods agree", "only one method had data",
                  "neither method had data", "—"):
            v = consensus_counts.get(k, 0)
            if v:
                integrity_lines.append(f"| {k} | {v} |")
        integrity_lines.append("")
        integrity_lines.append("| Extraction agreement (clone vs GitHub API) | Count |")
        integrity_lines.append("|---|---:|")
        for k in ("agree", "partial", "disagree", "single_source", "—"):
            v = extract_counts.get(k, 0)
            if v:
                integrity_lines.append(f"| {k} | {v} |")

    pass_n, refusal_n, issue_n = _outcome_buckets(summary)

    return (
        f"# Bench report — {summary.sample}\n\n"
        f"**Run timestamp**: {timestamp}\n\n"
        f"## Headline\n\n"
        f"| Metric | Value |\n"
        f"|---|---:|\n"
        f"| PASS | {passed} / {total} = {pct:.1f}% |\n"
        f"| Real source fixes | {source_hits} |\n"
        f"| Packaging/notes only (PASS but suspect) | {non_source} |\n"
        f"| Out of scope (correct refusals: UnsupportedSource + no_evidence) | {refusal_n} |\n"
        f"| Pipeline issues (budget caps, shape rejects, acquire fails) | {issue_n} |\n"
        f"| Cost total | ${cost_total:.2f} |\n"
        f"| Cost / CVE avg | ${cost_avg:.3f} |\n"
        f"| Wall (sum of per-CVE elapsed) | {wall_min:.1f} min |\n\n"
        f"_The agent declares **{refusal_n}** CVEs out of scope — closed-source vendors and "
        f"records with no public commit references. These are correct refusals, not pipeline "
        f"failures. Pipeline issues ({issue_n}) are the real misses to drive down._\n\n"
        f"## Outcome distribution\n\n"
        f"| Outcome | Count | % |\n"
        f"|---|---:|---:|\n"
        + "\n".join(outcome_lines) + "\n\n"
        f"## Diff integrity — sources + agreement\n\n"
        + (("\n".join(integrity_lines) + "\n\n") if integrity_lines else
           "_(no PASSes to compare)_\n\n")
        + f"## Recovery layers — what saved CVEs\n\n"
        f"| Layer | Triggered | Recovered (PASS) |\n"
        f"|---|---:|---:|\n"
        f"| In-loop LLM retry (3 attempts, 0/5/15s) | {in_loop_retry_triggered} | {in_loop_retry_recovered} |\n"
        f"| Meta-retry on budget+candidates | {meta_retry_triggered} | {meta_retry_recovered} |\n"
        f"| Bench-layer retry on transient errors | {bench_retry_triggered} | {bench_retry_recovered} |\n\n"
        f"## Tool usage (across {total} CVEs)\n\n"
        f"| Tool | Total calls | CVEs that used it |\n"
        f"|---|---:|---:|\n"
        + ("\n".join(tool_lines) if tool_lines else "_(no tool calls recorded)_") + "\n\n"
        f"## Failure cluster\n\n"
        + ("| CVE | Class | Error (first 200 chars) |\n"
           "|---|---|---|\n" + "\n".join(fail_lines) + "\n"
           if fail_lines else "_(none — all PASS)_\n")
    )


def _render_html(summary: _BenchSummary) -> str:
    pct = 100.0 * summary.passed / summary.total if summary.total else 0.0
    source_hits = sum(1 for r in summary.results if r.ok and r.shape == "source")
    non_source = summary.passed - source_hits
    pass_n, refusal_n, issue_n = _outcome_buckets(summary)

    rows: list[str] = []
    for r in summary.results:
        status_cls = "pass" if r.ok else "fail"
        status_text = "PASS" if r.ok else "FAIL"
        shape_cell = f'<span class="shape-{r.shape}">{r.shape}</span>' if r.shape else ""
        detail = (
            f"{r.files_changed} files · {r.diff_bytes:,} B"
            if r.ok
            else f'<span class="err">{r.error}</span>'
        )
        # Pointer consensus + extraction-agreement cells. Both empty
        # for FAIL rows (no bundle to integrity-check).
        if r.ok:
            if r.consensus_agree is None:
                cons_cell = "—"
            elif r.consensus_agree >= 2:
                cons_cell = '<span class="agree">2/2</span>'
            elif r.consensus_agree == 1:
                cons_cell = '<span class="partial">1/2</span>'
            else:
                cons_cell = '<span class="partial">0/2</span>'
            extract_cell_cls = {
                "agree": "agree", "partial": "partial",
                "disagree": "err", "single_source": "partial",
            }.get(r.extraction_agree, "")
            extract_cell = (
                f'<span class="{extract_cell_cls}">{r.extraction_agree}</span>'
                if r.extraction_agree else "—"
            )
        else:
            cons_cell = ""
            extract_cell = ""
        rows.append(
            f'<tr class="{status_cls}"><td>{r.cve_id}</td>'
            f'<td>{status_text}</td><td>{shape_cell}</td>'
            f'<td>{cons_cell}</td><td>{extract_cell}</td>'
            f'<td>{r.elapsed_s:.1f}s</td><td>{detail}</td></tr>'
        )
    table_rows = "\n".join(rows)

    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>cve-diff bench — {summary.sample}</title>
<style>
 body {{ font-family: -apple-system, system-ui, sans-serif; margin: 2rem; }}
 h1 {{ margin-bottom: .2rem; }}
 .meta {{ color: #666; margin-bottom: 1rem; }}
 table {{ border-collapse: collapse; width: 100%; }}
 th, td {{ padding: .4rem .6rem; border-bottom: 1px solid #eee; text-align: left; }}
 tr.pass td {{ background: #f6fff6; }}
 tr.fail td {{ background: #fff6f6; }}
 .shape-source {{ color: #2a7; }}
 .shape-packaging_only, .shape-notes_only {{ color: #c60; font-weight: 600; }}
 .err {{ color: #a00; font-family: ui-monospace, monospace; font-size: .9em; }}
 .agree {{ color: #2a7; font-weight: 600; }}
 .partial {{ color: #c60; }}
</style>
</head>
<body>
<h1>cve-diff bench</h1>
<div class="meta">
  sample: <code>{summary.sample}</code><br>
  <strong>{summary.passed}/{summary.total} passed ({pct:.1f}%)</strong> —
  {source_hits} real source fixes,
  {non_source} packaging/notes-only,
  {refusal_n} out-of-scope (correct refusals),
  {issue_n} pipeline issues
</div>
<table>
<thead><tr><th>CVE</th><th>status</th><th>shape</th><th>consensus<br><span style="font-weight:normal;font-size:.8em;color:#888">OSV+NVD</span></th><th>extraction<br><span style="font-weight:normal;font-size:.8em;color:#888">clone+API</span></th><th>elapsed</th><th>detail</th></tr></thead>
<tbody>
{table_rows}
</tbody>
</table>
</body>
</html>
"""


def bench(
    sample: Path = typer.Option(
        _PACKAGE_DATA_DIR / "samples" / "mvp_2024_2026.json",
        "--sample",
        help="Path to a JSON sample file with `cves: [{cve_id: ...}, ...]`.",
    ),
    output_dir: Path = typer.Option(
        None,
        "--output-dir",
        "-o",
        help="Per-CVE OSV reports + summary.{json,html} land here (default: temp dir).",
    ),
    limit: int = typer.Option(0, "--limit", help="Stop after N CVEs (0 = all)."),
    workers: int = typer.Option(
        1,
        "--workers",
        "-w",
        help="Parallel workers (ProcessPoolExecutor). 1 = sequential.",
    ),
    disk_limit_pct: float = typer.Option(
        80.0,
        "--disk-limit-pct",
        help="Abort threshold (filesystem-used %). Pipeline raises if disk exceeds this at any stage entry.",
    ),
    max_file_bytes: int = typer.Option(
        128 * 1024,
        "--max-file-bytes",
        help="Per-file source-blob cap (DiffBundle.files[*].before/after_source).",
    ),
    health_check: bool = typer.Option(
        False,
        "--health-check",
        help="Run service health probes before launching the bench. Abort if any CRITICAL service is down.",
    ),
) -> None:
    """Run the pipeline across each CVE in a sample file."""
    if output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="cve-diff-bench-"))
    warn_if_token_missing()
    api_status.print_to_stderr(api_status.render_startup_banner())
    if health_check:
        from cve_diff.infra import service_health
        results = service_health.run_all()
        typer.echo(service_health.render_table(results))
        if service_health.has_critical_failure(results):
            typer.echo("aborting bench: critical service unhealthy", err=True)
            raise typer.Exit(code=1)
    payload = json.loads(sample.read_text())
    cves = [c["cve_id"] for c in payload["cves"]]
    if limit > 0:
        cves = cves[:limit]

    output_dir.mkdir(parents=True, exist_ok=True)
    summary = _BenchSummary(sample=str(sample), total=len(cves), passed=0)
    n = len(cves)
    typer.echo(f"loading sample {sample} ({n} CVEs) — workers={workers}")

    summary_path = output_dir / "summary.json"

    def _flush() -> None:
        summary_path.write_text(json.dumps(asdict(summary), indent=2) + "\n")

    if workers <= 1:
        for i, cve_id in enumerate(cves, 1):
            r = _run_one(cve_id, str(output_dir), disk_limit_pct, max_file_bytes)
            summary.results.append(r)
            if r.ok:
                summary.passed += 1
            _echo_result(i, n, r)
            _flush()
    else:
        i = 0
        with ProcessPoolExecutor(max_workers=workers) as pool:
            futures = {pool.submit(_run_one, cid, str(output_dir), disk_limit_pct, max_file_bytes): cid for cid in cves}
            for fut in as_completed(futures):
                i += 1
                r = fut.result()
                summary.results.append(r)
                if r.ok:
                    summary.passed += 1
                _echo_result(i, n, r)
                _flush()
    # Sort in BOTH modes so summary.json ordering is deterministic
    # regardless of workers count (was sorted only in the parallel branch).
    summary.results.sort(key=lambda x: x.cve_id)

    # Bench-layer retry pass: re-run CVEs whose error class is
    # transient (LLM outage / network blip / per-CVE timeout). Settled
    # outcomes (UnsupportedSource / no_evidence / budget_*) are not
    # retried — those are conclusive. Sequential to keep small N
    # (typically < 5) deterministic and to avoid contention with the
    # primary loop's tempdirs.
    _run_bench_retry_pass(summary, str(output_dir), disk_limit_pct, max_file_bytes, n, _flush)

    pct = 100.0 * summary.passed / summary.total if summary.total else 0.0
    source_hits = sum(1 for r in summary.results if r.ok and r.shape == "source")
    non_source = summary.passed - source_hits
    pass_n, refusal_n, issue_n = _outcome_buckets(summary)
    _flush()
    (output_dir / "summary.html").write_text(_render_html(summary))
    (output_dir / "bench_report.md").write_text(_render_bench_markdown(summary))
    _persist_summary(output_dir / "summary.json", sample)
    typer.echo("")
    typer.echo(f"=== {summary.passed}/{summary.total} passed ({pct:.1f}%) ===")
    if non_source:
        typer.echo(
            f"    of which {non_source} are packaging_only/notes_only "
            f"(likely wrong repo); {source_hits} real source fixes"
        )
    if refusal_n or issue_n:
        typer.echo("")
        typer.echo("Outcome breakdown:")
        typer.echo(f"  PASS                       {pass_n:>4}  (real fix-commit identified)")
        typer.echo(
            f"  out of scope (refusals)    {refusal_n:>4}  "
            f"(agent declared closed-source / no public commit; correct refusals, not failures)"
        )
        typer.echo(f"  pipeline issues            {issue_n:>4}  (budget caps, shape rejects, acquire fails — real misses)")
    rate_limit_text = api_status.render_rate_limit_summary()
    if rate_limit_text:
        typer.echo("")
        typer.echo(rate_limit_text)
    cache_text = api_status.render_cache_summary()
    if cache_text:
        typer.echo("")
        typer.echo(cache_text)
    typer.echo(f"summary: {output_dir / 'summary.json'}")
    typer.echo(f"html:    {output_dir / 'summary.html'}")
    typer.echo(f"report:  {output_dir / 'bench_report.md'}")


def _persist_summary(summary_path: Path, sample: Path) -> None:
    """Copy a finished bench's summary.json into ``data/runs/<date>_<stem>.json``
    so the structured per-CVE outcome record survives /tmp cleanup. Best-effort:
    failure logs but does not fail the bench.

    Without this, the rich BenchResult fields (per-CVE outcome, cost,
    iterations, full tool-call list, retry flags, agreement verdicts) leak
    out of the corpus every time /tmp is cleaned. The 2026-05-01 corpus
    audit found 466 of 1,071 sampled CVEs had zero baseline mention because
    their bench dirs were cleaned before persistence.
    """
    try:
        runs_dir = _PACKAGE_DATA_DIR / "runs"
        if not runs_dir.is_dir():
            return  # data/runs/ missing; skip silently.
        dest = runs_dir / f"{date.today():%Y%m%d}_{sample.stem}.json"
        shutil.copy2(summary_path, dest)
        typer.echo(f"persisted: {dest}")
    except Exception as exc:  # noqa: BLE001 — never fail the bench on a copy
        typer.echo(f"(could not persist summary to data/runs/: {exc})", err=True)


# Error classes the bench-layer retry pass re-runs. Anything else is a
# conclusive outcome.
# Transient = network/API blip during the agent or acquisition.
# AcquisitionError covers "git clone died mid-fetch"; client_init_failed
# covers a transient API auth flake (rate limit, DNS hiccup). Settled
# outcomes (UnsupportedSource / no_evidence / budget_*) stay in.
_TRANSIENT_CLASSES = frozenset({
    "llm_error", "PerCveTimeout", "AcquisitionError", "client_init_failed",
})


def _run_bench_retry_pass(
    summary: "_BenchSummary",
    output_dir: str,
    disk_limit_pct: float,
    max_file_bytes: int,
    n: int,
    flush_fn,
) -> None:
    """Bench-layer retry: re-run CVEs whose error_class is in
    ``_TRANSIENT_CLASSES``. Splice updated results into ``summary.results``
    and bump ``summary.passed`` on flips. Settled outcomes
    (UnsupportedSource / no_evidence / budget_*) are not retried.

    Sequential by design — typical N < 5 makes parallelism overkill and
    serial avoids tempdir contention with the primary loop.
    """
    transient = [r for r in summary.results if not r.ok and r.error_class in _TRANSIENT_CLASSES]
    if not transient:
        return
    typer.echo("")
    typer.echo(f"=== bench-retry: re-running {len(transient)} transient failures ===")
    for r_old in transient:
        r_new = _run_one(r_old.cve_id, output_dir, disk_limit_pct, max_file_bytes)
        r_new.bench_retry_attempted = True
        for idx, existing in enumerate(summary.results):
            if existing.cve_id == r_new.cve_id:
                summary.results[idx] = r_new
                if r_new.ok and not r_old.ok:
                    summary.passed += 1
                break
        _echo_result(0, n, r_new)
    flush_fn()
