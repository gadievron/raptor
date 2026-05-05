"""``cve-diff`` CLI entry point.

Two top-level commands:

  * ``run <CVE-ID>``  — single-CVE pipeline. Validates the CVE id,
    runs ``Pipeline.run``, then writes 7 artifacts (osv.json, md,
    flow.jsonl, flow.md, clone.patch, plus per-second-source patches)
    and echoes the rendered pipeline trace to stdout. Maps each
    typed exception to a documented exit code (see README).
  * ``health``        — probe each external service (Anthropic API,
    NVD, GitHub, GitLab) and exit non-zero if any critical probe
    fails.

The ``bench`` command is registered here from
``cve_diff.cli.bench::bench`` for parallel CVE runs.
"""
from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Annotated

import typer

from cve_diff import __version__
from cve_diff.analysis.analyzer import RootCauseAnalysisError, RootCauseAnalyzer
from cve_diff.cli.bench import bench as _bench_cmd
from cve_diff.core.exceptions import (
    AcquisitionError,
    AnalysisError,
    DiscoveryError,
    IdenticalCommitsError,
    UnsupportedSource,
)
from cve_diff.infra import api_status
from cve_diff.infra.github_client import warn_if_token_missing
from cve_diff.llm.client import LLMCallFailed
from cve_diff.pipeline import Pipeline, PipelineResult  # noqa: F401  (PipelineResult used in type hint)
from cve_diff.report import markdown, osv_schema
from cve_diff.report.flow import write_flow_files, write_outcome_patches
from cve_diff.security.validators import validate_cve_id


def _echo_flow_md(output_dir: Path, cve_id: str, quiet: bool) -> None:
    """Print the rich pipeline-trace summary to stdout at end of run.

    The flow.md file already lives on disk thanks to
    ``_flow_from_pipeline``. We read it back instead of re-rendering so
    on-screen and on-disk are always in sync. Suppressed when the user
    passes ``--quiet`` (consistent with the API-key banner gate).
    """
    if quiet:
        return
    flow_md_path = output_dir / f"{cve_id}.flow.md"
    if not flow_md_path.exists():
        return
    try:
        body = flow_md_path.read_text()
    except OSError:
        return
    typer.echo("")
    typer.echo(f"=== {cve_id} — pipeline trace ===")
    typer.echo("")
    typer.echo(body.rstrip())
    typer.echo("")
    typer.echo("=== Artifacts ===")


def _flow_from_pipeline(
    output_dir: Path, cve_id: str, pipeline: Pipeline,
    *, ok: bool, error_class: str | None,
    pipeline_result: "PipelineResult | None" = None,
) -> None:
    """Read agent telemetry off the pipeline and emit per-CVE flow files.

    On PASS, ``pipeline_result`` is the successful ``PipelineResult``;
    its ``bundle`` and ``acquirer`` populate the post-discover stage
    signals (acquire layer / resolve before+after / diff shape+files+
    bytes / extraction agreement / consensus) so the rendered flow.md
    shows all 5 stages with the method picked at each.
    """
    tel = getattr(pipeline.agent, "last_telemetry", None) or {}
    raw = tel.get("tool_calls_with_args") or ()
    pairs = [tuple(t) for t in raw if isinstance(t, (list, tuple)) and len(t) == 2]

    stage_signals: dict | None = None
    if ok and pipeline_result is not None:
        bundle = pipeline_result.bundle
        layer = "?"
        try:
            layer = next(
                (r.name for r in pipeline_result.acquirer.reports if r.ok),
                "?",
            )
        except Exception:  # noqa: BLE001
            layer = "?"
        # Slug is best-effort: extract from a GitHub URL when present;
        # otherwise fall back to a host-tail label so the renderer's
        # forge-detection still finds the right reason text.
        slug: str | None = None
        try:
            from core.url_patterns import extract_github_slug
            slug = extract_github_slug(bundle.repo_ref.repository_url or "")
        except Exception:  # noqa: BLE001 — slug is presentation-only
            slug = None
        if slug is None:
            slug = (bundle.repo_ref.repository_url or "").lower()
        stage_signals = {
            "acquire": {"layer": layer},
            "resolve": {
                "before": (bundle.commit_before or "?")[:12],
                "after": (bundle.commit_after or "?")[:12],
            },
            "diff": {
                "shape": bundle.shape,
                "files_changed": bundle.files_changed,
                "diff_bytes": bundle.bytes_size,
                # Full N-source agreement dict. The renderer iterates
                # over ``agreement.sources`` to render one row per
                # extractor (clone + zero or more second sources).
                "extraction_agreement": bundle.extraction_agreement,
                "slug": slug,
                "sha": (bundle.commit_after or "")[:12] or None,
            },
            "render": {
                "consensus_count": (
                    (bundle.consensus or {}).get("agreement_count")
                    if bundle.consensus else None
                ),
            },
        }

    # Stage status — populated by Pipeline._emit on every run, including
    # FAIL paths. Read it ALWAYS (PASS or FAIL) so the trace renderer
    # can emit all 5 stage headers with the right ✓/✗/not-reached glyph.
    # User-stated requirement (2026-05-01): all stages must show, every
    # time. We've missed this in the past — this wiring is the guarantee.
    stage_status = dict(getattr(pipeline, "_stage_status", None) or {})

    write_flow_files(
        output_dir, cve_id,
        tool_calls_with_args=pairs,
        ok=ok,
        error_class=error_class,
        stage_signals=stage_signals,
        stage_status=stage_status,
    )

app = typer.Typer(
    name="cve-diff",
    help="CVE patch analysis pipeline — discover, acquire, diff, and explain.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode=None,
    context_settings={"max_content_width": 120},
)


# Match the surrender-reason fragment produced by the agent layer:
# `DiscoveryError: CVE-X: agent surrendered (REASON): ...`. Only the
# budget_* family is eligible for interactive extension.
_BUDGET_REASON_RE = re.compile(
    r"agent surrendered \((budget_cost_usd|budget_iterations|budget_tokens|budget_s)\)"
)


def _budget_reason(error_text: str) -> str | None:
    """Extract the budget-surrender reason from a DiscoveryError message,
    or None if the failure is not a budget cap."""
    m = _BUDGET_REASON_RE.search(error_text or "")
    return m.group(1) if m else None


# Surrender-reason fragments inside DiscoveryError messages. Used to
# classify a no-fix CVE for the per-CVE failure markdown.
_DISCOVERY_REASON_RE = re.compile(
    r"agent surrendered \(([a-zA-Z_]+)\)"
)


def _classify_discovery(error_text: str) -> str:
    """Pick the surrender reason out of a DiscoveryError so the failure
    markdown can label it with a structured class."""
    m = _DISCOVERY_REASON_RE.search(error_text or "")
    return m.group(1) if m else "DiscoveryError"


def _write_failure_md(output_dir: Path, cve_id: str, error_class: str,
                      error_text: str) -> None:
    """Write a per-CVE markdown surfacing the agent's surrender rationale.
    Helps users see WHY a CVE was refused without parsing JSON. Best-effort —
    failures here are not allowed to break the CLI's exit-code path."""
    try:
        text = markdown.render_failure(cve_id, error_class, error_text)
        (output_dir / f"{cve_id}.md").write_text(text)
        typer.echo(f"wrote {output_dir / f'{cve_id}.md'}")
    except Exception:  # noqa: BLE001 — never block the CLI on report-write
        pass


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"cve-diff {__version__}")
        raise typer.Exit()


@app.callback()
def _root(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Print version and exit.",
        ),
    ] = False,
) -> None:
    return None


@app.command()
def run(
    cve_id: Annotated[
        str,
        typer.Argument(metavar="<CVE-ID>", help="CVE identifier, e.g. CVE-2023-38545."),
    ],
    output_dir: Annotated[
        Path,
        typer.Option("--output-dir", "-o", help="Output directory for reports."),
    ] = Path("./out"),
    work_dir: Annotated[
        Path | None,
        typer.Option("--work-dir", help="Clone directory (default: temp dir)."),
    ] = None,
    keep_workdir: Annotated[
        bool, typer.Option("--keep-workdir", help="Keep clone directory after success.")
    ] = False,
    with_root_cause: Annotated[
        bool,
        typer.Option(
            "--with-root-cause",
            help="Run LLM root-cause analysis (extra API call).",
        ),
    ] = False,
    model_id: Annotated[
        str,
        typer.Option("--model", help="Model for root-cause analysis.", show_default=False),
    ] = "claude-opus-4-7",
    disk_limit_pct: Annotated[
        float,
        typer.Option("--disk-limit", help="Max filesystem usage %.", show_default=False),
    ] = 80.0,
    max_file_bytes: Annotated[
        int,
        typer.Option("--max-file", help="Per-file source cap in bytes.", show_default=False),
    ] = 128 * 1024,
    quiet: Annotated[
        bool,
        typer.Option(
            "--quiet", "-q",
            help="Suppress progress and API-key banner.",
        ),
    ] = False,
) -> None:
    """Discover, acquire, diff, and report the fix commit for a CVE."""
    warn_if_token_missing()
    cve_id = validate_cve_id(cve_id)
    # Both the agent loop and the optional root-cause analyzer now go
    # direct to the Anthropic SDK (no LiteLLM proxy). The legacy
    # `require_alive()` proxy gate was removed 2026-05-01 along with
    # exit code 8 (ProxyUnavailableError); only ANTHROPIC_API_KEY
    # is required, and the SDK itself surfaces auth errors at first call.
    output_dir.mkdir(parents=True, exist_ok=True)
    tmp_ctx: tempfile.TemporaryDirectory | None = None
    if work_dir is None:
        if keep_workdir:
            # `--keep-workdir` without `--work-dir` is meaningless: even if
            # we suppress tmp_ctx.cleanup(), TemporaryDirectory's GC
            # finalizer deletes the dir on collection. Refuse so the user
            # gets a clear error rather than the silent "kept dir vanished
            # anyway" surprise.
            typer.echo(
                "--keep-workdir requires --work-dir; the default temp "
                "directory is auto-deleted regardless of this flag.",
                err=True,
            )
            raise typer.Exit(code=2)
        tmp_ctx = tempfile.TemporaryDirectory(prefix="cve-diff-")
        work = Path(tmp_ctx.name)
    else:
        work_dir.mkdir(parents=True, exist_ok=True)
        work = work_dir

    if not quiet:
        api_status.print_to_stderr(api_status.render_startup_banner())

    progress_cb = None
    if not quiet:
        def progress_cb(stage: str, status: str, info: dict) -> None:
            kv = " ".join(f"{k}={v}" for k, v in info.items())
            typer.echo(f"  · {stage:<16} {status:<8} {kv}", err=True)

    # Track the most-recent Pipeline so the except handlers can read
    # agent telemetry off it for `<cve>.flow.{jsonl,md}` emission. A
    # single-element list is the simplest closure-friendly mutable slot.
    pipeline_slot: list[Pipeline | None] = [None]

    try:
        budget_multiplier = 1.0
        try:
            while True:
                try:
                    pipeline_slot[0] = Pipeline(
                        disk_limit_pct=disk_limit_pct,
                        max_file_bytes=max_file_bytes,
                        progress_callback=progress_cb,
                        agent_budget_multiplier=budget_multiplier,
                    )
                    result = pipeline_slot[0].run(cve_id, work)
                    break
                except DiscoveryError as exc:
                    reason = _budget_reason(str(exc))
                    if reason and sys.stdin.isatty():
                        new_mult = budget_multiplier * 2
                        typer.echo("", err=True)
                        typer.echo(
                            f"agent reached its budget cap ({reason}) at "
                            f"{budget_multiplier}× default.",
                            err=True,
                        )
                        if typer.confirm(
                            f"  extend to {new_mult}× and continue?",
                            default=False,
                        ):
                            budget_multiplier = new_mult
                            typer.echo(
                                f"  retrying with {new_mult}× budget …",
                                err=True,
                            )
                            continue
                    raise
        except UnsupportedSource as exc:
            typer.echo(f"unsupported source: {exc}", err=True)
            typer.echo(
                "hint: this CVE points at a closed-source vendor; cve-diff only handles OSS.",
                err=True,
            )
            _write_failure_md(output_dir, cve_id, "UnsupportedSource",
                              f"UnsupportedSource: {exc}")
            if pipeline_slot[0] is not None:
                _flow_from_pipeline(output_dir, cve_id, pipeline_slot[0],
                                    ok=False, error_class="UnsupportedSource")
            _echo_flow_md(output_dir, cve_id, quiet)
            raise typer.Exit(code=4) from exc
        except DiscoveryError as exc:
            typer.echo(f"discovery failed: {exc}", err=True)
            typer.echo(
                "hint: verify the CVE id, check OSV at https://api.osv.dev/v1/vulns/"
                f"{cve_id}, or set GITHUB_TOKEN if rate-limited.",
                err=True,
            )
            _write_failure_md(output_dir, cve_id,
                              _classify_discovery(str(exc)),
                              f"DiscoveryError: {exc}")
            if pipeline_slot[0] is not None:
                _flow_from_pipeline(output_dir, cve_id, pipeline_slot[0],
                                    ok=False,
                                    error_class=_classify_discovery(str(exc)))
            _echo_flow_md(output_dir, cve_id, quiet)
            raise typer.Exit(code=5) from exc
        except AcquisitionError as exc:
            typer.echo(f"acquisition failed: {exc}", err=True)
            typer.echo(
                "hint: check network / proxy; the discovered repo may have been renamed "
                "or made private since the OSV record was published.",
                err=True,
            )
            _write_failure_md(output_dir, cve_id, "AcquisitionError",
                              f"AcquisitionError: {exc}")
            if pipeline_slot[0] is not None:
                _flow_from_pipeline(output_dir, cve_id, pipeline_slot[0],
                                    ok=False, error_class="AcquisitionError")
            _echo_flow_md(output_dir, cve_id, quiet)
            raise typer.Exit(code=6) from exc
        except IdenticalCommitsError as exc:
            typer.echo(f"identical commits: {exc}", err=True)
            typer.echo(
                "hint: OSV record's fix sha and its parent resolved to the same commit; "
                "the record likely names a tag rather than the fix commit.",
                err=True,
            )
            _write_failure_md(output_dir, cve_id, "IdenticalCommits",
                              f"IdenticalCommitsError: {exc}")
            if pipeline_slot[0] is not None:
                _flow_from_pipeline(output_dir, cve_id, pipeline_slot[0],
                                    ok=False, error_class="IdenticalCommitsError")
            _echo_flow_md(output_dir, cve_id, quiet)
            raise typer.Exit(code=7) from exc
        except AnalysisError as exc:
            typer.echo(f"analysis rejected: {exc}", err=True)
            typer.echo(
                "hint: the diff shape is notes_only — the agent picked a downstream "
                "mirror rather than the upstream fix. Re-run with verbose tracing to "
                "see which slug it chose.",
                err=True,
            )
            _write_failure_md(output_dir, cve_id, "AnalysisError",
                              f"AnalysisError: {exc}")
            if pipeline_slot[0] is not None:
                _flow_from_pipeline(output_dir, cve_id, pipeline_slot[0],
                                    ok=False, error_class="AnalysisError")
            _echo_flow_md(output_dir, cve_id, quiet)
            raise typer.Exit(code=9) from exc

        rc = None
        if with_root_cause:
            try:
                rc = RootCauseAnalyzer(model_id=model_id).analyze(result.bundle)
                typer.echo(
                    f"root cause: {rc.cwe_id} ({rc.vulnerability_type}) "
                    f"conf={rc.confidence:.2f} tokens={rc.input_tokens}+{rc.output_tokens}"
                )
            except (RootCauseAnalysisError, LLMCallFailed) as exc:
                typer.echo(f"root-cause analysis failed: {exc}", err=True)
                raise typer.Exit(code=9) from exc

        osv_path = output_dir / f"{cve_id}.osv.json"
        md_path = output_dir / f"{cve_id}.md"
        osv_path.write_text(
            json.dumps(osv_schema.render(result.bundle, root_cause=rc), indent=2) + "\n"
        )
        md_path.write_text(markdown.render(result.bundle, root_cause=rc))
        if pipeline_slot[0] is not None:
            _flow_from_pipeline(output_dir, cve_id, pipeline_slot[0],
                                ok=True, error_class="PASS",
                                pipeline_result=result)
        # Write each extraction method's raw diff body as a separate
        # `.patch` file so a user can compare clone vs every other
        # source whenever the agreement verdict is majority_agree /
        # partial / disagree. Up to 3 files: clone + JSON API + patch
        # URL.
        extras_bundles = getattr(
            pipeline_slot[0], "_last_extra_bundles", []
        ) if pipeline_slot[0] else []
        write_outcome_patches(
            output_dir, cve_id,
            clone_diff_text=result.bundle.diff_text,
            extras=[(method, b.diff_text) for method, b in extras_bundles
                    if b.diff_text],
        )
        flow_jsonl_path = output_dir / f"{cve_id}.flow.jsonl"
        flow_md_path = output_dir / f"{cve_id}.flow.md"
        clone_patch_path = output_dir / f"{cve_id}.clone.patch"
        # Native end-of-run report: print the rich pipeline trace to
        # stdout so the user sees the report without `cat`-ing
        # flow.md. _echo_flow_md ends with the "=== Artifacts ===" divider
        # that flows naturally into the file-path lines below.
        _echo_flow_md(output_dir, cve_id, quiet)
        typer.echo(f"wrote {osv_path}")
        typer.echo(f"wrote {md_path}")
        if flow_jsonl_path.exists():
            typer.echo(f"wrote {flow_jsonl_path}")
            typer.echo(f"wrote {flow_md_path}")
        if clone_patch_path.exists():
            typer.echo(f"wrote {clone_patch_path}")
        # Echo each second-source `.patch` file (github_api / gitlab_api /
        # patch_url) that landed.
        for method, _b in extras_bundles:
            extra_path = output_dir / f"{cve_id}.{method}.patch"
            if extra_path.exists():
                typer.echo(f"wrote {extra_path}")
        if not quiet:
            api_status.print_to_stderr(api_status.render_rate_limit_summary())
    finally:
        if tmp_ctx is not None and not keep_workdir:
            tmp_ctx.cleanup()


app.command(name="bench")(_bench_cmd)


@app.command()
def health() -> None:
    """Probe each external service the pipeline depends on.

    Reports per-service: reachable / latency / rate-limit hint.
    Exits 0 if all CRITICAL probes pass; exit 1 otherwise.

    Run before a long bench to catch outages early. Run mid-bench
    if a worker is hanging to identify which service is degraded.
    """
    from cve_diff.infra import service_health

    results = service_health.run_all()
    typer.echo(service_health.render_table(results))
    if service_health.has_critical_failure(results):
        raise typer.Exit(code=1)
