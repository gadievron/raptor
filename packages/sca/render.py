"""``/sca render`` — re-emit report.md + findings.sarif from an existing
``findings.json`` without re-running the network pipeline.

Use cases:

- Operator hand-edited ``findings.json`` (added suppressions, dropped
  false positives) and wants a fresh report without re-querying OSV.
- A dashboard wants SARIF after an older analyse run that only kept
  ``findings.json``.
- CI wants to render against a pinned baseline file.

Inputs: ``findings.json``. Outputs (default): ``report.md`` and
``findings.sarif`` next to the input. Override paths with
``--out-md`` / ``--out-sarif`` or skip with ``--no-md`` / ``--no-sarif``.

Limitation: SBOM regeneration is **not** supported. The CycloneDX
emitter needs the resolved-dependency set (with parser confidence,
transitive depth, etc.) which isn't fully recoverable from the row
shape — re-run ``raptor-sca`` if a fresh SBOM is needed.
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import Any, TYPE_CHECKING

from .rows import FindingRow
from .sarif import write_sarif

from core.json import load_json
from core.reporting.options import ReportOptions, add_report_arguments, options_from_args
from core.security.log_sanitisation import sanitise_for_terminal as _sft

# findings.json artifacts are RAPTOR-written run output — the
# findings-class budget.
_MAX_FINDINGS_BYTES = 64 * 1024 * 1024

if TYPE_CHECKING:
    from collections.abc import Sequence

logger = logging.getLogger(__name__)


def main(argv: Sequence[str]) -> int:
    from .cli import _configure_logging

    args = _parse_args(argv)
    _configure_logging(args.verbose)

    findings_path = Path(args.findings).resolve()
    if not findings_path.exists():
        print(f"raptor-sca render: findings file not found: {_sft(str(findings_path))}",
              file=sys.stderr)
        return 2
    try:
        rows = load_json(
            findings_path, strict=True, max_bytes=_MAX_FINDINGS_BYTES,
        )
        if rows is None:
            # Strict load_json soft-returns None for a missing file.
            raise FileNotFoundError(findings_path)
    except (OSError, ValueError) as e:
        print(f"raptor-sca render: cannot read {_sft(str(findings_path))}: {_sft(str(e))}", file=sys.stderr)
        return 2
    if not isinstance(rows, list):
        print(f"raptor-sca render: {_sft(str(findings_path))} is not a finding list",
              file=sys.stderr)
        return 2

    base_dir = findings_path.parent
    sarif_path = Path(args.out_sarif).resolve() if args.out_sarif else (
        base_dir / "findings.sarif"
    )
    options = args.report_options
    report_destinations = []
    if options.enabled:
        from core.reporting.renderers import get_renderer
        for format in options.formats:
            output = options.output
            report_destinations.append((output if output and (options.output_is_file or output.suffix and not output.is_dir()) else (output or base_dir) / ("report" + get_renderer(format).extension)).resolve())
    if findings_path in report_destinations or (not args.no_sarif and (sarif_path == findings_path or sarif_path in report_destinations)):
        print("raptor-sca render: input, SARIF and report destinations must be distinct", file=sys.stderr)
        return 2
    if not args.no_sarif and (sarif_path.name in {"report-context.json", "report-document.json", "reporting-manifest.json", "summary.json", "summary.md", ".raptor-run.json", ".raptor-imported.json"}
                              or any(parent.name == ".reporting" for parent in sarif_path.parents)):
        print("raptor-sca render: SARIF output cannot replace reporting or lifecycle state", file=sys.stderr)
        return 2
    if args.no_md and args.no_sarif and not (args.report_format or args.report_output or args.no_report):
        print("raptor-sca render: nothing to do (both --no-md and --no-sarif supplied)", file=sys.stderr)
        return 2
    all_rows = rows
    try:
        rows = _apply_reachability_filters(rows, args)
    except ValueError as e:
        print(f"raptor-sca render: {_sft(str(e))}", file=sys.stderr)
        return 2

    target = Path(args.target).resolve() if args.target else base_dir
    wrote: list[str] = []
    sarif_errors = []
    if not args.no_sarif:
        try:
            write_sarif(sarif_path, target=target, rows=rows)
            wrote.append(f"findings.sarif → {sarif_path}")
        except (OSError, ValueError) as exc:
            print(f"raptor-sca render: SARIF write failed: {_sft(str(exc))}", file=sys.stderr)
            sarif_errors.append("SARIF export failed; the operator summary and requested reports are generated independently.")
    from .reporting import build_sca_document
    from core.reporting.service import complete_reporting
    try:
        context, document = build_sca_document(rows=rows, target=target, output_dir=base_dir,
                                               deps_analysed=None, cache_hits=None, cache_misses=None, rerender=True,
                                               artifacts=[{"path": str(findings_path)}, {"path": str(sarif_path)}],
                                               limitations=sarif_errors,
                                               selection={"source_rows": len(all_rows), "selected_rows": len(rows),
                                                 "reachability": args.reachability, "only_reachable": args.only_reachable,
                                                 "hide_not_reachable": args.hide_not_reachable})
        result = complete_reporting(context, base_dir, document=document, options=options, stream=sys.stdout)
    except (OSError, ValueError, TypeError) as exc:
        print(f"raptor-sca render: report failed: {_sft(str(exc))}", file=sys.stderr)
        return 1
    if result.publication:
        wrote.extend(f"{format} → {path}" for format, path in result.publication.outputs.items())
    if wrote:
        sys.stdout.write("raptor-sca render: wrote " + _sft("; ".join(wrote), max_len=4000) + "\n")
    sys.stdout.flush()

    # CI-gate threshold evaluation — only fires when --fail-on-* set.
    from .thresholds import (
        cfg_from_args, evaluate as eval_thresholds, print_result,
    )
    cfg = cfg_from_args(args)
    if cfg.is_active:
        try:
            passed, fails = eval_thresholds(all_rows, cfg)
        except ValueError as error:
            print("raptor-sca render: " + _sft(str(error)), file=sys.stderr)
            return 2
        print_result(passed, fails, prog="raptor-sca render")
        return 0 if passed and not result.errors and not sarif_errors else 1

    return 1 if result.errors or sarif_errors else 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _parse_args(argv: Sequence[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="raptor-sca render",
        description="Re-emit report.md + findings.sarif from an existing "
                    "findings.json without rerunning the network pipeline.",
    )
    p.add_argument("findings",
                   help="path to findings.json from a prior `raptor-sca` run")
    p.add_argument("--out-md", help="output path for the markdown report "
                                     "(default: alongside findings.json)")
    p.add_argument("--out-sarif", help="output path for findings.sarif")
    p.add_argument("--no-md", action="store_true",
                   help="skip the markdown report")
    p.add_argument("--no-sarif", action="store_true",
                   help="skip the SARIF emission")
    p.add_argument("--target",
                   help="target root used to relativise SARIF artefact URIs "
                        "(default: parent of findings.json)")
    p.add_argument("--only-reachable", action="store_true",
                   help="render only vulnerable dependency findings whose "
                        "reachability is likely_called or imported. "
                        "Non-vulnerability SCA rows are preserved.")
    p.add_argument("--hide-not-reachable", action="store_true",
                   help="hide vulnerable dependency findings whose "
                        "reachability is not_reachable or "
                        "not_function_reachable. Non-vulnerability SCA rows "
                        "are preserved.")
    p.add_argument("--reachability",
                   help="comma-separated reachability verdict allowlist for "
                        "vulnerable dependency findings, e.g. "
                        "likely_called,imported,not_evaluated. "
                        "Non-vulnerability SCA rows are preserved.")
    # CI gate flags — exit 1 if findings exceed thresholds.
    from .thresholds import add_threshold_args
    add_threshold_args(p)
    p.add_argument("-v", "--verbose", action="count", default=0)
    add_report_arguments(p)
    args = p.parse_args(argv)
    options = options_from_args(args, p)
    if args.out_md and (args.no_md or args.no_report or args.report_output or options.formats != ("markdown",)):
        p.error("--out-md requires Markdown output and conflicts with --no-md, --no-report, or --report-output")
    if args.no_md and args.report_format and "markdown" in options.formats:
        p.error("--no-md conflicts with requested Markdown output")
    if args.no_md and args.report_output and not args.report_format:
        p.error("--no-md with --report-output requires an explicit non-Markdown --report-format")
    try:
        args.report_options = ReportOptions(options.formats, Path(args.out_md) if args.out_md else options.output,
                                            options.enabled and not (args.no_md and not args.report_format),
                                            output_is_file=bool(args.out_md)).validate()
    except ValueError as exc:
        p.error(str(exc))
    return args


_REACHABLE_VERDICTS = {"likely_called", "imported"}
_NOT_REACHABLE_VERDICTS = {"not_reachable", "not_function_reachable"}


def _apply_reachability_filters(
    rows: list[dict[str, Any]], args: argparse.Namespace,
) -> list[dict[str, Any]]:
    """Filter vuln rows by reachability while preserving other rows."""
    requested = []
    if args.only_reachable:
        requested.append("--only-reachable")
    if args.hide_not_reachable:
        requested.append("--hide-not-reachable")
    if args.reachability:
        requested.append("--reachability")
    if len(requested) > 1:
        raise ValueError(
            "reachability filters are mutually exclusive: "
            + ", ".join(requested)
        )

    allowed = None
    denied = None
    if args.only_reachable:
        allowed = set(_REACHABLE_VERDICTS)
    elif args.hide_not_reachable:
        denied = set(_NOT_REACHABLE_VERDICTS)
    elif args.reachability:
        allowed = {
            item.strip()
            for item in str(args.reachability).split(",")
            if item.strip()
        }
        if not allowed:
            msg = "--reachability needs at least one verdict"
            raise ValueError(msg)

    if allowed is None and denied is None:
        return rows

    out: list[dict[str, Any]] = []
    for row in rows:
        fr = FindingRow.from_row(row)
        if fr is None or not fr.is_vulnerable_dependency:
            # Non-vulnerability rows (and stray non-dict elements in a
            # hand-edited findings.json) pass through untouched; the
            # renderers and the SARIF emitter each skip malformed
            # entries defensively.
            out.append(row)
            continue
        verdict = fr.reachability_verdict
        if allowed is not None and verdict not in allowed:
            continue
        if denied is not None and verdict in denied:
            continue
        out.append(row)
    return out


# ---------------------------------------------------------------------------
# Row-shaped markdown renderer
# ---------------------------------------------------------------------------

def _render_markdown(rows: list[dict[str, Any]], *, target: Path) -> str:
    """Compatibility API over the same portable builder used by scan."""
    from .reporting import build_sca_document
    from core.reporting.renderers import render_document
    _, document = build_sca_document(rows=rows, target=target, output_dir=target,
                                      deps_analysed=None, cache_hits=None, cache_misses=None, rerender=True)
    return render_document(document).content.decode("utf-8")


__all__ = ["main"]
