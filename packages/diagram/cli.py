"""Operator diagram rendering; native output and optional portable companions."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Sequence

from core.reporting.options import add_report_arguments, options_from_args
from core.security.log_sanitisation import sanitise_for_terminal


_MAX_CAPTURE_SOURCES = 1000

_USAGE = "Usage: raptor-render-diagrams <output_dir> [--target <name>] [--force] [--stdout] [--report-format FORMAT] [--report-output PATH] [--no-report]"


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(_USAGE, file=sys.stderr)
        return 1
    out_dir = Path(argv[0])
    force = "--force" in argv
    stdout = "--stdout" in argv
    target = None
    if "--target" in argv:
        idx = argv.index("--target")
        if idx + 1 >= len(argv):
            print("ERROR: --target requires a value (e.g. --target my-app)", file=sys.stderr)
            return 1
        target = argv[idx + 1]
        if target.startswith("--"):
            print(f"ERROR: --target value {sanitise_for_terminal(repr(target), max_len=300)} looks like a flag; --target requires a non-flag value", file=sys.stderr)
            return 1
    parser = argparse.ArgumentParser(prog="raptor-render-diagrams", add_help=False)
    add_report_arguments(parser)
    report_args, _ = parser.parse_known_args(argv[1:])
    report_args._report_options = options_from_args(report_args, parser)
    if not out_dir.exists():
        print(f"ERROR: directory not found: {sanitise_for_terminal(str(out_dir))}", file=sys.stderr)
        return 1
    default_out = out_dir / "diagrams.md"
    if default_out.exists() and not force and not stdout:
        print(f"ERROR: {sanitise_for_terminal(str(default_out))} already exists. Pass --force to overwrite.", file=sys.stderr)
        return 1
    try:
        from .renderer import render_and_write, render_directory
        selected = bool(report_args.report_format or report_args.report_output)
        sources: list[Path] = []
        seen_sources: set[Path] = set()
        report_args._source_capture_complete = True
        def capture_source(path: Path) -> None:
            if path in seen_sources:
                return
            if len(sources) >= _MAX_CAPTURE_SOURCES:
                report_args._source_capture_complete = False
                return
            seen_sources.add(path)
            sources.append(path)
        captured: list[str] = []
        if stdout:
            if selected:
                content = render_directory(out_dir, target=target, source_observer=capture_source)
            else:
                content = render_directory(out_dir, target=target)
            captured.append(content)
            print(content, end="")
        else:
            if selected:
                output = render_and_write(out_dir, target=target, source_observer=capture_source, rendered_observer=captured.append)
            else:
                output = render_and_write(out_dir, target=target, rendered_observer=captured.append)
            print(f"Diagrams: {sanitise_for_terminal(str(output))}")
    except Exception as exc:  # native renderer failures retain the existing CLI status
        print(f"Diagram error: {sanitise_for_terminal(str(exc))}", file=sys.stderr)
        return 1
    diagram_count = captured[0].count("```mermaid\n") if captured else None
    if not selected and diagram_count is not None:
        print(f"Diagrams rendered: {diagram_count}", file=sys.stderr)
    from .cli_reporting import complete_diagram_report
    result = complete_diagram_report(report_args, captured[0] if captured else None, out_dir, target, sources)
    if selected and result is None and diagram_count is not None:
        print(f"Diagrams rendered: {diagram_count}", file=sys.stderr)
    return 0
