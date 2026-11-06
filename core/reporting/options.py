"""Common opt-in report controls; human summaries are independent."""
from __future__ import annotations

import argparse
import re
from dataclasses import dataclass, replace
from pathlib import Path

from .renderers import get_renderer


@dataclass(frozen=True)
class ReportOptions:
    formats: tuple[str, ...] = ("markdown",)
    output: Path | None = None
    enabled: bool = True
    # Compatibility for explicit filename options such as SCA's --out-md.
    # The common --report-output option keeps its extension-based contract.
    output_is_file: bool = False
    filenames: tuple[tuple[str, str], ...] = ()

    def validate(self) -> ReportOptions:
        if not self.formats:
            raise ValueError("At least one report format is required")
        formats = tuple(dict.fromkeys(get_renderer(name).name for name in self.formats))
        overrides = {}
        for format_name, filename in self.filenames:
            format_name = get_renderer(format_name).name
            if (format_name in overrides or not isinstance(filename, str)
                    or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,100}", filename)
                    or not filename.endswith(get_renderer(format_name).extension)):
                raise ValueError("Invalid or duplicate report filename override")
            overrides[format_name] = filename
        if self.output_is_file:
            if self.output is None or self.output.is_dir() or len(formats) != 1:
                raise ValueError("An explicit report filename requires one format and a file destination")
        if self.output and len(formats) > 1 and self.output.suffix and not self.output.is_dir():
            raise ValueError("Multiple report formats require a directory destination")
        if not self.output_is_file and self.output and self.output.suffix and not self.output.is_dir() and len(formats) == 1:
            if self.output.suffix != get_renderer(formats[0]).extension:
                raise ValueError("Report filename extension does not match its format")
        filenames = tuple(overrides.items())
        return replace(self, formats=formats, filenames=filenames) if (formats != self.formats or filenames != self.filenames) else self


def add_report_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--report-format", action="append", metavar="FORMAT", help="Report format (markdown, json, html, xml); repeat for multiple outputs")
    parser.add_argument("--report-output", type=Path, metavar="PATH", help="Report file (one format) or directory")
    parser.add_argument("--no-report", action="store_true", help="Disable full report files; keep the operator summary and evidence")


def options_from_args(args: argparse.Namespace, parser: argparse.ArgumentParser | None = None) -> ReportOptions:
    try:
        if getattr(args, "no_report", False) and (getattr(args, "report_format", None) or getattr(args, "report_output", None)):
            raise ValueError("--no-report conflicts with --report-format/--report-output")
        return ReportOptions(tuple(dict.fromkeys(getattr(args, "report_format", None) or ["markdown"])),
                             getattr(args, "report_output", None), not getattr(args, "no_report", False)).validate()
    except ValueError as exc:
        if parser:
            parser.error(str(exc))
        raise
