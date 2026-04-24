"""Enumerate exploits, patches, reports, and activity across a project's runs.

Raptor writes artifacts into well-known subdirectories of each run:

    <run>/exploits/                 # source-analysis PoCs
    <run>/patches/                  # source-analysis fixes
    <run>/analysis/exploits/        # fuzzing PoCs (C code)
    <run>/*.md                      # markdown reports (validation-report.md, …)
    <run>/logs/*.jsonl              # structured logs
    <project_output>/logs/*.jsonl   # cross-run logs

This reader walks those locations best-effort. Missing directories are skipped.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


@dataclass
class Artifact:
    filename: str
    path: Path
    run_name: str
    size_bytes: int
    modified: str  # ISO-ish string


_EXPLOIT_SUBDIRS = ("exploits", "analysis/exploits")
_PATCH_SUBDIRS = ("patches",)
_REPORT_SUFFIXES = (".md",)
_REPORT_FILENAMES = ("validation-report.md", "codeql_report.md", "fuzzing_report.md", "raptor_agentic_report.md")


def _collect_files(
    dirs: Iterable[Path],
    extensions: tuple[str, ...] = (),
    names: tuple[str, ...] = (),
    run_name: str = "",
) -> list[Artifact]:
    out: list[Artifact] = []
    for d in dirs:
        if not d.is_dir():
            continue
        for f in sorted(d.iterdir()):
            if not f.is_file():
                continue
            if extensions and not any(f.name.endswith(ext) for ext in extensions):
                if not names or f.name not in names:
                    continue
            try:
                stat = f.stat()
                mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
                out.append(Artifact(
                    filename=f.name,
                    path=f,
                    run_name=run_name,
                    size_bytes=stat.st_size,
                    modified=mtime,
                ))
            except OSError:
                continue
    return out


def list_exploits(project) -> list[Artifact]:
    out: list[Artifact] = []
    for run in project.runs():
        dirs = [run.directory / sub for sub in _EXPLOIT_SUBDIRS]
        out.extend(_collect_files(dirs, run_name=run.name))
    # Newest first
    out.sort(key=lambda a: a.modified, reverse=True)
    return out


def list_patches(project) -> list[Artifact]:
    out: list[Artifact] = []
    for run in project.runs():
        dirs = [run.directory / sub for sub in _PATCH_SUBDIRS]
        out.extend(_collect_files(dirs, run_name=run.name))
    out.sort(key=lambda a: a.modified, reverse=True)
    return out


def list_reports(project) -> list[Artifact]:
    out: list[Artifact] = []
    for run in project.runs():
        # Markdown files directly in the run dir, and anything in _REPORT_FILENAMES.
        out.extend(_collect_files(
            [run.directory],
            extensions=_REPORT_SUFFIXES,
            names=_REPORT_FILENAMES,
            run_name=run.name,
        ))
    out.sort(key=lambda a: a.modified, reverse=True)
    return out


@dataclass
class LogEntry:
    timestamp: str
    level: str
    message: str
    run: str = ""


def tail_activity(project, limit: int = 200) -> list[LogEntry]:
    """Tail the JSONL audit log across a project's logs directory.

    Looks under <project.output_dir>/logs/ and each run's logs/ subdir.
    """
    files: list[tuple[Path, str]] = []  # (path, run_name)

    if project.output_dir.is_dir():
        main_logs = project.output_dir / "logs"
        if main_logs.is_dir():
            for f in main_logs.glob("*.jsonl"):
                files.append((f, ""))

    for run in project.runs():
        run_logs = run.directory / "logs"
        if run_logs.is_dir():
            for f in run_logs.glob("*.jsonl"):
                files.append((f, run.name))

    entries: list[LogEntry] = []
    for path, run_name in files:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            continue
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            entries.append(LogEntry(
                timestamp=str(data.get("timestamp", ""))[:23],
                level=str(data.get("level", "INFO")).upper(),
                message=str(data.get("message", "")),
                run=run_name,
            ))

    entries.sort(key=lambda e: e.timestamp, reverse=True)
    return entries[:limit]
