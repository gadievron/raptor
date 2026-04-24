"""Parse raptor validation-run artifacts.

Validation runs (produced by /validate or the validation phase of /agentic)
write a rich set of JSON files:

    checklist.json         # ground-truth list of functions to analyze
    findings.json          # validated findings with Stages A–F
    attack-tree.json       # knowledge graph of attack surface
    hypotheses.json        # tested exploitation hypotheses
    disproven.json         # failed approaches (learning)
    attack-paths.json      # paths tried + PROXIMITY tracking
    attack-surface.json    # sources, sinks, trust boundaries
    validation-report.md   # human-readable summary

This reader loads them best-effort; missing files produce None.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ValidationBundle:
    run_dir: Path
    checklist: list | None = None
    findings: list | None = None
    attack_tree: dict | list | None = None
    hypotheses: list | None = None
    disproven: list | None = None
    attack_paths: list | None = None
    attack_surface: dict | None = None
    report_md: str | None = None

    @property
    def has_any(self) -> bool:
        return any([
            self.checklist, self.findings, self.attack_tree, self.hypotheses,
            self.disproven, self.attack_paths, self.attack_surface, self.report_md,
        ])

    @property
    def counts(self) -> dict:
        def _len(x):
            return len(x) if isinstance(x, (list, dict)) else 0
        return {
            "checklist":    _len(self.checklist),
            "findings":     _len(self.findings),
            "attack_tree":  _len(self.attack_tree),
            "hypotheses":   _len(self.hypotheses),
            "disproven":    _len(self.disproven),
            "attack_paths": _len(self.attack_paths),
        }


def _try_load_json(path: Path):
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text())
    except (json.JSONDecodeError, OSError):
        return None


def _try_read_text(path: Path) -> str | None:
    if not path.is_file():
        return None
    try:
        return path.read_text()
    except OSError:
        return None


def load_validation_bundle(run_dir: Path) -> ValidationBundle:
    return ValidationBundle(
        run_dir=run_dir,
        checklist=_try_load_json(run_dir / "checklist.json"),
        findings=_try_load_json(run_dir / "findings.json"),
        attack_tree=_try_load_json(run_dir / "attack-tree.json"),
        hypotheses=_try_load_json(run_dir / "hypotheses.json"),
        disproven=_try_load_json(run_dir / "disproven.json"),
        attack_paths=_try_load_json(run_dir / "attack-paths.json"),
        attack_surface=_try_load_json(run_dir / "attack-surface.json"),
        report_md=_try_read_text(run_dir / "validation-report.md"),
    )


@dataclass
class DataflowDiagram:
    """A CodeQL dataflow visualization pair: SVG + (optional) JSON."""
    name: str          # stem, e.g. "dataflow_sql_injection_user_query"
    svg_filename: str  # just the basename
    json_filename: str | None = None
    size_bytes: int = 0


@dataclass
class RunArtifactSummary:
    """Lightweight summary of a single run directory for the run-overview page."""
    has_sarif: bool = False
    sarif_files: list = field(default_factory=list)  # filenames
    has_findings_json: bool = False
    findings_count: int = 0
    has_scan_metrics: bool = False
    scan_metrics: dict | None = None
    has_exploits: bool = False
    exploits_count: int = 0
    has_patches: bool = False
    patches_count: int = 0
    has_reports: bool = False
    report_files: list = field(default_factory=list)
    has_validation_bundle: bool = False
    validation_counts: dict | None = None
    fuzzing_report: dict | None = None
    afl_crashes_count: int = 0
    dataflow_diagrams: list[DataflowDiagram] = field(default_factory=list)


def summarize_run(run_dir: Path) -> RunArtifactSummary:
    """Produce a lightweight artifact summary for a run-overview page."""
    from packages.studio.services.sarif_reader import scan_metrics

    summary = RunArtifactSummary()

    if run_dir.is_dir():
        sarif_files = sorted(run_dir.glob("*.sarif"))
        summary.has_sarif = bool(sarif_files)
        summary.sarif_files = [f.name for f in sarif_files]

        for fname in ("findings.json", "findings_validated.json", "findings_agentic.json", "findings_merged.json"):
            f = run_dir / fname
            if f.is_file():
                summary.has_findings_json = True
                try:
                    data = json.loads(f.read_text())
                    if isinstance(data, list):
                        summary.findings_count = len(data)
                    elif isinstance(data, dict):
                        for key in ("findings", "items", "results"):
                            if isinstance(data.get(key), list):
                                summary.findings_count = len(data[key])
                                break
                except (json.JSONDecodeError, OSError):
                    pass
                break

        metrics = scan_metrics(run_dir)
        summary.has_scan_metrics = metrics is not None
        summary.scan_metrics = metrics

        exp_dir = run_dir / "exploits"
        if exp_dir.is_dir():
            exp_files = [f for f in exp_dir.iterdir() if f.is_file()]
            summary.has_exploits = bool(exp_files)
            summary.exploits_count = len(exp_files)
        analysis_exp = run_dir / "analysis" / "exploits"
        if analysis_exp.is_dir():
            summary.has_exploits = True
            summary.exploits_count += len([f for f in analysis_exp.iterdir() if f.is_file()])

        patch_dir = run_dir / "patches"
        if patch_dir.is_dir():
            patches = [f for f in patch_dir.iterdir() if f.is_file()]
            summary.has_patches = bool(patches)
            summary.patches_count = len(patches)

        md_files = sorted(run_dir.glob("*.md"))
        summary.has_reports = bool(md_files)
        summary.report_files = [f.name for f in md_files]

        bundle = load_validation_bundle(run_dir)
        if bundle.has_any:
            summary.has_validation_bundle = True
            summary.validation_counts = bundle.counts

        fuzz_report = run_dir / "fuzzing_report.json"
        if fuzz_report.is_file():
            try:
                summary.fuzzing_report = json.loads(fuzz_report.read_text())
            except (json.JSONDecodeError, OSError):
                pass

        crashes_dir = run_dir / "afl_output" / "main" / "crashes"
        if crashes_dir.is_dir():
            summary.afl_crashes_count = sum(
                1 for f in crashes_dir.iterdir()
                if f.is_file() and f.name != "README.txt"
            )

        # CodeQL dataflow visualizations: pair dataflow_*.svg with its JSON.
        svg_files = sorted(run_dir.glob("dataflow_*.svg"))
        for svg in svg_files:
            json_pair = run_dir / (svg.stem + ".json")
            try:
                size = svg.stat().st_size
            except OSError:
                size = 0
            summary.dataflow_diagrams.append(DataflowDiagram(
                name=svg.stem,
                svg_filename=svg.name,
                json_filename=json_pair.name if json_pair.is_file() else None,
                size_bytes=size,
            ))

    return summary
