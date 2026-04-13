"""Project report — merged view across all runs."""

from typing import Any, Dict


def generate_project_report(project) -> Dict[str, Any]:
    """Generate a merged report across all runs in _report/ directory.

    Non-destructive — runs preserved.
    """
    from core.project.merge import merge_findings
    from core.json import save_json

    report_dir = project.output_path / "_report"
    report_dir.mkdir(parents=True, exist_ok=True)

    run_dirs = project.get_run_dirs(sweep=True)
    if not run_dirs:
        return {"findings": 0, "runs": 0}

    # Merge findings
    merged = merge_findings(run_dirs)
    save_json(report_dir / "findings.json", {"findings": merged})

    return {
        "findings": len(merged),
        "runs": len(run_dirs),
        "report_dir": str(report_dir),
    }
