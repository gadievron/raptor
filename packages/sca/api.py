"""Programmatic API for the SCA pipeline.

Thin wrapper over :func:`pipeline.run_sca` that returns a structured
result dict suitable for JSON serialisation or direct consumption by
the ``/agentic`` orchestrator. Callers that need full control should
call :func:`pipeline.run_sca` directly.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from .pipeline import RunOptions, RunResult, run_sca

logger = logging.getLogger(__name__)


def analyse(
    target: Path,
    output_dir: Path,
    *,
    offline: bool = False,
    no_cache: bool = False,
    sarif_dirs: Optional[List[Path]] = None,
) -> Dict[str, Any]:
    """Run the full SCA pipeline and return a summary dict.

    Parameters
    ----------
    target:
        Root of the project to scan.
    output_dir:
        Where to write findings.json, report.md, sbom, sarif.
    offline:
        Skip all network calls.
    no_cache:
        Ignore cached data.
    sarif_dirs:
        Sibling SARIF directories from other tools (Semgrep, CodeQL).
        When provided, cross-tool ``related_findings`` linking is
        performed after the SCA run completes.

    Returns a dict with keys: ``status``, ``findings_path``,
    ``sarif_path``, ``vuln_findings``, ``hygiene_findings``,
    ``supply_chain_findings``, ``deps_analysed``, ``llm_cost``.
    """
    options = RunOptions(offline=offline, no_cache=no_cache)

    try:
        result = run_sca(
            target=Path(target).resolve(),
            output_dir=Path(output_dir),
            options=options,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("sca.api.analyse failed: %s", exc, exc_info=True)
        return {"status": "error", "error": str(exc)}

    if sarif_dirs:
        try:
            from .cross_tool import link_related_findings
            link_related_findings(
                sca_findings_path=result.findings_path,
                sarif_dirs=sarif_dirs,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("sca.api: cross-tool linking failed: %s", exc)

    return _summarise(result)


def _summarise(result: RunResult) -> Dict[str, Any]:
    return {
        "status": "ok",
        "findings_path": str(result.findings_path),
        "sarif_path": str(result.sarif_path),
        "report_path": str(result.report_path),
        "sbom_path": str(result.sbom_path),
        "vuln_findings": result.vuln_findings,
        "hygiene_findings": result.hygiene_findings,
        "supply_chain_findings": result.supply_chain_findings,
        "deps_analysed": result.deps_analysed,
        "suppressed_findings": result.suppressed_findings,
        "in_kev": result.in_kev,
        "llm_cost": result.llm_cost,
    }
