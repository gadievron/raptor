"""CodeQL tool runner for the IRIS refinement loop.

Adapts ``compile_codeql_config`` → temp QL pack → ``run_custom_queries``
→ SARIF parse → ``RefinementFeedback``.  Plugs into ``refine_loop``'s
``tool_runner`` slot alongside (or instead of) the Joern runner.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any

from core.run.scratch import scratch_dir

from .refine import RefinementFeedback
from .specs import TaintSpec, compile_codeql_config

logger = logging.getLogger(__name__)

_QLPACK_TEMPLATE = """\
name: raptor/iris-refinement
version: 0.0.1
dependencies:
  codeql/{lang}-all: "*"
"""


def _write_temp_pack(
    query_text: str,
    language: str,
    tmp_root: Path,
) -> Path:
    """Write a temporary QL pack containing the generated query."""
    pack_dir = tmp_root / "iris-pack"
    pack_dir.mkdir(parents=True, exist_ok=True)
    (pack_dir / "qlpack.yml").write_text(
        _QLPACK_TEMPLATE.replace("{lang}", language),
    )
    (pack_dir / "IrisSpecs.ql").write_text(query_text)
    return pack_dir


def _parse_sarif_matches(sarif_path: Path) -> list[dict[str, Any]]:
    """Extract match records from a SARIF file."""
    try:
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    matches = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            for loc in result.get("locations", []):
                phys = loc.get("physicalLocation", {})
                art = phys.get("artifactLocation", {})
                region = phys.get("region", {})
                matches.append({
                    "file": art.get("uri", ""),
                    "line": region.get("startLine", 0),
                    "message": result.get("message", {}).get("text", ""),
                    "rule_id": result.get("ruleId", ""),
                })
    return matches


def _match_to_spec_key(match: dict, specs: list[TaintSpec]) -> str | None:
    """Map a CodeQL match back to the spec that produced it."""
    msg = match.get("message", "")
    for spec in specs:
        if re.search(r'\b' + re.escape(spec.function) + r'\b', msg):
            return f"{spec.function}:{spec.file}:{spec.role}"
    return None


def make_codeql_tool_runner(
    db_path: Path,
    out_dir: Path,
    language: str = "cpp",
):
    """Build a ``ToolRunner`` callable for the IRIS refinement loop.

    Parameters
    ----------
    db_path:
        Path to a CodeQL database.
    out_dir:
        Output directory for SARIF results.
    language:
        Target language (``cpp``, ``python``, ``java``, etc.).

    Returns
    -------
    A callable ``(specs: list[TaintSpec]) -> RefinementFeedback``.
    Returns ``None`` if CodeQL CLI is not available.
    """
    try:
        from packages.codeql.query_runner import QueryRunner as CodeQLRunner
    except ImportError:
        logger.debug("CodeQL runner not importable")
        return None

    runner = CodeQLRunner()
    if not runner.is_available():
        logger.debug("CodeQL CLI not available for IRIS runner")
        return None

    if not db_path.is_dir():
        logger.debug("CodeQL database not found at %s", db_path)
        return None

    def _run(specs: list[TaintSpec]) -> RefinementFeedback:
        query_text = compile_codeql_config(specs, language=language)
        if not query_text.strip():
            return RefinementFeedback()

        with scratch_dir("raptor-iris-codeql-") as tmp_root:
            try:
                pack_dir = _write_temp_pack(query_text, language, tmp_root)
                result = runner.run_custom_queries(
                    database_path=db_path,
                    query_path=pack_dir,
                    out_dir=out_dir,
                    language=language,
                )

                if not result.success or not result.sarif_path:
                    return RefinementFeedback(
                        tool_errors=result.errors or ["codeql_analysis_failed"],
                    )

                matches = _parse_sarif_matches(result.sarif_path)
                confirmed_keys = []
                seen = set()
                for match in matches:
                    key = _match_to_spec_key(match, specs)
                    if key and key not in seen:
                        confirmed_keys.append(key)
                        seen.add(key)

                return RefinementFeedback(
                    confirmed_keys=confirmed_keys,
                )
            except Exception as exc:
                logger.debug("IRIS CodeQL runner failed: %s", exc, exc_info=True)
                return RefinementFeedback(tool_errors=[str(exc)])

    return _run
