"""LLM review of inline install files for missed package installs.

The mechanical ``inline_installs`` parser covers common managers
(pip, apt, yum, dnf, apk, npm, cargo, gem, brew, go) across
Dockerfile, devcontainer.json, shell scripts, and GHA workflows.

This LLM stage catches what the mechanical parser misses:
variable-expanded installs, uncommon managers, curl-pipe-bash,
Makefile recipes, and creative shell patterns.

**Mechanical override:** anything the mechanical parser found is
authoritative.  The LLM cannot remove or change mechanical results.
LLM-found installs carry ``parser_confidence="low"`` and
``source_kind="llm_inline_review"``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

from core.llm.task_types import TaskType
from ..models import Confidence, Dependency, PinStyle
from . import (
    StageResult,
    TaintedString,
    UntrustedBlock,
    run_stage,
)
from .prompts import INLINE_INSTALL_SYSTEM
from .schemas import InlineInstallVerdict

logger = logging.getLogger(__name__)

_MAX_FILE_CHARS = 50_000


def review_inline_installs(
    client,
    file_path: Path,
    file_content: str,
    mechanical_deps: List[Dependency],
    source_kind: str,
) -> List[Dependency]:
    """Ask the LLM to find package installs the mechanical parser missed.

    Args:
        client: LLMClient instance.
        file_path: Path to the file being reviewed.
        file_content: The file's text content.
        mechanical_deps: Dependencies already found by the mechanical parser.
        source_kind: One of 'dockerfile', 'devcontainer', 'shell_script',
            'gha_workflow'.

    Returns:
        List of Dependency objects for installs the LLM found that were
        not in ``mechanical_deps``.  Each has ``parser_confidence="low"``
        and ``source_kind="llm_inline_review"``.
    """
    if not file_content.strip():
        return []

    content = file_content[:_MAX_FILE_CHARS]

    mechanical_names = {(d.ecosystem, d.name) for d in mechanical_deps}
    mechanical_summary = "\n".join(
        f"  - {d.ecosystem}/{d.name}@{d.version or '?'}"
        for d in mechanical_deps[:50]
    ) or "  (none found)"

    user_content = (
        f"File: {file_path}\n"
        f"Type: {source_kind}\n\n"
        f"Mechanical parser already found:\n{mechanical_summary}\n\n"
        f"File content:\n{content}"
    )

    result: StageResult = run_stage(
        client=client,
        system=INLINE_INSTALL_SYSTEM,
        untrusted_blocks=(
            UntrustedBlock(
                content=user_content,
                kind="INLINE_INSTALL_FILE",
                origin=f"{source_kind} {file_path}",
            ),
        ),
        slots={
            "file_type": TaintedString(value=source_kind, trust="trusted"),
        },
        schema_cls=InlineInstallVerdict,
        task_type=TaskType.ANALYSE,
    )

    if result.error or result.model is None:
        logger.debug("sca.llm.inline_install_review: %s failed: %s",
                      file_path, result.error)
        return []

    verdict: InlineInstallVerdict = result.model  # type: ignore[assignment]
    if result.preflight_hit and verdict.confidence == "high":
        verdict = verdict.model_copy(update={"confidence": "medium"})

    new_deps: List[Dependency] = []
    for item in verdict.missed_installs:
        if (item.ecosystem, item.name) in mechanical_names:
            continue

        eco_lower = item.ecosystem.lower().replace("pypi", "pypi")
        purl = f"pkg:{eco_lower}/{item.name}"
        if item.version:
            purl += f"@{item.version}"
        dep = Dependency(
            ecosystem=item.ecosystem,
            name=item.name,
            version=item.version,
            declared_in=file_path,
            scope="main",
            is_lockfile=False,
            pin_style=PinStyle.UNKNOWN,
            direct=True,
            purl=purl,
            source_kind="llm_inline_review",
            parser_confidence=Confidence(
                level="low",
                reason=f"LLM-extracted via {item.manager_used}; not mechanically parseable",
            ),
        )
        new_deps.append(dep)

    return new_deps
