"""LLM review of binary files found in test directories.

The mechanical ``binary_in_tests`` detector flags non-text files in
``tests/``, ``test/``, ``__tests__/``, and ``fixtures/`` directories.
Many legitimate packages include binary test fixtures — this stage asks
the LLM to judge whether the binary's claimed purpose (per surrounding
test code) is plausible.

**Mechanical override:** the LLM verdict is additive signal.  A "benign"
LLM verdict does not suppress the mechanical ``binary_in_tests`` finding.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Optional

from core.llm.task_types import TaskType
from ..models import SupplyChainFinding
from . import (
    StageResult,
    TaintedString,
    UntrustedBlock,
    run_stage,
)
from .prompts import BINARY_IN_TESTS_SYSTEM
from .schemas import BinaryInTestsVerdict

logger = logging.getLogger(__name__)

_MAX_CONTEXT_CHARS = 50_000


def review_binary_in_tests(
    client,
    findings: List[SupplyChainFinding],
    target: Path,
) -> List[SupplyChainFinding]:
    """Enrich binary_in_tests findings with LLM plausibility assessment.

    Reads surrounding test files to provide context for the LLM's
    judgement.  Returns the same list with enriched findings.
    """
    bin_findings = [
        f for f in findings
        if f.kind == "binary_in_tests"
    ]
    if not bin_findings:
        return findings

    for finding in bin_findings:
        binary_path = finding.evidence.get("file_path", "")
        file_size = finding.evidence.get("file_size", 0)

        context = _gather_test_context(target, binary_path)

        verdict = _review_one(
            client, binary_path, file_size, context,
            finding.dependency.name, finding.dependency.ecosystem,
        )
        if verdict is None:
            continue

        finding.evidence["llm_binary_verdict"] = verdict.verdict
        finding.evidence["llm_binary_confidence"] = verdict.confidence
        finding.evidence["llm_binary_reasoning"] = verdict.reasoning
        if verdict.referenced_in_tests is not None:
            finding.evidence["llm_binary_referenced"] = verdict.referenced_in_tests

        if verdict.verdict == "suspicious":
            if finding.severity in ("info", "low"):
                finding.severity = "medium"
        elif verdict.verdict == "malicious":
            finding.severity = "high"

    return findings


def _review_one(
    client,
    binary_path: str,
    file_size: int,
    context: str,
    pkg_name: str,
    ecosystem: str,
) -> Optional[BinaryInTestsVerdict]:
    """Run the LLM on a single binary-in-tests finding."""
    content_parts = [
        f"Binary file: {binary_path}",
        f"Size: {file_size:,} bytes",
    ]
    if context:
        content_parts.append(f"\nSurrounding test code:\n{context}")
    else:
        content_parts.append("\nNo surrounding test code references this file.")

    result: StageResult = run_stage(
        client=client,
        system=BINARY_IN_TESTS_SYSTEM,
        untrusted_blocks=(
            UntrustedBlock(
                content="\n".join(content_parts),
                kind="BINARY_CONTEXT",
                origin=f"{ecosystem}/{pkg_name} test binary {binary_path}",
            ),
        ),
        slots={
            "package_name": TaintedString(value=pkg_name, trust="untrusted"),
            "ecosystem": TaintedString(value=ecosystem, trust="trusted"),
        },
        schema_cls=BinaryInTestsVerdict,
        task_type=TaskType.ANALYSE,
    )

    if result.error or result.model is None:
        logger.debug("sca.llm.binary_in_tests: %s/%s failed: %s",
                      ecosystem, pkg_name, result.error)
        return None

    verdict: BinaryInTestsVerdict = result.model  # type: ignore[assignment]
    if result.preflight_hit and verdict.confidence == "high":
        verdict = verdict.model_copy(update={"confidence": "medium"})
    return verdict


def _gather_test_context(target: Path, binary_path: str) -> str:
    """Read nearby test files that might reference the binary."""
    if not binary_path:
        return ""

    binary = target / binary_path
    if not binary.exists():
        return ""

    parent = binary.parent
    binary_name = binary.name
    chunks: list[str] = []
    total = 0

    for test_file in sorted(parent.glob("*.py")) + sorted(parent.glob("*.js")) + sorted(parent.glob("*.ts")):
        if test_file == binary:
            continue
        try:
            text = test_file.read_text(encoding="utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if binary_name not in text:
            continue
        header = f"--- {test_file.relative_to(target)} ---\n"
        chunk = header + text[:10_000]
        if total + len(chunk) > _MAX_CONTEXT_CHARS:
            break
        chunks.append(chunk)
        total += len(chunk)

    return "\n".join(chunks)
