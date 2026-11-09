"""Side-effect-free report capabilities, scoped to actual command boundaries.

This registry describes completion adapters, not a promise that every subcommand
of a domain accepts report flags. Specialized views keep their own serializers.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class CommandCapability:
    command: str
    document_kind: str
    artifact_policy: str
    summary: str
    compatibility: str = ""
    formats: tuple[str, ...] = ()


CAPABILITIES = (
    CommandCapability("scan", "triage", "automatic", "terminal and summary.md"),
    CommandCapability("codeql", "triage", "automatic", "terminal and summary.md"),
    CommandCapability("validate", "validation", "automatic", "terminal, summary.md and legacy summary.txt"),
    CommandCapability("agentic", "agentic", "automatic", "summary.md and existing terminal summary"),
    CommandCapability("project report", "project", "automatic", "terminal and summary.md", "native finding/annotation exports retained"),
    CommandCapability("sca scan", "sca", "automatic", "terminal and summary.md", "--html adds HTML"),
    CommandCapability("sca render", "sca", "existing output policy", "terminal and summary.md", "offline; legacy Markdown/SARIF switches retained"),
    CommandCapability("sca diff", "sca-diff", "explicit destination required", "existing stdout; report summary on stderr", "native --json/--out and gate status retained"),
    CommandCapability("sca check", "sca-check", "explicit destination required", "existing stdout; report summary on stderr", "native verdict and unavailable-advisory status retained"),
    CommandCapability("sca verify", "sca-verify", "explicit destination required", "existing stdout; report summary on stderr", "native overlay, delta artifacts and gate status retained"),
    CommandCapability("sca upgrade", "sca-upgrade", "explicit destination required", "existing stdout; report summary on stderr", "pairwise, candidates and add/remove comparisons; domain status retained"),
    CommandCapability("sca fix", "sca-fix", "explicit destination required", "existing stdout; report summary on stderr", "standard plan/proposed/apply modes; cve-only and harden retain domain interfaces"),
    CommandCapability("sca sbom inspect", "sbom-inspect", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom stats", "sbom-stats", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom diff", "sbom-diff", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom why", "sbom-why", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom plan", "sbom-plan", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom verify-plan", "sbom-verify-plan", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom collect", "sbom-collect", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("sca sbom notices", "sbom-notices", "explicit output or native directory", "stderr and captured summary", "native evidence formats retained", ("markdown", "json", "xml")),
    CommandCapability("web", "web", "automatic", "terminal and summary.md", "existing redaction applies before capture"),
    CommandCapability("fuzz", "fuzz", "automatic", "terminal and summary.md", "corpus preparation excluded"),
    CommandCapability("openant", "openant", "automatic", "terminal and summary.md", "recovered hints separate from findings"),
    CommandCapability("audit run", "audit", "automatic detailed reports", "existing terminal summary and summary.md", "canonical domain JSON retained; rendered JSON uses companion filename"),
    CommandCapability("audit resume", "audit", "automatic detailed reports", "existing terminal summary and summary.md", "canonical domain JSON retained; rendered JSON uses companion filename"),
    CommandCapability("audit report", "audit", "automatic detailed reports", "existing terminal summary and summary.md", "canonical domain JSON retained; rendered JSON uses companion filename"),
    CommandCapability("engagement report", "engagement", "automatic detailed reports", "existing terminal summary and summary.md", "canonical domain JSON retained; rendered JSON uses companion filename"),
    CommandCapability("describe", "describe", "explicit destination required", "existing stdout and captured summary", "no default file writes"),
    CommandCapability("binary report", "binary", "explicit export", "existing report display or export summary", "no analysis is run"),
)


def _capability_row(capability: CommandCapability) -> dict:
    from .renderers import available_formats
    return {**asdict(capability), "formats": [name for name in available_formats() if not capability.formats or name in capability.formats], "summary_independent": True}


def command_capabilities() -> list[dict]:
    return [_capability_row(capability) for capability in CAPABILITIES]
