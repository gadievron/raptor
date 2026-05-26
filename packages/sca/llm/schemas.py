"""Pydantic schemas for LLM stage structured outputs.

Every field the LLM populates is bounded and typed so the mechanical
layer never acts on free-form text without validation.  String fields
are sanitised post-validation by :func:`packages.sca.llm.run_stage`.
"""

from __future__ import annotations

from typing import List, Literal, Optional

from pydantic import BaseModel, Field


# ------------------------------------------------------------------
# Install-hook review (design §957–§970)
# ------------------------------------------------------------------

class InstallHookVerdict(BaseModel):
    """LLM verdict on an install lifecycle script."""

    verdict: Literal["benign", "suspicious", "malicious"]
    confidence: Literal["low", "medium", "high"]
    behaviours: List[Literal[
        "outbound_network",
        "filesystem_write_outside_build",
        "credential_read",
        "exec_decoded_payload",
        "external_resource_download",
        "obfuscation",
        "process_backgrounding",
        "ci_runner_registration",
    ]] = Field(default_factory=list)
    evidence_quotes: List[str] = Field(
        default_factory=list,
        description="Verbatim quotes from the script (max 200 chars each)",
    )
    reasoning: str = Field(
        default="",
        max_length=500,
        description="One-paragraph explanation of the verdict",
    )


# ------------------------------------------------------------------
# Version-diff review (design §976–§998)
# ------------------------------------------------------------------

class DiffAnomaly(BaseModel):
    """A single anomalous change found in a version diff."""

    file_path: str = Field(description="Path within the package archive")
    description: str = Field(max_length=300)
    severity: Literal["info", "suspicious", "malicious"] = "info"


class VersionDiffVerdict(BaseModel):
    """LLM verdict on a version-to-version source diff."""

    verdict: Literal["clean", "suspicious", "malicious"]
    confidence: Literal["low", "medium", "high"]
    changelog_consistent: bool = Field(
        description="True if observed changes match the documented changelog",
    )
    anomalies: List[DiffAnomaly] = Field(default_factory=list)
    behaviours: List[Literal[
        "obfuscated_code_added",
        "binary_added",
        "network_call_added",
        "credential_access_added",
        "test_fixture_binary_changed",
        "build_script_changed",
        "obfuscation",
    ]] = Field(default_factory=list)
    summary: str = Field(
        default="",
        max_length=500,
        description="One-paragraph summary of what changed",
    )


# ------------------------------------------------------------------
# Maintainer-trust synthesis (design §1000–§1008)
# ------------------------------------------------------------------

class MaintainerTrustVerdict(BaseModel):
    """LLM trust assessment of a package's maintainership."""

    trust_level: Literal["high", "medium", "low", "unknown"]
    confidence: Literal["low", "medium", "high"]
    concerns: List[str] = Field(
        default_factory=list,
        description="Specific trust concerns (max 5)",
    )
    summary: str = Field(
        default="",
        max_length=500,
        description="3-sentence trust assessment",
    )


class SlopsquatVerdict(BaseModel):
    """LLM assessment of a candidate slopsquat package — does
    the name + registry-metadata profile match the LLM-hallucination
    bait shape?

    ``verdict`` semantics:
      * ``probably_slopsquat`` — name is LLM-shape AND registry
        signals fit the bait archetype (new package, low
        downloads, anonymous publisher, no upstream repo).
      * ``probably_legit`` — name MIGHT be LLM-shape but registry
        signals don't fit bait (established package, real repo,
        active maintainer history).
      * ``inconclusive`` — signals mixed or insufficient.
    """

    verdict: Literal[
        "probably_slopsquat", "probably_legit", "inconclusive",
    ]
    confidence: Literal["low", "medium", "high"]
    concerns: List[str] = Field(
        default_factory=list,
        description=(
            "Specific bait-shape concerns (e.g. 'first published "
            "3 days ago', 'single maintainer with no other "
            "packages', 'README is empty'). Max 5."
        ),
    )
    summary: str = Field(
        default="",
        max_length=500,
        description="3-sentence verdict aimed at the operator.",
    )


# ------------------------------------------------------------------
# Binary-in-tests review (design §973)
# ------------------------------------------------------------------

class BinaryInTestsVerdict(BaseModel):
    """LLM assessment of a binary file found in a test directory."""

    verdict: Literal["benign", "suspicious", "malicious"]
    confidence: Literal["low", "medium", "high"]
    referenced_in_tests: Optional[bool] = Field(
        default=None,
        description="Whether surrounding test code actually uses this file",
    )
    reasoning: str = Field(
        default="",
        max_length=500,
        description="Why the binary is or isn't plausible as a test fixture",
    )


# ------------------------------------------------------------------
# Triage (design §597–§603)
# ------------------------------------------------------------------

class TriageItem(BaseModel):
    """LLM-assigned priority bucket for a single finding."""

    finding_id: str
    priority_bucket: Literal["fix_today", "this_sprint", "this_quarter", "accept"]
    one_line_rationale: str = Field(default="", max_length=200)
    confidence: Literal["low", "medium", "high"] = "medium"


class TriageResult(BaseModel):
    """Complete triage output for a run's findings."""

    items: List[TriageItem] = Field(default_factory=list)
    project_context_summary: str = Field(
        default="",
        max_length=500,
        description="How the project's threat model influenced ranking",
    )


# ------------------------------------------------------------------
# Inline-install review (Follow-up #6)
# ------------------------------------------------------------------

class InlineInstallItem(BaseModel):
    """A single package install the LLM found that the mechanical parser missed."""

    ecosystem: str = Field(description="Package ecosystem (e.g. npm, PyPI, Cargo)")
    name: str = Field(max_length=200)
    version: Optional[str] = Field(default=None, max_length=100)
    line_no: int = Field(description="Approximate line number in the source file")
    manager_used: str = Field(
        max_length=100,
        description="The install command used (e.g. 'brew install', 'cargo install')",
    )
    reasoning: str = Field(default="", max_length=300)


class InlineInstallVerdict(BaseModel):
    """LLM verdict on missed inline package installs."""

    missed_installs: List[InlineInstallItem] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "low"
    notes: str = Field(
        default="",
        max_length=500,
        description="Any caveats about the analysis",
    )


# ------------------------------------------------------------------
# Upgrade impact analysis (Follow-up #7)
# ------------------------------------------------------------------

class BreakingChange(BaseModel):
    """A specific call site affected by a dependency upgrade."""

    site: str = Field(description="File path and line, e.g. 'src/foo.py:42'")
    what_breaks: str = Field(max_length=300)
    suggested_fix: str = Field(default="", max_length=300)


class UpgradeImpactVerdict(BaseModel):
    """LLM assessment of a dependency upgrade's impact on the project."""

    verdict: Literal["safe", "minor_migration", "major_migration"]
    confidence: Literal["low", "medium", "high"]
    breaking_changes: List[BreakingChange] = Field(default_factory=list)
    summary: str = Field(
        default="",
        max_length=500,
        description="One-line operator-facing summary",
    )


class UpgradeImpactPrefilter(BaseModel):
    """Cheap-tier verdict — does this upgrade need full analysis?

    Asymmetric framing: only ``clear_safe`` short-circuits. Anything
    else (including ``needs_analysis`` for ambiguous cases and any
    risky-looking changes) falls through to the full
    :class:`UpgradeImpactVerdict` reviewer. The cheap model is never
    asked to greenlight a major migration — it's a filter for the
    obviously-safe cases (semver patch bump, type-additive changelog,
    no API surface in changelog).
    """

    verdict: Literal["clear_safe", "needs_analysis"]
    reasoning: str = Field(
        default="",
        max_length=500,
        description="One-or-two-sentence justification",
    )
