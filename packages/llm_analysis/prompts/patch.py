"""Patch generation prompt builder.

Builds the secure patch prompt from a finding/vulnerability context as a
``PromptBundle`` with envelope-quarantined untrusted content.
"""

import json
from typing import Any

from core.security.prompt_defense_profiles import CONSERVATIVE
from core.security.prompt_envelope import (
    ModelDefenseProfile,
    PromptBundle,
    TaintedString,
    UntrustedBlock,
    build_prompt,
)

PATCH_SYSTEM_PROMPT = """You are a senior security engineer responsible for secure code reviews.
Create patches that are:
- Secure and comprehensive
- Maintainable and well-documented
- Tested and production-ready
- Following security best practices (OWASP, CWE guidance)

Balance security with usability and performance."""


PATCH_TASK_INSTRUCTIONS = """You are a senior software security engineer creating a secure patch.

The user message contains: a prior analysis (untrusted, propagated from earlier LLM output), the vulnerable code, the full file content (truncated for size), feasibility hints, and any attack-path the framework traced. Identifiers are passed through named slots; refer to slot values by name.

**Your Task:**
Create a SECURE PATCH that:
1. Completely fixes the vulnerability
2. Preserves all existing functionality
3. Follows the code's existing style and patterns
4. Includes clear comments explaining the fix
5. Adds input validation/sanitisation where needed
6. Uses modern security best practices

If the user message contains an attack-path block, prefer patching at the earliest step that breaks the chain.

Provide:
1. The fix as a UNIFIED DIFF in a single ```diff fenced code block.
   - Standard unified diff format: `--- a/<file>` and `+++ b/<file>` headers (use the `file_path` slot value as the file), then `@@ -start,count +start,count @@` hunks with context lines.
   - Diff against the vulnerable file only, and keep every hunk close to the flagged lines — the diff is mechanically validated (applied to a scratch copy, hunk scope checked against the finding span, and re-checked with the original detector). A free-form or malformed patch fails the format check.
2. A clear explanation of what changed and why
3. Testing recommendations

Make this production-ready, not just a quick fix."""


def _format_what_would_help(feasibility: dict[str, Any]) -> str:
    what_would_help = feasibility.get("what_would_help") or []
    if not what_would_help:
        return ""
    return "Attacker enablers (block these in the patch):\n" + "\n".join(
        f"  - {w}" for w in what_would_help
    )


def _format_attack_path(attack_path: dict[str, Any]) -> str:
    path = attack_path.get("path") or []
    if not path:
        return ""
    parts: list[str] = ["Attack path (consider patching at earliest step):"]
    for step in path:
        parts.append(
            f"  Step {step.get('step', '?')}: "
            f"{step.get('action', '')} -> {step.get('result', '')}"
        )
    return "\n".join(parts)


def build_patch_prompt_bundle(
    *,
    rule_id: str,
    file_path: str,
    start_line: int,
    end_line: int,
    message: str,
    analysis: dict[str, Any],
    code: str = "",
    full_file_content: str = "",
    feasibility: dict[str, Any] | None = None,
    attack_path: dict[str, Any] | None = None,
    profile: ModelDefenseProfile | None = None,
    extra_blocks: tuple[UntrustedBlock, ...] = (),
    ast_view: dict[str, Any] | None = None,
) -> PromptBundle:
    """Build the patch prompt as a PromptBundle (system + user, role-separated)."""
    profile = profile or CONSERVATIVE

    system = PATCH_SYSTEM_PROMPT + "\n\n" + PATCH_TASK_INSTRUCTIONS

    blocks: list[UntrustedBlock] = []

    if message:
        blocks.append(UntrustedBlock(
            content=message,
            kind="scanner-message",
            origin=f"{rule_id}:{file_path}:{start_line}",
        ))

    if analysis:
        blocks.append(UntrustedBlock(
            content=json.dumps(analysis, indent=2)[:10000],
            kind="prior-analysis",
            origin=f"{rule_id}:{file_path}",
        ))

    if feasibility:
        wwh = _format_what_would_help(feasibility)
        if wwh:
            blocks.append(UntrustedBlock(
                content=wwh,
                kind="attacker-enablers",
                origin=f"feasibility:{rule_id}",
            ))

    if attack_path:
        ap = _format_attack_path(attack_path)
        if ap:
            blocks.append(UntrustedBlock(
                content=ap,
                kind="attack-path",
                origin=f"feasibility:{rule_id}",
            ))

    # Per-function AST view (signature, calls inside body, returns,
    # inline-asm flag). Gives the patch-generating LLM the
    # function's current shape so the fix can preserve existing
    # call semantics, return paths, and parameter contracts.
    # Particularly useful for patches that must add a check
    # without breaking other return paths — the LLM sees every
    # exit point. Block sits BEFORE vulnerable-code so the LLM
    # has the function's current contract before editing the
    # buggy span.
    if ast_view:
        from packages.llm_analysis.prompts.analysis import (
            _render_ast_view_block,
        )
        view_text = _render_ast_view_block(
            ast_view, file_path_override=file_path,
        )
        if view_text:
            blocks.append(UntrustedBlock(
                content=view_text,
                kind="ast-view",
                origin=f"{file_path}:{ast_view.get('function', '?')}",
            ))

    if code:
        blocks.append(UntrustedBlock(
            content=code,
            kind="vulnerable-code",
            origin=f"{file_path}:{start_line}-{end_line}",
        ))

    if full_file_content:
        blocks.append(UntrustedBlock(
            content=full_file_content[:5000],
            kind="full-file-content",
            origin=file_path,
        ))

    blocks.extend(extra_blocks)

    slots = {
        "rule_id": TaintedString(value=rule_id, trust="untrusted"),
        "file_path": TaintedString(value=file_path, trust="untrusted"),
        "lines": TaintedString(value=f"{start_line}-{end_line}", trust="untrusted"),
    }

    return build_prompt(
        system=system,
        profile=profile,
        untrusted_blocks=tuple(blocks),
        slots=slots,
    )


def build_patch_prompt_bundle_from_finding(
    finding: dict[str, Any],
    full_file_content: str = "",
    attack_path: dict[str, Any] | None = None,
    *,
    profile: ModelDefenseProfile | None = None,
    extra_blocks: tuple[UntrustedBlock, ...] = (),
) -> PromptBundle:
    """Bundle equivalent of ``build_patch_prompt_from_finding``."""
    if (
        finding.get("source_type") == "dependency"
        or finding.get("vuln_type", "").startswith("sca:")
        or finding.get("rule_id", "").startswith("sca:")
    ):
        return build_sca_patch_prompt_bundle(finding, profile=profile)
    return build_patch_prompt_bundle(
        rule_id=finding.get("rule_id", "unknown"),
        file_path=finding.get("file_path", "unknown"),
        start_line=finding.get("start_line", 0),
        end_line=finding.get("end_line", finding.get("start_line", 0)),
        message=finding.get("message", ""),
        analysis=finding.get("analysis", {}),
        code=finding.get("code", ""),
        full_file_content=full_file_content,
        feasibility=finding.get("feasibility"),
        attack_path=attack_path,
        profile=profile,
        extra_blocks=extra_blocks,
        # Per-function structured AST view (shared with the
        # analysis-family tasks via the agent's enrichment loop).
        ast_view=finding.get("ast_view"),
    )


# ---------------------------------------------------------------------------
# SCA manifest-level patches: version bumps in dependency files
# ---------------------------------------------------------------------------

SCA_PATCH_SYSTEM_PROMPT = """\
You are a software engineer writing a minimal, safe dependency upgrade \
patch for a manifest file.

Create a unified diff that bumps the vulnerable dependency to the fixed \
version.  Preserve the manifest's existing formatting, comments, and \
pin style.  If the manifest uses exact pins, produce an exact pin.  \
If it uses range pins, produce the tightest range that includes the fix.

Only change the one dependency — do not touch unrelated lines.

If NO fixed version exists (the "Fixed version" field is empty), do not \
invent one.  Say so explicitly and suggest a workaround instead: an \
alternative package, a version constraint excluding the vulnerable \
range, or a configuration-level mitigation."""


def build_sca_patch_prompt_bundle(
    finding: dict[str, Any],
    *,
    profile: ModelDefenseProfile | None = None,
) -> PromptBundle:
    """Build a patch prompt for an SCA finding (manifest version bump)."""
    profile = profile or CONSERVATIVE
    system = SCA_PATCH_SYSTEM_PROMPT

    sca = finding.get("sca", {})
    dep_name = sca.get("name", "unknown")
    dep_version = sca.get("version", "")
    ecosystem = sca.get("ecosystem", "")
    # `or ""` (not a dict-get default): SCA emits the key with an
    # explicit None when no fixed release exists, and a None value
    # crashes the envelope's slot renderer. The empty string keeps
    # the "Fixed version:" line blank, which is what the system
    # prompt's no-fixed-version workaround guidance keys off.
    fixed_version = sca.get("fixed_version") or ""
    manifest_path = sca.get("declared_in", finding.get("file_path", ""))
    advisory = sca.get("advisory", {})
    cve_id = ""
    if advisory.get("aliases"):
        cve_id = advisory["aliases"][0]
    elif advisory.get("id"):
        cve_id = advisory["id"]

    context = (
        f"Dependency: {ecosystem}/{dep_name}\n"
        f"Current version: {dep_version}\n"
        f"Fixed version: {fixed_version}\n"
        f"Manifest: {manifest_path}\n"
        f"Advisory: {cve_id}\n"
    )

    blocks: list[UntrustedBlock] = [
        UntrustedBlock(
            content=context,
            kind="sca-upgrade-context",
            origin=f"{ecosystem}/{dep_name}",
        ),
    ]

    manifest_content = finding.get("code", "")
    if manifest_content:
        blocks.append(UntrustedBlock(
            content=manifest_content,
            kind="manifest-content",
            origin=str(manifest_path),
        ))

    slots = {
        "package": TaintedString(value=f"{ecosystem}/{dep_name}", trust="untrusted"),
        "from_version": TaintedString(value=dep_version, trust="untrusted"),
        "to_version": TaintedString(value=fixed_version, trust="untrusted"),
        "manifest": TaintedString(value=str(manifest_path), trust="untrusted"),
    }

    return build_prompt(
        system=system,
        profile=profile,
        untrusted_blocks=tuple(blocks),
        slots=slots,
    )
