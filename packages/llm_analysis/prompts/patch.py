"""Patch generation prompt builder.

Builds the secure patch prompt from a finding/vulnerability context as a
``PromptBundle`` with envelope-quarantined untrusted content.
"""

import json
from typing import Any, Dict, List, Optional

from core.security.prompt_envelope import (
    ModelDefenseProfile,
    PromptBundle,
    TaintedString,
    UntrustedBlock,
    build_prompt,
)
from core.security.prompt_defense_profiles import CONSERVATIVE


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

Provide BOTH:
1. The complete fixed code (not just the diff)
2. A clear explanation of what changed and why
3. Testing recommendations

Make this production-ready, not just a quick fix."""


def _format_what_would_help(feasibility: Dict[str, Any]) -> str:
    what_would_help = feasibility.get("what_would_help") or []
    if not what_would_help:
        return ""
    return "Attacker enablers (block these in the patch):\n" + "\n".join(
        f"  - {w}" for w in what_would_help
    )


def _format_attack_path(attack_path: Dict[str, Any]) -> str:
    path = attack_path.get("path") or []
    if not path:
        return ""
    parts: List[str] = ["Attack path (consider patching at earliest step):"]
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
    analysis: Dict[str, Any],
    code: str = "",
    full_file_content: str = "",
    feasibility: Optional[Dict[str, Any]] = None,
    attack_path: Optional[Dict[str, Any]] = None,
    profile: Optional[ModelDefenseProfile] = None,
    extra_blocks: tuple[UntrustedBlock, ...] = (),
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
    finding: Dict[str, Any],
    full_file_content: str = "",
    attack_path: Optional[Dict[str, Any]] = None,
    *,
    profile: Optional[ModelDefenseProfile] = None,
    extra_blocks: tuple[UntrustedBlock, ...] = (),
) -> PromptBundle:
    """Bundle equivalent of ``build_patch_prompt_from_finding``."""
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
    )
