"""Patch generation prompt builder.

Builds the secure patch prompt from a finding/vulnerability context.
"""

import json
from typing import Any, Dict, List, Optional

PATCH_SYSTEM_PROMPT = """You are a senior security engineer responsible for secure code reviews.
Create patches that are:
- Secure and comprehensive
- Maintainable and well-documented
- Tested and production-ready
- Following security best practices (OWASP, CWE guidance)

Balance security with usability and performance."""


def build_patch_prompt(
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
) -> str:
    """Build the secure patch generation prompt."""
    prompt = f"""You are a senior software security engineer creating a secure patch.

**Vulnerability:**
- Type: {rule_id}
- File: {file_path}:{start_line}-{end_line}
- Description: {message}

**Analysis:**
{json.dumps(analysis, indent=2)}
"""

    if feasibility:
        what_would_help = feasibility.get("what_would_help")
        if what_would_help:
            prompt += "\n**What Would Help Attacker (block these):**\n"
            for wh in what_would_help:
                prompt += f"  - {wh}\n"

        if attack_path and attack_path.get("path"):
            prompt += "\n**Attack Path (consider patching at earliest step):**\n"
            for step in attack_path["path"]:
                prompt += f"  Step {step.get('step', '?')}: {step.get('action', '')} -> {step.get('result', '')}\n"

    prompt += f"""
**Vulnerable Code:**
```
{code}
```

**Full File Content:**
```
{full_file_content[:5000]}
```

**Your Task:**
Create a SECURE PATCH that:
1. Completely fixes the vulnerability
2. Preserves all existing functionality
3. Follows the code's existing style and patterns
4. Includes clear comments explaining the fix
5. Adds input validation/sanitisation where needed
6. Uses modern security best practices

Provide BOTH:
1. The complete fixed code (not just the diff)
2. A clear explanation of what changed and why
3. Testing recommendations

Make this production-ready, not just a quick fix."""

    return prompt


def build_patch_prompt_from_finding(
    finding: Dict[str, Any],
    full_file_content: str = "",
    attack_path: Optional[Dict[str, Any]] = None,
) -> str:
    """Build patch prompt from a finding dict."""
    return build_patch_prompt(
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
    )
