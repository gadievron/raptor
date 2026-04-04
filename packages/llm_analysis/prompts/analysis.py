"""Analysis prompt builder.

Builds the vulnerability analysis prompt from a finding dict or VulnerabilityContext.
Used by agent.py (external LLM path) and orchestrator.py (parallel dispatch).
"""

import json
from typing import Any, Dict, Optional

from .schemas import ANALYSIS_SCHEMA, DATAFLOW_SCHEMA_FIELDS

ANALYSIS_SYSTEM_PROMPT = """You are a security vulnerability validator and analyst.

Your goal is to determine whether scanner findings are real, reachable, and exploitable.
Work through each finding systematically. Do not skip, sample, or guess.

Rules (from exploitation-validator methodology):
- ASSUME-EXPLOIT: Investigate as if exploitable until proven otherwise. Do not dismiss.
- NO-HEDGING: If your reasoning includes "if", "maybe", or "uncertain", verify the claim.
- PROOF: Show the vulnerable code for every claim. Quote the actual line.
- EVIDENCE: Back causal claims with specifics (function name, line number). "Input is sanitized" is not sufficient; "htmlEscape() at line 47" is.
- FULL-COVERAGE: Assess every aspect — do not skip steps or take shortcuts."""


def build_analysis_schema(has_dataflow: bool = False) -> Dict[str, str]:
    """Build the analysis schema, optionally including dataflow fields."""
    schema = dict(ANALYSIS_SCHEMA)
    if has_dataflow:
        schema.update(DATAFLOW_SCHEMA_FIELDS)
    return schema


def build_analysis_prompt(
    rule_id: str,
    level: str,
    file_path: str,
    start_line: int,
    end_line: int,
    message: str,
    code: str = "",
    surrounding_context: str = "",
    has_dataflow: bool = False,
    dataflow_source: Optional[Dict[str, Any]] = None,
    dataflow_sink: Optional[Dict[str, Any]] = None,
    dataflow_steps: Optional[list] = None,
) -> str:
    """Build the vulnerability analysis prompt.

    For external LLM: includes full code and dataflow in the prompt.
    """
    prompt = f"""You are an expert security researcher analysing a potential vulnerability. Reason with your deep knowledge of software security, exploit development, and real-world attack scenarios. Do not guess or assume at any time.

**Vulnerability Details:**
- Rule: {rule_id}
- Severity: {level}
- File: {file_path}
- Lines: {start_line}-{end_line}
- Description: {message}
"""

    if has_dataflow and dataflow_source and dataflow_sink:
        prompt += f"""
**🔍 COMPLETE DATAFLOW PATH ANALYSIS (Source → Sink):**

This vulnerability has a complete dataflow path tracked by CodeQL from tainted source to dangerous sink.

**1. SOURCE (Where tainted data originates):**
   Location: {dataflow_source['file']}:{dataflow_source['line']}
   Type: {dataflow_source['label']}

   Code:
   ```
{dataflow_source.get('code', '')}
   ```

"""
        if dataflow_steps:
            prompt += f"**2. DATAFLOW PATH ({len(dataflow_steps)} intermediate step(s)):**\n\n"
            for i, step in enumerate(dataflow_steps, 1):
                marker = "🛡️ SANITIZER/VALIDATOR" if step.get('is_sanitizer') else "⚙️ TRANSFORMATION"
                prompt += f"""   {marker} Step {i}: {step.get('label', '')}
   Location: {step['file']}:{step['line']}

   Code:
   ```
{step.get('code', '')}
   ```

"""

        prompt += f"""**3. SINK (Dangerous operation where tainted data is used):**
   Location: {dataflow_sink['file']}:{dataflow_sink['line']}
   Type: {dataflow_sink['label']}

   Code:
   ```
{dataflow_sink.get('code', '')}
   ```

**⚠️ CRITICAL DATAFLOW ANALYSIS REQUIRED:**

You have the COMPLETE attack path from source to sink. Use this to make an informed decision:

1. **Is the SOURCE actually attacker-controlled?**
   - HTTP parameter, user input, file upload → HIGH risk, attacker controls this
   - Configuration file, environment variable → MEDIUM risk, requires other access
   - Hardcoded constant, internal data → FALSE POSITIVE, not attacker-controlled

2. **Are any sanitizers in the path EFFECTIVE?**
   - For each sanitizer/validator step, determine if it actually prevents exploitation
   - Can an attacker bypass it with encoding, special characters, or edge cases?
   - Is it applied correctly to all code paths?

3. **Is the complete path EXPLOITABLE?**
   - Can you trace a realistic attack from source through all steps to sink?
   - What payload would bypass sanitizers and reach the sink with malicious content?

4. **What's the ACTUAL exploitability** considering the full dataflow path?

"""
    else:
        prompt += f"""
**Vulnerable Code:**
```
{code}
```

**Surrounding Context:**
```
{surrounding_context}
```

"""

    prompt += """
**Your Task — work through each stage in sequence:**

**Stage A: One-shot verification**
Is the vulnerability pattern real? Does the code actually do what the scanner claims?
Attempt to confirm exploitability. If clearly a false positive, explain why.

**Stage B: Attack path analysis**
What is the attack path from attacker-controlled input to the vulnerable code?
What preconditions does an attacker need? Are those preconditions realistic?
What blocks exploitation? What enables it?
If you identify blockers, can they be bypassed?

**Stage C: Sanity check**
Does the code at the stated location match the finding description?
Is the source-to-sink flow real, or did the scanner fabricate a connection?
Is this code reachable from an entry point, or is it dead code?

**Stage D: Ruling**
Is this test code, example code, or documentation?
Does exploitation require another vulnerability as a prerequisite?
Does exploitation require the victim to perform an unlikely action?
If your reasoning hedges ("maybe", "in theory"), verify the claim or rule it out.

**Final assessment:**
Based on your analysis through Stages A-D:
- Set is_true_positive based on whether the vulnerability pattern is real
- Set is_exploitable based on whether a realistic attack path exists
- Rate exploitability_score from 0.0 (impossible) to 1.0 (trivial to exploit)
- Set confidence to high, medium, or low based on how certain you are
- Set ruling to exactly one of: validated, false_positive, unreachable, test_code, dead_code, mitigated
- Set severity_assessment to one of: critical, high, medium, low, informational
- Set cwe_id to the most specific applicable CWE. Always provide one (e.g., CWE-120 for buffer overflow, CWE-78 for command injection, CWE-79 for XSS, CWE-89 for SQL injection, CWE-416 for use-after-free, CWE-134 for format string, CWE-190 for integer overflow)
- Set vuln_type category (e.g., command_injection, xss, buffer_overflow, format_string, use_after_free, sql_injection)
- Set cvss_vector as a CVSS v3.1 vector string by choosing: Attack Vector (N/A/L/P), Attack Complexity (L/H), Privileges Required (N/L/H), User Interaction (N/R), Scope (U/C), Confidentiality (N/L/H), Integrity (N/L/H), Availability (N/L/H). Format: CVSS:3.1/AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_. The numeric score is computed automatically — do not estimate it. Score the vulnerability's **inherent impact**, not binary mitigations. A heap overflow capable of code execution = C:H/I:H/A:H even with RELRO+PIE. AV = how the attacker reaches the code: CLI binary = AV:L, network service = AV:N.
- Describe the attack scenario if exploitable
- Summarize the dataflow as a concise source->sink chain (e.g., "request.getParameter('id') -> Statement.executeQuery()")
- Provide remediation guidance: what should the developer do to fix this?
- If ruling is false_positive, set false_positive_reason to explain why

**Consistency checks (mandatory):**
- Your ruling, is_true_positive, and is_exploitable MUST be consistent with your reasoning. Do not mark a finding as exploitable if your reasoning concludes it is safe.
- severity_assessment must be consistent with cvss_vector. High severity with a low CVSS score (or vice versa) indicates an error — review and correct.
- If you generated a PoC exploit, it must produce observable evidence: a crash, changed output, callback, file read, error message, or measurable state change. "Ran without error" is not evidence.

Be rigorous. False positives waste significant downstream effort (exploit generation,
patch creation, review). But do not dismiss real vulnerabilities — investigate first."""

    return prompt


def build_analysis_prompt_from_finding(finding: Dict[str, Any]) -> str:
    """Build analysis prompt from a finding dict (e.g. from to_dict() or prep report).

    Convenience wrapper that unpacks the finding dict into build_analysis_prompt() args.
    """
    dataflow = finding.get("dataflow", {})
    return build_analysis_prompt(
        rule_id=finding.get("rule_id", "unknown"),
        level=finding.get("level", "warning"),
        file_path=finding.get("file_path", "unknown"),
        start_line=finding.get("start_line", 0),
        end_line=finding.get("end_line", finding.get("start_line", 0)),
        message=finding.get("message", ""),
        code=finding.get("code", ""),
        surrounding_context=finding.get("surrounding_context", ""),
        has_dataflow=finding.get("has_dataflow", False),
        dataflow_source=dataflow.get("source") if dataflow else None,
        dataflow_sink=dataflow.get("sink") if dataflow else None,
        dataflow_steps=dataflow.get("steps") if dataflow else None,
    )
