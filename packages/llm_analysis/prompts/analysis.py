"""Analysis prompt builder.

Builds the vulnerability analysis prompt from a finding dict or VulnerabilityContext.
Used by agent.py (external LLM path) and orchestrator.py (parallel dispatch).
"""

import json
from typing import Any, Dict, Optional

from .schemas import ANALYSIS_SCHEMA, DATAFLOW_SCHEMA_FIELDS

ANALYSIS_SYSTEM_PROMPT = """You are a senior security researcher with expertise in:
- Vulnerability analysis and exploit development
- Secure code review
- Static and variant analysis
- Real-world attack scenarios

Provide honest, technical assessments. Don't overstate severity, but don't downplay real risks."""


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
**Your Task:**
Analyse this vulnerability in depth:
1. Is this a TRUE POSITIVE or FALSE POSITIVE?
2. Is it actually EXPLOITABLE in practice?
3. What's the real-world exploitability score (0.0 = impossible, 1.0 = trivial)?
4. What would an attacker need to exploit this?
5. What's the potential impact?
6. Provide a CVSS score estimate (0.0-10.0)
7. Explain your reasoning in detail.
8. Showcase how modern mitigations might affect exploitability.

Provide detailed technical analysis based on actual code review, not just the rule match."""

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
