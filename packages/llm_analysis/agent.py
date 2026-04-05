#!/usr/bin/env python3
"""
RAPTOR Truly Autonomous Security Agent

This agent provides TRUE agentic behaviour with NO templates:
1. LLM-powered vulnerability analysis
2. Context-aware exploit generation
3. Intelligent patch creation
4. Multi-model support (Claude, GPT-4, Ollama/DeepSeek/Qwen)
5. Automatic fallback and cost optimisation

"""

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Add parent directory to path for core imports
# Add current directory to path for llm imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.json import load_json, save_json
sys.path.insert(0, str(Path(__file__).parent))
from core.config import RaptorConfig
from core.logging import get_logger
from core.progress import HackerProgress
from core.sarif.parser import parse_sarif_findings, deduplicate_findings
from core.inventory.lookup import lookup_function as _lookup_function
from llm.client import LLMClient, _is_auth_error
from llm.config import LLMConfig, detect_llm_availability
from llm.providers import ClaudeCodeProvider

logger = get_logger()


def get_vuln_type(rule_id: str) -> Optional[str]:
    """Map SARIF rule_id to vulnerability type for mitigation checks."""
    try:
        from packages.exploit_feasibility import get_vuln_type_for_rule
        return get_vuln_type_for_rule(rule_id)
    except ImportError:
        return None


class VulnerabilityContext:
    """Represents a vulnerability with full context for autonomous analysis."""

    def __init__(self, finding: Dict[str, Any], repo_path: Path):
        self.finding = finding
        self.repo_path = repo_path
        self.finding_id = finding.get("finding_id")
        self.rule_id = finding.get("rule_id")
        self.file_path = finding.get("file")
        self.start_line = finding.get("startLine")
        self.end_line = finding.get("endLine")
        self.snippet = finding.get("snippet")
        self.message = finding.get("message")
        self.level = finding.get("level", "warning")
        self.cwe_id = finding.get("cwe_id")
        self.tool = finding.get("tool")

        # Dataflow analysis fields
        self.has_dataflow: bool = finding.get("has_dataflow", False)
        self.dataflow_path: Optional[Dict[str, Any]] = finding.get("dataflow_path")
        self.dataflow_source: Optional[Dict[str, Any]] = None
        self.dataflow_sink: Optional[Dict[str, Any]] = None
        self.dataflow_steps: List[Dict[str, Any]] = []
        self.sanitizers_found: List[str] = []

        # Function metadata from inventory (if available)
        self.metadata: Optional[Dict[str, Any]] = finding.get("metadata")

        # Feasibility data from validation pipeline (if available)
        from packages.exploitability_validation.models import Feasibility
        self.feasibility: Dict[str, Any] = Feasibility.from_dict(finding.get("feasibility")).to_dict()
        self.attack_path_ref: Optional[str] = self.feasibility.get("attack_path_ref")

        # Will be populated by LLM analysis
        self.full_code: Optional[str] = None
        self.surrounding_context: Optional[str] = None
        self.exploitable: bool = False
        self.exploitability_score: float = 0.0
        self.exploit_code: Optional[str] = None
        self.patch_code: Optional[str] = None
        self.analysis: Optional[Dict[str, Any]] = None

    def get_full_file_path(self) -> Optional[Path]:
        """Get absolute path to vulnerable file."""
        if not self.file_path:
            return None
        clean_path = self.file_path.replace("file://", "")
        return self.repo_path / clean_path

    def read_vulnerable_code(self) -> bool:
        """Read the actual vulnerable code from the file."""
        file_path = self.get_full_file_path()
        if not file_path or not file_path.exists():
            logger.warning(f"Cannot read file: {file_path}")
            return False

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            # Get the specific vulnerable lines
            if self.start_line and self.end_line:
                start_idx = max(0, self.start_line - 1)
                end_idx = min(len(lines), self.end_line)
                self.full_code = "".join(lines[start_idx:end_idx])

                # Get surrounding context (50 lines before and after)
                context_start = max(0, start_idx - 50)
                context_end = min(len(lines), end_idx + 50)
                self.surrounding_context = "".join(lines[context_start:context_end])
            else:
                # If no line numbers, take first 100 lines
                self.full_code = "".join(lines[:100])
                self.surrounding_context = self.full_code

            return True
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return False

    def _read_code_at_location(self, file_uri: str, line: int, context_lines: int = 5) -> str:
        """
        Read code at a specific location with surrounding context.

        Args:
            file_uri: File URI from SARIF
            line: Line number (1-indexed)
            context_lines: Number of lines before/after to include

        Returns:
            Code snippet with context
        """
        try:
            # Clean up the file URI and validate path stays within repo
            clean_path = file_uri.replace("file://", "")
            file_path = (self.repo_path / clean_path).resolve()

            if not str(file_path).startswith(str(self.repo_path.resolve())):
                return f"[Path traversal blocked: {file_uri}]"

            if not file_path.exists():
                return f"[File not found: {file_uri}]"

            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            # Get context around the line
            start = max(0, line - context_lines - 1)
            end = min(len(lines), line + context_lines)

            context = []
            for i in range(start, end):
                marker = ">>>" if i == line - 1 else "   "
                context.append(f"{marker} {i + 1:4d} | {lines[i].rstrip()}")

            return "\n".join(context)

        except Exception as e:
            return f"[Error reading code: {e}]"

    def _is_sanitizer(self, label: str) -> bool:
        """
        Heuristic to identify if a dataflow step is a sanitizer.

        Args:
            label: Step label from SARIF

        Returns:
            True if this looks like a sanitizer
        """
        sanitizer_keywords = [
            'sanitiz', 'validat', 'filter', 'escape', 'encode',
            'clean', 'strip', 'remove', 'replace', 'whitelist',
            'blacklist', 'check', 'verify', 'safe'
        ]

        label_lower = label.lower()
        return any(keyword in label_lower for keyword in sanitizer_keywords)

    def extract_dataflow(self) -> bool:
        """
        Extract and enrich dataflow path information.

        Returns:
            True if dataflow was successfully extracted
        """
        if not self.has_dataflow or not self.dataflow_path:
            return False

        try:
            # Extract source
            if self.dataflow_path.get("source"):
                src = self.dataflow_path["source"]
                self.dataflow_source = {
                    "file": src["file"],
                    "line": src["line"],
                    "column": src.get("column", 0),
                    "label": src["label"],
                    "snippet": src.get("snippet", ""),
                    "code": self._read_code_at_location(src["file"], src["line"])
                }

            # Extract sink
            if self.dataflow_path.get("sink"):
                sink = self.dataflow_path["sink"]
                self.dataflow_sink = {
                    "file": sink["file"],
                    "line": sink["line"],
                    "column": sink.get("column", 0),
                    "label": sink["label"],
                    "snippet": sink.get("snippet", ""),
                    "code": self._read_code_at_location(sink["file"], sink["line"])
                }

            # Extract intermediate steps
            for step in self.dataflow_path.get("steps", []):
                is_sanitizer = self._is_sanitizer(step["label"])

                step_info = {
                    "file": step["file"],
                    "line": step["line"],
                    "column": step.get("column", 0),
                    "label": step["label"],
                    "snippet": step.get("snippet", ""),
                    "is_sanitizer": is_sanitizer,
                    "code": self._read_code_at_location(step["file"], step["line"])
                }

                self.dataflow_steps.append(step_info)

                if is_sanitizer:
                    self.sanitizers_found.append(step["label"])

            logger.info(f"✓ Extracted dataflow: {len(self.dataflow_steps)} steps, {len(self.sanitizers_found)} sanitizers")
            return True

        except Exception as e:
            logger.error(f"Failed to extract dataflow: {e}")
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialisation."""
        result = {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "level": self.level,
            "message": self.message,
            "cwe_id": self.cwe_id,
            "tool": self.tool,
            "exploitable": self.exploitable,
            "exploitability_score": self.exploitability_score,
            "analysis": self.analysis,
            "has_exploit": self.exploit_code is not None,
            "has_patch": self.patch_code is not None,
        }

        # Add function metadata if available (from inventory checklist)
        if self.metadata:
            result["metadata"] = self.metadata

        # Add code context if available (populated by read_vulnerable_code)
        if self.full_code:
            result["code"] = self.full_code
        if self.surrounding_context:
            result["surrounding_context"] = self.surrounding_context

        # Add feasibility data if present (always a dict, check for non-default)
        if self.feasibility.get("status", "pending") != "pending" or self.feasibility.get("verdict"):
            result["feasibility"] = self.feasibility

        # Add dataflow information if present
        if self.has_dataflow:
            result["has_dataflow"] = True
            result["dataflow"] = {
                "source": self.dataflow_source,
                "sink": self.dataflow_sink,
                "steps": self.dataflow_steps,
                "sanitizers_found": self.sanitizers_found,
                "total_steps": len(self.dataflow_steps) + 2  # +2 for source and sink
            }
        else:
            result["has_dataflow"] = False

        return result


def convert_validated_to_agent_format(data: dict) -> List[Dict[str, Any]]:
    """Convert validation pipeline findings.json to VulnerabilityContext format.

    Skips ruled_out, confirmed_blocked, and unlikely-verdict findings.
    Normalizes status fields in-place before filtering (idempotent).
    """
    from packages.exploitability_validation.models import Finding

    try:
        from packages.exploitability_validation import normalize_findings
        normalize_findings(data)
    except ImportError:
        pass
    converted = []
    for raw in data.get("findings", []):
        f = Finding.from_dict(raw)
        # Check both status and final_status for exclusion
        if f.status in ("ruled_out", "disproven"):
            continue
        if f.final_status in ("ruled_out", "confirmed_blocked"):
            continue
        if f.feasibility.verdict == "unlikely":
            continue

        feasibility_d = f.feasibility.to_dict()
        converted.append({
            "finding_id": f.id,
            "rule_id": f.rule_id or f.vuln_type,
            "file": f.file,
            "startLine": f.line,
            "endLine": f.line,
            "snippet": f.proof.vulnerable_code,
            "message": f.candidate_reasoning or f.message or f.rule_id or f"{f.vuln_type} in {f.function or 'unknown'}",
            "level": "error" if f.final_status in ("exploitable", "likely_exploitable", "confirmed_constrained") else "warning",
            "has_dataflow": bool(f.proof.flow),
            "feasibility": feasibility_d,
            "attack_path_ref": f.feasibility.attack_path_ref,
            "ruling": f.ruling.to_dict(),
            "final_status": f.final_status or "pending",
            "tool": f.tool,
            "cwe_id": f.cwe_id,
        })
    return converted


class AutonomousSecurityAgentV2:
    def __init__(self, repo_path: Path, out_dir: Path, llm_config: Optional[LLMConfig] = None,
                 prep_only: bool = False):
        self.repo_path = repo_path
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)

        # Detect LLM availability and choose provider
        availability = detect_llm_availability()

        if prep_only:
            # Phase 3 prep — read code, build structured findings
            self.llm_config = None
            self.llm = ClaudeCodeProvider()
            logger.debug(f"Prep mode: {repo_path} → {out_dir}")
        elif availability.external_llm:
            # External LLM configured — use LLMClient
            self.llm_config = llm_config or LLMConfig()
            self.llm = LLMClient(self.llm_config)

            logger.info("RAPTOR Autonomous Security Agent initialised")
            logger.info(f"Repository: {repo_path}")
            logger.info(f"Output: {out_dir}")
            logger.info(f"LLM: {self.llm_config.primary_model.provider}/{self.llm_config.primary_model.model_name}")

            # Also print to console so user can see
            print(f"\n🤖 Using LLM: {self.llm_config.primary_model.provider}/{self.llm_config.primary_model.model_name}")
            if self.llm_config.primary_model.cost_per_1k_tokens > 0:
                print(f"💰 Cost: ${self.llm_config.primary_model.cost_per_1k_tokens:.4f} per 1K tokens")
            else:
                print(f"💰 Cost: FREE (self-hosted model)")

            # Warn about Ollama model limitations for exploit generation
            if "ollama" in self.llm_config.primary_model.provider.lower():
                print()
                print("IMPORTANT: You are using an Ollama model.")
                print("   • Vulnerability analysis and patching: Works well with Ollama models")
                print("   • Exploit generation: Requires frontier models (Anthropic Claude / OpenAI GPT-4)")
                print("   • Ollama models may generate invalid/non-compilable exploit code")
                print()
                print("   For production-quality exploits, use:")
                print("     export ANTHROPIC_API_KEY=your_key  (recommended)")
                print("     export OPENAI_API_KEY=your_key")
            print()
        else:
            # No external LLM — use ClaudeCodeProvider
            self.llm_config = None
            self.llm = ClaudeCodeProvider()

            logger.info("RAPTOR Autonomous Security Agent initialised (prep-only mode)")
            logger.info(f"Repository: {repo_path}")
            logger.info(f"Output: {out_dir}")

            if availability.claude_code:
                print("\n🤖 No external LLM configured — Claude Code will handle analysis")
            else:
                print("\n⚠️  No LLM available — producing structured findings for manual review")
            print()

    def _load_attack_path(self, ref: str) -> Optional[Dict[str, Any]]:
        """Load attack path from a ref like 'attack-paths.json#PATH-001'."""
        if not ref or '#' not in ref:
            return None
        try:
            file_name, path_id = ref.split('#', 1)
            # Search in validation directory — check multiple likely locations
            candidates = [
                self.out_dir.parent / "validation" / file_name,    # Normal pipeline layout
                self.out_dir / file_name,                           # Same directory as findings
                self.out_dir.parent / file_name,                    # One level up
            ]
            for search_path in candidates:
                paths = load_json(search_path)
                if paths is not None and isinstance(paths, list):
                    return next((p for p in paths if p.get("id") == path_id), None)
            return None
        except (json.JSONDecodeError, OSError, StopIteration) as e:
            logger.debug(f"Failed to load attack path from '{ref}': {e}")
            return None

    def validate_dataflow(self, vuln: VulnerabilityContext) -> Dict[str, Any]:
        """
        Deep validation of dataflow path using LLM to assess true exploitability.

        This is the CRITICAL step that separates real vulnerabilities from false positives.

        Args:
            vuln: VulnerabilityContext with extracted dataflow

        Returns:
            Dictionary with validation results
        """
        if not vuln.has_dataflow or not vuln.dataflow_source or not vuln.dataflow_sink:
            logger.warning("No dataflow to validate")
            return {}

        logger.info("=" * 70)
        logger.info("DATAFLOW VALIDATION (Deep Analysis)")
        logger.info("=" * 70)

        # Build comprehensive validation prompt
        validation_prompt = f"""You are an elite security researcher performing DEEP VALIDATION of a dataflow path detected by CodeQL.

**CRITICAL MISSION:** Determine if this is a REAL exploitable vulnerability or a FALSE POSITIVE.

**VULNERABILITY:** {vuln.rule_id}
**MESSAGE:** {vuln.message}

═══════════════════════════════════════════════════════════════
COMPLETE DATAFLOW PATH ANALYSIS
═══════════════════════════════════════════════════════════════

**SOURCE (Where data enters the system):**
Location: {vuln.dataflow_source['file']}:{vuln.dataflow_source['line']}
Type: {vuln.dataflow_source['label']}

Code:
```
{vuln.dataflow_source['code']}
```

"""

        # Add each intermediate step with detailed analysis
        if vuln.dataflow_steps:
            validation_prompt += f"**INTERMEDIATE STEPS ({len(vuln.dataflow_steps)} transformations):**\n\n"

            for i, step in enumerate(vuln.dataflow_steps, 1):
                marker = "🛡️ SANITIZER" if step['is_sanitizer'] else "⚙️ TRANSFORMATION"
                validation_prompt += f"""{marker} #{i}: {step['label']}
Location: {step['file']}:{step['line']}

Code:
```
{step['code']}
```

"""

        validation_prompt += f"""**SINK (Where data reaches dangerous operation):**
Location: {vuln.dataflow_sink['file']}:{vuln.dataflow_sink['line']}
Type: {vuln.dataflow_sink['label']}

Code:
```
{vuln.dataflow_sink['code']}
```

═══════════════════════════════════════════════════════════════
VALIDATION TASKS (BE BRUTALLY HONEST)
═══════════════════════════════════════════════════════════════

**1. SOURCE CONTROL ANALYSIS:**
   Examine the source code carefully:
   - Is this data from HTTP request, user input, file upload? → ATTACKER CONTROLLED ✅
   - Is it from config file, environment variable? → REQUIRES ACCESS FIRST 🔶
   - Is it a hardcoded constant, internal variable? → FALSE POSITIVE ❌

   Look at the actual code - what does it show?

**2. SANITIZER EFFECTIVENESS ANALYSIS:**
"""

        if vuln.sanitizers_found:
            validation_prompt += f"""   You detected {len(vuln.sanitizers_found)} sanitizer(s): {', '.join(vuln.sanitizers_found)}

   For EACH sanitizer, analyze the actual code:
   - What exactly does it do? (trim, replace, escape, encode, validate)
   - Is it appropriate for the vulnerability type?
     * SQL injection needs parameterized queries or escaping
     * XSS needs HTML entity encoding
     * Command injection needs input validation or safe APIs
   - Can it be bypassed? Common bypasses:
     * Incomplete sanitization (only filters some chars)
     * Encoding bypasses (URL encoding, double encoding)
     * Case sensitivity issues
     * Unicode/UTF-8 bypasses
   - Is it applied to ALL code paths?

"""
        else:
            validation_prompt += """   NO sanitizers detected in dataflow path!
   - Is there implicit sanitization (type checking, framework protection)?
   - Are there barriers in the runtime environment?

"""

        validation_prompt += """**3. REACHABILITY ANALYSIS:**
   - Can an attacker actually trigger this code path?
   - Are there authentication/authorization checks?
   - Are there prerequisites that block exploitation?
   - Is this code path actually used in production?

**4. EXPLOITABILITY ASSESSMENT:**
   Consider the COMPLETE path from source to sink:
   - Can attacker-controlled data reach the sink with malicious content intact?
   - What specific payload would exploit this?
   - What is the attack complexity (low/medium/high)?

**5. IMPACT ANALYSIS:**
   If exploitable, what can an attacker achieve?
   - Code execution, data exfiltration, privilege escalation?
   - Estimate CVSS score (0.0-10.0)

═══════════════════════════════════════════════════════════════
YOUR VERDICT
═══════════════════════════════════════════════════════════════

Provide a structured assessment covering ALL points above.
Be specific - cite actual code and explain your reasoning.
If you find this is NOT exploitable, explain exactly why (don't just say "sanitized").
If it IS exploitable, provide the exact attack path and payload concept.
"""

        # Validation schema
        validation_schema = {
            "source_type": "string - describe what type of source this is (user_input/config/hardcoded/etc)",
            "source_attacker_controlled": "boolean - can attacker control this source?",
            "source_reasoning": "string - explain why source is or isn't attacker-controlled",

            "sanitizers_found": f"integer - number of sanitizers ({len(vuln.sanitizers_found)})",
            "sanitizers_effective": "boolean - do sanitizers prevent exploitation?",
            "sanitizer_details": "list of dicts with keys: name, purpose, bypass_possible, bypass_method",

            "path_reachable": "boolean - can this code path be reached by attacker?",
            "reachability_barriers": "list of strings - what blocks reaching this path?",

            "is_exploitable": "boolean - FINAL VERDICT: is this truly exploitable?",
            "exploitability_confidence": "float (0.0-1.0) - how confident in this assessment?",
            "exploitability_reasoning": "string - detailed explanation of verdict",

            "attack_complexity": "string - low/medium/high - difficulty of exploitation",
            "attack_prerequisites": "list of strings - what attacker needs to succeed",
            "attack_payload_concept": "string - describe what payload would work, or empty if not exploitable",

            "impact_if_exploited": "string - what attacker can achieve",
            "cvss_estimate": "float (0.0-10.0) - severity score",

            "false_positive": "boolean - is this a false positive?",
            "false_positive_reason": "string - why it's false positive, or empty",
        }

        system_prompt = """You are an elite security researcher specializing in:
- Advanced vulnerability analysis and exploit development
- Sanitizer bypass techniques and evasion
- Real-world attack scenarios and feasibility assessment
- CVSS scoring and risk assessment

Your job is to validate dataflow findings with BRUTAL HONESTY:
- If it's a false positive, say so clearly and explain why
- If sanitizers are effective, explain exactly how they work
- If it's exploitable, provide specific attack details
- Base ALL conclusions on the actual code provided

Do NOT:
- Guess or assume
- Give generic answers
- Overstate or understate severity
- Ignore sanitizers or barriers"""

        try:
            logger.info("Sending dataflow to LLM for deep validation...")

            validation, _response = self.llm.generate_structured(
                prompt=validation_prompt,
                schema=validation_schema,
                system_prompt=system_prompt
            )

            if validation is None:
                logger.info("No external LLM available — skipping dataflow validation")
                return {}

            logger.info("✓ Dataflow validation complete:")
            logger.info(f"  Source attacker-controlled: {validation.get('source_attacker_controlled')}")
            logger.info(f"  Sanitizers effective: {validation.get('sanitizers_effective')}")
            logger.info(f"  Path reachable: {validation.get('path_reachable')}")
            logger.info(f"  Is exploitable: {validation.get('is_exploitable')}")
            logger.info(f"  Confidence: {validation.get('exploitability_confidence', 0):.2f}")
            logger.info(f"  Attack complexity: {validation.get('attack_complexity')}")
            logger.info(f"  False positive: {validation.get('false_positive')}")

            if validation.get('sanitizer_details'):
                logger.info(f"\n  Sanitizer Analysis:")
                for san_detail in validation.get('sanitizer_details', []):
                    logger.info(f"    - {san_detail.get('name')}")
                    logger.info(f"      Purpose: {san_detail.get('purpose')}")
                    logger.info(f"      Bypassable: {san_detail.get('bypass_possible')}")
                    if san_detail.get('bypass_method'):
                        logger.info(f"      Bypass: {san_detail.get('bypass_method')[:100]}")

            if validation.get('attack_payload_concept'):
                logger.info(f"\n  Attack Payload Concept:")
                logger.info(f"    {validation.get('attack_payload_concept')[:200]}")

            # Save validation details
            validation_file = self.out_dir / "validation" / f"{vuln.finding_id}_validation.json"
            save_json(validation_file, validation)

            return validation

        except Exception as e:
            logger.error(f"✗ Dataflow validation failed: {e}")
            return {}

    def analyze_vulnerability(self, vuln: VulnerabilityContext) -> bool:
        is_prep = isinstance(self.llm, ClaudeCodeProvider)

        if is_prep:
            logger.debug(f"Prepping: {vuln.rule_id} at {vuln.file_path}:{vuln.start_line}")
        else:
            logger.info("=" * 70)
            logger.info(f"Analysing vulnerability: {vuln.rule_id}")
            logger.info(f"  File: {vuln.file_path}:{vuln.start_line}")
            logger.info(f"  Severity: {vuln.level}")
            logger.info(f"  Has dataflow: {'Yes' if vuln.has_dataflow else 'No'}")
            logger.info(f"  Message: {vuln.message[:100]}..." if len(vuln.message) > 100 else f"  Message: {vuln.message}")

        # Read the actual vulnerable code
        if not vuln.read_vulnerable_code():
            logger.error(f"✗ Cannot read code for {vuln.finding_id}")
            return False

        if not is_prep:
            logger.info(f"✓ Read vulnerable code ({len(vuln.full_code)} chars)")
            logger.info(f"✓ Read context ({len(vuln.surrounding_context)} chars)")

        # Extract dataflow path if available
        if vuln.has_dataflow:
            if vuln.extract_dataflow():
                logger.info(f"✓ Dataflow path: {vuln.dataflow_path.get('total_steps', 0)} total steps")
                if vuln.sanitizers_found:
                    logger.info(f"  ⚠️  Sanitizers detected: {', '.join(vuln.sanitizers_found)}")
            else:
                logger.warning(f"⚠️  Failed to extract dataflow path")

        # Generate analysis using LLM
        from packages.llm_analysis.prompts import (
            build_analysis_prompt, build_analysis_schema, ANALYSIS_SYSTEM_PROMPT,
        )

        analysis_schema = build_analysis_schema(has_dataflow=vuln.has_dataflow)

        prompt = build_analysis_prompt(
            rule_id=vuln.rule_id,
            level=vuln.level,
            file_path=vuln.file_path,
            start_line=vuln.start_line,
            end_line=vuln.end_line,
            message=vuln.message,
            code=vuln.full_code,
            surrounding_context=vuln.surrounding_context,
            has_dataflow=vuln.has_dataflow,
            dataflow_source=vuln.dataflow_source,
            dataflow_sink=vuln.dataflow_sink,
            dataflow_steps=vuln.dataflow_steps,
        )

        system_prompt = ANALYSIS_SYSTEM_PROMPT

        try:
            if not isinstance(self.llm, ClaudeCodeProvider):
                logger.info("Sending vulnerability to LLM for analysis...")

            # Use LLM for intelligent analysis
            analysis, _full_response = self.llm.generate_structured(
                prompt=prompt,
                schema=analysis_schema,
                system_prompt=system_prompt
            )

            if analysis is None:
                logger.debug("Prep mode — Phase 4 will handle analysis")
                return False

            vuln.exploitable = analysis.get("is_exploitable", False)
            vuln.exploitability_score = analysis.get("exploitability_score", 0.0)
            vuln.analysis = analysis

            logger.info("✓ LLM analysis complete:")
            logger.info(f"  True Positive: {analysis.get('is_true_positive', False)}")
            logger.info(f"  Exploitable: {vuln.exploitable}")
            logger.info(f"  Exploitability Score: {vuln.exploitability_score:.2f}")
            logger.info(f"  Severity Assessment: {analysis.get('severity_assessment', 'unknown')}")
            # Compute CVSS score from vector if provided
            from packages.cvss import score_finding
            score_finding(analysis)
            if analysis.get("cvss_score_estimate"):
                logger.info(f"  CVSS: {analysis['cvss_score_estimate']} ({analysis.get('severity_assessment', '?')}) from {analysis.get('cvss_vector')}")
            else:
                logger.info(f"  CVSS Estimate: {analysis.get('cvss_score_estimate', 'N/A')}")

            # Log dataflow-specific analysis
            if vuln.has_dataflow and 'source_attacker_controlled' in analysis:
                logger.info(f"\n  Dataflow Analysis:")
                logger.info(f"    Source attacker-controlled: {analysis.get('source_attacker_controlled', 'N/A')}")
                logger.info(f"    Sanitizers effective: {analysis.get('sanitizers_effective', 'N/A')}")
                if analysis.get('sanitizer_bypass_technique'):
                    logger.info(f"    Bypass technique: {(analysis.get('sanitizer_bypass_technique') or '')[:100]}...")
                logger.info(f"    Dataflow exploitable: {analysis.get('dataflow_exploitable', 'N/A')}")

            logger.info(f"\n  Reasoning: {(analysis.get('reasoning') or '')[:150]}...")
            if analysis.get('attack_scenario'):
                logger.info(f"  Attack Scenario: {analysis.get('attack_scenario')[:150]}...")

            # Deep dataflow validation for high-confidence findings
            if vuln.has_dataflow and vuln.exploitable:
                logger.info("\n" + "─" * 70)
                logger.info("🔍 Performing DEEP DATAFLOW VALIDATION...")
                logger.info("─" * 70)

                validation = self.validate_dataflow(vuln)

                if validation:
                    # Update exploitability based on validation
                    if validation.get('false_positive'):
                        logger.info(f"⚠️  Validation marked as FALSE POSITIVE:")
                        logger.info(f"    Reason: {validation.get('false_positive_reason')}")
                        vuln.exploitable = False
                        vuln.exploitability_score = 0.0
                    elif not validation.get('is_exploitable'):
                        logger.info(f"⚠️  Validation determined NOT EXPLOITABLE:")
                        logger.info(f"    Reason: {(validation.get('exploitability_reasoning') or '')[:150]}")
                        vuln.exploitable = False
                        vuln.exploitability_score = validation.get('exploitability_confidence', 0.0) * 0.5
                    else:
                        # Validation confirms exploitability
                        logger.info(f"✓ Validation confirms EXPLOITABLE")
                        # Use validation confidence to refine score
                        vuln.exploitability_score = max(
                            vuln.exploitability_score,
                            validation.get('exploitability_confidence', vuln.exploitability_score)
                        )

                    # Store validation in analysis
                    analysis['dataflow_validation'] = validation

            # Save detailed analysis
            analysis_file = self.out_dir / "analysis" / f"{vuln.finding_id}.json"
            save_json(analysis_file, {
                "finding_id": vuln.finding_id,
                "rule_id": vuln.rule_id,
                "file": vuln.file_path,
                "analysis": analysis,
            })

            return True

        except Exception as e:
            logger.error(f"✗ LLM analysis failed: {e}")
            if _is_auth_error(e):
                print("⚠️  LLM authentication failed — check your API key. Falling back to heuristic analysis.")
            else:
                logger.warning("  Using fallback heuristic analysis")
            # Fallback to marking as potentially exploitable
            vuln.exploitable = vuln.level == "error"
            vuln.exploitability_score = 0.5
            return False

    def generate_exploit(self, vuln: VulnerabilityContext) -> bool:

        if not vuln.exploitable:
            logger.debug(f"⊘ Skipping exploit generation (not exploitable)")
            return False

        logger.info("─" * 70)
        logger.info(f"Generating exploit PoC for {vuln.rule_id}")
        logger.info(f"   Target: {vuln.file_path}:{vuln.start_line}")

        from packages.llm_analysis.prompts import (
            build_exploit_prompt, EXPLOIT_SYSTEM_PROMPT,
        )

        prompt = build_exploit_prompt(
            rule_id=vuln.rule_id,
            file_path=vuln.file_path,
            start_line=vuln.start_line,
            level=vuln.level,
            analysis=vuln.analysis,
            code=vuln.full_code,
            surrounding_context=vuln.surrounding_context,
            feasibility=vuln.feasibility if hasattr(vuln, 'feasibility') else None,
        )

        system_prompt = EXPLOIT_SYSTEM_PROMPT

        try:
            logger.info("Requesting exploit code from LLM...")

            response = self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.8  # Higher creativity for exploit generation. YMMV
            )

            if response is None:
                logger.info("No external LLM available — skipping exploit generation")
                return False

            # Extract code from response
            exploit_code = self._extract_code(response.content)

            if exploit_code:
                vuln.exploit_code = exploit_code

                # Save exploit
                exploit_file = self.out_dir / "exploits" / f"{vuln.finding_id}_exploit.cpp"
                exploit_file.parent.mkdir(exist_ok=True, parents=True)
                exploit_file.write_text(exploit_code)

                logger.info(f"   ✓ Exploit generated: {len(exploit_code)} bytes")
                logger.info(f"   ✓ Saved to: {exploit_file.name}")
                return True
            else:
                logger.warning("   ✗ LLM response did not contain valid code")
                return False

        except Exception as e:
            logger.error(f"   ✗ Exploit generation failed: {e}")
            if _is_auth_error(e):
                print("⚠️  LLM authentication failed — check your API key.")
            return False

    def generate_patch(self, vuln: VulnerabilityContext) -> bool:
        logger.info("─" * 70)
        logger.info(f"🔧 Generating secure patch for {vuln.rule_id}")
        logger.info(f"   Target: {vuln.file_path}:{vuln.start_line}")

        # Read full file content for better context
        file_path = vuln.get_full_file_path()
        if not file_path or not file_path.exists():
            logger.error(f"   ✗ File not found: {file_path}")
            return False

        logger.info(f"   ✓ Reading full file for context...")

        with open(file_path) as f:
            full_file_content = f.read()

        from packages.llm_analysis.prompts import (
            build_patch_prompt, PATCH_SYSTEM_PROMPT,
        )

        # Load attack path if available
        attack_path = None
        if vuln.attack_path_ref:
            attack_path = self._load_attack_path(vuln.attack_path_ref)

        prompt = build_patch_prompt(
            rule_id=vuln.rule_id,
            file_path=vuln.file_path,
            start_line=vuln.start_line,
            end_line=vuln.end_line,
            message=vuln.message,
            analysis=vuln.analysis,
            code=vuln.full_code,
            full_file_content=full_file_content,
            feasibility=vuln.feasibility,
            attack_path=attack_path,
        )

        system_prompt = PATCH_SYSTEM_PROMPT

        try:
            logger.info("   🤖 Requesting secure patch from LLM...")

            response = self.llm.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.3  # Lower temperature for safer patches
            )

            if response is None:
                logger.info("   No external LLM available — skipping patch generation")
                return False

            patch_content = response.content

            # Save patch
            patch_file = self.out_dir / "patches" / f"{vuln.finding_id}_patch.md"
            patch_file.parent.mkdir(exist_ok=True, parents=True)

            patch_content_formatted = f"""# Security Patch for {vuln.rule_id}

**File:** {vuln.file_path}
**Lines:** {vuln.start_line}-{vuln.end_line}
**Severity:** {vuln.level}

## Vulnerability Analysis
{json.dumps(vuln.analysis, indent=2)}

## Patch

{patch_content}

---
*Generated by RAPTOR Autonomous Security Agent*
*Review and test before applying to production*
"""

            patch_file.write_text(patch_content_formatted)
            vuln.patch_code = patch_content

            logger.info(f"   ✓ Patch generated: {len(patch_content)} bytes")
            logger.info(f"   ✓ Saved to: {patch_file.name}")
            return True

        except Exception as e:
            logger.error(f"   ✗ Patch generation failed: {e}")
            if _is_auth_error(e):
                print("⚠️  LLM authentication failed — check your API key.")
            return False

    def _extract_code(self, content: str) -> Optional[str]:
        """Extract code from LLM response (handles markdown code blocks)."""
        # Try to find C++ code block first
        if "```cpp" in content:
            parts = content.split("```cpp")
            if len(parts) > 1:
                code = parts[1].split("```")[0].strip()
                return code
        # Try to find C code block
        elif "```c" in content:
            parts = content.split("```c")
            if len(parts) > 1:
                code = parts[1].split("```")[0].strip()
                return code
        # Try to find Python code block
        elif "```python" in content:
            parts = content.split("```python")
            if len(parts) > 1:
                code = parts[1].split("```")[0].strip()
                return code
        elif "```" in content:
            parts = content.split("```")
            if len(parts) > 1:
                code = parts[1].strip()
                return code

        # If no code block, return content as-is
        return content.strip()

    def _load_validated_findings(self, findings_path: str) -> List[Dict[str, Any]]:
        """Load pre-validated findings from the validation pipeline's findings.json.

        Skips ruled_out findings and unlikely verdict findings.
        Converts validation format to VulnerabilityContext expected format.
        """
        data = load_json(findings_path, strict=True)
        if data is None:
            raise FileNotFoundError(f"Findings file not found: {findings_path}")

        converted = convert_validated_to_agent_format(data)

        logger.info(f"Loaded {len(converted)} findings from {Path(findings_path).name} "
                    f"(skipped {len(data.get('findings', [])) - len(converted)} ruled out/unlikely)")
        return converted

    def process_findings(self, sarif_paths: List[str] = None, findings_path: str = None,
                         max_findings: int = 10, checklist: Dict[str, Any] = None) -> Dict[str, Any]:
        """Process findings with full LLM-powered autonomous workflow."""
        start_time = time.time()

        # Parse findings
        is_prep_only = isinstance(self.llm, ClaudeCodeProvider)
        if not is_prep_only:
            logger.info("=" * 70)
            logger.info("AUTONOMOUS VULNERABILITY ANALYSIS")
            logger.info("=" * 70)

        if findings_path:
            # Load pre-validated findings
            unique_findings = self._load_validated_findings(findings_path)
        else:
            all_findings = []
            for sarif_path in (sarif_paths or []):
                findings = parse_sarif_findings(Path(sarif_path))
                logger.info(f"Loaded {len(findings)} findings from {Path(sarif_path).name}")
                all_findings.extend(findings)

            unique_findings = deduplicate_findings(all_findings)

        # Prioritize findings with dataflow paths (for better validation coverage)
        findings_with_dataflow = [f for f in unique_findings if f.get('has_dataflow')]
        findings_without_dataflow = [f for f in unique_findings if not f.get('has_dataflow')]

        # Put dataflow findings first, then others
        prioritized_findings = findings_with_dataflow + findings_without_dataflow
        if not is_prep_only:
            # Cap in sequential mode — in prep mode, Phase 4 enforces the cap
            prioritized_findings = prioritized_findings[:max_findings]

        if is_prep_only:
            logger.debug(f"Dedup: {len(unique_findings)} unique, {len(findings_with_dataflow)} with dataflow")
        else:
            logger.info(f"After deduplication: {len(unique_findings)} unique findings")
            logger.info(f"  With dataflow: {len(findings_with_dataflow)}")
            logger.info(f"  Without dataflow: {len(findings_without_dataflow)}")
            logger.info(f"Processing top {max_findings} findings (dataflow prioritized)")
            logger.info("=" * 70)

        unique_findings = prioritized_findings

        results = []
        analyzed = 0
        exploitable = 0
        exploits_generated = 0
        patches_generated = 0
        dataflow_validated = 0
        false_positives_found = 0
        idx = 0  # Initialize idx to prevent UnboundLocalError when unique_findings is empty

        is_prep = isinstance(self.llm, ClaudeCodeProvider)

        with HackerProgress(total=len(unique_findings), operation="Analyzing vulnerabilities",
                            disabled=is_prep) as progress:
            for idx, finding in enumerate(unique_findings, 1):
                progress.update(current=idx, message=f"{finding.get('rule_id', 'unknown')}")

                if is_prep and idx % 10 == 0:
                    print(f"  Preparing... {idx}/{len(unique_findings)}", flush=True)

                if not is_prep:
                    logger.info("")
                    logger.info(f"{'█' * 70}")
                    logger.info(f"VULNERABILITY {idx}/{len(unique_findings)}")
                    logger.info(f"{'█' * 70}")

                # Attach function metadata from inventory checklist
                if checklist and not finding.get("metadata"):
                    fpath = finding.get("file_path") or finding.get("file") or ""
                    fline = finding.get("start_line") if finding.get("start_line") is not None else finding.get("startLine", 0)
                    func = _lookup_function(
                        checklist, fpath, fline,
                        repo_root=str(self.repo_path),
                    )
                    if func and func.get("metadata"):
                        finding["metadata"] = dict(func["metadata"])

                vuln = VulnerabilityContext(finding, self.repo_path)

                # 1. Autonomous analysis (LLM-powered, or prep-only)
                if self.analyze_vulnerability(vuln):
                    analyzed += 1

                    # Track dataflow validation
                    if vuln.has_dataflow and vuln.analysis and 'dataflow_validation' in vuln.analysis:
                        dataflow_validated += 1
                        validation = vuln.analysis['dataflow_validation']
                        if validation.get('false_positive'):
                            false_positives_found += 1

                    if vuln.exploitable:
                        exploitable += 1

                        # 2. Generate exploit using LLM
                        if self.generate_exploit(vuln):
                            exploits_generated += 1

                        # 3. Generate patch using LLM (only for exploitable)
                        if self.generate_patch(vuln):
                            patches_generated += 1
                    else:
                        logger.debug(f"⊘ Skipping patch generation (not exploitable)")

                # Always include finding in results (with or without LLM analysis)
                results.append(vuln.to_dict())

            # Show progress
            if isinstance(self.llm, ClaudeCodeProvider):
                logger.debug(f"Progress: {idx}/{len(unique_findings)} prepped")
            else:
                logger.info("")
                logger.info(f"Progress: {idx}/{len(unique_findings)} analyzed, "
                           f"{exploitable} exploitable, "
                           f"{exploits_generated} exploits, "
                           f"{patches_generated} patches, "
                           f"{dataflow_validated} dataflow validated")

        execution_time = time.time() - start_time

        # Get LLM stats from client (aggregates all provider stats)
        llm_stats = self.llm.get_stats()

        # Determine mode: full (external LLM did analysis) or prep_only (mechanical prep,
        # Claude Code or manual review handles reasoning)
        is_prep_only = isinstance(self.llm, ClaudeCodeProvider)

        report = {
            "mode": "prep_only" if is_prep_only else "full",
            "processed": len(unique_findings),
            "prepped": len(results),
            "analyzed": analyzed,
            "exploitable": exploitable,
            "exploits_generated": exploits_generated,
            "patches_generated": patches_generated,
            "dataflow_validated": dataflow_validated,
            "false_positives_caught": false_positives_found,
            "execution_time": execution_time,
            "llm_stats": llm_stats,
            "results": results,
        }

        # Save report
        report_file = self.out_dir / "autonomous_analysis_report.json"
        save_json(report_file, report)

        if is_prep_only:
            logger.debug(f"Prep complete: {len(unique_findings)} findings")
        else:
            logger.info(f"✓ Processed: {len(unique_findings)} findings")
            logger.info(f"✓ Analyzed: {analyzed} with LLM")
            logger.info(f"✓ Exploitable: {exploitable} vulnerabilities")
            logger.info(f"✓ Exploits generated: {exploits_generated}")
            logger.info(f"✓ Patches generated: {patches_generated}")
            logger.info(f"")
            if dataflow_validated > 0:
                logger.info(f"Dataflow Validation:")
                logger.info(f"   Deep validated: {dataflow_validated} dataflow paths")
                logger.info(f"   False positives caught: {false_positives_found}")
                logger.info(f"")
            logger.info(f"LLM Statistics:")
            logger.info(f"   Total requests: {llm_stats['total_requests']}")
            logger.info(f"   Total cost: ${llm_stats['total_cost']:.4f}")
            logger.info(f"   Execution time: {execution_time:.1f}s")
        if not is_prep_only:
            logger.info(f"")
            logger.info(f"Report saved: {report_file}")
            logger.info("=" * 70)

        return report


def find_validation_artifacts(workdir: Path = None) -> Optional[Path]:
    """Search for validation artifacts from recent pipeline runs.

    Checks:
    - workdir/validation/findings.json (from /agentic)
    - .out/exploitability-validation-*/findings.json (from /validate)

    Returns the most recent findings.json path, or None.
    """
    candidates = []

    # Check workdir/validation/ (from /agentic pipeline)
    if workdir:
        agentic_findings = workdir / "validation" / "findings.json"
        if agentic_findings.exists():
            candidates.append(agentic_findings)

    # Check .out/exploitability-validation-*/ (from /validate)
    out_dir = Path(".out").resolve()  # Lock to absolute path at call time
    if out_dir.exists():
        for d in sorted(out_dir.glob("exploitability-validation-*"), reverse=True):
            findings_path = d / "findings.json"
            if findings_path.exists():
                candidates.append(findings_path)
                break  # Most recent only

    if candidates:
        # Return most recently modified
        return max(candidates, key=lambda p: p.stat().st_mtime)
    return None


def main() -> None:
    ap = argparse.ArgumentParser(
        description="RAPTOR Autonomous Security Agent"
    )
    ap.add_argument("--repo", required=True, help="Repository path")
    ap.add_argument("--sarif", nargs="+", help="SARIF files")
    ap.add_argument("--findings", help="Validated findings.json from exploitability validation pipeline")
    ap.add_argument("--out", help="Output directory")
    ap.add_argument("--max-findings", type=int, default=10, help="Max findings to process")
    ap.add_argument("--checklist", help="Inventory checklist.json for function metadata lookup")
    ap.add_argument("--prep-only", action="store_true",
                    help="Skip LLM analysis; produce structured findings for external orchestration")

    args = ap.parse_args()

    if not args.sarif and not args.findings:
        ap.error("Either --sarif or --findings is required")

    # Suggest --findings if validation artifacts exist nearby
    if args.sarif and not args.findings:
        out_path = Path(args.out).resolve() if args.out else None
        nearby = find_validation_artifacts(out_path)
        if nearby:
            logger.info(f"Validation artifacts found at {nearby}")
            logger.info("Use --findings for enriched analysis with feasibility data")

    repo_path = Path(args.repo).resolve()
    if args.out:
        out_dir = Path(args.out).resolve()
    else:
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        out_dir = RaptorConfig.get_out_dir() / f"autonomous_v2_{timestamp}"

    # Initialize agent with LLM
    agent = AutonomousSecurityAgentV2(repo_path, out_dir, prep_only=args.prep_only)

    # Load checklist for metadata lookup
    checklist = None
    if args.checklist:
        # Non-strict: checklist is optional metadata, pipeline continues without it
        checklist = load_json(args.checklist)
        if checklist:
            logger.info(f"Loaded inventory checklist: {args.checklist}")
        else:
            logger.warning(f"Could not load checklist: {args.checklist}")

    # Process findings - route based on input type
    if args.findings:
        report = agent.process_findings(findings_path=args.findings, max_findings=args.max_findings,
                                        checklist=checklist)
    else:
        report = agent.process_findings(sarif_paths=args.sarif, max_findings=args.max_findings,
                                        checklist=checklist)

    if report.get('mode') != 'prep_only':
        print("\n" + "=" * 70)
        print("Autonomous Security Agent Report")
        print("=" * 70)
        print(f"Analyzed: {report['analyzed']}")
        print(f"Exploitable: {report['exploitable']}")
        print(f"Exploits generated: {report['exploits_generated']} (LLM-generated)")
        print(f"Patches generated: {report['patches_generated']} (LLM-generated)")
        print(f"LLM cost: ${report['llm_stats']['total_cost']:.4f}")
        print(f"Output: {out_dir}")
        print("=" * 70)


if __name__ == "__main__":
    main()
