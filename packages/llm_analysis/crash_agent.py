#!/usr/bin/env python3
"""
Crash Analysis Agent

LLM-powered analysis of crashes from fuzzing.
"""

import json
import time
from pathlib import Path
from typing import Any, Dict, List

from core.logging import get_logger
from packages.binary_analysis import CrashContext
from packages.fuzzing import Crash
from .llm.client import LLMClient
from .llm.config import LLMConfig

logger = get_logger()


class CrashAnalysisAgent:
    """LLM-powered crash analysis agent."""

    def __init__(self, binary_path: Path, out_dir: Path, llm_config: LLMConfig = None):
        self.binary = Path(binary_path)
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

        # Initialize LLM client with multi-model support, fallback, and retry
        self.llm_config = llm_config or LLMConfig()
        self.llm = LLMClient(self.llm_config)

        logger.info("RAPTOR Crash Analysis Agent initialized")
        logger.info(f"Binary: {binary_path}")
        logger.info(f"Output: {out_dir}")
        logger.info(f"LLM: {self.llm_config.primary_model.provider}/{self.llm_config.primary_model.model_name}")

        # Also print to console
        print(f"\n Using LLM: {self.llm_config.primary_model.provider}/{self.llm_config.primary_model.model_name}")
        if self.llm_config.primary_model.cost_per_1k_tokens > 0:
            print(f"Cost: ${self.llm_config.primary_model.cost_per_1k_tokens:.4f} per 1K tokens")
        else:
            print(f"Cost: FREE (self-hosted model)")

        # Warn about Ollama model limitations for exploit generation
        if "ollama" in self.llm_config.primary_model.provider.lower():
            print()
            print("⚠️  IMPORTANT: You are using an Ollama model.")
            print("   • Crash analysis and triage: Works well with Ollama models")
            print("   • Exploit generation: Requires frontier models (Anthropic Claude / OpenAI GPT-4)")
            print("   • Ollama models may generate invalid/non-compilable exploit code")
            print()
            print("   For production-quality exploits, use:")
            print("     export ANTHROPIC_API_KEY=your_key  (recommended)")
            print("     export OPENAI_API_KEY=your_key")
        print()

    def analyse_crash(self, crash_context: CrashContext) -> bool:
        """
        Analyse a crash using LLM.

        Args:
            crash_context: Crash context with debugging information

        Returns:
            True if analysis succeeded
        """
        logger.info("=" * 70)
        logger.info(f"Analysing crash: {crash_context.crash_id}")
        logger.info(f"  Signal: {crash_context.signal}")
        logger.info(f"  Function: {crash_context.function_name}")
        logger.info(f"  Crash address: {crash_context.crash_address}")

        # Build prompt for LLM
        prompt = f"""Analyse this crash from fuzzing:

**Binary:** {crash_context.binary_path.name}
**Crash ID:** {crash_context.crash_id}
**Signal:** {self._signal_name(crash_context.signal)}

**Stack Trace:**
```
{crash_context.stack_trace or "No stack trace available"}
```

**Registers:**
```
{self._format_registers(crash_context.registers)}
```

**Crash Instruction:**
```
{crash_context.crash_instruction or "No crash instruction available"}
```

**Crash Address:** {crash_context.crash_address or "Unknown"}
**Function:** {crash_context.function_name or "Unknown"}
**Source Location:** {crash_context.source_location or "Unknown"}

**Disassembly (crash site):**
```assembly
{crash_context.disassembly or "No disassembly available"}
```

**Memory Layout & Protections:**
- ASLR: {crash_context.binary_info.get('aslr_enabled', 'unknown')}
- Stack Canaries: {crash_context.binary_info.get('stack_canaries', 'unknown')}
- NX/DEP: {crash_context.binary_info.get('nx_enabled', 'unknown')}
- ASan Enabled: {crash_context.binary_info.get('asan_enabled', 'unknown')}
- Memory Region: {crash_context.binary_info.get('memory_region', 'unknown')}
- Environmental Crash: {crash_context.binary_info.get('environmental_crash', 'false')} ({crash_context.binary_info.get('reason', '')})

**ASan Diagnostics (if available):**
```
{crash_context.binary_info.get('asan_output', 'No ASan diagnostics available')}
```

**Input that triggered crash:**
Size: {crash_context.input_file.stat().st_size} bytes
Path: {crash_context.input_file}

**Hex Dump (first 512 bytes):**
```
{crash_context.input_file.read_bytes()[:512].hex(' ', 16)}
```

**Printable ASCII (if any):**
```
{''.join(chr(b) if 32 <= b <= 126 else '.' for b in crash_context.input_file.read_bytes()[:512])}
```

**Your Task:**
Analyse this crash and provide:
1. **is_exploitable** (boolean): Can this be exploited for arbitrary code execution or memory disclosure?
2. **exploitability_score** (float 0-1): Confidence that this is exploitable
3. **crash_type** (string): Classify the crash (heap_overflow, stack_overflow, use_after_free, null_deref, format_string, integer_overflow, etc.)
4. **severity_assessment** (string): low/medium/high/critical
5. **cvss_estimate** (float): CVSS 3.1 base score estimate
6. **attack_scenario** (string): Describe how an attacker would exploit this
7. **exploitation_primitives** (list): What primitives are needed (arbitrary_write, controlled_pc, info_leak, etc.)
8. **recommended_next_steps** (string): What to try for exploitation
9. **is_true_positive** (boolean): Is this a real crash or false positive?
10. **control_flow_hijack** (boolean): Can the control flow (PC/RIP) be hijacked?
11. **memory_write** (boolean): Is there an arbitrary memory write primitive?

**Critical Analysis Points:**
- **Environmental Detection**: If environmental_crash=true, this may be a debugger breakpoint or sanitizer artifact, not a real vulnerability
- **Memory Region Analysis**: Consider if crash is in null_page, low_memory, mmap_region, or pie_base regions
- **Protection Analysis**: Factor in ASLR, stack canaries, and NX/DEP status when assessing exploitability
- **Address Patterns**: Look for controlled addresses, heap/stack proximity, or predictable memory layouts

**Additional Context:**
- Consider modern exploit mitigations (ASLR, DEP, stack canaries)
- Consider CPU architecture specifics (x86-64 calling conventions, register usage)
- Be realistic about real-world exploit feasibility. You are Mark Dowd or Charlie Miller. Do not guess wildly.

Focus on:
- Can we control PC/RIP despite protections?
- What memory corruption primitives are available?
- Is this a true bug or environmental issue (debugger/sanitizer artifact)?
- Does the crash location suggest controllable memory corruption?

If crash details are incomplete, make reasonable assumptions based on the signal type and available information, but clearly state your assumptions."""

        analysis_schema = {
            "is_true_positive": "boolean",
            "is_exploitable": "boolean", 
            "exploitability_score": "float",
            "crash_type": "string",
            "severity_assessment": "string",
            "cvss_estimate": "float",
            "attack_scenario": "string",
            "exploitation_primitives": "list",
            "recommended_next_steps": "string",
            "control_flow_hijack": "boolean",
            "memory_write": "boolean",
        }

        system_prompt = """You are an expert vulnerability researcher and exploit developer specializing in binary exploitation.

Analyse crashes from fuzzing and assess their exploitability with technical precision. Consider:
- Modern exploit mitigations (ASLR, DEP, stack canaries, CFI)
- CPU architecture specifics (x86-64 calling conventions, register usage)
- Exploit primitives (arbitrary write, controlled jump, info leak)
- Real-world attack feasibility

Be honest about exploitability - not every crash is exploitable."""

        try:
            logger.info("Sending crash to LLM for analysis...")

            analysis, full_response = self.llm.generate_structured(
                prompt=prompt,
                schema=analysis_schema,
                system_prompt=system_prompt,
            )

            # Update crash context
            crash_context.exploitability = "exploitable" if analysis.get("is_exploitable") else "not_exploitable"
            crash_context.crash_type = analysis.get("crash_type", "unknown")
            crash_context.cvss_estimate = analysis.get("cvss_estimate", 0.0)
            crash_context.analysis = analysis

            logger.info("✓ LLM analysis complete:")
            logger.info(f"  True Positive: {analysis.get('is_true_positive', False)}")
            logger.info(f"  Exploitable: {analysis.get('is_exploitable', False)}")
            logger.info(f"  Crash Type: {analysis.get('crash_type', 'unknown')}")
            logger.info(f"  Severity: {analysis.get('severity_assessment', 'unknown')}")
            logger.info(f"  CVSS: {analysis.get('cvss_estimate', 0.0)}")
            if analysis.get('attack_scenario'):
                logger.info(f"  Attack: {analysis.get('attack_scenario')[:150]}...")
            
            # Log some reasoning from the full response
            if full_response:
                # Extract reasoning (look for common patterns in LLM responses)
                reasoning_lines = []
                for line in full_response.split('\n')[:10]:  # First 10 lines
                    line = line.strip()
                    if line and not line.startswith('{') and not line.startswith('```') and len(line) > 20:
                        reasoning_lines.append(line[:200])  # Truncate long lines
                
                if reasoning_lines:
                    logger.info("  Reasoning: " + " | ".join(reasoning_lines[:3]))  # Show first 3 reasoning lines
            
            # Log summary of LLM reasoning
            if full_response:
                logger.info(f"  Full reasoning saved ({len(full_response)} chars)")
                # Show first few lines of reasoning for context
                reasoning_preview = full_response[:200].replace('\n', ' ').strip()
                if len(full_response) > 200:
                    reasoning_preview += "..."
                logger.debug(f"  Reasoning preview: {reasoning_preview}")

            # Save analysis
            analysis_file = self.out_dir / "analysis" / f"{crash_context.crash_id}.json"
            analysis_file.parent.mkdir(exist_ok=True)
            
            # Include input file information
            input_info = {
                "input_file_path": str(crash_context.input_file),
                "input_file_size": crash_context.input_file.stat().st_size,
            }
            
            # Include input content (truncated if too large)
            try:
                with open(crash_context.input_file, 'rb') as f:
                    input_data = f.read()
                    input_info["input_content_hex"] = input_data.hex()
                    # Include ASCII representation for readability
                    input_info["input_content_ascii"] = input_data.decode('ascii', errors='replace')[:500]  # Truncate long inputs
                    if len(input_data) > 500:
                        input_info["input_content_ascii"] += "... (truncated)"
            except Exception as e:
                input_info["input_content_error"] = str(e)
            
            with open(analysis_file, 'w') as f:
                json.dump({
                    "crash_id": crash_context.crash_id,
                    "crash_type": crash_context.crash_type,
                    "exploitability": crash_context.exploitability,
                    "input_info": input_info,
                    "analysis": analysis,
                    "full_response": full_response,  
                }, f, indent=2)

            return True

        except Exception as e:
            logger.error(f"✗ LLM analysis failed: {e}")
            return False

    def generate_exploit(self, crash_context: CrashContext) -> bool:
        """Generate exploit PoC for crash."""
        if crash_context.exploitability != "exploitable":
            logger.debug("⊘ Skipping exploit generation (not exploitable)")
            return False

        logger.info("─" * 70)
        logger.info(f" Generating exploit PoC for {crash_context.crash_type}")
        logger.info(f"   Target: {crash_context.binary_path.name}")

        # Warn if using Ollama model
        if "ollama" in self.llm_config.primary_model.provider.lower():
            logger.warning("⚠️  Using Ollama model - exploit code may not compile correctly")
            logger.warning("   For production exploits, use Anthropic Claude or OpenAI GPT-4")

        # Read the input file content for the prompt
        input_content = ""
        try:
            with open(crash_context.input_file, 'rb') as f:
                input_bytes = f.read()
                input_content = f"Hex: {input_bytes.hex()}\nASCII: {input_bytes.decode('ascii', errors='replace')}"
        except Exception as e:
            input_content = f"Error reading input file: {e}"

        prompt = f"""Generate a proof-of-concept exploit for this crash:

**Binary:** {crash_context.binary_path.name}
**Crash Type:** {crash_context.crash_type}
**Exploitability:** {crash_context.exploitability}
**CVSS:** {crash_context.cvss_estimate}

**Analysis:**
{json.dumps(crash_context.analysis, indent=2)}

**Crash Details:**
- Signal: {crash_context.signal}
- Function: {crash_context.function_name}
- Crash Address: {crash_context.crash_address}

**Input that triggered crash:**
Size: {crash_context.input_file.stat().st_size} bytes
Path: {crash_context.input_file}
Content:
{input_content}

**CRITICAL INSTRUCTIONS:**
Create a working proof-of-concept exploit that demonstrates the vulnerability by sending the crashing input to the target binary.

The exploit must:
1. Execute the target binary ({crash_context.binary_path.name})
2. Send the exact input bytes that caused the crash to trigger the vulnerability
3. Demonstrate that the vulnerability can be reached and exploited
4. Include full logging and visible terminal output showing the exploit in action


Respond with valid JSON containing exactly these fields:
- "code": The complete, compilable C++ exploit code as a string
- "reasoning": Any reasoning or explanation about the exploit technique

The "code" field must contain ONLY valid C++ code that can be compiled with:
g++ -o exploit exploit.cpp -fno-stack-protector

Example response format:
{{
  "code": "#include <iostream>\\n#include <unistd.h>\\nint main() {{ /* exploit code that runs target binary */ }}",
  "reasoning": "This exploit works by..."
}}"""

        exploit_schema = {
            "code": "string",
            "reasoning": "string"
        }

        system_prompt = """You are an expert binary exploitation specialist.
Generate structured JSON output with exploit code and reasoning.

CRITICAL: The exploit must actually run the target binary and send input to it to trigger the vulnerability.
Do NOT generate code that just demonstrates the vulnerability in isolation.

The exploit should:
1. Use execve() or system() to run the target binary
2. Send the exact crashing input bytes via stdin or a file
3. Demonstrate that the vulnerability is triggered

The "code" field must contain complete, compilable C++ code only.
The "reasoning" field can contain explanations and analysis."""

        try:
            logger.info("Requesting exploit code from LLM...")

            exploit_data, full_response = self.llm.generate_structured(
                prompt=prompt,
                schema=exploit_schema,
                system_prompt=system_prompt,
            )

            # Extract code from structured response
            logger.debug(f"Exploit data type: {type(exploit_data)}")
            logger.debug(f"Exploit data content: {exploit_data}")
            
            # Handle case where exploit_data might be a list (fallback extraction)
            if isinstance(exploit_data, list):
                logger.warning(f"Exploit data is a list with {len(exploit_data)} elements")
                if not exploit_data:
                    logger.error("Exploit data is an empty list - LLM returned invalid response")
                    return False
                elif isinstance(exploit_data[0], dict):
                    logger.info("Extracting first dict element from list")
                    exploit_data = exploit_data[0]
                else:
                    logger.error(f"First list element is {type(exploit_data[0])}, not dict. Content: {exploit_data[0]}")
                    # Try to parse as JSON string if it's a string
                    if isinstance(exploit_data[0], str):
                        try:
                            exploit_data = json.loads(exploit_data[0])
                            logger.info("Successfully parsed string as JSON")
                        except Exception as e:
                            logger.error(f"Failed to parse string as JSON: {e}")
                            return False
                    else:
                        return False
            
            # Ensure exploit_data is a dict at this point
            if not isinstance(exploit_data, dict):
                logger.error(f"Exploit data is still not a dict after processing: {type(exploit_data)}")
                return False

            exploit_code = exploit_data.get("code", "").strip()
            reasoning = exploit_data.get("reasoning", "")

            if not exploit_code:
                logger.error("No exploit code in structured response")
                logger.debug(f"Response keys: {exploit_data.keys()}")
                return False

            if exploit_code:
                crash_context.exploit_code = exploit_code

                # Save exploit with full response for debugging
                exploit_file = self.out_dir / "exploits" / f"{crash_context.crash_id}_exploit.cpp"
                exploit_file.parent.mkdir(exist_ok=True)
                exploit_file.write_text(exploit_code)

                # Save full response for analysis
                response_file = self.out_dir / "exploits" / f"{crash_context.crash_id}_exploit_response.txt"
                response_content = f"""REASONING:
{reasoning}

FULL LLM RESPONSE:
{full_response}"""
                response_file.write_text(response_content)

                logger.info(f"   ✓ Exploit generated: {len(exploit_code)} bytes")
                logger.info(f"   ✓ Saved to: {exploit_file.name}")
                return True
            else:
                logger.warning("   ✗ LLM response did not contain valid code")
                return False

        except Exception as e:
            logger.error(f"   ✗ Exploit generation failed: {e}")
            return False

    def _signal_name(self, signal: str) -> str:
        """Convert signal number to name."""
        signal_names = {
            "04": "SIGILL (Illegal Instruction)",
            "05": "SIGTRAP (Trace/Breakpoint Trap)",
            "06": "SIGABRT (Abort / Heap Corruption)",
            "07": "SIGBUS (Bus Error)",
            "08": "SIGFPE (Floating Point Exception)",
            "11": "SIGSEGV (Segmentation Fault)",
        }
        return signal_names.get(signal, f"Signal {signal}")

    def _format_registers(self, registers: Dict[str, str]) -> str:
        """Format registers for display."""
        if not registers:
            return "No register information available"

        lines = []
        for reg, value in sorted(registers.items()):
            lines.append(f"{reg:8s} = {value}")
        return "\n".join(lines)
