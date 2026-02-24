#!/usr/bin/env python3
"""
RAPTOR Meta-Orchestrator

Intelligent coordination of all RAPTOR tools with full awareness of:
- Tool capabilities and limitations
- When to use which tool
- How to combine tools synergistically
- Feedback loops between static/dynamic analysis

This is the "brain" that understands the value of each tool and
how they work together to achieve security goals.
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging
import time

# Add to path for imports
sys.path.insert(0, str(Path(__file__).parent))

try:
    from packages.llm_analysis.llm.client import LLMClient
except ImportError:
    LLMClient = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("meta-orchestrator")


class ToolCapability:
    """Represents what a tool can do and when to use it."""

    def __init__(self, name: str, capabilities: List[str], best_for: List[str],
                 limitations: List[str], integrates_with: List[str]):
        self.name = name
        self.capabilities = capabilities
        self.best_for = best_for
        self.limitations = limitations
        self.integrates_with = integrates_with


class RAPTORMetaOrchestrator:
    """
    Meta-level orchestrator that understands all RAPTOR tools and
    intelligently coordinates them to achieve security objectives.
    """

    def __init__(self, goal: str, target: str):
        """
        Initialize meta-orchestrator.

        Args:
            goal: Security objective (e.g., "Find RCE vulnerabilities")
            target: Target to analyze (repo path, binary, URL)
        """
        self.goal = goal
        self.target = target
        self.llm_client = LLMClient() if LLMClient else None

        # Define tool ecosystem
        self.tools = self._define_tool_ecosystem()

        # Tracking
        self.executed_tools: List[str] = []
        self.all_findings: Dict[str, Any] = {}
        self.iteration = 0
        self.max_iterations = 10

        # Frida resilience: track strategies tried and failures
        self.frida_strategies = {
            'spawn': {'tried': False, 'success': False, 'error': None},
            'attach': {'tried': False, 'success': False, 'error': None},
            'spawn-suspended': {'tried': False, 'success': False, 'error': None},
            'sudo-spawn': {'tried': False, 'success': False, 'error': None},
        }
        self.frida_fully_exhausted = False

        # Resolve actual binary for .app bundles
        self.resolved_binary = self._resolve_binary_target()

    def _resolve_binary_target(self) -> str:
        """
        Resolve the actual binary path for the target.
        For .app bundles, finds the executable inside Contents/MacOS/.
        """
        if not self.target.endswith('.app'):
            return self.target

        app_path = Path(self.target)
        if not app_path.exists():
            return self.target

        # Look for executable in Contents/MacOS/
        macos_dir = app_path / 'Contents' / 'MacOS'
        if macos_dir.exists():
            executables = list(macos_dir.iterdir())
            if executables:
                # Usually the main executable has the same name as the app
                app_name = app_path.stem  # e.g., "ZAP" from "ZAP.app"
                for exe in executables:
                    if exe.name == app_name or exe.name.lower() == app_name.lower():
                        logger.info(f"Resolved .app bundle to binary: {exe}")
                        return str(exe)
                # Otherwise return the first executable
                logger.info(f"Resolved .app bundle to binary: {executables[0]}")
                return str(executables[0])

        return self.target

    def _detect_target_type(self) -> str:
        """
        Detect whether target is a binary, source code, or web target.
        This determines which tools are appropriate.
        """
        target = self.target.lower()

        # Web targets
        if target.startswith(('http://', 'https://', 'www.')):
            return "WEB_APPLICATION"

        # Check if it's a file path
        target_path = Path(self.target)

        # macOS app bundle detection (BEFORE directory check)
        if self.target.endswith('.app') or '/.app/' in self.target:
            return "MACOS_APP_BUNDLE"

        # Binary detection
        if target_path.exists():
            # Check for executable
            if target_path.is_file():
                # Common binary locations
                if '/bin/' in self.target or '/sbin/' in self.target or '/opt/' in self.target:
                    return "BINARY_EXECUTABLE"
                # Check file extension
                suffix = target_path.suffix.lower()
                if suffix in ('', '.exe', '.so', '.dylib', '.dll', '.bin'):
                    return "BINARY_EXECUTABLE"
                # Source code extensions
                if suffix in ('.py', '.js', '.ts', '.java', '.c', '.cpp', '.go', '.rs', '.rb'):
                    return "SOURCE_CODE"

            # Directory - likely source code repo
            if target_path.is_dir():
                return "SOURCE_CODE_REPOSITORY"

        # Default: assume binary if path looks like executable
        if '/bin/' in self.target or self.target.endswith(('.exe', '.so', '.dylib')):
            return "BINARY_EXECUTABLE"

        return "UNKNOWN (treat as binary)"

    def _define_tool_ecosystem(self) -> Dict[str, ToolCapability]:
        """Define the complete RAPTOR tool ecosystem."""
        return {
            'semgrep': ToolCapability(
                name='Semgrep',
                capabilities=[
                    'Fast pattern matching',
                    'Known vulnerability detection',
                    'Code quality issues',
                    'Secrets scanning'
                ],
                best_for=[
                    'Initial triage',
                    'Quick security checks',
                    'Finding common vulnerabilities',
                    'Secrets and credentials detection'
                ],
                limitations=[
                    'No deep dataflow analysis',
                    'False positives on complex code',
                    'Misses context-dependent vulns'
                ],
                integrates_with=['codeql', 'frida', 'llm-analysis']
            ),

            'codeql': ToolCapability(
                name='CodeQL',
                capabilities=[
                    'Deep dataflow analysis',
                    'Taint tracking',
                    'Complex query language',
                    'Low false positive rate'
                ],
                best_for=[
                    'Complex vulnerability chains',
                    'Dataflow analysis',
                    'Custom security properties',
                    'High-confidence findings'
                ],
                limitations=[
                    'Slower than Semgrep',
                    'Requires database creation',
                    'Limited language support'
                ],
                integrates_with=['semgrep', 'frida', 'llm-analysis']
            ),

            'frida': ToolCapability(
                name='Frida',
                capabilities=[
                    'Runtime instrumentation',
                    'API hooking',
                    'Memory inspection',
                    'Behavior observation',
                    'Binary analysis without source code',
                    'Function tracing and interception',
                    'Security bypass detection'
                ],
                best_for=[
                    'BINARY ANALYSIS (PRIMARY TOOL for compiled executables)',
                    'Analyzing closed-source binaries',
                    'Runtime vulnerability discovery',
                    'Understanding runtime behavior',
                    'Bypassing protections',
                    'Finding runtime-only bugs',
                    'API abuse detection'
                ],
                limitations=[
                    'Needs running process',
                    'May miss code paths without fuzzing'
                ],
                integrates_with=['semgrep', 'codeql', 'afl', 'llm-analysis']
            ),

            'afl': ToolCapability(
                name='AFL++',
                capabilities=[
                    'Coverage-guided fuzzing',
                    'Crash discovery',
                    'Edge case generation',
                    'Automated input mutation'
                ],
                best_for=[
                    'Finding memory corruption',
                    'Crash/DoS discovery',
                    'Input validation bugs',
                    'Unknown vulnerabilities'
                ],
                limitations=[
                    'Time-consuming',
                    'Binary-only',
                    'Needs instrumentation',
                    'May not reach deep code'
                ],
                integrates_with=['frida', 'crash-analysis', 'codeql']
            ),

            'web-scanner': ToolCapability(
                name='Web Scanner',
                capabilities=[
                    'OWASP Top 10 testing',
                    'Crawling and discovery',
                    'Parameter fuzzing',
                    'XSS/SQLi detection'
                ],
                best_for=[
                    'Web application testing',
                    'API security',
                    'OWASP compliance',
                    'Quick web vulnerability scan'
                ],
                limitations=[
                    'Alpha/stub status',
                    'Limited coverage',
                    'May miss authenticated areas'
                ],
                integrates_with=['frida', 'semgrep']
            ),

            'llm-analysis': ToolCapability(
                name='LLM Analysis',
                capabilities=[
                    'Natural language reasoning',
                    'Pattern recognition',
                    'Hypothesis formation',
                    'Cross-tool synthesis'
                ],
                best_for=[
                    'Analyzing complex findings',
                    'Prioritizing vulnerabilities',
                    'Explaining security issues',
                    'Guiding tool selection'
                ],
                limitations=[
                    'Depends on input quality',
                    'May hallucinate',
                    'Needs verification'
                ],
                integrates_with=['semgrep', 'codeql', 'frida', 'afl']
            )
        }

    def llm_decide_strategy(self) -> Dict[str, Any]:
        """
        Use LLM to decide optimal tool strategy based on:
        - Security goal
        - Target type
        - Previous findings
        - Tool capabilities
        """
        if not self.llm_client:
            return self._fallback_strategy()

        # Build context
        tool_descriptions = {}
        for tool_name, tool in self.tools.items():
            tool_descriptions[tool_name] = {
                'capabilities': tool.capabilities,
                'best_for': tool.best_for,
                'limitations': tool.limitations,
                'already_used': tool_name in self.executed_tools
            }

        # Detect target type
        target_type = self._detect_target_type()

        # Build Frida strategy status
        frida_status = {
            'strategies_tried': [k for k, v in self.frida_strategies.items() if v['tried']],
            'strategies_remaining': [k for k, v in self.frida_strategies.items() if not v['tried']],
            'successful_strategies': [k for k, v in self.frida_strategies.items() if v['success']],
            'failed_strategies': {k: v['error'] for k, v in self.frida_strategies.items() if v['error']},
            'fully_exhausted': self.frida_fully_exhausted
        }

        # Include resolved binary info if different from target
        resolved_info = ""
        if self.resolved_binary != self.target:
            resolved_info = f"\nRESOLVED BINARY: {self.resolved_binary} (actual executable inside bundle)"

        prompt = f"""
You are the RAPTOR Meta-Orchestrator. Your job is to intelligently coordinate security tools to achieve the user's goal.

GOAL: {self.goal}
TARGET: {self.target}
TARGET TYPE: {target_type}{resolved_info}
ITERATION: {self.iteration + 1}/{self.max_iterations}

AVAILABLE TOOLS:
{json.dumps(tool_descriptions, indent=2)}

FRIDA STRATEGY STATUS:
{json.dumps(frida_status, indent=2)}

PREVIOUS FINDINGS:
{json.dumps(self.all_findings, indent=2) if self.all_findings else "None yet"}

TOOLS ALREADY EXECUTED:
{json.dumps(self.executed_tools) if self.executed_tools else "None"}

CRITICAL TOOL SELECTION RULES:
- For BINARY targets: Frida is the PRIMARY tool. Semgrep/CodeQL require source code and are NOT useful for binaries.
- For MACOS_APP_BUNDLE targets: Treat as BINARY. The actual executable inside the bundle will be targeted. Use Frida as PRIMARY tool.
- For SOURCE CODE targets: Start with Semgrep/CodeQL, then use Frida to verify findings at runtime.
- For WEB targets: Use web-scanner as primary, Frida for client-side analysis.
- FRIDA RESILIENCE: If Frida failed, check strategies_remaining. If strategies remain, select "frida" again to try the next strategy.
- NEVER abandon Frida until ALL strategies are exhausted (fully_exhausted=true).
- Only move to AFL/other tools AFTER Frida has succeeded OR all Frida strategies are exhausted.

Based on the goal, target type, and current state, decide:
1. Which tool(s) should run next?
2. Why is this the best choice?
3. How should tools work together?
4. What findings would indicate we've achieved the goal?
5. Should we continue after this, or are we done?

Respond with JSON only:
{{
    "next_tools": ["tool1", "tool2"],
    "reasoning": "why these tools are optimal for this target type",
    "integration_strategy": "how tools will work together",
    "success_criteria": "what findings mean we achieved the goal",
    "continue_after": true/false,
    "estimated_progress": "0-100% toward goal"
}}
        """

        try:
            response = self.llm_client.generate(prompt)
            # Extract JSON from response (may contain text before/after JSON)
            content = response.content
            # Find JSON object in response
            start = content.find('{')
            end = content.rfind('}') + 1
            if start != -1 and end > start:
                json_str = content[start:end]
                strategy = json.loads(json_str)
            else:
                raise ValueError("No JSON object found in response")
            logger.info(f"LLM Strategy: {strategy.get('reasoning')}")
            return strategy

        except Exception as e:
            logger.error(f"LLM strategy failed: {e}")
            return self._fallback_strategy()

    def _fallback_strategy(self) -> Dict[str, Any]:
        """Fallback strategy if LLM unavailable - target-type aware."""
        target_type = self._detect_target_type()

        if "BINARY" in target_type or "MACOS_APP" in target_type:
            # For binaries and .app bundles: Frida is PRIMARY, AFL for fuzzing
            return {
                "next_tools": ["frida", "afl"],
                "reasoning": f"LLM unavailable. Target is {target_type} - using Frida (primary) + AFL for binary analysis",
                "integration_strategy": "Frida for runtime instrumentation, AFL for crash discovery",
                "success_criteria": "Runtime vulnerabilities, crashes, or security bypasses found",
                "continue_after": True,
                "estimated_progress": "50%"
            }
        elif "SOURCE" in target_type:
            # For source code: static analysis + Frida verification
            return {
                "next_tools": ["semgrep", "codeql", "frida"],
                "reasoning": f"LLM unavailable. Target is {target_type} - using static analysis + Frida verification",
                "integration_strategy": "Static analysis finds candidates, Frida verifies at runtime",
                "success_criteria": "Confirmed vulnerabilities with static + dynamic evidence",
                "continue_after": True,
                "estimated_progress": "50%"
            }
        elif "WEB" in target_type:
            return {
                "next_tools": ["web-scanner", "frida"],
                "reasoning": f"LLM unavailable. Target is {target_type} - using web scanner + Frida",
                "integration_strategy": "Web scanner for OWASP testing, Frida for client-side analysis",
                "success_criteria": "Web vulnerabilities discovered",
                "continue_after": True,
                "estimated_progress": "50%"
            }
        else:
            # Unknown: use Frida as safe default for any executable
            return {
                "next_tools": ["frida"],
                "reasoning": f"LLM unavailable. Unknown target type - defaulting to Frida for runtime analysis",
                "integration_strategy": "Frida instrumentation to understand target behavior",
                "success_criteria": "Any security findings",
                "continue_after": True,
                "estimated_progress": "30%"
            }

    def _get_next_frida_strategy(self) -> Optional[str]:
        """Get the next untried Frida strategy."""
        for strategy, state in self.frida_strategies.items():
            if not state['tried']:
                return strategy
        return None

    def _detect_frida_failure(self, output: str, stderr: str) -> Optional[str]:
        """Detect why Frida failed and suggest recovery."""
        combined = (output + stderr).lower()

        if 'permission denied' in combined or 'operation not permitted' in combined:
            return 'permission_denied'
        elif 'unable to find executable' in combined or 'no such file' in combined:
            return 'target_not_found'
        elif 'failed to spawn' in combined:
            return 'spawn_failed'
        elif 'failed to attach' in combined:
            return 'attach_failed'
        elif 'process crashed' in combined or 'terminated' in combined:
            return 'process_crashed'
        elif 'timeout' in combined:
            return 'timeout'
        elif 'no vulnerabilities' in combined or 'findings: 0' in combined:
            return 'no_findings_yet'  # Not a failure, but may need different approach
        return None

    def _execute_frida_with_fallback(self) -> Dict[str, Any]:
        """
        Execute Frida with multiple fallback strategies.
        Tries different approaches until one succeeds or all are exhausted.
        """
        import subprocess

        strategy = self._get_next_frida_strategy()
        if not strategy:
            self.frida_fully_exhausted = True
            return {
                'status': 'exhausted',
                'message': 'All Frida strategies attempted',
                'strategies_tried': list(self.frida_strategies.keys()),
                'errors': {k: v['error'] for k, v in self.frida_strategies.items() if v['error']}
            }

        # Use resolved binary (handles .app bundles)
        frida_target = self.resolved_binary
        logger.info(f"Trying Frida strategy: {strategy} on {frida_target}")

        # Build command based on strategy
        if strategy == 'spawn':
            cmd = [sys.executable, 'raptor.py', 'frida-auto', '--target', frida_target, '--goal', self.goal]
        elif strategy == 'attach':
            cmd = [sys.executable, 'raptor.py', 'frida-auto', '--target', frida_target, '--goal', self.goal, '--attach']
        elif strategy == 'spawn-suspended':
            cmd = [sys.executable, 'raptor.py', 'frida-auto', '--target', frida_target, '--goal', self.goal, '--suspended']
        elif strategy == 'sudo-spawn':
            cmd = ['sudo', sys.executable, 'raptor.py', 'frida-auto', '--target', frida_target, '--goal', self.goal]
        else:
            cmd = [sys.executable, 'raptor.py', 'frida-auto', '--target', frida_target, '--goal', self.goal]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            self.frida_strategies[strategy]['tried'] = True

            # Detect failure type
            failure_type = self._detect_frida_failure(result.stdout, result.stderr)

            if failure_type and failure_type not in ('no_findings_yet',):
                self.frida_strategies[strategy]['success'] = False
                self.frida_strategies[strategy]['error'] = failure_type
                logger.warning(f"Frida strategy '{strategy}' failed: {failure_type}")

                return {
                    'status': 'failed',
                    'strategy': strategy,
                    'failure_type': failure_type,
                    'output': result.stdout,
                    'stderr': result.stderr,
                    'strategies_remaining': [k for k, v in self.frida_strategies.items() if not v['tried']],
                    'recommendation': self._get_frida_recovery_recommendation(failure_type)
                }
            else:
                self.frida_strategies[strategy]['success'] = True
                return {
                    'status': 'completed',
                    'strategy': strategy,
                    'output': result.stdout
                }

        except subprocess.TimeoutExpired:
            self.frida_strategies[strategy]['tried'] = True
            self.frida_strategies[strategy]['error'] = 'timeout'
            return {
                'status': 'timeout',
                'strategy': strategy,
                'strategies_remaining': [k for k, v in self.frida_strategies.items() if not v['tried']]
            }
        except Exception as e:
            self.frida_strategies[strategy]['tried'] = True
            self.frida_strategies[strategy]['error'] = str(e)
            return {
                'status': 'error',
                'strategy': strategy,
                'error': str(e),
                'strategies_remaining': [k for k, v in self.frida_strategies.items() if not v['tried']]
            }

    def _get_frida_recovery_recommendation(self, failure_type: str) -> str:
        """Get recovery recommendation for a Frida failure type."""
        recommendations = {
            'permission_denied': 'Try sudo-spawn strategy or check SIP/entitlements',
            'target_not_found': 'Verify target path exists and is executable',
            'spawn_failed': 'Try attach strategy (start process manually first)',
            'attach_failed': 'Try spawn strategy or check if process is running',
            'process_crashed': 'Binary may have anti-instrumentation; try spawn-suspended',
            'timeout': 'Increase timeout or try simpler hooking scripts',
        }
        return recommendations.get(failure_type, 'Try next Frida strategy')

    def execute_tool(self, tool_name: str) -> Dict[str, Any]:
        """
        Execute a tool and return its findings.

        Args:
            tool_name: Name of tool to execute

        Returns:
            Tool findings
        """
        logger.info(f"Executing {tool_name}...")

        tool_findings = {}

        try:
            if tool_name == 'semgrep':
                # Run Semgrep
                import subprocess
                result = subprocess.run(
                    [sys.executable, 'raptor.py', 'scan', '--repo', self.target],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                tool_findings = {'status': 'completed', 'output': result.stdout}

            elif tool_name == 'codeql':
                # Run CodeQL
                import subprocess
                result = subprocess.run(
                    [sys.executable, 'raptor.py', 'codeql', '--repo', self.target],
                    capture_output=True,
                    text=True,
                    timeout=600
                )
                tool_findings = {'status': 'completed', 'output': result.stdout}

            elif tool_name == 'frida':
                # Run Frida with resilient multi-strategy approach
                tool_findings = self._execute_frida_with_fallback()

            elif tool_name == 'afl':
                # Run AFL fuzzing
                import subprocess
                result = subprocess.run(
                    [sys.executable, 'raptor.py', 'fuzz', '--binary', self.target, '--duration', '300'],
                    capture_output=True,
                    text=True,
                    timeout=400
                )
                tool_findings = {'status': 'completed', 'output': result.stdout}

            else:
                tool_findings = {'status': 'skipped', 'reason': f'Unknown tool: {tool_name}'}

        except Exception as e:
            logger.error(f"Tool {tool_name} failed: {e}")
            tool_findings = {'status': 'error', 'error': str(e)}

        self.executed_tools.append(tool_name)
        self.all_findings[tool_name] = tool_findings

        return tool_findings

    def run_orchestrated_analysis(self) -> Dict[str, Any]:
        """
        Run complete orchestrated security analysis.

        Returns:
            Complete findings from all tools
        """
        logger.info("="*70)
        logger.info("RAPTOR META-ORCHESTRATOR")
        logger.info("="*70)
        logger.info(f"Goal: {self.goal}")
        logger.info(f"Target: {self.target}")
        logger.info("="*70)

        while self.iteration < self.max_iterations:
            logger.info(f"\n{'='*70}")
            logger.info(f"ITERATION {self.iteration + 1}/{self.max_iterations}")
            logger.info(f"{'='*70}")

            # LLM decides strategy
            strategy = self.llm_decide_strategy()

            logger.info(f"Strategy: {strategy.get('reasoning')}")
            logger.info(f"Progress: {strategy.get('estimated_progress')}")

            # Execute chosen tools
            next_tools = strategy.get('next_tools', [])
            for tool_name in next_tools:
                if tool_name in self.tools:
                    self.execute_tool(tool_name)
                else:
                    logger.warning(f"Unknown tool: {tool_name}")

            # Check if we should continue
            if not strategy.get('continue_after', True):
                logger.info("Goal achieved, stopping")
                break

            self.iteration += 1

        # Final summary
        logger.info("\n" + "="*70)
        logger.info("ANALYSIS COMPLETE")
        logger.info("="*70)
        logger.info(f"Tools executed: {', '.join(self.executed_tools)}")
        logger.info(f"Iterations: {self.iteration}")
        logger.info("="*70)

        return self.all_findings


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="RAPTOR Meta-Orchestrator - Intelligent multi-tool coordination"
    )
    parser.add_argument('--target', required=True,
                       help='Target to analyze (repo, binary, URL)')
    parser.add_argument('--goal', required=True,
                       help='Security goal (e.g., "Find RCE vulnerabilities")')
    parser.add_argument('--max-iterations', type=int, default=10,
                       help='Maximum analysis iterations')

    args = parser.parse_args()

    orchestrator = RAPTORMetaOrchestrator(args.goal, args.target)
    orchestrator.max_iterations = args.max_iterations

    findings = orchestrator.run_orchestrated_analysis()

    # Output findings
    output_path = Path('out') / f'meta_analysis_{int(time.time())}.json'
    output_path.parent.mkdir(exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(findings, f, indent=2)

    print(f"\n✓ Analysis complete: {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
