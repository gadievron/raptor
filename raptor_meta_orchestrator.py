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
                    'Behavior observation'
                ],
                best_for=[
                    'Verifying static analysis findings',
                    'Understanding runtime behavior',
                    'Bypassing protections',
                    'Finding runtime-only bugs'
                ],
                limitations=[
                    'Needs running process',
                    'May miss code paths',
                    'Target-dependent'
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

        prompt = f"""
You are the RAPTOR Meta-Orchestrator. Your job is to intelligently coordinate security tools to achieve the user's goal.

GOAL: {self.goal}
TARGET: {self.target}
ITERATION: {self.iteration + 1}/{self.max_iterations}

AVAILABLE TOOLS:
{json.dumps(tool_descriptions, indent=2)}

PREVIOUS FINDINGS:
{json.dumps(self.all_findings, indent=2) if self.all_findings else "None yet"}

TOOLS ALREADY EXECUTED:
{json.dumps(self.executed_tools) if self.executed_tools else "None"}

Based on the goal, target, and current state, decide:
1. Which tool(s) should run next?
2. Why is this the best choice?
3. How should tools work together?
4. What findings would indicate we've achieved the goal?
5. Should we continue after this, or are we done?

Respond with JSON:
{{
    "next_tools": ["tool1", "tool2"],  // Tools to run next (can be parallel)
    "reasoning": "why these tools are optimal",
    "integration_strategy": "how tools will work together",
    "success_criteria": "what findings mean we achieved the goal",
    "continue_after": true/false,
    "estimated_progress": "0-100% toward goal"
}}

IMPORTANT: Consider tool synergies:
- Static analysis (semgrep/codeql) finds suspicious code → Frida verifies at runtime
- Frida finds interesting behavior → CodeQL tracks dataflow to confirm
- Fuzzing (afl) finds crashes → Frida + CodeQL analyze root cause
- LLM analyzes all findings → Guides next tool selection
        """

        try:
            response = self.llm_client.chat(prompt)
            strategy = json.loads(response)
            logger.info(f"LLM Strategy: {strategy.get('reasoning')}")
            return strategy

        except Exception as e:
            logger.error(f"LLM strategy failed: {e}")
            return self._fallback_strategy()

    def _fallback_strategy(self) -> Dict[str, Any]:
        """Fallback strategy if LLM unavailable."""
        # Default: comprehensive scan
        return {
            "next_tools": ["semgrep", "frida"],
            "reasoning": "LLM unavailable, using default comprehensive scan",
            "integration_strategy": "Static analysis first, then dynamic verification",
            "success_criteria": "Any security findings",
            "continue_after": True,
            "estimated_progress": "50%"
        }

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
                # Run Frida autonomous mode with goal
                import subprocess
                result = subprocess.run(
                    [sys.executable, 'raptor.py', 'frida-auto', '--target', self.target, '--goal', self.goal],
                    capture_output=True,
                    text=True,
                    timeout=300
                )
                tool_findings = {'status': 'completed', 'output': result.stdout}

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
