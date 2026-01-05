#!/usr/bin/env python3
"""
RAPTOR Autonomous Frida Analysis

Combines static analysis + LLM reasoning + dynamic instrumentation
for intelligent, goal-directed security testing.

Workflow:
1. Static analysis identifies interesting functions/APIs
2. LLM decides which Frida hooks would be most valuable
3. Generate custom Frida scripts targeting specific behaviors
4. Run instrumentation and collect runtime data
5. LLM analyzes findings and suggests next steps
6. Iterate until security goals achieved
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import logging

# Add parent to path for RAPTOR imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    from packages.llm_analysis.llm.client import LLMClient
except ImportError:
    print("✗ LLM client not available")
    LLMClient = None

from packages.frida.scanner import FridaScanner

logger = logging.getLogger("frida.autonomous")


class AutonomousFridaAnalyzer:
    """
    Autonomous Frida analyzer that uses LLM to guide instrumentation.
    """

    def __init__(self, target: str, goal: str = "Find security vulnerabilities"):
        """
        Initialize autonomous analyzer.

        Args:
            target: Binary path, process name, or PID
            goal: Security testing goal (guides LLM decisions)
        """
        self.target = target
        self.goal = goal
        self.llm_client = LLMClient() if LLMClient else None
        self.frida_scanner = FridaScanner()
        self.iteration = 0
        self.max_iterations = 5
        self.findings_history: List[Dict] = []

    def analyze_static(self) -> Dict[str, Any]:
        """
        Perform static analysis to identify interesting functions/APIs.

        Returns:
            Dict of static analysis results
        """
        logger.info(f"Static analysis of {self.target}")

        # TODO: Integration with existing RAPTOR static analysis
        # For now, use basic symbol enumeration via Frida

        static_info = {
            "binary_path": self.target,
            "interesting_functions": [],
            "imported_libraries": [],
            "security_features": []
        }

        # Use Frida to enumerate without running
        try:
            import frida
            device = frida.get_local_device()

            # Analyze binary symbols
            # This is a placeholder - would integrate with RAPTOR's binary_analysis package
            logger.info("Enumerating binary information...")

        except Exception as e:
            logger.warning(f"Static analysis limited: {e}")

        return static_info

    def llm_decide_hooks(self, static_info: Dict, previous_findings: List[Dict]) -> Dict[str, Any]:
        """
        Use LLM to decide which Frida hooks to install based on:
        - Static analysis results
        - Security goal
        - Previous findings

        Returns:
            Dict with hook strategy and generated script
        """
        if not self.llm_client:
            logger.warning("LLM not available, using default hooks")
            return {
                "strategy": "default",
                "hooks": ["api-trace"],
                "reasoning": "LLM unavailable, using basic API tracing"
            }

        # Prepare context for LLM
        context = {
            "goal": self.goal,
            "target": self.target,
            "static_analysis": static_info,
            "previous_findings": previous_findings,
            "iteration": self.iteration
        }

        prompt = f"""
You are a security researcher using Frida for dynamic instrumentation.

GOAL: {self.goal}
TARGET: {self.target}
ITERATION: {self.iteration + 1}/{self.max_iterations}

STATIC ANALYSIS:
{json.dumps(static_info, indent=2)}

PREVIOUS FINDINGS:
{json.dumps(previous_findings, indent=2) if previous_findings else "None yet"}

Based on the goal and current information, decide:
1. Which APIs/functions should be hooked with Frida?
2. What runtime behavior are we looking for?
3. What would be the most valuable data to collect?

Respond with a JSON object:
{{
    "strategy": "brief description of approach",
    "priority_hooks": ["function1", "function2", ...],
    "reasoning": "why these hooks will help achieve the goal",
    "expected_findings": "what we expect to discover"
}}
        """

        try:
            response = self.llm_client.chat(prompt)
            # Parse JSON from response
            # This is simplified - real implementation would use structured output
            decision = json.loads(response)
            logger.info(f"LLM Strategy: {decision.get('strategy')}")
            return decision

        except Exception as e:
            logger.error(f"LLM decision failed: {e}")
            return {
                "strategy": "fallback",
                "hooks": ["api-trace"],
                "reasoning": f"LLM error: {e}"
            }

    def generate_frida_script(self, hook_decision: Dict) -> str:
        """
        Generate custom Frida script based on LLM decision.

        Args:
            hook_decision: Hook strategy from LLM

        Returns:
            JavaScript source code for Frida
        """
        priority_hooks = hook_decision.get('priority_hooks', [])

        # Generate targeted hooks
        script_parts = [
            "// Auto-generated by RAPTOR Autonomous Frida",
            f"// Strategy: {hook_decision.get('strategy')}",
            f"// Goal: {self.goal}",
            "",
            "function log(msg, level) {",
            "    send({ level: level || 'info', message: msg });",
            "}",
            "",
            "function sendFinding(title, severity, details) {",
            "    send({",
            "        type: 'finding',",
            "        level: severity,",
            "        title: title,",
            "        details: details,",
            "        timestamp: Date.now()",
            "    });",
            "}",
            "",
            "log('Autonomous Frida script loaded', 'info');",
            ""
        ]

        # Add hooks for priority functions
        for func_name in priority_hooks:
            script_parts.extend([
                f"// Hook: {func_name}",
                f"const {func_name}_ptr = Module.findExportByName(null, '{func_name}');",
                f"if ({func_name}_ptr) {{",
                f"    Interceptor.attach({func_name}_ptr, {{",
                "        onEnter: function(args) {",
                f"            log('{func_name}() called', 'info');",
                "            sendFinding(",
                f"                '{func_name} Invoked',",
                "                'info',",
                f"                '{func_name} was called at runtime'",
                "            );",
                "        }",
                "    });",
                f"    log('{func_name} hooked', 'info');",
                "} else {",
                f"    log('{func_name} not found', 'warning');",
                "}",
                ""
            ])

        return "\n".join(script_parts)

    def llm_analyze_findings(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Use LLM to analyze runtime findings and suggest next steps.

        Args:
            findings: List of findings from Frida

        Returns:
            Analysis and recommendations
        """
        if not self.llm_client:
            return {
                "analysis": "LLM unavailable",
                "continue": False
            }

        prompt = f"""
You are analyzing runtime behavior from Frida instrumentation.

GOAL: {self.goal}
ITERATION: {self.iteration + 1}/{self.max_iterations}

RUNTIME FINDINGS:
{json.dumps(findings, indent=2)}

Analyze these findings:
1. Do they reveal security issues?
2. Do they help achieve our goal?
3. Should we continue instrumenting (what to hook next)?
4. Or have we found what we needed?

Respond with JSON:
{{
    "security_issues": ["issue1", "issue2", ...],
    "goal_progress": "how close are we to the goal (0-100%)",
    "continue": true/false,
    "next_focus": "what to investigate next",
    "recommendations": "suggested next steps"
}}
        """

        try:
            response = self.llm_client.chat(prompt)
            analysis = json.loads(response)
            logger.info(f"LLM Analysis: {analysis.get('goal_progress')}% complete")
            return analysis

        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return {
                "analysis": f"Error: {e}",
                "continue": self.iteration < self.max_iterations
            }

    def run_autonomous(self, duration_per_iteration: int = 30) -> List[Dict]:
        """
        Run autonomous analysis loop.

        Args:
            duration_per_iteration: How long to run each instrumentation (seconds)

        Returns:
            List of all findings
        """
        logger.info(f"Starting autonomous Frida analysis")
        logger.info(f"Goal: {self.goal}")
        logger.info(f"Target: {self.target}")

        all_findings = []

        while self.iteration < self.max_iterations:
            logger.info(f"\n{'='*70}")
            logger.info(f"ITERATION {self.iteration + 1}/{self.max_iterations}")
            logger.info(f"{'='*70}")

            # Step 1: Static analysis (only on first iteration)
            if self.iteration == 0:
                static_info = self.analyze_static()
            else:
                static_info = {}

            # Step 2: LLM decides which hooks to use
            hook_decision = self.llm_decide_hooks(static_info, all_findings)

            # Step 3: Generate Frida script
            frida_script = self.generate_frida_script(hook_decision)

            # Step 4: Run instrumentation
            try:
                self.frida_scanner.spawn_process(self.target)
                self.frida_scanner.load_script(frida_script, f"auto_iteration_{self.iteration}")
                self.frida_scanner.resume_process()

                logger.info(f"Running instrumentation for {duration_per_iteration}s...")
                import time
                time.sleep(duration_per_iteration)

                # Collect findings
                iteration_findings = self.frida_scanner.findings
                all_findings.extend(iteration_findings)

                logger.info(f"Iteration {self.iteration + 1} found {len(iteration_findings)} findings")

            except Exception as e:
                logger.error(f"Instrumentation failed: {e}")
                break
            finally:
                self.frida_scanner.detach()

            # Step 5: LLM analyzes findings and decides if we should continue
            analysis = self.llm_analyze_findings(all_findings)

            if not analysis.get('continue', False):
                logger.info("LLM determined goal achieved or no further value")
                break

            self.iteration += 1

        # Final report
        logger.info(f"\nAutonomous analysis complete: {len(all_findings)} total findings")
        self.frida_scanner.findings = all_findings
        self.frida_scanner.generate_report()

        return all_findings


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="RAPTOR Autonomous Frida Analysis"
    )
    parser.add_argument('--target', required=True,
                       help='Binary to analyze')
    parser.add_argument('--goal', default='Find security vulnerabilities',
                       help='Security testing goal')
    parser.add_argument('--max-iterations', type=int, default=5,
                       help='Maximum analysis iterations')
    parser.add_argument('--duration', type=int, default=30,
                       help='Duration per iteration (seconds)')

    args = parser.parse_args()

    analyzer = AutonomousFridaAnalyzer(args.target, args.goal)
    analyzer.max_iterations = args.max_iterations
    findings = analyzer.run_autonomous(args.duration)

    print(f"\n✓ Found {len(findings)} security findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
