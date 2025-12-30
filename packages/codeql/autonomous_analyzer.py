#!/usr/bin/env python3
"""
CodeQL Autonomous Analyzer

Fully autonomous analysis of CodeQL findings with:
- Deep LLM analysis using multi-turn dialogue
- Dataflow path validation
- Exploitability assessment
- PoC exploit generation
- Exploit validation and refinement
"""

import json
import sys
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.logging import get_logger
from packages.codeql.dataflow_validator import DataflowValidator, DataflowValidation
from packages.codeql.dataflow_visualizer import DataflowVisualizer

logger = get_logger()


@dataclass
class CodeQLFinding:
    """Parsed CodeQL finding from SARIF."""
    rule_id: str
    rule_name: str
    message: str
    level: str  # error, warning, note
    file_path: str
    start_line: int
    end_line: int
    snippet: str
    cwe: Optional[str] = None
    has_dataflow: bool = False
    dataflow_path_count: int = 0


@dataclass
class VulnerabilityAnalysis:
    """LLM analysis result."""
    is_true_positive: bool
    is_exploitable: bool
    exploitability_score: float  # 0.0-1.0
    severity_assessment: str
    reasoning: str
    attack_scenario: str
    prerequisites: List[str]
    impact: str
    cvss_estimate: float  # 0.0-10.0
    mitigation: str


@dataclass
class AutonomousAnalysisResult:
    """Complete autonomous analysis result."""
    finding: CodeQLFinding
    analysis: VulnerabilityAnalysis
    dataflow_validation: Optional[DataflowValidation]
    exploitable: bool
    exploit_code: Optional[str]
    exploit_compiled: bool
    validation_result: Optional[Dict]
    refinement_iterations: int
    total_duration_seconds: float


class AutonomousCodeQLAnalyzer:
    """
    Fully autonomous CodeQL finding analyzer.

    Integrates:
    - CodeQL SARIF parsing
    - Dataflow validation
    - Multi-turn LLM analysis
    - Exploit generation
    - Exploit validation & refinement
    """

    def __init__(
        self,
        llm_client,
        exploit_validator,
        multi_turn_analyzer=None,
        enable_visualization=True
    ):
        """
        Initialize autonomous analyzer.

        Args:
            llm_client: LLM client from packages/llm_analysis/llm/client.py
            exploit_validator: ExploitValidator from packages/autonomous/exploit_validator.py
            multi_turn_analyzer: MultiTurnAnalyser from packages/autonomous/dialogue.py (optional)
            enable_visualization: Enable dataflow visualizations (default: True)
        """
        self.llm = llm_client
        self.validator = exploit_validator
        self.multi_turn = multi_turn_analyzer
        self.dataflow_validator = DataflowValidator(llm_client)
        self.enable_visualization = enable_visualization
        self.logger = get_logger()

    def parse_sarif_finding(self, result: Dict, run: Dict) -> CodeQLFinding:
        """
        Parse SARIF result into CodeQLFinding.

        Args:
            result: SARIF result object
            run: SARIF run object (for rule metadata)

        Returns:
            CodeQLFinding object
        """
        # Extract rule information
        rule_id = result.get("ruleId", "")
        rule_index = result.get("ruleIndex", 0)

        # Get rule metadata
        rules = run.get("tool", {}).get("driver", {}).get("rules", [])
        rule = rules[rule_index] if rule_index < len(rules) else {}

        rule_name = rule.get("name", rule_id)

        # Extract location
        locations = result.get("locations", [])
        location = locations[0] if locations else {}
        physical_loc = location.get("physicalLocation", {})
        region = physical_loc.get("region", {})
        artifact = physical_loc.get("artifactLocation", {})

        # Extract CWE
        cwe = None
        properties = rule.get("properties", {})
        tags = properties.get("tags", [])
        for tag in tags:
            if tag.startswith("external/cwe/cwe-"):
                cwe = tag.replace("external/cwe/", "").upper()
                break

        # Check for dataflow
        code_flows = result.get("codeFlows", [])
        has_dataflow = len(code_flows) > 0
        dataflow_path_count = len(code_flows)

        return CodeQLFinding(
            rule_id=rule_id,
            rule_name=rule_name,
            message=result.get("message", {}).get("text", ""),
            level=result.get("level", "warning"),
            file_path=artifact.get("uri", ""),
            start_line=region.get("startLine", 0),
            end_line=region.get("endLine", 0),
            snippet=region.get("snippet", {}).get("text", ""),
            cwe=cwe,
            has_dataflow=has_dataflow,
            dataflow_path_count=dataflow_path_count
        )

    def read_vulnerable_code(
        self,
        finding: CodeQLFinding,
        repo_path: Path,
        context_lines: int = 50
    ) -> str:
        """
        Read vulnerable code with surrounding context.

        Args:
            finding: CodeQLFinding object
            repo_path: Repository root path
            context_lines: Lines before/after to include

        Returns:
            Source code with context
        """
        file_path = repo_path / finding.file_path

        try:
            with open(file_path) as f:
                lines = f.readlines()

            start = max(0, finding.start_line - context_lines - 1)
            end = min(len(lines), finding.end_line + context_lines)

            context = []
            for i in range(start, end):
                if finding.start_line - 1 <= i < finding.end_line:
                    marker = ">>> "
                else:
                    marker = "    "
                context.append(f"{marker}{i + 1:4d}: {lines[i].rstrip()}")

            return "\n".join(context)

        except Exception as e:
            self.logger.warning(f"Failed to read vulnerable code: {e}")
            return finding.snippet

    def analyze_vulnerability(
        self,
        finding: CodeQLFinding,
        vulnerable_code: str,
        dataflow_validation: Optional[DataflowValidation] = None
    ) -> VulnerabilityAnalysis:
        """
        Perform deep LLM analysis of vulnerability.

        Args:
            finding: CodeQLFinding object
            vulnerable_code: Source code context
            dataflow_validation: Dataflow validation result (if applicable)

        Returns:
            VulnerabilityAnalysis result
        """
        self.logger.info(f"Analyzing vulnerability: {finding.rule_id}")

        # Build analysis prompt
        prompt = f"""You are an expert security researcher analyzing a CodeQL finding.

FINDING DETAILS:
Rule: {finding.rule_id} - {finding.rule_name}
Severity: {finding.level}
CWE: {finding.cwe or 'Not specified'}
Message: {finding.message}

LOCATION:
File: {finding.file_path}
Lines: {finding.start_line}-{finding.end_line}

VULNERABLE CODE:
{vulnerable_code}
"""

        # Add dataflow information if available
        if dataflow_validation:
            prompt += f"""
DATAFLOW ANALYSIS:
- Exploitable: {dataflow_validation.is_exploitable}
- Confidence: {dataflow_validation.confidence:.2f}
- Sanitizers effective: {dataflow_validation.sanitizers_effective}
- Bypass possible: {dataflow_validation.bypass_possible}
- Attack complexity: {dataflow_validation.attack_complexity}

Dataflow reasoning: {dataflow_validation.reasoning}
"""

        prompt += """
Analyze this finding and provide:

1. **True Positive Assessment**: Is this a real vulnerability or false positive?
2. **Exploitability**: Can this be exploited by an attacker?
3. **Exploitability Score**: Rate 0.0 (not exploitable) to 1.0 (easily exploitable)
4. **Severity Assessment**: Critical, High, Medium, Low
5. **Attack Scenario**: Detailed step-by-step exploitation scenario
6. **Prerequisites**: What must an attacker control or know?
7. **Impact**: What happens if successfully exploited?
8. **CVSS Estimate**: Estimated CVSS score (0.0-10.0)
9. **Mitigation**: How to fix this vulnerability

Respond in JSON format:
{
    "is_true_positive": boolean,
    "is_exploitable": boolean,
    "exploitability_score": float (0.0-1.0),
    "severity_assessment": string,
    "reasoning": string,
    "attack_scenario": string,
    "prerequisites": [list of strings],
    "impact": string,
    "cvss_estimate": float (0.0-10.0),
    "mitigation": string
}
"""

        try:
            # Use LLM for analysis (Bug #15: multi_turn path removed - analyze_vulnerability_deeply() doesn't exist)
            response_dict, _ = self.llm.generate_structured(
                prompt=prompt,
                schema=VulnerabilityAnalysis,
                system_prompt="You are Mark Dowd, an expert security researcher."
            )

            # Defensive: LLM might return extra fields not in schema
            # Filter to only include VulnerabilityAnalysis fields to prevent TypeErrors
            valid_fields = {f.name for f in VulnerabilityAnalysis.__dataclass_fields__.values()}
            filtered_response = {k: v for k, v in response_dict.items() if k in valid_fields}

            # Log any unexpected fields for debugging
            unexpected_fields = set(response_dict.keys()) - valid_fields
            if unexpected_fields:
                self.logger.debug(
                    f"LLM response included unexpected fields (ignored): {unexpected_fields}"
                )

            analysis = VulnerabilityAnalysis(**filtered_response)

            self.logger.info(
                f"Analysis complete: exploitable={analysis.is_exploitable}, "
                f"score={analysis.exploitability_score:.2f}"
            )

            return analysis

        except Exception as e:
            self.logger.error(f"Vulnerability analysis failed: {e}")

            # Return conservative default
            return VulnerabilityAnalysis(
                is_true_positive=False,
                is_exploitable=False,
                exploitability_score=0.0,
                severity_assessment="Unknown",
                reasoning=f"Analysis failed: {str(e)}",
                attack_scenario="Could not determine",
                prerequisites=[],
                impact="Unknown",
                cvss_estimate=0.0,
                mitigation="Review manually"
            )

    def generate_exploit(
        self,
        finding: CodeQLFinding,
        analysis: VulnerabilityAnalysis,
        vulnerable_code: str
    ) -> Optional[str]:
        """
        Generate PoC exploit code.

        Args:
            finding: CodeQLFinding object
            analysis: VulnerabilityAnalysis result
            vulnerable_code: Source code context

        Returns:
            Exploit code or None
        """
        self.logger.info(f"Generating exploit for: {finding.rule_id}")

        prompt = f"""You are an expert security researcher creating a proof-of-concept exploit for authorized security testing.

VULNERABILITY:
Rule: {finding.rule_id} - {finding.rule_name}
CWE: {finding.cwe or 'Not specified'}
Message: {finding.message}

VULNERABLE CODE:
{vulnerable_code}

ANALYSIS:
{analysis.reasoning}

ATTACK SCENARIO:
{analysis.attack_scenario}

PREREQUISITES:
{', '.join(analysis.prerequisites)}

Create a WORKING proof-of-concept exploit that:
1. Demonstrates this specific vulnerability
2. Is safe to run in an isolated lab environment
3. Includes clear comments explaining each step
4. Has detailed output showing successful exploitation
5. Includes responsible disclosure warnings
6. Uses appropriate language (Java for Java vulns, Python for general PoCs)

Provide ONLY the complete, working exploit code. Include a header comment explaining usage.
"""

        try:
            response = self.llm.generate(
                prompt=prompt,
                system_prompt="You are Mark Dowd, creating exploits for authorized security testing only.",
                temperature=0.8
            )

            # Extract code from response
            exploit_code = response.strip()

            # Remove markdown code blocks if present
            if "```" in exploit_code:
                lines = exploit_code.split("\n")
                code_lines = []
                in_code_block = False

                for line in lines:
                    if line.startswith("```"):
                        in_code_block = not in_code_block
                        continue
                    if in_code_block:
                        code_lines.append(line)

                exploit_code = "\n".join(code_lines)

            self.logger.info(f"Exploit generated ({len(exploit_code)} bytes)")
            return exploit_code

        except Exception as e:
            self.logger.error(f"Exploit generation failed: {e}")
            return None

    def analyze_finding_autonomous(
        self,
        sarif_result: Dict,
        sarif_run: Dict,
        repo_path: Path,
        out_dir: Path,
        max_refinement: int = 3
    ) -> AutonomousAnalysisResult:
        """
        Fully autonomous analysis of a single CodeQL finding.

        Pipeline:
        1. Parse SARIF finding
        2. Read vulnerable code context
        3. Validate dataflow path (if applicable)
        4. Perform deep LLM analysis
        5. Generate PoC exploit (if exploitable)
        6. Validate and refine exploit

        Args:
            sarif_result: SARIF result object
            sarif_run: SARIF run object
            repo_path: Repository root path
            out_dir: Output directory
            max_refinement: Max exploit refinement iterations

        Returns:
            AutonomousAnalysisResult
        """
        import time
        start_time = time.time()

        # Stage 1: Parse finding
        finding = self.parse_sarif_finding(sarif_result, sarif_run)
        self.logger.info(f"🤖 AUTONOMOUS ANALYSIS: {finding.rule_id}")

        # Stage 2: Read vulnerable code
        vulnerable_code = self.read_vulnerable_code(finding, repo_path)

        # Stage 3: Dataflow validation (if applicable)
        dataflow_validation = None
        visualization_paths = {}
        if finding.has_dataflow:
            self.logger.info("Validating dataflow path...")
            dataflow_validation = self.dataflow_validator.validate_finding(
                sarif_result,
                repo_path
            )

            # Generate visualizations
            if self.enable_visualization:
                self.logger.info("📊 Generating dataflow visualizations...")
                try:
                    # Extract dataflow for visualization
                    dataflow = self.dataflow_validator.extract_dataflow_from_sarif(sarif_result)
                    if dataflow:
                        visualizer = DataflowVisualizer(out_dir / "visualizations")
                        finding_id = f"{finding.rule_id}_{finding.start_line}".replace("/", "_")
                        visualization_paths = visualizer.visualize_all_formats(
                            dataflow,
                            finding_id,
                            repo_path
                        )
                        self.logger.info(f"✓ Generated {len(visualization_paths)} visualization formats")
                except Exception as e:
                    self.logger.warning(f"Failed to generate visualizations: {e}")

            if dataflow_validation and not dataflow_validation.is_exploitable:
                self.logger.info("❌ Dataflow not exploitable - skipping exploit generation")
                return AutonomousAnalysisResult(
                    finding=finding,
                    analysis=None,
                    dataflow_validation=dataflow_validation,
                    exploitable=False,
                    exploit_code=None,
                    exploit_compiled=False,
                    validation_result=None,
                    refinement_iterations=0,
                    total_duration_seconds=time.time() - start_time
                )

        # Stage 4: Deep LLM analysis
        self.logger.info("Performing deep vulnerability analysis...")
        analysis = self.analyze_vulnerability(
            finding,
            vulnerable_code,
            dataflow_validation
        )

        if not analysis.is_exploitable:
            self.logger.info("❌ Not exploitable - skipping exploit generation")
            return AutonomousAnalysisResult(
                finding=finding,
                analysis=analysis,
                dataflow_validation=dataflow_validation,
                exploitable=False,
                exploit_code=None,
                exploit_compiled=False,
                validation_result=None,
                refinement_iterations=0,
                total_duration_seconds=time.time() - start_time
            )

        # Stage 5: Check mitigations before exploit generation
        if self.validator:
            vuln_type = finding.rule_id  # Use CodeQL rule ID
            viable, reason = self.validator.check_mitigations(vuln_type=vuln_type)
            if not viable:
                self.logger.warning(f"Mitigation check: {reason}")
                self.logger.warning("Exploit generation may fail - proceeding anyway")

        # Stage 6: Generate PoC exploit
        self.logger.info("🔨 Generating PoC exploit...")
        exploit_code = self.generate_exploit(finding, analysis, vulnerable_code)

        if not exploit_code:
            self.logger.warning("Failed to generate exploit")
            return AutonomousAnalysisResult(
                finding=finding,
                analysis=analysis,
                dataflow_validation=dataflow_validation,
                exploitable=True,
                exploit_code=None,
                exploit_compiled=False,
                validation_result=None,
                refinement_iterations=0,
                total_duration_seconds=time.time() - start_time
            )

        # Stage 7: Validate and refine exploit
        exploit_compiled = False
        validation_result = None
        refinement_count = 0

        if self.validator:
            self.logger.info("🔍 Validating exploit...")
            validation_result = self.validator.validate_exploit(
                exploit_code,
                f"{finding.rule_id}_{finding.start_line}"
            )

            exploit_compiled = validation_result.success

            # Refine if needed
            while not validation_result.success and refinement_count < max_refinement:
                refinement_count += 1
                self.logger.info(f"🔄 Refining exploit (attempt {refinement_count}/{max_refinement})...")

                # TODO: Implement refinement using multi-turn dialogue
                # For now, just break
                break

        # Save artifacts
        out_dir.mkdir(parents=True, exist_ok=True)

        # Save analysis
        analysis_file = out_dir / f"{finding.rule_id}_{finding.start_line}_analysis.json"
        with open(analysis_file, 'w') as f:
            analysis_data = {
                "finding": asdict(finding),
                "analysis": asdict(analysis),
                "dataflow_validation": asdict(dataflow_validation) if dataflow_validation else None,
            }
            # Add visualization paths if available
            if visualization_paths:
                analysis_data["visualizations"] = {
                    fmt: str(path) for fmt, path in visualization_paths.items()
                }
            json.dump(analysis_data, f, indent=2)

        # Save exploit
        if exploit_code:
            exploit_ext = ".java" if "java" in finding.file_path.lower() else ".py"
            exploit_file = out_dir / f"{finding.rule_id}_{finding.start_line}_exploit{exploit_ext}"
            with open(exploit_file, 'w') as f:
                f.write(exploit_code)
            self.logger.info(f"✓ Exploit saved: {exploit_file}")

        return AutonomousAnalysisResult(
            finding=finding,
            analysis=analysis,
            dataflow_validation=dataflow_validation,
            exploitable=True,
            exploit_code=exploit_code,
            exploit_compiled=exploit_compiled,
            validation_result=asdict(validation_result) if validation_result else None,
            refinement_iterations=refinement_count,
            total_duration_seconds=time.time() - start_time
        )


def main():
    """CLI entry point for testing."""
    import argparse

    parser = argparse.ArgumentParser(description="Autonomous CodeQL Analysis")
    parser.add_argument("--sarif", required=True, help="SARIF file")
    parser.add_argument("--repo", required=True, help="Repository path")
    parser.add_argument("--out", required=True, help="Output directory")
    parser.add_argument("--max-findings", type=int, default=10, help="Max findings to analyze")
    args = parser.parse_args()

    print(f"Loading SARIF: {args.sarif}")
    with open(args.sarif) as f:
        sarif = json.load(f)

    run = sarif["runs"][0]
    results = run["results"]

    print(f"Found {len(results)} findings")
    print(f"Analyzing up to {args.max_findings} findings...")

    for i, result in enumerate(results[:args.max_findings]):
        print(f"\n[{i+1}/{min(len(results), args.max_findings)}] {result.get('ruleId')}")
        # Would need LLM client and validator for full analysis
        # analyzer = AutonomousCodeQLAnalyzer(llm_client, validator)
        # analysis = analyzer.analyze_finding_autonomous(result, run, Path(args.repo), Path(args.out))


if __name__ == "__main__":
    main()
