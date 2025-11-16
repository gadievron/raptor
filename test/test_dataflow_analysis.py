#!/usr/bin/env python3
"""
Test script to demonstrate dataflow-aware vulnerability analysis.

This shows how RAPTOR now leverages CodeQL dataflow paths for smarter analysis.
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from core.sarif.parser import parse_sarif_findings
from packages.llm_analysis.agent import VulnerabilityContext

def main():
    print("=" * 80)
    print("RAPTOR Dataflow-Aware Analysis Test")
    print("=" * 80)

    # Load SARIF with dataflow paths
    sarif_path = Path("out/raptor_acme-healthcare-main_20251114_100855/codeql/codeql_java.sarif")

    if not sarif_path.exists():
        print(f"\n❌ SARIF file not found: {sarif_path}")
        print("\nPlease run a CodeQL scan first:")
        print("  python3 raptor_agentic.py --repo <path> --codeql --languages java")
        return 1

    print(f"\n[1] Loading SARIF file: {sarif_path.name}")
    findings = parse_sarif_findings(sarif_path)

    print(f"\n[2] Found {len(findings)} total findings")
    findings_with_dataflow = [f for f in findings if f.get('has_dataflow')]
    print(f"    {len(findings_with_dataflow)} have dataflow paths")

    if not findings_with_dataflow:
        print("\n⚠️  No dataflow findings found in SARIF")
        return 1

    # Pick the first dataflow finding
    finding = findings_with_dataflow[0]

    print(f"\n[3] Testing with finding: {finding['rule_id']}")
    print(f"    Message: {finding['message'][:80]}...")

    # Create VulnerabilityContext
    repo_path = Path("/Users/daniel/O365/CSR/Code/CodeQL-Crypto-Research/GHUniverse/acme-healthcare-main")
    vuln = VulnerabilityContext(finding, repo_path)

    print(f"\n[4] Vulnerability Context:")
    print(f"    Finding ID: {vuln.finding_id[:50]}...")
    print(f"    Has dataflow: {vuln.has_dataflow}")
    print(f"    File: {vuln.file_path}")
    print(f"    Lines: {vuln.start_line}-{vuln.end_line}")

    # Extract dataflow
    if vuln.has_dataflow:
        print(f"\n[5] Extracting dataflow path...")
        if vuln.extract_dataflow():
            print(f"    ✓ Dataflow extracted successfully")
            print(f"\n    SOURCE:")
            print(f"      Location: {vuln.dataflow_source['file']}:{vuln.dataflow_source['line']}")
            print(f"      Label: {vuln.dataflow_source['label']}")
            print(f"      Code snippet:")
            for line in vuln.dataflow_source['code'].split('\n')[:5]:
                print(f"        {line}")

            if vuln.dataflow_steps:
                print(f"\n    INTERMEDIATE STEPS: {len(vuln.dataflow_steps)}")
                for i, step in enumerate(vuln.dataflow_steps, 1):
                    marker = "🛡️" if step['is_sanitizer'] else "⚙️"
                    print(f"      {marker} Step {i}: {step['label']}")
                    print(f"         {step['file']}:{step['line']}")

            print(f"\n    SINK:")
            print(f"      Location: {vuln.dataflow_sink['file']}:{vuln.dataflow_sink['line']}")
            print(f"      Label: {vuln.dataflow_sink['label']}")
            print(f"      Code snippet:")
            for line in vuln.dataflow_sink['code'].split('\n')[:5]:
                print(f"        {line}")

            if vuln.sanitizers_found:
                print(f"\n    ⚠️  SANITIZERS DETECTED:")
                for san in vuln.sanitizers_found:
                    print(f"      - {san}")

        else:
            print(f"    ❌ Failed to extract dataflow")
            return 1

    print(f"\n[6] What happens next in LLM analysis:")
    print(f"\n    The LLM will receive:")
    print(f"    ✓ Complete attack path from source to sink")
    print(f"    ✓ Code at each step in the dataflow")
    print(f"    ✓ Identification of sanitizers")
    print(f"    ✓ Specific questions about:")
    print(f"      - Is source attacker-controlled?")
    print(f"      - Are sanitizers effective?")
    print(f"      - How to bypass sanitizers?")
    print(f"      - Is the complete path exploitable?")

    print(f"\n[7] Example LLM Prompt Enhancement:")
    print(f"\n    BEFORE (without dataflow):")
    print(f"    ------------------------")
    print(f"    'Analyze this vulnerability at line {vuln.start_line}'")
    print(f"    '+ 50 lines of context'")

    print(f"\n    AFTER (with dataflow):")
    print(f"    ------------------------")
    print(f"    'SOURCE: {vuln.dataflow_source['label']}'")
    print(f"    '+ code showing where tainted data originates'")
    print(f"    ''")
    for i, step in enumerate(vuln.dataflow_steps, 1):
        print(f"    'STEP {i}: {step['label']}'")
        print(f"    '+ code showing transformation'")
        print(f"    ''")
    print(f"    'SINK: {vuln.dataflow_sink['label']}'")
    print(f"    '+ code showing dangerous operation'")
    print(f"    ''")
    print(f"    'Q: Is the source attacker-controlled?'")
    print(f"    'Q: Are sanitizers effective?'")
    print(f"    'Q: What's the exploit path?'")

    print(f"\n{'=' * 80}")
    print(f"✓ Dataflow-aware analysis is ready!")
    print(f"{'=' * 80}")

    print(f"\n💡 To see it in action:")
    print(f"   python3 raptor_agentic.py \\")
    print(f"       --repo {repo_path} \\")
    print(f"       --codeql \\")
    print(f"       --languages java \\")
    print(f"       --max-findings 3")

    print(f"\n   The LLM analysis will now be 10x smarter about exploitability!")
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
