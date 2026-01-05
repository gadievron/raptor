#!/usr/bin/env python3
"""
RAPTOR Finding Normalizer

Converts outputs from all RAPTOR tools into a unified format
that the meta-orchestrator and LLM can understand.

Unified Finding Format:
{
    "id": "unique-id",
    "tool": "semgrep|codeql|frida|afl|web",
    "severity": "critical|high|medium|low|info",
    "title": "Human-readable title",
    "description": "What was found",
    "location": {
        "file": "path/to/file.py",
        "line": 123,
        "function": "authenticate",
        "address": "0x12345" (for binaries)
    },
    "category": "injection|crypto|auth|memory|race|...",
    "cwe": "CWE-89",
    "evidence": {
        "static": {...},  # From Semgrep/CodeQL
        "dynamic": {...}, # From Frida
        "fuzzing": {...}  # From AFL
    },
    "confidence": 0.95,
    "exploitability": "high|medium|low",
    "context": {
        "dependencies": [],
        "env_vars": {},
        "runtime_behavior": {},
        ...
    }
}
"""

import json
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger("finding-normalizer")


class UnifiedFinding:
    """Represents a security finding in unified format."""

    def __init__(self):
        self.id = None
        self.tool = None
        self.severity = None
        self.title = None
        self.description = None
        self.location = {}
        self.category = None
        self.cwe = None
        self.evidence = {'static': {}, 'dynamic': {}, 'fuzzing': {}}
        self.confidence = 0.0
        self.exploitability = None
        self.context = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'tool': self.tool,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'location': self.location,
            'category': self.category,
            'cwe': self.cwe,
            'evidence': self.evidence,
            'confidence': self.confidence,
            'exploitability': self.exploitability,
            'context': self.context
        }


class FindingNormalizer:
    """Normalizes findings from all RAPTOR tools."""

    def __init__(self):
        self.findings: List[UnifiedFinding] = []
        self.finding_id_counter = 0

    def parse_semgrep(self, sarif_path: Path) -> List[UnifiedFinding]:
        """
        Parse Semgrep SARIF output.

        Args:
            sarif_path: Path to SARIF file

        Returns:
            List of unified findings
        """
        logger.info(f"Parsing Semgrep output: {sarif_path}")

        findings = []

        try:
            with open(sarif_path) as f:
                sarif = json.load(f)

            for run in sarif.get('runs', []):
                for result in run.get('results', []):
                    finding = UnifiedFinding()
                    finding.id = f"semgrep-{self.finding_id_counter}"
                    self.finding_id_counter += 1
                    finding.tool = 'semgrep'

                    # Map severity
                    level = result.get('level', 'warning')
                    finding.severity = self._map_severity(level)

                    # Extract info
                    finding.title = result.get('message', {}).get('text', 'Unknown')
                    finding.description = result.get('message', {}).get('text', '')

                    # Location
                    if result.get('locations'):
                        loc = result['locations'][0]['physicalLocation']
                        finding.location = {
                            'file': loc.get('artifactLocation', {}).get('uri', ''),
                            'line': loc.get('region', {}).get('startLine', 0)
                        }

                    # Category/CWE
                    rule_id = result.get('ruleId', '')
                    finding.category = self._extract_category(rule_id)

                    # Evidence
                    finding.evidence['static'] = {
                        'rule_id': rule_id,
                        'snippet': result.get('message', {}).get('text', '')
                    }

                    finding.confidence = 0.85  # Semgrep has good precision

                    findings.append(finding)

            logger.info(f"Parsed {len(findings)} Semgrep findings")
            return findings

        except Exception as e:
            logger.error(f"Failed to parse Semgrep: {e}")
            return []

    def parse_codeql(self, sarif_path: Path) -> List[UnifiedFinding]:
        """
        Parse CodeQL SARIF output.

        Args:
            sarif_path: Path to SARIF file

        Returns:
            List of unified findings
        """
        logger.info(f"Parsing CodeQL output: {sarif_path}")

        findings = []

        try:
            with open(sarif_path) as f:
                sarif = json.load(f)

            for run in sarif.get('runs', []):
                for result in run.get('results', []):
                    finding = UnifiedFinding()
                    finding.id = f"codeql-{self.finding_id_counter}"
                    self.finding_id_counter += 1
                    finding.tool = 'codeql'

                    # Severity
                    level = result.get('level', 'warning')
                    finding.severity = self._map_severity(level)

                    # Info
                    finding.title = result.get('message', {}).get('text', 'Unknown')
                    finding.description = result.get('message', {}).get('text', '')

                    # Location
                    if result.get('locations'):
                        loc = result['locations'][0]['physicalLocation']
                        finding.location = {
                            'file': loc.get('artifactLocation', {}).get('uri', ''),
                            'line': loc.get('region', {}).get('startLine', 0)
                        }

                    # CWE
                    rule = result.get('rule', {})
                    properties = rule.get('properties', {})
                    if 'cwe' in properties:
                        finding.cwe = properties['cwe']

                    # Evidence
                    finding.evidence['static'] = {
                        'query': result.get('ruleId', ''),
                        'dataflow': result.get('codeFlows', [])
                    }

                    finding.confidence = 0.95  # CodeQL has very high precision

                    findings.append(finding)

            logger.info(f"Parsed {len(findings)} CodeQL findings")
            return findings

        except Exception as e:
            logger.error(f"Failed to parse CodeQL: {e}")
            return []

    def parse_frida(self, json_path: Path) -> List[UnifiedFinding]:
        """
        Parse Frida JSON output.

        Args:
            json_path: Path to Frida report

        Returns:
            List of unified findings
        """
        logger.info(f"Parsing Frida output: {json_path}")

        findings = []

        try:
            with open(json_path) as f:
                data = json.load(f)

            for frida_finding in data.get('findings', []):
                finding = UnifiedFinding()
                finding.id = f"frida-{self.finding_id_counter}"
                self.finding_id_counter += 1
                finding.tool = 'frida'

                # Severity
                finding.severity = frida_finding.get('level', 'info')

                # Info
                finding.title = frida_finding.get('title', 'Unknown')
                finding.description = str(frida_finding.get('details', ''))

                # Category
                finding.category = self._categorize_frida_finding(finding.title)

                # Evidence
                finding.evidence['dynamic'] = {
                    'runtime_observation': frida_finding.get('details', {}),
                    'timestamp': frida_finding.get('timestamp', 0)
                }

                # Context from binary analysis
                if 'libraries' in data:
                    finding.context['loaded_libraries'] = data['libraries']
                if 'dependency_tree' in data:
                    finding.context['dependencies'] = data['dependency_tree']

                finding.confidence = 0.90  # Runtime observation is reliable

                findings.append(finding)

            logger.info(f"Parsed {len(findings)} Frida findings")
            return findings

        except Exception as e:
            logger.error(f"Failed to parse Frida: {e}")
            return []

    def parse_afl(self, crashes_dir: Path) -> List[UnifiedFinding]:
        """
        Parse AFL++ crashes.

        Args:
            crashes_dir: Directory with crash files

        Returns:
            List of unified findings
        """
        logger.info(f"Parsing AFL crashes: {crashes_dir}")

        findings = []

        try:
            if not crashes_dir.exists():
                return findings

            crash_files = list(crashes_dir.glob('id:*'))

            for crash_file in crash_files:
                finding = UnifiedFinding()
                finding.id = f"afl-{self.finding_id_counter}"
                self.finding_id_counter += 1
                finding.tool = 'afl'
                finding.severity = 'high'  # Crashes are always serious

                finding.title = f"Crash: {crash_file.name}"
                finding.description = "AFL++ discovered a crash"

                finding.category = 'memory'  # Most fuzzing finds are memory issues

                finding.evidence['fuzzing'] = {
                    'crash_file': str(crash_file),
                    'crash_id': crash_file.name
                }

                finding.confidence = 1.0  # Crash is definite

                findings.append(finding)

            logger.info(f"Parsed {len(findings)} AFL crashes")
            return findings

        except Exception as e:
            logger.error(f"Failed to parse AFL: {e}")
            return []

    def merge_findings(self) -> List[UnifiedFinding]:
        """
        Merge related findings from different tools.

        For example:
        - Semgrep finds SQL injection
        - Frida confirms it at runtime
        - Merge into single high-confidence finding

        Returns:
            Merged findings
        """
        logger.info("Merging related findings...")

        merged = []

        # Group by location
        by_location = {}

        for finding in self.findings:
            file = finding.location.get('file', 'unknown')
            line = finding.location.get('line', 0)
            key = f"{file}:{line}"

            if key not in by_location:
                by_location[key] = []
            by_location[key].append(finding)

        # Merge findings at same location
        for location, group in by_location.items():
            if len(group) == 1:
                merged.append(group[0])
            else:
                # Multiple tools found issue at same location
                merged_finding = group[0]  # Start with first
                merged_finding.id = f"merged-{location}"

                # Combine evidence
                for other in group[1:]:
                    if other.tool == 'frida':
                        merged_finding.evidence['dynamic'].update(other.evidence.get('dynamic', {}))
                    elif other.tool in ['semgrep', 'codeql']:
                        merged_finding.evidence['static'].update(other.evidence.get('static', {}))
                    elif other.tool == 'afl':
                        merged_finding.evidence['fuzzing'].update(other.evidence.get('fuzzing', {}))

                # Upgrade confidence if multiple tools agree
                merged_finding.confidence = min(0.99, merged_finding.confidence + 0.1 * len(group))

                # Upgrade severity if confirmed dynamically
                if any(f.tool == 'frida' for f in group):
                    merged_finding.exploitability = 'high'

                merged.append(merged_finding)

        logger.info(f"Merged into {len(merged)} findings")
        return merged

    def _map_severity(self, level: str) -> str:
        """Map tool severity to unified severity."""
        mapping = {
            'error': 'high',
            'warning': 'medium',
            'note': 'low',
            'none': 'info'
        }
        return mapping.get(level.lower(), 'medium')

    def _extract_category(self, rule_id: str) -> str:
        """Extract category from rule ID."""
        if 'sql' in rule_id.lower():
            return 'injection'
        elif 'xss' in rule_id.lower():
            return 'injection'
        elif 'crypto' in rule_id.lower():
            return 'crypto'
        elif 'auth' in rule_id.lower():
            return 'auth'
        else:
            return 'unknown'

    def _categorize_frida_finding(self, title: str) -> str:
        """Categorize Frida finding by title."""
        title_lower = title.lower()

        if 'toctou' in title_lower:
            return 'race'
        elif 'ssl' in title_lower or 'crypto' in title_lower:
            return 'crypto'
        elif 'memory' in title_lower or 'leak' in title_lower:
            return 'memory'
        elif 'suid' in title_lower or 'setuid' in title_lower:
            return 'privilege'
        else:
            return 'runtime'

    def normalize_all(self, semgrep_sarif: Optional[Path] = None,
                     codeql_sarif: Optional[Path] = None,
                     frida_json: Optional[Path] = None,
                     afl_crashes: Optional[Path] = None) -> List[Dict[str, Any]]:
        """
        Normalize findings from all tools.

        Args:
            semgrep_sarif: Semgrep SARIF path
            codeql_sarif: CodeQL SARIF path
            frida_json: Frida JSON path
            afl_crashes: AFL crashes directory

        Returns:
            List of unified findings as dicts
        """
        self.findings = []

        if semgrep_sarif and semgrep_sarif.exists():
            self.findings.extend(self.parse_semgrep(semgrep_sarif))

        if codeql_sarif and codeql_sarif.exists():
            self.findings.extend(self.parse_codeql(codeql_sarif))

        if frida_json and frida_json.exists():
            self.findings.extend(self.parse_frida(frida_json))

        if afl_crashes and afl_crashes.exists():
            self.findings.extend(self.parse_afl(afl_crashes))

        # Merge related findings
        merged_findings = self.merge_findings()

        return [f.to_dict() for f in merged_findings]


def main():
    """CLI for testing normalizer."""
    import argparse

    parser = argparse.ArgumentParser(description="RAPTOR Finding Normalizer")
    parser.add_argument('--semgrep', help='Semgrep SARIF file')
    parser.add_argument('--codeql', help='CodeQL SARIF file')
    parser.add_argument('--frida', help='Frida JSON file')
    parser.add_argument('--afl', help='AFL crashes directory')
    parser.add_argument('--out', help='Output JSON file')

    args = parser.parse_args()

    normalizer = FindingNormalizer()
    unified = normalizer.normalize_all(
        semgrep_sarif=Path(args.semgrep) if args.semgrep else None,
        codeql_sarif=Path(args.codeql) if args.codeql else None,
        frida_json=Path(args.frida) if args.frida else None,
        afl_crashes=Path(args.afl) if args.afl else None
    )

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(unified, f, indent=2)
        print(f"✓ Normalized {len(unified)} findings to {args.out}")
    else:
        print(json.dumps(unified, indent=2))

    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
