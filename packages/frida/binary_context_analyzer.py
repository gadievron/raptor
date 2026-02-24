#!/usr/bin/env python3
"""
RAPTOR Binary Context Analyzer

Combines Frida runtime analysis with static analysis of the entire
execution environment:
- Binary dependencies
- Symlinks and TOCTOU
- LD_PRELOAD opportunities
- Environment variables
- SUID/SGID binaries
- File descriptors and IPC

Feeds findings back to:
- Semgrep/CodeQL: Analyze dependency source code
- LLM: Reason about attack surface
- Fuzzing: Target vulnerable components
- Meta-orchestrator: Coordinate comprehensive analysis
"""

import json
import sys
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from packages.frida.scanner import FridaScanner

logger = logging.getLogger("binary-context")


class BinaryContextAnalyzer:
    """
    Analyzes complete binary execution context and feeds findings
    to other RAPTOR tools for comprehensive security assessment.
    """

    def __init__(self, binary_path: str):
        """
        Initialize binary context analyzer.

        Args:
            binary_path: Path to binary to analyze
        """
        self.binary_path = Path(binary_path)
        self.frida_scanner = FridaScanner()
        self.context = {
            'libraries': [],
            'dependencies': {},
            'symlinks': [],
            'env_vars': {},
            'suid_sgid': False,
            'file_descriptors': [],
            'ipc_mechanisms': [],
            'toctou_risks': [],
            'ld_preload_opportunities': []
        }

    def analyze_static_dependencies(self) -> List[str]:
        """
        Analyze static dependencies using ldd/otool.

        Returns:
            List of dependency paths
        """
        logger.info("Analyzing static dependencies...")

        dependencies = []

        try:
            # Use ldd on Linux, otool on macOS
            if sys.platform == 'darwin':
                result = subprocess.run(
                    ['otool', '-L', str(self.binary_path)],
                    capture_output=True,
                    text=True
                )
            else:
                result = subprocess.run(
                    ['ldd', str(self.binary_path)],
                    capture_output=True,
                    text=True
                )

            for line in result.stdout.splitlines():
                line = line.strip()
                if '=>' in line:
                    # Linux: libname.so => /path/to/lib
                    parts = line.split('=>')
                    if len(parts) >= 2:
                        dep_path = parts[1].strip().split()[0]
                        dependencies.append(dep_path)
                elif line.startswith('/'):
                    # macOS: /path/to/lib
                    dep_path = line.split()[0]
                    dependencies.append(dep_path)

            self.context['dependencies']['static'] = dependencies
            logger.info(f"Found {len(dependencies)} static dependencies")

            return dependencies

        except Exception as e:
            logger.error(f"Failed to analyze static dependencies: {e}")
            return []

    def check_suid_sgid(self) -> Dict[str, Any]:
        """
        Check if binary has SUID/SGID bits set.

        Returns:
            Dict with SUID/SGID status
        """
        logger.info("Checking SUID/SGID bits...")

        import stat

        try:
            st = self.binary_path.stat()
            is_suid = bool(st.st_mode & stat.S_ISUID)
            is_sgid = bool(st.st_mode & stat.S_ISGID)

            self.context['suid_sgid'] = {
                'suid': is_suid,
                'sgid': is_sgid,
                'owner': st.st_uid,
                'group': st.st_gid,
                'permissions': oct(st.st_mode)
            }

            if is_suid or is_sgid:
                logger.warning(f"SUID/SGID binary detected: SUID={is_suid}, SGID={is_sgid}")

            return self.context['suid_sgid']

        except Exception as e:
            logger.error(f"Failed to check SUID/SGID: {e}")
            return {}

    def find_symlinks(self) -> List[Dict[str, str]]:
        """
        Find symlinks related to the binary.

        Returns:
            List of symlink info
        """
        logger.info("Searching for symlinks...")

        symlinks = []

        # Check if binary itself is a symlink
        if self.binary_path.is_symlink():
            target = self.binary_path.resolve()
            symlinks.append({
                'path': str(self.binary_path),
                'target': str(target),
                'type': 'binary'
            })
            logger.warning(f"Binary is symlink: {self.binary_path} -> {target}")

        # Check dependencies for symlinks
        for dep_path in self.context['dependencies'].get('static', []):
            dep = Path(dep_path)
            if dep.exists() and dep.is_symlink():
                target = dep.resolve()
                symlinks.append({
                    'path': str(dep),
                    'target': str(target),
                    'type': 'dependency'
                })

        self.context['symlinks'] = symlinks
        logger.info(f"Found {len(symlinks)} symlinks")

        return symlinks

    def check_ld_preload_opportunities(self) -> List[Dict[str, Any]]:
        """
        Identify LD_PRELOAD injection opportunities.

        Returns:
            List of potential injection points
        """
        logger.info("Analyzing LD_PRELOAD opportunities...")

        opportunities = []

        # Check if binary uses any hookable functions
        hookable_functions = [
            'malloc', 'free', 'read', 'write', 'open', 'close',
            'socket', 'connect', 'send', 'recv', 'system', 'exec'
        ]

        try:
            if sys.platform == 'darwin':
                result = subprocess.run(
                    ['nm', '-u', str(self.binary_path)],
                    capture_output=True,
                    text=True
                )
            else:
                result = subprocess.run(
                    ['nm', '-D', str(self.binary_path)],
                    capture_output=True,
                    text=True
                )

            for line in result.stdout.splitlines():
                for func in hookable_functions:
                    if func in line:
                        opportunities.append({
                            'function': func,
                            'risk': 'Can be intercepted via LD_PRELOAD',
                            'impact': 'High if SUID/SGID'
                        })

            self.context['ld_preload_opportunities'] = opportunities
            logger.info(f"Found {len(opportunities)} LD_PRELOAD opportunities")

            return opportunities

        except Exception as e:
            logger.error(f"Failed to analyze LD_PRELOAD opportunities: {e}")
            return []

    def run_frida_analysis(self, duration: int = 30) -> Dict[str, Any]:
        """
        Run Frida with binary-environment template.

        Args:
            duration: How long to run analysis

        Returns:
            Frida findings
        """
        logger.info(f"Running Frida analysis for {duration}s...")

        try:
            self.frida_scanner.spawn_process(str(self.binary_path))
            self.frida_scanner.load_template('binary-environment')
            self.frida_scanner.resume_process()

            import time
            time.sleep(duration)

            self.frida_scanner.detach()

            # Extract runtime context
            for finding in self.frida_scanner.findings:
                if finding.get('type') == 'libraries':
                    self.context['libraries'] = finding.get('data', [])
                elif finding.get('type') == 'dependency_tree':
                    self.context['dependencies']['runtime'] = finding.get('data', {})
                elif finding.get('title') == 'Potential TOCTOU Vulnerability':
                    self.context['toctou_risks'].append(finding.get('details', {}))

            logger.info(f"Frida analysis complete: {len(self.frida_scanner.findings)} findings")

            return {'findings': self.frida_scanner.findings}

        except Exception as e:
            logger.error(f"Frida analysis failed: {e}")
            return {}

    def feed_to_static_analysis(self) -> List[str]:
        """
        Generate list of source files to analyze with Semgrep/CodeQL.

        Returns:
            List of paths to analyze
        """
        logger.info("Identifying source files for static analysis...")

        sources_to_analyze = []

        # Analyze all dependencies
        all_deps = (
            self.context['dependencies'].get('static', []) +
            list(self.context['dependencies'].get('runtime', {}).keys())
        )

        for dep_path in all_deps:
            dep = Path(dep_path)
            if dep.exists():
                sources_to_analyze.append(str(dep))

                # Also check if source is available (e.g., in /usr/src)
                # This is simplified - real implementation would map binaries to source
                logger.info(f"Dependency to analyze: {dep}")

        return sources_to_analyze

    def generate_attack_surface_report(self) -> Dict[str, Any]:
        """
        Generate comprehensive attack surface report.

        Returns:
            Attack surface analysis
        """
        logger.info("Generating attack surface report...")

        attack_surface = {
            'summary': {
                'binary': str(self.binary_path),
                'suid_sgid': self.context['suid_sgid'],
                'total_dependencies': len(self.context['dependencies'].get('static', [])),
                'symlinks': len(self.context['symlinks']),
                'toctou_risks': len(self.context['toctou_risks']),
                'ld_preload_opportunities': len(self.context['ld_preload_opportunities'])
            },
            'high_priority_risks': [],
            'recommendations': []
        }

        # Identify high-priority risks
        if self.context['suid_sgid'].get('suid') or self.context['suid_sgid'].get('sgid'):
            attack_surface['high_priority_risks'].append({
                'risk': 'SUID/SGID Binary',
                'severity': 'critical',
                'description': 'All vulnerabilities become privilege escalation'
            })

        if self.context['toctou_risks']:
            attack_surface['high_priority_risks'].append({
                'risk': 'TOCTOU Vulnerabilities',
                'severity': 'high',
                'count': len(self.context['toctou_risks']),
                'description': 'Race conditions in file operations'
            })

        if self.context['ld_preload_opportunities']:
            attack_surface['high_priority_risks'].append({
                'risk': 'LD_PRELOAD Injection',
                'severity': 'high' if self.context['suid_sgid'] else 'medium',
                'count': len(self.context['ld_preload_opportunities']),
                'description': 'Library injection attack vectors'
            })

        # Generate recommendations
        attack_surface['recommendations'].append(
            'Run static analysis on all dependencies'
        )

        if self.context['toctou_risks']:
            attack_surface['recommendations'].append(
                'Fix TOCTOU vulnerabilities by using openat() family functions'
            )

        if self.context['suid_sgid']:
            attack_surface['recommendations'].append(
                'CRITICAL: All findings in this binary are privilege escalation risks'
            )

        return attack_surface

    def run_comprehensive_analysis(self, frida_duration: int = 30) -> Dict[str, Any]:
        """
        Run complete binary context analysis.

        Args:
            frida_duration: How long to run Frida

        Returns:
            Complete analysis results
        """
        logger.info("="*70)
        logger.info("BINARY CONTEXT ANALYSIS")
        logger.info("="*70)
        logger.info(f"Binary: {self.binary_path}")
        logger.info("="*70)

        # Step 1: Static analysis
        self.analyze_static_dependencies()
        self.check_suid_sgid()
        self.find_symlinks()
        self.check_ld_preload_opportunities()

        # Step 2: Dynamic analysis
        self.run_frida_analysis(frida_duration)

        # Step 3: Generate reports
        attack_surface = self.generate_attack_surface_report()
        sources_to_analyze = self.feed_to_static_analysis()

        # Step 4: Output results
        results = {
            'context': self.context,
            'attack_surface': attack_surface,
            'sources_for_static_analysis': sources_to_analyze,
            'frida_findings': self.frida_scanner.findings
        }

        logger.info("="*70)
        logger.info("ANALYSIS COMPLETE")
        logger.info("="*70)
        logger.info(f"Dependencies: {len(self.context['dependencies'].get('static', []))}")
        logger.info(f"TOCTOU risks: {len(self.context['toctou_risks'])}")
        logger.info(f"LD_PRELOAD opportunities: {len(self.context['ld_preload_opportunities'])}")
        logger.info(f"Symlinks: {len(self.context['symlinks'])}")
        logger.info("="*70)

        return results


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="RAPTOR Binary Context Analyzer"
    )
    parser.add_argument('--binary', required=True,
                       help='Binary to analyze')
    parser.add_argument('--duration', type=int, default=30,
                       help='Frida analysis duration (seconds)')
    parser.add_argument('--out', help='Output file for results')

    args = parser.parse_args()

    analyzer = BinaryContextAnalyzer(args.binary)
    results = analyzer.run_comprehensive_analysis(args.duration)

    # Save results
    if args.out:
        output_path = Path(args.out)
    else:
        import time
        output_path = Path('out') / f'binary_context_{int(time.time())}.json'

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\n✓ Analysis complete: {output_path}")

    # Print summary
    print("\nATTACK SURFACE SUMMARY:")
    print(json.dumps(results['attack_surface'], indent=2))

    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())
