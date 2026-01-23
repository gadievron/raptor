#!/usr/bin/env python3
"""
Autonomous Web Security Scanner

Combines crawling, fuzzing, and LLM analysis for complete web app testing.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any

# Add paths for cross-package imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from core.logging import get_logger
from packages.llm_analysis.llm.providers import LLMProvider
from packages.web.client import WebClient
from packages.web.crawler import WebCrawler
from packages.web.fuzzer import WebFuzzer

logger = get_logger()


class WebScanner:
    """Fully autonomous web application security scanner."""

    def __init__(self, base_url: str, llm: LLMProvider, out_dir: Path, verify_ssl: bool = True):
        self.base_url = base_url
        self.llm = llm
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.client = WebClient(base_url, verify_ssl=verify_ssl)
        self.crawler = WebCrawler(self.client)
        self.fuzzer = WebFuzzer(self.client, llm)

        logger.info(f"Web scanner initialized for {base_url} (verify_ssl={verify_ssl})")

    def scan(self) -> Dict[str, Any]:
        """
        Run complete autonomous web security scan.

        Returns:
            Scan results with findings
        """
        logger.info("Starting autonomous web security scan")

        # Phase 1: Discovery
        logger.info("Phase 1: Web Discovery and Crawling")
        crawl_results = self.crawler.crawl(self.base_url)

        # Save crawl results
        crawl_file = self.out_dir / "crawl_results.json"
        with open(crawl_file, 'w') as f:
            json.dump(crawl_results, f, indent=2)

        logger.info(f"Discovery complete: {crawl_results['stats']}")

        # Phase 2: Intelligent Fuzzing
        logger.info("Phase 2: Intelligent Fuzzing")
        fuzzing_findings = []

        # Fuzz all discovered parameters
        for param in crawl_results['discovered_parameters']:
            findings = self.fuzzer.fuzz_parameter(
                self.base_url,
                param,
                vulnerability_types=['sqli', 'xss', 'command_injection']
            )
            fuzzing_findings.extend(findings)

        # Phase 3: Generate Report
        logger.info("Phase 3: Generating Security Report")
        report = {
            'target': self.base_url,
            'discovery': crawl_results['stats'],
            'findings': fuzzing_findings,
            'total_vulnerabilities': len(fuzzing_findings),
        }

        # Save report
        report_file = self.out_dir / "web_scan_report.json"
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Web scan complete. Found {len(fuzzing_findings)} potential vulnerabilities")
        logger.info(f"Report saved to {report_file}")

        return report


def main():
    """CLI entry point for web scanner."""
    import argparse
    import time
    from core.config import RaptorConfig

    parser = argparse.ArgumentParser(
        description="RAPTOR Web Application Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan a web application
  python3 scanner.py --url https://example.com

  # Scan with custom output directory
  python3 scanner.py --url http://localhost:3000 --out /path/to/output
        """
    )

    parser.add_argument("--url", required=True, help="Target web application URL")
    parser.add_argument("--out", help="Output directory for results")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum crawl depth (default: 3)")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages to crawl (default: 50)")
    parser.add_argument("--insecure", action="store_true", help="Skip SSL/TLS certificate verification (INSECURE but you know what you are doing, right?)")

    args = parser.parse_args()

    # Determine output directory
    if args.out:
        out_dir = Path(args.out)
    else:
        timestamp = int(time.time())
        out_dir = RaptorConfig.get_out_dir() / f"web_scan_{timestamp}"

    out_dir.mkdir(parents=True, exist_ok=True)

    print("\n" + "=" * 70)
    print("RAPTOR WEB APPLICATION SECURITY SCANNER")
    print("=" * 70)
    print(f"Target: {args.url}")
    print(f"Output: {out_dir}")
    print(f"Max depth: {args.max_depth}")
    print(f"Max pages: {args.max_pages}")
    print("=" * 70 + "\n")

    logger.info("=" * 70)
    logger.info("RAPTOR WEB SCAN STARTED")
    logger.info("=" * 70)
    logger.info(f"Target: {args.url}")
    logger.info(f"Output: {out_dir}")

    # Initialize LLM client with multi-model support, fallback, and retry
    try:
        from packages.llm_analysis.llm.client import LLMClient
        from packages.llm_analysis.llm.config import LLMConfig

        llm_config = LLMConfig()
        llm = LLMClient(llm_config)
        logger.info("LLM client initialized")
    except Exception as e:
        print(f"\n⚠️  Warning: Could not initialize LLM client: {e}")
        print("    Web scanning will work but fuzzing will be limited")
        logger.warning(f"LLM initialization failed: {e}")
        # Create a dummy LLM for basic scanning
        llm = None

    # Run scan
    verify_ssl = not args.insecure
    scanner = WebScanner(args.url, llm, out_dir, verify_ssl=verify_ssl)

    try:
        results = scanner.scan()

        print("\n" + "=" * 70)
        print("SCAN COMPLETE")
        print("=" * 70)
        print(f"✓ Pages crawled: {results['discovery'].get('total_pages', 0)}")
        print(f"✓ Parameters found: {results['discovery'].get('total_parameters', 0)}")
        print(f"✓ Vulnerabilities found: {results['total_vulnerabilities']}")
        print(f"\n📁 Results saved to: {out_dir}")
        print(f"   - Crawl results: {out_dir}/crawl_results.json")
        print(f"   - Security report: {out_dir}/web_scan_report.json")
        print("=" * 70 + "\n")

        logger.info("=" * 70)
        logger.info("WEB SCAN COMPLETE")
        logger.info("=" * 70)
        logger.info(f"Vulnerabilities found: {results['total_vulnerabilities']}")

        return 0 if results['total_vulnerabilities'] == 0 else 1

    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        logger.warning("Scan interrupted by user")
        return 130
    except Exception as e:
        print(f"\n❌ Scan failed: {e}")
        logger.error(f"Scan failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
