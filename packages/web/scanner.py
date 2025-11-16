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
sys.path.insert(0, str(Path(__file__).parent.parent / "llm-analysis"))

from core.logging import get_logger
from llm.client import LLMClient
from .client import WebClient
from .crawler import WebCrawler
from .fuzzer import WebFuzzer

logger = get_logger()


class WebScanner:
    """Fully autonomous web application security scanner."""

    def __init__(self, base_url: str, llm: LLMClient, out_dir: Path):
        self.base_url = base_url
        self.llm = llm
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components
        self.client = WebClient(base_url)
        self.crawler = WebCrawler(self.client)
        self.fuzzer = WebFuzzer(self.client, llm)

        logger.info(f"Web scanner initialized for {base_url}")

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
